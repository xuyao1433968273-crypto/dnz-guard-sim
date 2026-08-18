#include "dnz_hook.h"
#include "dnz_ept.h"
#include "dnz_pool.h"
#include <string.h>

/* 模型工具：客人 VA 读 QWORD（老师: HV_TranslateGuestVa_Present + Util_Memcpy 8 字节） */
uint64_t dnz_read_guest_qword(uint64_t guest_va)
{
    uint64_t phys = hv_translate_guest_va_present(g_dnz.guest_cr3, guest_va, NULL);
    if (phys == 0 || phys > 0x8000000000ULL) return 0;
    return dnz_load_qword(dnz_phys_ptr(phys));
}

/* 模型工具：置 EPT 冲刷标志（老师: *(v+24768)&=~0x10; *(v+24668)=3） */
static void dnz_mark_ept_flush(void)
{
    if (g_dnz.vcpu) {
        g_dnz.vcpu->ept_flags &= ~0x10u;
        g_dnz.vcpu->ept_state = 3;
    }
}

/*
 * ============================================================
 * 01742. HV_EptInstallHook (0x140115980)
 * ------------------------------------------------------------
 * 老师注释：Install EPT hook: dual-view entries (exec vs read/write)
 * on primary+shadow EPT roots
 * 流程：
 *   空闲栈弹节点 → 挂到钩子链表头
 *   记录 gpa_idx / hook_pfn
 *   主根条目 → 老师: *v12 & 0x7FFFFFFFFFFFF1FD | 0x8000000000000402
 *   影子根条目 → 老师: (a3<<12) & 0xFFFFFFFFFF000 ^ *v14 & 0x7FF0000000000FFF
 *   置 EPT 冲刷标志
 * ============================================================
 */
bool hv_ept_install_hook(uint64_t *ctx, uint32_t gpa_idx, uint32_t hook_pfn)
{
    if (!g_dnz.hook_free) return false;               /* 老师: !a1[789710] → 0 */

    dnz_hook_node *node = g_dnz.hook_free;
    g_dnz.hook_free = node->next;                     /* 弹栈 */
    node->next = g_dnz.hook_list;                     /* 挂到链表头 */
    g_dnz.hook_list = node;
    node->gpa_idx  = gpa_idx;
    node->hook_pfn = hook_pfn;

    uint64_t gpa = (uint64_t)gpa_idx << 12;

    uint64_t *primary = hv_lookup_ept(ctx, gpa, true);            /* 老师: v12 */
    uint64_t *shadow  = hv_lookup_ept(dnz_root_shadow(), gpa, true); /* 老师: v14 */
    if (!primary || !shadow) {
        dnz_mark_ept_flush();
        return false;
    }

    /* 老师: *v12 = *v12 & 0x7FFFFFFFFFFFF1FD | 0x8000000000000402 */
    *primary = (*primary & 0x7FFFFFFFFFFFF1FDULL) | 0x8000000000000402ULL;
    /* 老师: *v14 = (a3<<12)&0xFFFFFFFFFF000 ^ *v14 & 0x7FF0000000000FFF */
    *shadow = ((uint64_t)hook_pfn << 12) & EPT_ADDR_MASK
              ^ (*shadow & 0x7FF0000000000FFFULL);

    dnz_mark_ept_flush();
    return true;
}

/*
 * ============================================================
 * 01743. HV_EptRemoveHook (0x140115ac0)
 * ------------------------------------------------------------
 * 老师注释：Remove EPT hook: restore identity mapping, free hook list node
 * 流程：按 gpa 找链表节点（含头节点特判）→ 摘除 → 还回空闲栈
 *       主根 → 恢复恒等 (gpa<<12) | 3
 *       影子根 → 老师: (gpa<<12) ^ (*v13 & 0x7FF0000000000FFF | 0x8000000000000000)
 * ============================================================
 */
void hv_ept_remove_hook(uint64_t *ctx, uint32_t gpa_idx)
{
    dnz_hook_node *prev = NULL;
    dnz_hook_node *cur  = g_dnz.hook_list;
    if (!cur) return;                                 /* 老师: !v2 → return */

    while (cur && cur->gpa_idx != gpa_idx) {          /* 老师: 循环找匹配节点 */
        prev = cur;
        cur = cur->next;
    }
    if (!cur) return;

    /* 摘链（老师：把节点从链表挪到空闲栈，保持链表不断） */
    if (prev) prev->next = cur->next;
    else      g_dnz.hook_list = cur->next;
    cur->next = g_dnz.hook_free;
    g_dnz.hook_free = cur;

    uint64_t gpa = (uint64_t)gpa_idx << 12;

    uint64_t *primary = hv_lookup_ept(ctx, gpa, false);
    if (primary) {
        /* 老师: *v10 = (gpa<<12) & 0xFFFFFFFFFF000 ^ (*v10 & 0x7FF00000000001FC | 3) */
        *primary = (gpa & EPT_ADDR_MASK)
                   ^ ((*primary & 0x7FF00000000001FCULL) | 3);
    }
    uint64_t *shadow = hv_lookup_ept(dnz_root_shadow(), gpa, false);
    if (shadow) {
        /* 老师: *v13 = (gpa<<12) ^ (*v13 & 0x7FF0000000000FFF | 0x8000000000000000) */
        *shadow = (gpa & EPT_ADDR_MASK)
                  ^ ((*shadow & 0x7FF0000000000FFFULL) | 0x8000000000000000ULL);
    }
    dnz_mark_ept_flush();
}

/*
 * ============================================================
 * 01744. HV_EptHidePages (0x140115c20)
 * ------------------------------------------------------------
 * 老师注释：Hide pages: remap EPT PFN via g_HvGlobalState hash table;
 * dual-view RW vs X
 * 流程：a2 = 客人 VA（存放 a3 个 QWORD 的 PFN 数组）
 *   逐个：翻译读 8 字节 → v14 = 要藏的 PFN
 *         主根条目 → *v15 & 0x7FFFFFFFFFFFF1FC | 0x8000000000000201
 *         藏页哈希取假帧 v20 = *(g + 8*(v14&0x7FF) + 6311952)
 *         主根条目 PFN 换成假帧
 *         藏页影子根条目 → 指向真实帧 (v14<<12) | 0x203
 * ============================================================
 */
bool hv_ept_hide_pages(uint64_t *ctx, uint64_t guest_va, uint64_t count)
{
    for (uint64_t i = 0; i < count; i++) {
        /* 老师: HV_TranslateGuestVa_Present + Util_Memcpy 读 8 字节 */
        uint64_t pfn_to_hide = dnz_read_guest_qword(guest_va + i * 8);
        if (pfn_to_hide == 0) continue;               /* 老师: !v23 → LABEL_13 */

        uint64_t gpa = pfn_to_hide << 12;
        uint64_t *primary = hv_lookup_ept(ctx, gpa, true);             /* 老师: v15 */
        uint64_t *shadow2 = hv_lookup_ept(dnz_root_shadow2(), gpa, true); /* 老师: v17 */
        if (!primary || !shadow2) break;

        /* 老师: *v15 = *v15 & 0x7FFFFFFFFFFFF1FC | 0x8000000000000201 */
        uint64_t v19 = (*primary & 0x7FFFFFFFFFFFF1FCULL) | 0x8000000000000201ULL;
        /* 老师: v20 = *(g + 8*(v14&0x7FF) + 6311952) —— 哈希表给假帧 */
        uint64_t fake = g_dnz.hide_hash[pfn_to_hide & 0x7FF];
        /* 老师: *v15 = (v20<<12) ^ ((v20<<12)^v19) & 0xFFF0000000000FFF */
        *primary = (fake << 12) ^ (((fake << 12) ^ v19) & 0xFFF0000000000FFFULL);
        /* 老师: *v17 = *v17 & 0x7FF00000000001FC | ((v14&0xFFFFFFFFFF)<<12) | 0x203 */
        *shadow2 = (*shadow2 & 0x7FF00000000001FCULL)
                   | ((pfn_to_hide & 0xFFFFFFFFFFULL) << 12) | 0x203;
    }
    dnz_mark_ept_flush();
    return true;
}

/*
 * ============================================================
 * 01745. HV_EptUnhidePages (0x140115e10)
 * ------------------------------------------------------------
 * 老师：恢复被藏页 —— 主根 → (真实帧<<12) | 3
 *       藏页影子根 → 老师: (帧<<12) | *v19 & 0xFFF00000000001FF | 0x8000000000000003
 * ============================================================
 */
bool hv_ept_unhide_pages(uint64_t *ctx, uint64_t guest_va, uint64_t count)
{
    for (uint64_t i = 0; i < count; i++) {
        uint64_t pfn = dnz_read_guest_qword(guest_va + i * 8);
        if (pfn == 0) continue;

        uint64_t gpa = pfn << 12;
        uint64_t *primary = hv_lookup_ept(ctx, gpa, false);
        if (primary) {
            /* 老师: *v16 = v18 | *v16 & 0x7FF00000000001FC | 3 */
            *primary = (gpa & EPT_ADDR_MASK) | (*primary & 0x7FF00000000001FCULL) | 3;
        }
        uint64_t *shadow2 = hv_lookup_ept(dnz_root_shadow2(), gpa, false);
        if (shadow2) {
            /* 老师: *v19 = v18 | *v19 & 0xFFF00000000001FF | 0x8000000000000003 */
            *shadow2 = (gpa & EPT_ADDR_MASK)
                       | (*shadow2 & 0xFFF00000000001FFULL)
                       | 0x8000000000000003ULL;
        }
    }
    dnz_mark_ept_flush();
    return true;
}

/*
 * ============================================================
 * 03277. HV_RemoveEptHook_Wrapper (0x1401da0b0)
 * ------------------------------------------------------------
 * 老师：遍历全部钩子逐个卸（g_UseRealVmxInstr 走 RealVmx 分支），
 *       按注册位图清位：_interlockedbittestandreset(&dword_14DD8A000[v16>>17], (v16>>12)&0x1F)
 * 模型：把整个链表清空，逐个卸；位图用 hook_count 计数值近似。
 * ============================================================
 */
void hv_remove_ept_hook_wrapper(uint64_t *ctx, bool flush_after)
{
    dnz_hook_node *cur = g_dnz.hook_list;
    while (cur) {
        dnz_hook_node *nx = cur->next;
        hv_ept_remove_hook(ctx, cur->gpa_idx);
        cur = nx;
    }
    g_dnz.hook_count = 0;
    (void)flush_after;
}
