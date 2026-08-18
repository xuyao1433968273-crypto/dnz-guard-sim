#include "dnz_realvmx.h"
#include "dnz_ept.h"
#include "dnz_hook.h"

/* sub_1401E06C6(2, &x) —— 老师代码里的 TLB/EPT 冲刷原语（模型：置冲刷标志） */
static void dnz_flush_invalidate(void)
{
    if (g_dnz.vcpu) {
        g_dnz.vcpu->ept_flags &= ~0x10u;
        g_dnz.vcpu->ept_state = 3;
    }
}

/* sub_1401248E0 —— RealVmx 路径的"查 EPT 条目"（老师：影子 VMCS VMREAD 链）。
 * 模型：直接走 hv_lookup_ept（语义一致）。 */
static uint64_t *dnz_realvmx_lookup(uint64_t *ctx, uint64_t gpa, bool allow_split)
{
    return hv_lookup_ept(ctx, gpa, allow_split);
}

/*
 * ============================================================
 * 01861. HV_EptInstallHook_RealVmx (0x140124cf0)
 * ------------------------------------------------------------
 * 老师核心行：
 *   v5 = sub_1401248E0(a1, a2<<12, a3)
 *   *v5 = (v4<<12) & 0xFFFFFFFFF000 ^ (*v5 & 0xFFFF000000000FF8 | 4) | 0x100000000000000
 *   （v4 = a3 = 双视图页号；0x100000000000000 = bit52，EPT 里为"超级页/大页"标记位）
 * ============================================================
 */
bool hv_ept_install_hook_realvmx(uint64_t *ctx, uint32_t gpa_idx, uint32_t hook_pfn)
{
    uint64_t gpa = (uint64_t)gpa_idx << 12;
    uint64_t *entry = dnz_realvmx_lookup(ctx, gpa, true);
    if (!entry) return false;

    dnz_flush_invalidate();
    /* 老师: *v5 = (a3<<12)&0xFFFFFFFFF000 ^ (*v5 & 0xFFFF000000000FF8|4) | 0x100000000000000 */
    *entry = ((uint64_t)hook_pfn << 12) & 0xFFFFFFFFF000ULL
             ^ ((*entry & 0xFFFF000000000FF8ULL) | 4)
             | 0x100000000000000ULL;
    dnz_flush_invalidate();
    return true;
}

/*
 * ============================================================
 * 01862. HV_EptRemoveHook_RealVmx (0x140124db0)
 * ------------------------------------------------------------
 * 老师核心行：
 *   v9 = sub_1401248E0(a1, a2<<12, 0)
 *   *v9 = (a2<<12) & 0xFFFFFFFFF000 ^ (*v9 & 0xFEFF000000000FF8 | 7)
 * ============================================================
 */
void hv_ept_remove_hook_realvmx(uint64_t *ctx, uint32_t gpa_idx)
{
    uint64_t gpa = (uint64_t)gpa_idx << 12;
    uint64_t *entry = dnz_realvmx_lookup(ctx, gpa, false);
    if (!entry) return;

    dnz_flush_invalidate();
    *entry = (gpa & 0xFFFFFFFFF000ULL)
             ^ ((*entry & 0xFEFF000000000FF8ULL) | 7);
    dnz_flush_invalidate();
}

/*
 * ============================================================
 * 01863. HV_EptHidePages_RealVmx (0x140124ea0)
 * ------------------------------------------------------------
 * 老师核心行（逐条对照）：
 *   主根: *v14 = *v14 & 0xF7FFFFFFFFFFFFF8 | 0x800000000000001
 *         v19 = *(g + 8*(v13&0x7FF) + 6311952) << 12
 *         *v14 = v19 ^ (v19^v18) & 0xFFFF000000000FFF
 *   藏页影子: *v16 = *v16 & 0xFFFF000000000FFF | ((v13&0xFFFFFFFFF)<<12) | 0x800000000000007
 * ============================================================
 */
bool hv_ept_hide_pages_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count)
{
    for (uint64_t i = 0; i < count; i++) {
        uint64_t pfn = dnz_read_guest_qword(guest_va + i * 8);
        if (pfn == 0) continue;

        uint64_t gpa = pfn << 12;
        uint64_t *primary = dnz_realvmx_lookup(ctx, gpa, true);
        uint64_t *shadow2 = dnz_realvmx_lookup(dnz_root_shadow2(), gpa, true);
        if (!primary || !shadow2) break;

        dnz_flush_invalidate();
        uint64_t v18 = (*primary & 0xF7FFFFFFFFFFFFF8ULL) | 0x800000000000001ULL;
        uint64_t fake = g_dnz.hide_hash[pfn & 0x7FF] << 12;
        *primary = fake ^ ((fake ^ v18) & 0xFFFF000000000FFFULL);
        *shadow2 = (*shadow2 & 0xFFFF000000000FFFULL)
                   | ((pfn & 0xFFFFFFFFFULL) << 12) | 0x800000000000007ULL;
        dnz_flush_invalidate();
    }
    return true;
}

/*
 * ============================================================
 * 01864. HV_EptUnhidePages_RealVmx (0x1401250a0)
 * ------------------------------------------------------------
 * 老师核心行：
 *   *v13 = v15 | *v13 & 0xF7FF000000000FFF | 7
 *   *v16 = v15 | *v16 & 0xF7FF000000000FFF | 7
 * ============================================================
 */
bool hv_ept_unhide_pages_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count)
{
    for (uint64_t i = 0; i < count; i++) {
        uint64_t pfn = dnz_read_guest_qword(guest_va + i * 8);
        if (pfn == 0) continue;

        uint64_t gpa = pfn << 12;
        uint64_t v15 = (gpa & EPT_ADDR_MASK);

        uint64_t *primary = dnz_realvmx_lookup(ctx, gpa, false);
        if (primary) {
            dnz_flush_invalidate();
            *primary = v15 | (*primary & 0xF7FF000000000FFFULL) | 7;
            dnz_flush_invalidate();
        }
        uint64_t *shadow2 = dnz_realvmx_lookup(dnz_root_shadow2(), gpa, false);
        if (shadow2) {
            dnz_flush_invalidate();
            *shadow2 = v15 | (*shadow2 & 0xF7FF000000000FFFULL) | 7;
            dnz_flush_invalidate();
        }
    }
    return true;
}

/*
 * ============================================================
 * 01866. HV_EptOpA_RealVmx (0x140125440)
 * ------------------------------------------------------------
 * 老师核心行（条目内存类型/执行位重写）：
 *   v20 = v18 & 0xFF8FFFFFFFFFFFFB | v17
 *   v19 = 0x20000000000000 或 0x40000000000000（内存类型）
 *   v21 = ((v16 & 0xFFFFFFFFFFFFFFF9)<<52) | v19 & 0xFFBFFFFFFFFFFFFF | v20
 *   v22 = 0x40000000000000
 *   v23 = v16 & 0xFF8FFFFFFFFFFFF9 | *v15 & 0xFF8FFFFFFFFFFFF8 | v22 | v21 | 0x80000000000000
 *   若 a4: *v15 = v23 & 0xFFDFFFFFFFFFFFFD
 * ============================================================
 */
bool hv_ept_op_a_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count, bool apply)
{
    (void)apply;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t pfn = dnz_read_guest_qword(guest_va + i * 8);
        if (pfn == 0) continue;

        uint64_t *entry = dnz_realvmx_lookup(ctx, pfn << 12, true);
        if (!entry) break;

        dnz_flush_invalidate();
        /* 老师逐条：v17 = 传入的访问位；模型取条目里原有的低 12 位保留 */
        uint64_t v16 = *entry;
        uint64_t v17 = 0x2ULL;                                  /* RW */
        uint64_t v18 = v16;
        uint64_t v19 = 0x40000000000000ULL;                     /* WT 内存类型 */
        uint64_t v20 = (v18 & 0xFF8FFFFFFFFFFFFBULL) | v17;
        uint64_t v21 = ((v16 & 0xFFFFFFFFFFFFFFF9ULL) << 52)
                       | (v19 & 0xFFBFFFFFFFFFFFFFULL) | v20;
        uint64_t v22 = 0x40000000000000ULL;
        uint64_t v23 = (v16 & 0xFF8FFFFFFFFFFFF9ULL)
                       | (*entry & 0xFF8FFFFFFFFFFFF8ULL)
                       | v22 | v21 | 0x80000000000000ULL;
        *entry = v23 & 0xFFDFFFFFFFFFFFFDULL;
        dnz_flush_invalidate();
    }
    return true;
}

/*
 * ============================================================
 * 01867. HV_EptOpB_RealVmx (0x1401256b0)
 * ------------------------------------------------------------
 * 老师核心行：*v12 = *v12 & 0xFF0FFFFFFFFFFFF8 | 7
 * ============================================================
 */
bool hv_ept_op_b_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count)
{
    for (uint64_t i = 0; i < count; i++) {
        uint64_t pfn = dnz_read_guest_qword(guest_va + i * 8);
        if (pfn == 0) continue;

        uint64_t *entry = dnz_realvmx_lookup(ctx, pfn << 12, false);
        if (!entry) break;

        dnz_flush_invalidate();
        *entry = (*entry & 0xFF0FFFFFFFFFFFF8ULL) | 7;
        dnz_flush_invalidate();
    }
    return true;
}

/*
 * ============================================================
 * 01818 / 01819. HV_Api_Install/RemoveEptHook
 * ------------------------------------------------------------
 * 老师：g_UseRealVmxInstr ? HV_Vmcall(cmd, ...) : HV_Vmmcall(cmd, ...)
 * 模型：直接在两条路径里二选一，返回值 0=成功（老师返回 rdgsbase 结果）。
 * ============================================================
 */
uint64_t hv_api_install_ept_hook(uint64_t gpa_idx, uint64_t hook_pfn)
{
    bool ok = g_dnz.g_use_real_vmx
              ? hv_ept_install_hook_realvmx(dnz_root_primary(), (uint32_t)gpa_idx, (uint32_t)hook_pfn)
              : hv_ept_install_hook(dnz_root_primary(), (uint32_t)gpa_idx, (uint32_t)hook_pfn);
    return ok ? 0 : 1;
}

uint64_t hv_api_remove_ept_hook(uint64_t gpa_idx)
{
    if (g_dnz.g_use_real_vmx)
        hv_ept_remove_hook_realvmx(dnz_root_primary(), (uint32_t)gpa_idx);
    else
        hv_ept_remove_hook(dnz_root_primary(), (uint32_t)gpa_idx);
    return 0;
}
