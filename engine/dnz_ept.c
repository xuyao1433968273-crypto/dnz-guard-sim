#include "dnz_ept.h"
#include "dnz_pool.h"
#include <string.h>
#include <stdio.h>

uint64_t *dnz_root_primary(void) { return g_dnz.ept_primary; }
uint64_t *dnz_root_shadow(void)  { return g_dnz.ept_shadow; }
uint64_t *dnz_root_shadow2(void) { return g_dnz.ept_shadow2; }

/* 模型工具：把 EPT 上下文里的根映射到老师偏移布局。
 * 老师代码里 a1 是一个大上下文，主根在偏移 0（a1）、影子根在 a1+263680、藏页影子在 a1+2109440。 */
uint64_t *dnz_ctx_root(uint64_t *ctx, uint64_t root_kind)
{
    if (ctx == dnz_root_primary()) {
        if (root_kind == 0) return dnz_root_primary();
        if (root_kind == 1) return dnz_root_shadow();
        return dnz_root_shadow2();
    }
    return ctx; /* 模型里其它 ctx 就是根本身 */
}

/*
 * ============================================================
 * 01738. HV_LookupEptEntry (0x140115220)
 * ------------------------------------------------------------
 * 老师结构（逐行分析）：
 *   v6 = (a2>>39)&0x1FF; 读 PML4E；空则返回 0
 *   取 PDPTE；取 PDE 指针
 *   若 PDE 是 2M 大页且允许拆页 → HV_EptSplitLargePage 后重走
 *   返回 PTE 指针（直接映射地址）
 * ============================================================
 */
uint64_t *hv_lookup_ept(uint64_t *root, uint64_t gpa, bool allow_split)
{
    unsigned pml4 = EPT_IDX_PML4(gpa);
    unsigned pdpt = EPT_IDX_PDPT(gpa);
    unsigned pd   = EPT_IDX_PD(gpa);
    unsigned pt   = EPT_IDX_PT(gpa);

    uint64_t pml4e = root[pml4];
    if (!(pml4e & EPT_PRESENT)) return NULL;          /* 老师: !v9 → return 0 */

    uint64_t *pdpt_tbl = (uint64_t *)dnz_phys_ptr(pml4e & EPT_ADDR_MASK);
    uint64_t pdpte = pdpt_tbl[pdpt];
    if (!(pdpte & EPT_PRESENT)) return NULL;

    uint64_t *pd_tbl = (uint64_t *)dnz_phys_ptr(pdpte & EPT_ADDR_MASK);
    uint64_t pde = pd_tbl[pd];

    if ((pde & 0x80) && !(pde & 0x40)) {              /* 2M 大页（bit7=1, bit6=0） */
        if (!allow_split) return NULL;
        if (!hv_ept_split_large_page(root, gpa, false)) return NULL;
        /* 拆页后重走 */
        pml4e = root[pml4];
        if (!(pml4e & EPT_PRESENT)) return NULL;
        pdpt_tbl = (uint64_t *)dnz_phys_ptr(pml4e & EPT_ADDR_MASK);
        pdpte = pdpt_tbl[pdpt];
        if (!(pdpte & EPT_PRESENT)) return NULL;
        pd_tbl = (uint64_t *)dnz_phys_ptr(pdpte & EPT_ADDR_MASK);
        pde = pd_tbl[pd];
    }
    if (!(pde & EPT_PRESENT)) return NULL;

    uint64_t *pt_tbl = (uint64_t *)dnz_phys_ptr(pde & EPT_ADDR_MASK);
    uint64_t entry = pt_tbl[pt];
    if (!(entry & EPT_PRESENT)) return NULL;

    return &pt_tbl[pt];   /* 老师: 返回 PTE 指针 */
}

/*
 * ============================================================
 * 01739. HV_EptSplitLargePage (0x140115400)
 * ------------------------------------------------------------
 * 老师注释原文：Split 2M EPT page to 512x4K; fill PTEs with XD flag
 * from a5; classic split-page prep for EPT hooks
 * 模型：分配 4K 页表 → 512 个 PTE 填帧号 + 属性（a5=1 清 XD）
 * ============================================================
 */
bool hv_ept_split_large_page(uint64_t *root, uint64_t gpa, bool clear_xd)
{
    unsigned pml4 = EPT_IDX_PML4(gpa);
    unsigned pdpt = EPT_IDX_PDPT(gpa);
    unsigned pd   = EPT_IDX_PD(gpa);

    uint64_t pml4e = root[pml4];
    if (!(pml4e & EPT_PRESENT)) return false;

    uint64_t *pdpt_tbl = (uint64_t *)dnz_phys_ptr(pml4e & EPT_ADDR_MASK);
    uint64_t pdpte = pdpt_tbl[pdpt];
    if (!(pdpte & EPT_PRESENT)) return false;

    uint64_t *pd_tbl = (uint64_t *)dnz_phys_ptr(pdpte & EPT_ADDR_MASK);
    uint64_t pde = pd_tbl[pd];
    if (!(pde & 0x80) || (pde & 0x40)) return false;  /* 不是 2M 大页 */

    /* 老师: 从池取页表页；池满写 0x80000212 到退出标志并失败 */
    void *pt_page = dnz_pool_alloc_page();
    if (!pt_page) return false;

    uint64_t base = pde & 0xFFFFFFFFFFE00FFFULL;      /* 大页基址（清低 21 位） */
    /* 老师: memset64(v11, ((a5<<63)^0x8000000000000007)|7, 0x200) */
    uint64_t flags = (clear_xd ? 0x7ULL : (EPT_XD | 0x7ULL));

    uint64_t *ptes = (uint64_t *)pt_page;
    for (int i = 0; i < 512; i++) {
        /* 老师: 每 4 项一组写入 (v14 + base - 偏移) ^ 保留属性位 */
        ptes[i] = (base + (uint64_t)i * DNZ_PAGE_SIZE) | flags;
    }

    /* 老师: *(_QWORD*)v8 = ((v12&0xFFFFFFFFFF)<<12)|7 —— PDE 指向新页表 */
    uint64_t pt_frame = ((uint64_t)(uintptr_t)pt_page - (uint64_t)(uintptr_t)g_dnz_phys) >> 12;
    pd_tbl[pd] = (pt_frame << 12) | 0x7ULL;

    /* 老师收尾: 置 EPT 冲刷标志（24768 &= ~0x10; 24668 = 3） */
    if (g_dnz.vcpu) {
        g_dnz.vcpu->ept_flags &= ~0x10u;
        g_dnz.vcpu->ept_state = 3;
    }
    return true;
}

/*
 * ============================================================
 * 01740. HV_EptEnsureSplitPage (0x140115620)
 * ------------------------------------------------------------
 * 老师：初始化 PDPT + 512×512 项 PD 大页表（低 512GB 恒等映射），
 *       再 HV_EptSplitLargePage(0 / 0x200000 / 0x400000 / 0x600000)
 * 模型：PML4E[0]→PDPT；PDPT[0]→PD；PD 512 项 2M 大页恒等映射 1GB；
 *       拆前 4 个 2M 页。
 * ============================================================
 */
bool hv_ept_ensure_split_page(uint64_t *root, bool clear_xd)
{
    void *pdpt_page = dnz_pool_alloc_page();
    if (!pdpt_page) return false;
    uint64_t pdpt_frame = ((uint64_t)(uintptr_t)pdpt_page - (uint64_t)(uintptr_t)g_dnz_phys) >> 12;
    root[0] = (pdpt_frame << 12) | 0x7ULL;

    void *pd_page = dnz_pool_alloc_page();
    if (!pd_page) return false;
    uint64_t pd_frame = ((uint64_t)(uintptr_t)pd_page - (uint64_t)(uintptr_t)g_dnz_phys) >> 12;
    ((uint64_t *)pdpt_page)[0] = (pd_frame << 12) | 0x7ULL;

    uint64_t *pd_entries = (uint64_t *)pd_page;
    for (int i = 0; i < 512; i++) {
        /* 老师: memset64(v8, 0x87 模式, 0x40000) + 每项步进 0x200000 */
        pd_entries[i] = ((uint64_t)i << 21) | 0x87ULL;
    }

    if (!hv_ept_split_large_page(root, 0x000000ULL, clear_xd)) return false;
    if (!hv_ept_split_large_page(root, 0x200000ULL, clear_xd)) return false;
    if (!hv_ept_split_large_page(root, 0x400000ULL, clear_xd)) return false;
    if (!hv_ept_split_large_page(root, 0x600000ULL, clear_xd)) return false;
    return true;
}

/*
 * ============================================================
 * 01741. HV_EptMapGuestAccess (0x1401157c0)
 * ------------------------------------------------------------
 * 老师：客人访问未映射区域时调用；PML4E 空则分配页表；
 *       建 PDPT 项 + PD 表；PD 填 512 项 2M 大页（恒等映射 1GB）。
 * ============================================================
 */
bool hv_ept_map_guest_access(uint64_t *root, uint64_t gpa, bool clear_xd)
{
    unsigned pml4 = EPT_IDX_PML4(gpa);
    unsigned pdpt = EPT_IDX_PDPT(gpa);

    if (!(root[pml4] & EPT_PRESENT)) {
        void *pdpt_page = dnz_pool_alloc_page();
        if (!pdpt_page) return false;
        uint64_t f = ((uint64_t)(uintptr_t)pdpt_page - (uint64_t)(uintptr_t)g_dnz_phys) >> 12;
        root[pml4] = (f << 12) | 0x7ULL;
    }

    uint64_t *pdpt_tbl = (uint64_t *)dnz_phys_ptr(root[pml4] & EPT_ADDR_MASK);
    if (pdpt_tbl[pdpt] & EPT_PRESENT) return false;   /* 老师: 已映射 → return 0 */

    void *pd_page = dnz_pool_alloc_page();
    if (!pd_page) return false;
    uint64_t pd_frame = ((uint64_t)(uintptr_t)pd_page - (uint64_t)(uintptr_t)g_dnz_phys) >> 12;
    pdpt_tbl[pdpt] = (pd_frame << 12) | 0x7ULL;

    uint64_t *pd_entries = (uint64_t *)pd_page;
    uint64_t region_base = ((uint64_t)gpa >> 30) << 30;
    for (int i = 0; i < 512; i++) {
        pd_entries[i] = (region_base + (uint64_t)i * DNZ_LARGE_PAGE_SIZE)
                        | (clear_xd ? 0x87ULL : (EPT_XD | 0x87ULL));
    }

    if (g_dnz.vcpu) {
        g_dnz.vcpu->ept_flags &= ~0x10u;
        g_dnz.vcpu->ept_state = 3;
    }
    return true;
}

/*
 * ============================================================
 * 01747. HV_EptSplitPage_ClearXD (0x140116020)
 * ------------------------------------------------------------
 * 老师注释：clear XD bit (bit63) on EPT entry for execute-from-guest
 * ============================================================
 */
bool hv_ept_split_page_clear_xd(uint64_t *root, uint64_t guest_va)
{
    uint64_t cr3 = g_dnz.vcpu ? g_dnz.vcpu->guest_cr3 : 0;
    uint64_t phys = hv_translate_guest_va_present(cr3, guest_va, NULL);
    if (phys == 0 || phys > 0x8000000000ULL) return false;

    uint64_t *entry = hv_lookup_ept(dnz_root_shadow2(), phys, true);
    if (!entry) return false;

    if (*entry & EPT_XD) {                            /* 老师: if (v7 < 0) */
        *entry &= 0x7FFFFFFFFFFFFFFFULL;              /* 清 bit63 */
        if (g_dnz.vcpu) {
            g_dnz.vcpu->ept_flags &= ~0x10u;
            g_dnz.vcpu->ept_state = 3;
        }
    }
    return true;
}

/*
 * ============================================================
 * 0x14011c2a0 HV_TranslateGuestVa_Present（模型辅助）
 * ------------------------------------------------------------
 * 老师：按客人 CR3 翻译客人 VA → 物理地址，同时输出"本页还剩多少字节"。
 * 模型：客人地址空间 = 模拟物理内存低 32KB（客人恒等映射）。
 * ============================================================
 */
uint64_t hv_translate_guest_va_present(uint64_t guest_cr3, uint64_t va, uint64_t *bytes_left)
{
    (void)guest_cr3;
    if (va >= DNZ_PHYS_SIZE) return 0;
    if (bytes_left) {
        *bytes_left = DNZ_PAGE_SIZE - (va & (DNZ_PAGE_SIZE - 1));
    }
    return va;
}
