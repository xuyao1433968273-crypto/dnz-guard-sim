#pragma once
#include "dnz_types.h"

/*
 * EPT 核心模块 —— 对应老师代码（阶段 04-内存映射与隐藏）：
 *   01738 HV_LookupEptEntry         0x140115220  四层页表走查
 *   01739 HV_EptSplitLargePage      0x140115400  2MB 大页拆 512×4K
 *   01740 HV_EptEnsureSplitPage     0x140115620  初始化 EPT 并拆前 4 个 2M 页
 *   01741 HV_EptMapGuestAccess      0x1401157c0  给客人映射 1GB 大页区域
 *   01747 HV_EptSplitPage_ClearXD   0x140116020  清 EPT 项 XD 位
 * 附带模型辅助：HV_TranslateGuestVa_Present（老师 0x14011c2a0）
 */

/* 页表索引（老师代码: (a2>>39)&0x1FF 等） */
#define EPT_IDX_PML4(gpa)  (((gpa) >> 39) & 0x1FF)
#define EPT_IDX_PDPT(gpa)  (((gpa) >> 30) & 0x1FF)
#define EPT_IDX_PD(gpa)    (((gpa) >> 21) & 0x1FF)
#define EPT_IDX_PT(gpa)    (((gpa) >> 12) & 0x1FF)

/*
 * HV_LookupEptEntry —— 四层 EPT 走查，返回指向目标 PTE 的指针
 * （老师返回"页表项在直接映射里的地址"，模型返回指向模型物理内存的指针）。
 * 命中 2M 大页且 allow_split=1 时先拆页。找不到返回 NULL。
 */
uint64_t *hv_lookup_ept(uint64_t *root, uint64_t gpa, bool allow_split);

/* 老师 01739：把 2M 大页拆成 512 个 4K 页；a5=1 时清 XD（可执行） */
bool hv_ept_split_large_page(uint64_t *root, uint64_t gpa, bool clear_xd);

/* 老师 01740：初始化 EPT 根（含低 1GB 恒等映射），并把前 4 个 2M 页拆掉 */
bool hv_ept_ensure_split_page(uint64_t *root, bool clear_xd);

/* 老师 01741：给 1GB 区域建 PDPT+PD，映射 512 个 2M 大页（恒等映射） */
bool hv_ept_map_guest_access(uint64_t *root, uint64_t gpa, bool clear_xd);

/* 老师 01747：翻译客人 VA→物理，清对应 EPT 项的 XD 位 */
bool hv_ept_split_page_clear_xd(uint64_t *root, uint64_t guest_va);

/* 老师 0x14011c2a0（辅助）：客人 VA→物理；成功返回物理地址并填剩余字节数 */
uint64_t hv_translate_guest_va_present(uint64_t guest_cr3, uint64_t va, uint64_t *bytes_left);

/* 模型工具：把"逻辑 EPT 上下文"映射到老师结构布局：
 *   a1        = ept 上下文（主根在偏移 0）
 *   a1+263680 = 影子根
 *   a1+2109440= 藏页影子根
 * 模型里这三者分别是 ept_primary / ept_shadow / ept_shadow2 */
uint64_t *dnz_root_primary(void);
uint64_t *dnz_root_shadow(void);
uint64_t *dnz_root_shadow2(void);
