#pragma once
#include "dnz_types.h"

/*
 * 双视图装卸/藏页模块 —— 对应老师代码：
 *   01742 HV_EptInstallHook      0x140115980  装双视图（主根+影子根）
 *   01743 HV_EptRemoveHook       0x140115ac0  卸双视图（恢复恒等映射+还节点）
 *   01744 HV_EptHidePages        0x140115c20  藏页（走客人 VA→PFN 列表→哈希换帧）
 *   01745 HV_EptUnhidePages      0x140115e10  放页（恢复）
 *   03277 HV_RemoveEptHook_Wrapper 0x1401da0b0 遍历卸全部钩子（含位图清理）
 *
 * ctx = ept 上下文（模型里即主根数组，影子根/藏页根在全局里）。
 */

/* 装双视图：a2=客户机页号，a3=双视图页(假页)页号 */
bool hv_ept_install_hook(uint64_t *ctx, uint32_t gpa_idx, uint32_t hook_pfn);

/* 卸双视图：a2=客户机页号；从链表摘节点还回空闲栈，恢复恒等映射 */
void hv_ept_remove_hook(uint64_t *ctx, uint32_t gpa_idx);

/* 藏页：a2=客人 VA（存着 a3 个 QWORD 的 PFN 数组），逐个换帧 */
bool hv_ept_hide_pages(uint64_t *ctx, uint64_t guest_va, uint64_t count);

/* 放页：恢复被藏页 */
bool hv_ept_unhide_pages(uint64_t *ctx, uint64_t guest_va, uint64_t count);

/* 03277：遍历钩子链表全部卸掉（g_UseRealVmxInstr 分流），清注册位图 */
void hv_remove_ept_hook_wrapper(uint64_t *ctx, bool flush_after);

/* 模型工具：客人 VA 处读一个 QWORD（走翻译） */
uint64_t dnz_read_guest_qword(uint64_t guest_va);
