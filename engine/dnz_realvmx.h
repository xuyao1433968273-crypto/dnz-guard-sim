#pragma once
#include "dnz_types.h"

/*
 * RealVmx 指令路径模块 —— 对应老师代码：
 *   01861 HV_EptInstallHook_RealVmx   0x140124cf0  真 VMX 路径装双视图
 *   01862 HV_EptRemoveHook_RealVmx    0x140124db0  真 VMX 路径卸双视图
 *   01863 HV_EptHidePages_RealVmx     0x140124ea0  真 VMX 路径藏页
 *   01864 HV_EptUnhidePages_RealVmx   0x1401250a0  真 VMX 路径放页
 *   01866 HV_EptOpA_RealVmx           0x140125440  条目位操作 A（内存类型/执行位）
 *   01867 HV_EptOpB_RealVmx           0x1401256b0  条目位操作 B
 *   01818 HV_Api_InstallEptHook       0x14011e790  客人 API: vmcall/vmmcall cmd=3
 *   01819 HV_Api_RemoveEptHook        0x14011e7f0  客人 API: vmcall/vmmcall cmd=4
 *
 * 模型里 "RealVmx" 与软件路径的区别：RealVmx 直接改 EPT 条目并调
 * 刷新原语（sub_1401E06C6(2,...)），软件路径维护钩子链表（dnz_hook.c）。
 */

/* 01861：真 VMX 装双视图 */
bool hv_ept_install_hook_realvmx(uint64_t *ctx, uint32_t gpa_idx, uint32_t hook_pfn);

/* 01862：真 VMX 卸双视图 */
void hv_ept_remove_hook_realvmx(uint64_t *ctx, uint32_t gpa_idx);

/* 01863/01864：真 VMX 藏页/放页 */
bool hv_ept_hide_pages_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count);
bool hv_ept_unhide_pages_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count);

/* 01866/01867：条目位操作 */
bool hv_ept_op_a_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count, bool apply);
bool hv_ept_op_b_realvmx(uint64_t *ctx, uint64_t guest_va, uint64_t count);

/* 01818/01819：客人 API（模型=直接调对应路径，注释保留 vmcall 语义） */
uint64_t hv_api_install_ept_hook(uint64_t gpa_idx, uint64_t hook_pfn);
uint64_t hv_api_remove_ept_hook(uint64_t gpa_idx);
