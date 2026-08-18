#pragma once
#include "dnz_types.h"

/*
 * 翻镜子/收尾/校验模块 —— 对应老师代码：
 *   01753 HV_HandleGuestFaultOrExit     0x140116b70  客人访问故障/退出总入口
 *   01754 HV_Svm_MsrInterceptHandler    0x140116d90  AMD MSR 拦截处理
 *   01757 HV_AfterEptViolation          0x140116ed0  收尾：拷页+埋跳板
 *   01758 HV_EptSwapHookOnViolation     0x140116f90  翻镜子（含跨核等待+计时记账）
 *   01785 HV_InvalidateGuestTlbOrEpt    0x14011b560  刷新客人 TLB/EPT
 *   01872 HV_ClearPendingExceptionState 0x140125f40  清待处理异常状态
 *   01873 HV_TryFastExitPath            0x140126020  快车道退出
 *   01875 HV_ValidateEptExitState       0x1401266e0  校验退出状态
 */

/* 01753 */
int hv_handle_guest_fault_or_exit(dnz_global *g, dnz_exit_info *info);

/* 01754 */
uint64_t hv_svm_msr_intercept_handler(uint64_t msr_index, uint64_t *value, bool write);

/* 01757 */
void hv_after_ept_violation(dnz_global *g, uint64_t fault_gpa);

/* 01758：翻镜子。who=0 表示住户访问（正常放行），1 表示保安查房（换干净面） */
bool hv_ept_swap_hook_on_violation(dnz_global *g, uint64_t fault_gpa, bool observer_is_guard);

/* 01785 */
bool hv_invalidate_guest_tlb_or_ept(uint64_t addr, uint64_t *root_a, uint64_t *root_b);

/* 01872 */
uint64_t hv_clear_pending_exception_state(dnz_global *g);

/* 01873 */
bool hv_try_fast_exit_path(dnz_global *g, dnz_exit_info *info);

/* 01875 */
bool hv_validate_ept_exit_state(dnz_global *g, dnz_exit_info *info);

/* 模型：模拟 CPU 时钟（老师: __rdtsc），用于跨核等待与计时记账 */
uint64_t dnz_tsc(void);
