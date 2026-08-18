#pragma once
#include "dnz_types.h"

/*
 * 超调用/分派模块 —— 对应老师代码：
 *   01766 HV_HypercallDispatch          0x140117f20  超调用命令开关（magic 0x69695269）
 *   01850 HV_HypercallDispatch_FromGuestFrame 0x1401239b0 客人栈帧分派（RealVmx 分流）
 *   030043 HV_RaiseException_C0000450   0x14e814604  抛 0xC0000450 异常
 * 外加：门口 HV_DispatchExitHandlers_Ept（0x1401171c0，登记表 g_ExitHandlerTable）
 */

/* 01766：超调用入口。params[0]=命令号，params[1..2]=参数 */
uint64_t hv_hypercall_dispatch(dnz_global *g, uint64_t *params);

/* 01850：从客人栈帧分派（比较返回地址识别 API 并走 RealVmx/软件两路） */
uint64_t hv_hypercall_dispatch_from_guest_frame(dnz_global *g, uint64_t return_address,
                                                uint64_t arg1, uint64_t arg2);

/* 30043：抛 0xC0000450 */
uint64_t hv_raise_exception_c0000450(dnz_global *g);

/* 门口：按退出原因查登记表并分发（0=没认领） */
int hv_dispatch_exit_handlers_ept(dnz_global *g, dnz_exit_info *info);

/* 模型：注册退出处理认领者（老师: g_ExitHandlerTable） */
void hv_register_exit_handler(uint32_t reason, dnz_exit_handler_fn fn);
