#include "dnz_dispatch.h"
#include "dnz_ept.h"
#include "dnz_hook.h"
#include "dnz_realvmx.h"
#include "dnz_violation.h"
#include <string.h>

/* 退出处理登记表（老师: g_ExitHandlerTable） */
static dnz_exit_handler g_exit_handlers[32];
static uint32_t         g_exit_handler_count;

void hv_register_exit_handler(uint32_t reason, dnz_exit_handler_fn fn)
{
    if (g_exit_handler_count >= 32) return;
    g_exit_handlers[g_exit_handler_count].reason = reason;
    g_exit_handlers[g_exit_handler_count].fn     = fn;
    g_exit_handler_count++;
}

/*
 * ============================================================
 * 01766. HV_HypercallDispatch (0x140117f20)
 * ------------------------------------------------------------
 * 老师注释原文：
 *   Hypercall cmd switch: 1=ping, 2=host enter, 3/4=EPT hook,
 *   5-8=hide/unhide, 0xC=copy, 0xD/E=translate, 0xF=force exit;
 *   magic 0x69695269
 * 流程：*a2 > 0x69695269 → 非法；switch 命令号分发。
 * ============================================================
 */
uint64_t hv_hypercall_dispatch(dnz_global *g, uint64_t *params)
{
    if (params[0] > DNZ_MAGIC_HYPERCALL) return DNZ_ERR_RETURN;  /* 老师: 魔数校验 */

    switch (params[0]) {
    case DNZ_CMD_PING: {
        /* 老师: *(a1+24588) = ... & 0xFFFFFBBD | 2; *(a1+24768) &= 0xFFFFFF7E */
        if (g->vcpu) {
            g->vcpu->ctrl_flags = (g->vcpu->ctrl_flags & 0xFFFFFBBDu) | 2;
            g->vcpu->ept_flags &= 0xFFFFFF7Eu;
        }
        return 0;
    }
    case DNZ_CMD_HOST_ENTER: {
        /* 老师: EFER &= 0xFFFFEFFF; writeeflags(...&~0x200); 返回 */
        return 0;
    }
    case DNZ_CMD_EPT_HOOK_SET:
        return hv_ept_install_hook(dnz_root_primary(), (uint32_t)params[1], (uint32_t)params[2]) ? 0 : 1;
    case DNZ_CMD_EPT_HOOK_CLR:
        hv_ept_remove_hook(dnz_root_primary(), (uint32_t)params[1]);
        return 0;
    case DNZ_CMD_HIDE:
        return hv_ept_hide_pages(dnz_root_primary(), params[1], params[2]) ? 0 : 1;
    case DNZ_CMD_UNHIDE:
        return hv_ept_unhide_pages(dnz_root_primary(), params[1], params[2]) ? 0 : 1;
    case DNZ_CMD_COPY: {
        /* 老师: HV_ExportSharedBufferToGuest(dst_va, size) —— 模型: 拷贝客人内存 */
        uint64_t size = params[2] & 0xFFFFFFFFULL;
        if (size > 0x10000) size = 0x10000;
        uint64_t src = 0x8000;                    /* 模型里的共享缓冲 */
        uint64_t dst = params[1];
        for (uint64_t i = 0; i < size && dst + i < DNZ_PHYS_SIZE && src + i < DNZ_PHYS_SIZE; i++) {
            dnz_phys_ptr(dst + i)[0] = dnz_phys_ptr(src + i)[0];
        }
        return 0;
    }
    case DNZ_CMD_TRANSLATE:
        return hv_translate_guest_va_present(g->guest_cr3, params[1], NULL);
    case DNZ_CMD_TRANSLATE2:
        return hv_translate_guest_va_present(g->guest_cr3, params[1], NULL);
    case DNZ_CMD_FORCE_EXIT:
        return 0x6D772324CE8FCDB9ULL ^ g->g_encrypted_vmcall_target;
    default:
        return DNZ_ERR_RETURN;    /* 老师: return 0x6969696969696969 */
    }
}

/*
 * ============================================================
 * 01850. HV_HypercallDispatch_FromGuestFrame (0x1401239b0)
 * ------------------------------------------------------------
 * 老师：比较返回地址（v27 处的函数指针）识别 API：
 *   HV_Api_ForceExit / HV_Api_InstallEptHook / RemoveEptHook /
 *   HidePages / UnhidePages / Hypercall_CmdA / Hypercall_CmdB
 *   命中后按 g_UseRealVmxInstr 走 RealVmx 或软件路径。
 * 模型：return_address 直接是命令号（简化），按命令分派。
 * ============================================================
 */
uint64_t hv_hypercall_dispatch_from_guest_frame(dnz_global *g, uint64_t return_address,
                                                uint64_t arg1, uint64_t arg2)
{
    (void)g;
    bool real = g->g_use_real_vmx != 0;

    switch (return_address) {
    case DNZ_CMD_EPT_HOOK_SET:
        return real ? hv_ept_install_hook_realvmx(dnz_root_primary(), (uint32_t)arg1, (uint32_t)arg2)
                          : hv_ept_install_hook(dnz_root_primary(), (uint32_t)arg1, (uint32_t)arg2)
                    ? 0 : 1;
    case DNZ_CMD_EPT_HOOK_CLR:
        if (real) hv_ept_remove_hook_realvmx(dnz_root_primary(), (uint32_t)arg1);
        else      hv_ept_remove_hook(dnz_root_primary(), (uint32_t)arg1);
        return 0;
    case DNZ_CMD_HIDE:
        return real ? hv_ept_hide_pages_realvmx(dnz_root_primary(), arg1, arg2)
                          : hv_ept_hide_pages(dnz_root_primary(), arg1, arg2)
                    ? 0 : 1;
    case DNZ_CMD_UNHIDE:
        return real ? hv_ept_unhide_pages_realvmx(dnz_root_primary(), arg1, arg2)
                          : hv_ept_unhide_pages(dnz_root_primary(), arg1, arg2)
                    ? 0 : 1;
    default:
        return DNZ_ERR_RETURN;
    }
}

/*
 * ============================================================
 * 30043. HV_RaiseException_C0000450 (0x14e814604)
 * ------------------------------------------------------------
 * 老师：向客人注入 0xC0000450（KMODE_EXCEPTION_NOT_HANDLED 类）。
 * 模型：设置 vcpu 待处理异常，返回异常码。
 * ============================================================
 */
uint64_t hv_raise_exception_c0000450(dnz_global *g)
{
    if (g->vcpu) g->vcpu->pending_event = 0xC0000450ULL;
    return 0xC0000450ULL;
}

/*
 * ============================================================
 * 门口：HV_DispatchExitHandlers_Ept（0x1401171c0）
 * ------------------------------------------------------------
 * 老师：把退出原因 + CS RPL + CR3 递给 g_ExitHandlerTable 里的
 *       每个认领者，谁认领谁处理。
 * 模型：遍历登记表分发。
 * ============================================================
 */
int hv_dispatch_exit_handlers_ept(dnz_global *g, dnz_exit_info *info)
{
    for (uint32_t i = 0; i < g_exit_handler_count; i++) {
        if (g_exit_handlers[i].reason == info->exit_reason) {
            return g_exit_handlers[i].fn(g, info);
        }
    }
    return 0;   /* 没人认领 */
}
