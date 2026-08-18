#pragma once
/* 老师原名 → 模型函数 映射（登记表/文档用老师原名，模型实现用小写名） */
#include "dnz_ept.h"
#include "dnz_hook.h"
#include "dnz_realvmx.h"
#include "dnz_violation.h"
#include "dnz_dispatch.h"
#include "dnz_hooks.h"
#include "dnz_pool.h"

#define HV_LookupEptEntry               hv_lookup_ept
#define HV_EptSplitLargePage            hv_ept_split_large_page
#define HV_EptEnsureSplitPage           hv_ept_ensure_split_page
#define HV_EptMapGuestAccess            hv_ept_map_guest_access
#define HV_EptInstallHook               hv_ept_install_hook
#define HV_EptRemoveHook                hv_ept_remove_hook
#define HV_EptHidePages                 hv_ept_hide_pages
#define HV_EptUnhidePages               hv_ept_unhide_pages
#define HV_EptSplitPage_ClearXD         hv_ept_split_page_clear_xd
#define HV_HandleGuestFaultOrExit       hv_handle_guest_fault_or_exit
#define HV_Svm_MsrInterceptHandler      hv_svm_msr_intercept_handler
#define HV_AfterEptViolation            hv_after_ept_violation
#define HV_EptSwapHookOnViolation       hv_ept_swap_hook_on_violation
#define HV_HypercallDispatch            hv_hypercall_dispatch
#define HV_InvalidateGuestTlbOrEpt      hv_invalidate_guest_tlb_or_ept
#define HV_Api_InstallEptHook           hv_api_install_ept_hook
#define HV_Api_RemoveEptHook            hv_api_remove_ept_hook
#define HV_HypercallDispatch_FromGuestFrame hv_hypercall_dispatch_from_guest_frame
#define HV_EptInstallHook_RealVmx       hv_ept_install_hook_realvmx
#define HV_EptRemoveHook_RealVmx        hv_ept_remove_hook_realvmx
#define HV_EptHidePages_RealVmx         hv_ept_hide_pages_realvmx
#define HV_EptUnhidePages_RealVmx       hv_ept_unhide_pages_realvmx
#define HV_EptOpA_RealVmx               hv_ept_op_a_realvmx
#define HV_EptOpB_RealVmx               hv_ept_op_b_realvmx
#define HV_ClearPendingExceptionState   hv_clear_pending_exception_state
#define HV_TryFastExitPath              hv_try_fast_exit_path
#define HV_ValidateEptExitState         hv_validate_ept_exit_state
#define Mem_PoolAlloc                   dnz_pool_alloc_page
#define Mem_HeapFreeTracked             dnz_pool_free_frame
#define Hook_OnGuestCr3Change           hook_on_guest_cr3_change
#define Hook_SeedFromTickCount          hook_seed_from_tickcount
#define Hook_InitEnv                    hook_init_env
#define Hook_LookupByPid                hook_lookup_by_pid
#define Hook_LogListEntry               hook_log_list_entry
#define Hv_ReadProcessListFromGuest     hv_read_process_list_from_guest
#define Hook_RegisterSoftBp             hook_register_softbp
#define Hook_InstallAll                 hook_install_all
#define HV_RemoveEptHook_Wrapper        hv_remove_ept_hook_wrapper
#define HV_RaiseException_C0000450      hv_raise_exception_c0000450
