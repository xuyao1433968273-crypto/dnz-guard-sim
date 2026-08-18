/*++
 * dnz_hook.c — 认人（PID/CR3 过滤 + RIP 黑名单）+ 跨核同步（TSC 限时等待）。
 *
 * 对应老师驱动：
 *   Hook_NtApi_VmExitHandler (0x1401906E0) —— 开头查 PID，不是游戏就 return 0
 *   HV_EptSwapHookOnViolation (0x140116F90) —— 跨核 spin-wait + 8×预算周期 TSC 超时
 *   *(a1+24656) = 预期时间 - 实际时间      —— 翻镜子计时账本
 * --*/

#include "dnz_hook.h"

/* 未导出的内核 API，手工声明 */
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

DNZ_HOOK_CONTEXT g_DnzHook;

/* ============ 认人（老师: Hook_NtApi_VmExitHandler 的 PID 检查） ============ */

INT
DnzRecognizeAccessor(
    _In_ UINT64 GuestCr3
    )
{
    ULONG i;

    //
    // 老师逻辑：if (PID != 游戏进程PID) return 0;
    // 认人信号用 CR3（地址地图）对比——每个进程的 CR3 唯一。
    //
    for (i = 0; i < DNZ_MAX_HOOKED_PROC; i++)
    {
        if (g_DnzHook.Procs[i].Active &&
            g_DnzHook.Procs[i].Cr3 == GuestCr3)
        {
            //
            // 是"住户"（被钩进程）在访问 → 看钩子视图（假页）
            //
            return 1;
        }
    }

    //
    // 不是被钩进程——老师代码里这里 return 0，直接放行。
    // 注意：本骨架不区分"保安"，所有非被钩进程统一视为外部访问者。
    // 演示翻镜子时，调用方可以把任何"非住户"当作保安处理（见 dnz_ept.c）。
    //
    return 0;
}

/* ============ RIP 黑名单（老师: Hook_NtApi_VmExitHandler 第二招） ============ */

BOOLEAN
DnzRipInBlacklist(
    _In_ UINT64 GuestRip
    )
{
    ULONG i;

    //
    // 老师逻辑：拿 guest RIP 去和登记表（g_Hook_NtosOffsetsCtx 的十几个偏移）
    // 逐个对，RIP == 偏移 N 的位置就按 N 的处理方式模拟那个 API。
    // 教学骨架：直接对比绝对 RIP（IOCTL 注册的黑名单）。
    //
    for (i = 0; i < DNZ_MAX_RIP_BLACKLIST; i++)
    {
        if (g_DnzHook.Rips[i].Active &&
            g_DnzHook.Rips[i].Rip == GuestRip)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============ 跨核同步（老师: 翻镜子里的 spin-wait + TSC 超时） ============ */

BOOLEAN
DnzSyncFlipBegin(
    _In_ ULONG CpuNumber,
    _In_ UINT64 TimeoutTsc
    )
{
    LONG   old;
    UINT64 deadline;
    UINT64 now;

    //
    // 抢占翻镜子权：0 -> 1（CAS）。抢不到说明别的核正在翻，spin-wait 等它翻完（状态变 2）。
    //
    old = InterlockedCompareExchange(&g_DnzHook.Sync.State, 1, 0);
    if (old != 0)
    {
        //
        // 别人正在翻。等它变成 2（翻完）。老师代码配了 mfence/pause + 时限。
        //
        deadline = __rdtsc() + TimeoutTsc;
        for (;;)
        {
            _mm_pause();
            if (g_DnzHook.Sync.State == 2)
            {
                break;
            }
            now = __rdtsc();
            if (now > deadline)
            {
                //
                // 超时，放弃（老师: 防自己卡死）
                //
                return FALSE;
            }
        }

        //
        // 翻完了，再抢一次
        //
        old = InterlockedCompareExchange(&g_DnzHook.Sync.State, 1, 2);
        if (old != 2)
        {
            return FALSE;
        }
    }

    //
    // 抢到了。记下是谁在翻。
    //
    InterlockedExchange(&g_DnzHook.Sync.FlipCpu, (LONG)CpuNumber);
    return TRUE;
}

VOID
DnzSyncFlipEnd(
    VOID
    )
{
    //
    // 翻完，把状态从 1 置成 2（老师: 状态计数器 = 2 表示干完了）
    //
    InterlockedExchange(&g_DnzHook.Sync.State, 2);
}

VOID
DnzSyncRecordSwap(
    _In_ LONGLONG ExpectedTsc,
    _In_ LONGLONG ActualTsc
    )
{
    //
    // 老师: *(a1 + 24656) = 预期时间 - 实际时间;
    // 记账目的：翻镜子耗时被记录，用于校准、掩盖延迟（防时间差检测）。
    //
    InterlockedExchange64(&g_DnzHook.Sync.LastSwapTsc, ExpectedTsc - ActualTsc);
    InterlockedIncrement(&g_DnzHook.Sync.SwapCount);
}

/* ============ 注册/注销 ============ */

NTSTATUS
DnzRegisterProc(
    _In_ ULONG Pid
    )
{
    ULONG i;
    PEPROCESS process;
    NTSTATUS status;

    if (Pid == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    for (i = 0; i < DNZ_MAX_HOOKED_PROC; i++)
    {
        if (!g_DnzHook.Procs[i].Active)
        {
            g_DnzHook.Procs[i].Pid = Pid;
            /* CR3 用当前线程的（注册通常发生在目标进程上下文）；更准的版本
             * 应通过 EPROCESS.DirectoryTableBase 读取（教学骨架从简） */
            g_DnzHook.Procs[i].Cr3 = (UINT64)__readcr3();
            g_DnzHook.Procs[i].Eprocess = (UINT64)process;
            g_DnzHook.Procs[i].Active = TRUE;
            ObDereferenceObject(process);
            return STATUS_SUCCESS;
        }
    }

    ObDereferenceObject(process);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
DnzUnregisterAll(
    VOID
    )
{
    RtlZeroMemory(g_DnzHook.Procs, sizeof(g_DnzHook.Procs));
    RtlZeroMemory(g_DnzHook.Rips, sizeof(g_DnzHook.Rips));
    return STATUS_SUCCESS;
}

NTSTATUS
DnzRegisterRip(
    _In_ ULONG64 Rip
    )
{
    ULONG i;

    for (i = 0; i < DNZ_MAX_RIP_BLACKLIST; i++)
    {
        if (!g_DnzHook.Rips[i].Active)
        {
            g_DnzHook.Rips[i].Rip = Rip;
            g_DnzHook.Rips[i].Opcode = 0xCC;
            g_DnzHook.Rips[i].Active = TRUE;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
DnzHookInit(
    VOID
    )
{
    RtlZeroMemory(&g_DnzHook, sizeof(g_DnzHook));
    g_DnzHook.Sync.State = 0;
    InterlockedExchange(&g_DnzHook.Initialized, 1);
}

VOID
DnzHookCleanup(
    VOID
    )
{
    InterlockedExchange(&g_DnzHook.Initialized, 0);
    RtlZeroMemory(&g_DnzHook, sizeof(g_DnzHook));
}
