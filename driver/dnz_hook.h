/*++
 * dnz_hook.h — 老师驱动的工程细节（认人/翻镜子/跨核同步），叠在 SimpleVisor 骨架上。
 *
 * 对应老师 IDA 分析：
 *   认人      — Hook_NtApi_VmExitHandler (0x1401906E0)：PID/CR3 过滤 + RIP 黑名单
 *   装钩      — Hook_RegisterSoftBp / Hook_InstallAll (0x140185B50 / 0x1401891D0)
 *   翻镜子    — HV_EptSwapHookOnViolation (0x140116F90)：换面 + 计时账本
 *   跨核同步  — 翻镜子里的跨核等待（spin-wait + TSC 限时，8×预算周期）
 *   认人信号  — g_Hook_GuestCr3OrCtx（当前被钩进程的 CR3/PID）
 *
 * 边界：这是教学骨架，演示"认人→换面→单步→恢复"的完整机制，
 *       不针对任何反作弊，不包含任何具体游戏的偏移。
 * --*/

#pragma once
#include <ntddk.h>
#include "shv_x.h"

/* ================= 认人：进程钩子表 ================= */

#define DNZ_MAX_HOOKED_PROC   16
#define DNZ_MAX_RIP_BLACKLIST 32

typedef struct _DNZ_HOOKED_PROC {
    UINT32  Pid;              /* 要钩的进程 PID（老师: g_Hook_GuestCr3OrCtx 的 PID） */
    UINT64  Cr3;              /* 该进程的 CR3（认人主信号） */
    UINT64  Eprocess;         /* EPROCESS（保留） */
    BOOLEAN Active;
} DNZ_HOOKED_PROC, *PDNZ_HOOKED_PROC;

typedef struct _DNZ_RIP_ENTRY {
    UINT64  Rip;              /* 黑名单 RIP（老师: g_Hook_NtosOffsetsCtx 的偏移表） */
    UINT8   Opcode;           /* 常为 0xCC */
    UINT8   Active;
} DNZ_RIP_ENTRY, *PDNZ_RIP_ENTRY;

/* ================= 跨核同步状态（老师: 翻镜子里的状态计数器） =================
 * 0 = 空闲；1 = 某核正在翻镜子；2 = 翻完
 * 翻镜子时其他核 spin-wait 等状态变成 2，TSC 超时放弃。 */

typedef struct _DNZ_SYNC_STATE {
    volatile LONG  State;     /* 0/1/2 */
    volatile LONG  FlipCpu;   /* 正在翻镜子的核号 */
    volatile LONG  SwapCount; /* 翻镜子次数（账本） */
    volatile LONGLONG LastSwapTsc;   /* 上次翻镜子耗时（TSC ticks） */
} DNZ_SYNC_STATE, *PDNZ_SYNC_STATE;

/* ================= 双视图 EPT 钩子（每个 VCPU 一套） =================
 * 老师: HV_EptInstallHook 在 a1（EPT ctx）里建 16 字节节点：
 *   [0] next, [8] gpa 页号, [12] hook 页号
 * 以及主根/影子根（a1 / a1+263680 / a1+2109440）。 */

typedef struct _DNZ_EPT_HOOK {
    UINT64  Gpa;              /* 客户机物理页（4K 对齐） */
    UINT64  CleanPfn;         /* 干净视图：真实物理帧号 */
    UINT64  FakePfn;          /* 钩子视图：假页物理帧号（放"改过"的内容） */
    BOOLEAN Installed;
    BOOLEAN FlipState;        /* 当前面向谁：FALSE=住户(看假页) TRUE=保安(看真页) */
} DNZ_EPT_HOOK, *PDNZ_EPT_HOOK;

/* ================= 全局钩子上下文 ================= */

typedef struct _DNZ_HOOK_CONTEXT {
    DNZ_HOOKED_PROC Procs[DNZ_MAX_HOOKED_PROC];
    DNZ_RIP_ENTRY   Rips[DNZ_MAX_RIP_BLACKLIST];
    DNZ_EPT_HOOK    Hooks[8];
    DNZ_SYNC_STATE  Sync;
    volatile LONG   Initialized;
} DNZ_HOOK_CONTEXT, *PDNZ_HOOK_CONTEXT;

extern DNZ_HOOK_CONTEXT g_DnzHook;

/* ================= 认人（老师: Hook_NtApi_VmExitHandler） =================
 * guest_cr3 = 当前访问者的 CR3。
 * 返回：0 = 不是被钩进程（不关我事）；1 = 是住户（游戏，看假页）；2 = 保安（查房，看真页）
 * 认人信号就是 CR3 对比 g_DnzHook.Procs[].Cr3。 */
INT
DnzRecognizeAccessor(
    _In_ UINT64 GuestCr3
    );

/* RIP 黑名单命中检查（老师: Hook_NtApi_VmExitHandler 第二招——
 * 拿 guest RIP 去对 g_Hook_NtosOffsetsCtx 的偏移表，命中才处理） */
BOOLEAN
DnzRipInBlacklist(
    _In_ UINT64 GuestRip
    );

/* 跨核同步（老师: 翻镜子里的 spin-wait + TSC 限时） */
BOOLEAN
DnzSyncFlipBegin(
    _In_ ULONG CpuNumber,
    _In_ UINT64 TimeoutTsc
    );

VOID
DnzSyncFlipEnd(
    VOID
    );

/* 注册/注销进程钩子（IOCTL 用） */
NTSTATUS
DnzRegisterProc(
    _In_ ULONG Pid
    );

NTSTATUS
DnzUnregisterAll(
    VOID
    );

/* 注册 RIP 黑名单 */
NTSTATUS
DnzRegisterRip(
    _In_ ULONG64 Rip
    );

/* 计时账本（老师: *(a1+24656) = 预期时间 - 实际时间） */
VOID
DnzSyncRecordSwap(
    _In_ LONGLONG ExpectedTsc,
    _In_ LONGLONG ActualTsc
    );

/* 初始化/清理 */
VOID
DnzHookInit(
    VOID
    );

VOID
DnzHookCleanup(
    VOID
    );
