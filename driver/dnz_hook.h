/*++
 * dnz_hook.h — 老师驱动的认人（PID 对比 + 偏移表分派 + FNV 链表）+ 跨核同步。
 * 按老师 IDA 分析原样实现：
 *
 *   ACE_NtApiHook_ExitHandler (0x1401906e0)  认人两招：
 *     第一招：guest 当前进程 PID != g_Hook_GuestCr3OrCtx.Pid -> return 0
 *     第二招：guest RIP 对 g_Hook_NtosOffsetsCtx 偏移表，命中哪个模拟哪个 API
 *   ACE_LookupListHookByPid (FNV-1a 哈希查 ListHook 链表)
 *   HV_EptSwapHookOnViolation 的跨核等待（内层 1000 次 mfence/pause +
 *     外层 8×预算 TSC 限时，等状态变 2 后归零 + lfence）
 *   计时账本：*(a1+24656) = *(a1+6427312) - 当前TSC（记录点 - 现在）
 * --*/

#pragma once
#include <ntddk.h>
#include "shv_x.h"

/* ================= g_Hook_GuestCr3OrCtx（老师全局：被钩进程上下文） =================
 * 老师: *(_DWORD*)g_Hook_GuestCr3OrCtx = PID（第一招比对用）
 *       Hv_ReadGuestU64(g_Hook_GuestCr3OrCtx, ...) 内部用 CR3 翻译（+8） */

typedef struct _DNZ_GUEST_CTX {
    UINT32 Pid;              /* +0 老师: *(_DWORD*)g_Hook_GuestCr3OrCtx */
    UINT32 Pad;              /* +4 */
    UINT64 Cr3;              /* +8 guest CR3（地址翻译） */
} DNZ_GUEST_CTX, *PDNZ_GUEST_CTX;

/* ================= g_Hook_NtosOffsetsCtx（老师全局：RIP 偏移表） =================
 * 老师用 +1936/+1944/.../+2072 字节偏移索引（QWORD 数组元素 242~259）。
 * 我们建 16 槽 QWORD 数组，槽 0 对应老师 +1936。guest RIP 命中哪个槽就
 * 走哪个分支的"替身模拟"。 */

#define DNZ_NTOS_OFFSETS_MAX 16

/* ================= g_Hook_OffsetTable（老师全局：DWORD 偏移表） =================
 * 老师用 +116/+124/+168/+252/+1072/+1076/+1080 索引。32 槽够用。 */

#define DNZ_OFFSET_TABLE_MAX 512

/* ================= ListHook FNV-1a 链表（老师: ACE_LookupListHookByPid） =================
 * FNV-1a：基数 0xCBF29CE484222325，质数 0x100000001B3
 * 桶: g_Hook_ListBuckets + 16 * (g_Hook_ListMask & hash)
 * 节点: +8 = next, +16 = PID(DWORD), +24 = 数据(24字节) */

#define DNZ_HOOK_LIST_BUCKETS 64
#define DNZ_FNV_OFFSET_BASIS  0xCBF29CE484222325ULL
#define DNZ_FNV_PRIME         0x100000001B3ULL

typedef struct _DNZ_LIST_NODE {
    struct _DNZ_LIST_NODE* Next;   /* +0 */
    UINT32 Pid;                    /* +8  老师: +16 偏移是合并布局，我们紧凑化 */
    UINT32 Pad;
    UINT64 Data[3];                /* +16 24 字节（老师: +24 拷 24 字节） */
} DNZ_LIST_NODE, *PDNZ_LIST_NODE;

/* ================= 跨核同步状态（老师: 翻镜子里的状态计数器） =================
 * 0 = 空闲；1 = 某核正在翻镜子；2 = 翻完（单步完成）
 * 状态非 0 就等变 2（内层 1000 次 mfence/pause + 外层 8×预算 TSC 限时），
 * 等完归零 + lfence。 */

typedef struct _DNZ_SYNC_STATE {
    volatile LONG  State;          /* 0/1/2（老师: a1+6427304） */
    volatile LONG  FlipCpu;        /* 正在翻镜子的核号 */
    volatile LONG  SwapCount;      /* 翻镜子次数（账本） */
    volatile LONGLONG LastSwapTsc; /* 上次翻镜子耗时（老师: a1+24656） */
} DNZ_SYNC_STATE, *PDNZ_SYNC_STATE;

/* ================= 全局钩子上下文 ================= */

typedef struct _DNZ_HOOK_CONTEXT {
    DNZ_GUEST_CTX GuestCtx;                 /* g_Hook_GuestCr3OrCtx */
    UINT64        NtosOffsets[DNZ_NTOS_OFFSETS_MAX];  /* g_Hook_NtosOffsetsCtx */
    UINT32        OffsetTable[DNZ_OFFSET_TABLE_MAX];  /* g_Hook_OffsetTable */
    DNZ_LIST_NODE Buckets[DNZ_HOOK_LIST_BUCKETS];     /* ListHook 桶数组 */
    DNZ_LIST_NODE Nodes[64];                          /* ListHook 节点池 */
    volatile LONG ListLock;                 /* 链表自旋锁（老师: qword_14DB95CB0） */
    volatile LONG SyncStateLock;            /* 跨核状态锁（老师: qword_14DB95CC0） */
    DNZ_SYNC_STATE Sync;
    LONGLONG       SwapBudgetTsc;           /* 老师: 8×预算里的预算 */
    UINT64         SwapRecordPoint;         /* 老师: a1+6427312（记录点） */
    volatile LONG  Initialized;
} DNZ_HOOK_CONTEXT, *PDNZ_HOOK_CONTEXT;

extern DNZ_HOOK_CONTEXT g_DnzHook;

/* ================= 认人第一招（老师: ACE_NtApiHook_ExitHandler 开头） =================
 * 拿当前 guest 进程 PID（EPROCESS->UniqueProcessId）和 g_Hook_GuestCr3OrCtx.Pid 比，
 * 不一样 return 0（放行）。VpData->GuestGsBase 是 VM-exit 时 VMREAD(GUEST_GS_BASE)
 * 存的 guest KPCRB 地址（虚拟）。 */
INT
DnzRecognizeAccessor(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3
    );

/* ================= 认人第二招（老师: ACE_NtApiHook_ExitHandler 偏移表分派） =================
 * guest RIP 对 g_Hook.NtosOffsets 逐个比，命中哪个就按老师的替身模拟动作执行
 * （RIP 前移 + 写 guest 寄存器/栈/内存）。GuestCtx = PCONTEXT（a2），
 * a2[N] = CONTEXT 偏移 N*8（a2[31] = Rip）。返回 TRUE=已模拟。 */
BOOLEAN
DnzDispatchNtApi(
    _In_ PSHV_VP_DATA VpData,
    _In_ PCONTEXT GuestCtx,
    _In_ UINT64  GuestRip
    );

/* FNV-1a 哈希（老师: ACE_LookupListHookByPid 的哈希式） */
UINT64
DnzFnv1a(
    _In_ UINT32 Pid
    );

/* 按 PID 查 ListHook 链表（老师: ACE_LookupListHookByPid 原样）。
 * 找到返回节点指针；找不到返回 NULL。 */
PDNZ_LIST_NODE
DnzLookupListHookByPid(
    _In_ UINT32 Pid
    );

/* 往 ListHook 链表加/删节点（注册/注销进程用） */
NTSTATUS
DnzListHookAdd(
    _In_ UINT32 Pid,
    _In_ UINT64 Data0,
    _In_ UINT64 Data1,
    _In_ UINT64 Data2
    );

NTSTATUS
DnzListHookRemove(
    _In_ UINT32 Pid
    );

/* ================= 跨核同步（老师: 翻镜子里的跨核等待） ================= */

BOOLEAN
DnzSyncFlipBegin(
    _In_ ULONG  CpuNumber,
    _In_ UINT64 TimeoutTsc
    );

/* 老师原样收尾：状态置 2（单步完成）-> 内层1000次/外层8×预算等待 -> 归零 + lfence */
VOID
DnzSyncFinish(
    VOID
    );

/* 计时账本（老师: *(a1+24656) = *(a1+6427312) - 当前TSC，记录点 - 现在） */
VOID
DnzSyncRecordSwap(
    VOID
    );

/* ================= 注册/注销（IOCTL 用） ================= */

NTSTATUS
DnzRegisterProc(
    _In_ ULONG Pid
    );

NTSTATUS
DnzUnregisterAll(
    VOID
    );

/* 注册 RIP 偏移表槽（对应老师 g_Hook_NtosOffsetsCtx + 偏移） */
NTSTATUS
DnzRegisterRip(
    _In_ ULONG64 Rip
    );

VOID
DnzHookInit(
    VOID
    );

VOID
DnzHookCleanup(
    VOID
    );
