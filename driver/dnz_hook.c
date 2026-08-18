/*++
 * dnz_hook.c — 老师驱动的认人（PID 对比 + 偏移表分派 + FNV 链表）+ 跨核同步。
 * 按老师 IDA 分析原样实现：
 *
 *   ACE_NtApiHook_ExitHandler (0x1401906e0)
 *     - 第一招：当前 guest 进程 PID != g_Hook_GuestCr3OrCtx.Pid -> return 0
 *     - 第二招：guest RIP 对 g_Hook_NtosOffsetsCtx 偏移表，命中哪个模拟哪个 API
 *   ACE_LookupListHookByPid (FNV-1a 哈希查 ListHook 链表，自旋锁 + 桶 + 遍历)
 *   HV_EptSwapHookOnViolation 的跨核等待（内层 1000 次 mfence/pause +
 *     外层 8×预算 TSC 限时，等状态变 2 后归零 + lfence）
 *   计时账本：*(a1+24656) = *(a1+6427312) - 当前TSC（记录点 - 现在）
 * --*/

#include <intrin.h>
#include "dnz_hook.h"
#include "dnz_guest.h"

/* 未导出的内核 API，手工声明 */
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

DNZ_HOOK_CONTEXT g_DnzHook;

/* 老师 ACE_NtApiHook_ExitHandler 的全局小变量（按原样保留语义） */
static UINT8  g_B5Flag;            /* byte_14026E0B5 */
static volatile LONG g_C030;       /* dword_14026C030 */
static volatile LONG g_C02C;       /* dword_14026C02C */
static volatile LONG g_C034;       /* dword_14026C034 */
static volatile LONG g_V0228;      /* dword_140270228 */
static volatile LONG g_V0230;      /* dword_140270230 */
static UINT64 g_V07A8;             /* qword_1402707A8 */
static UINT32 g_V0234;             /* dword_140270234 */

/* a2 = PCONTEXT（老师把 guest 寄存器帧当 QWORD 数组，a2[N] = CONTEXT 偏移 N*8，
 * a2[31] = Rip）。 */
#define CTX_Q(ctx, n) (*(UINT64*)((PUCHAR)(ctx) + (n) * 8))

/* ============ FNV-1a（老师: ACE_LookupListHookByPid 的哈希式） ============ */

UINT64
DnzFnv1a(
    _In_ UINT32 Pid
    )
{
    //
    // 老师原样：对 PID 的 4 个字节做 FNV-1a
    // 0x100000001B3 * (HIBYTE ^ (0x100000001B3 * (BYTE2 ^ (0x100000001B3 *
    //   (BYTE1 ^ (0x100000001B3 * (BYTE0 ^ 0xCBF29CE484222325))))))))
    //
    UINT64 h = DNZ_FNV_OFFSET_BASIS;
    h = DNZ_FNV_PRIME * ((UINT8)Pid ^ h);
    h = DNZ_FNV_PRIME * ((UINT8)(Pid >> 8) ^ h);
    h = DNZ_FNV_PRIME * ((UINT8)(Pid >> 16) ^ h);
    h = DNZ_FNV_PRIME * ((UINT8)(Pid >> 24) ^ h);
    return h;
}

/* ============ ListHook 链表（老师: ACE_LookupListHookByPid 原样） ============ */

PDNZ_LIST_NODE
DnzLookupListHookByPid(
    _In_ UINT32 Pid
    )
{
    UINT64 hash;
    ULONG bucket;
    PDNZ_LIST_NODE node, sentinel;

    if (Pid == 0)
    {
        return NULL;
    }

    //
    // 老师: 自旋锁（CAS 0->1，抢不到 pause 等）
    //
    while (InterlockedCompareExchange(&g_DnzHook.ListLock, 1, 0) == 1)
    {
        _mm_pause();
    }

    //
    // 老师: 桶 = g_Hook_ListMask & hash；从桶链表头开始找
    //
    hash = DnzFnv1a(Pid);
    bucket = (ULONG)(hash & (DNZ_HOOK_LIST_BUCKETS - 1));
    sentinel = &g_DnzHook.Buckets[bucket];
    node = sentinel->Next;

    while (node != NULL && node != sentinel)
    {
        if (node->Pid == Pid)
        {
            break;
        }
        node = node->Next;
    }
    if (node == sentinel || node == NULL)
    {
        node = NULL;
    }

    InterlockedExchange(&g_DnzHook.ListLock, 0);
    return node;
}

NTSTATUS
DnzListHookAdd(
    _In_ UINT32 Pid,
    _In_ UINT64 Data0,
    _In_ UINT64 Data1,
    _In_ UINT64 Data2
    )
{
    UINT64 hash;
    ULONG bucket;
    ULONG i;
    PDNZ_LIST_NODE node, head;

    if (Pid == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    while (InterlockedCompareExchange(&g_DnzHook.ListLock, 1, 0) == 1)
    {
        _mm_pause();
    }

    //
    // 找空闲节点池
    //
    node = NULL;
    for (i = 0; i < 64; i++)
    {
        if (g_DnzHook.Nodes[i].Pid == 0)
        {
            node = &g_DnzHook.Nodes[i];
            break;
        }
    }
    if (node == NULL)
    {
        InterlockedExchange(&g_DnzHook.ListLock, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    node->Pid = Pid;
    node->Data[0] = Data0;
    node->Data[1] = Data1;
    node->Data[2] = Data2;

    //
    // 头插到桶链表
    //
    hash = DnzFnv1a(Pid);
    bucket = (ULONG)(hash & (DNZ_HOOK_LIST_BUCKETS - 1));
    head = &g_DnzHook.Buckets[bucket];
    node->Next = head->Next;
    head->Next = node;

    InterlockedExchange(&g_DnzHook.ListLock, 0);
    return STATUS_SUCCESS;
}

NTSTATUS
DnzListHookRemove(
    _In_ UINT32 Pid
    )
{
    UINT64 hash;
    ULONG bucket;
    PDNZ_LIST_NODE head, prev, cur;

    if (Pid == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    while (InterlockedCompareExchange(&g_DnzHook.ListLock, 1, 0) == 1)
    {
        _mm_pause();
    }

    hash = DnzFnv1a(Pid);
    bucket = (ULONG)(hash & (DNZ_HOOK_LIST_BUCKETS - 1));
    head = &g_DnzHook.Buckets[bucket];
    prev = head;
    cur = head->Next;

    while (cur != NULL && cur != head)
    {
        if (cur->Pid == Pid)
        {
            prev->Next = cur->Next;
            RtlZeroMemory(cur, sizeof(*cur));
            break;
        }
        prev = cur;
        cur = cur->Next;
    }

    InterlockedExchange(&g_DnzHook.ListLock, 0);
    return STATUS_SUCCESS;
}

/* ============ guest 当前进程 PID（老师第一招的 v4） ============ */

/* 老师用偏移表（g_Off_EPROCESS_UniqueProcessId 等）拿进程信息，我们也用偏移：
 * Win10/11 x64 稳定偏移（与老师 g_Off_* 偏移表同一个思路） */
#define DNZ_KPCRB_CURRENT_THREAD 0x48    /* KPCRB.CurrentThread（自 1607 未变） */
#define DNZ_KTHREAD_PROCESS       0x98    /* KTHREAD->Process（KPROCESS=EPROCESS 头） */
#define DNZ_EPROCESS_UNIQUE_PID   0x440   /* EPROCESS->UniqueProcessId（1607~23H2 未变） */

UINT64
DnzGetGuestPid(
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestGsBase
    )
{
    UINT64 phys;
    UINT64 kthread, eprocess, pid;

    //
    // 老师: v4 = *(EPROCESS + g_Off_EPROCESS_UniqueProcessId)
    // 我们从 guest KPCRB（GS base）出发：CurrentThread -> KTHREAD->Process
    // -> EPROCESS->UniqueProcessId，全程用 guest CR3 翻译读 guest 内存。
    //
    if (GuestGsBase == 0)
    {
        return 0;
    }

    // guest KPCRB.CurrentThread（guest 虚拟地址处的指针）
    if (!Hv_TranslateGuestVa_Present(GuestCr3,
                                     GuestGsBase + DNZ_KPCRB_CURRENT_THREAD,
                                     &phys))
    {
        return 0;
    }
    kthread = DnzReadPhys64(phys);

    // KTHREAD->Process（偏移 0x98）
    if (!Hv_TranslateGuestVa_Present(GuestCr3,
                                     kthread + DNZ_KTHREAD_PROCESS,
                                     &phys))
    {
        return 0;
    }
    eprocess = DnzReadPhys64(phys);

    // EPROCESS->UniqueProcessId（偏移 0x440）
    if (!Hv_TranslateGuestVa_Present(GuestCr3,
                                     eprocess + DNZ_EPROCESS_UNIQUE_PID,
                                     &phys))
    {
        return 0;
    }
    pid = DnzReadPhys64(phys);
    return pid;
}

/* ============ 认人第一招（老师: ACE_NtApiHook_ExitHandler 开头） ============ */

INT
DnzRecognizeAccessor(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3
    )
{
    UINT64 pid;

    //
    // 老师原样：
    //   if ( v4 != *(_DWORD *)g_Hook_GuestCr3OrCtx ) return 0;
    // v4 = 当前 guest 进程 PID；g_Hook_GuestCr3OrCtx.Pid = 被钩进程 PID
    //
    pid = DnzGetGuestPid(GuestCr3, VpData->GuestGsBase);
    if (pid != g_DnzHook.GuestCtx.Pid)
    {
        return 0;
    }
    return 1;
}

/* ============ 认人第二招：偏移表分派（老师: ACE_NtApiHook_ExitHandler 原样） ============ */

BOOLEAN
DnzDispatchNtApi(
    _In_ PSHV_VP_DATA VpData,
    _In_ PCONTEXT GuestCtx,
    _In_ UINT64  GuestRip
    )
{
    UINT64 rip = GuestRip;
    UINT64 ctx = (UINT64)&g_DnzHook.GuestCtx;
    UINT8  v26[16];

    UNREFERENCED_PARAMETER(VpData);

    // ===== +1936 =====
    if (rip == g_DnzHook.NtosOffsets[0])
    {
        UINT64 v8 = CTX_Q(GuestCtx, 22);              /* Rdi */
        Hv_ReadGuestBytes(ctx, v26, CTX_Q(GuestCtx, 20) + 48, 16);  /* Rbp+48 */
        /* 老师: sub_140175230(v8, v26) —— 待逐行还原 */
        (void)v8;
        (void)v26;
        CTX_Q(GuestCtx, 31) += 4;                     /* Rip += 4 */
        CTX_Q(GuestCtx, 16) = CTX_Q(GuestCtx, 20) - 32;  /* Rcx = Rbp - 32 */
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +1944 =====
    if (rip == g_DnzHook.NtosOffsets[1])
    {
        UINT64 v11 = CTX_Q(GuestCtx, 16);             /* Rcx */
        Hv_ReadGuestBytes(ctx, v26, CTX_Q(GuestCtx, 17) + 16, 16);  /* Rdx+16 */
        /* 老师: sub_140175230(v11, v26) —— 待逐行还原 */
        (void)v11;
        CTX_Q(GuestCtx, 19) -= 48;                    /* Rsp -= 48 */
        CTX_Q(GuestCtx, 31) += 4;                     /* Rip += 4 */
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +2032 =====
    if (rip == g_DnzHook.NtosOffsets[2])
    {
        if (g_V0234)
        {
            /* 老师: sub_140176310(a2[23]) 算哈希后与两个魔数比较 —— 待逐行还原 */
        }
        Hv_WriteGuestU64(ctx, CTX_Q(GuestCtx, 19) + 32, CTX_Q(GuestCtx, 24));
        CTX_Q(GuestCtx, 31) += 5;
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +2040 =====
    if (rip == g_DnzHook.NtosOffsets[3])
    {
        UINT64 v17 = CTX_Q(GuestCtx, 19);             /* Rsp */
        if (g_B5Flag)
        {
            UINT64 v18 = Hv_ReadGuestU64(ctx, v17);
            CTX_Q(GuestCtx, 19) += 8;                 /* Rsp += 8 */
            CTX_Q(GuestCtx, 31) = v18;                /* Rip = 读到的返回地址（ret 模拟） */
            InterlockedCompareExchange(&g_C030, 0, 1);
        }
        else
        {
            Hv_WriteGuestU64(ctx, v17 + 16, CTX_Q(GuestCtx, 17));  /* 写 Rsp+16 = Rdx */
            CTX_Q(GuestCtx, 31) += 5;
        }
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +1952 =====
    if (rip == g_DnzHook.NtosOffsets[4])
    {
        CTX_Q(GuestCtx, 31) += 5;
        CTX_Q(GuestCtx, 16) = 12;                     /* Rcx = 12 */
        /* 老师: 配置标志判断 + sub_1401944D0 —— 待逐行还原 */
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +1960 / +1968 / +1976（老师调 sub_140187B90 / sub_140187E60 / sub_1401881D0）=====
    if (rip == g_DnzHook.NtosOffsets[5] ||
        rip == g_DnzHook.NtosOffsets[6] ||
        rip == g_DnzHook.NtosOffsets[7])
    {
        /* 老师: sub_140187B90 / sub_140187E60 / sub_1401881D0 —— 待逐行还原 */
        CTX_Q(GuestCtx, 31) += 8;
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +2008 / +2016（同一段，偏移表槽不同）=====
    if (rip == g_DnzHook.NtosOffsets[8] ||
        rip == g_DnzHook.NtosOffsets[9])
    {
        UINT32 off = (rip == g_DnzHook.NtosOffsets[8])
                         ? g_DnzHook.OffsetTable[29]    /* 老师: +116/4 */
                         : g_DnzHook.OffsetTable[31];   /* 老师: +124/4 */
        UINT64 v21 = CTX_Q(GuestCtx, 19) + off;         /* Rsp + off */
        InterlockedIncrement(&g_V0228);
        CTX_Q(GuestCtx, 31) += 8;
        InterlockedExchange(&g_V0230, 0);
        CTX_Q(GuestCtx, 17) = v21;                      /* Rdx = Rsp + off */
        g_V07A8 = v21;
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +2024 / +2048 / +2056 / +2072（老师调子函数）=====
    if (rip == g_DnzHook.NtosOffsets[10] ||
        rip == g_DnzHook.NtosOffsets[11] ||
        rip == g_DnzHook.NtosOffsets[12] ||
        rip == g_DnzHook.NtosOffsets[14])
    {
        /* 老师: sub_140168A70 / sub_140179540 / sub_140179790 / sub_14017BAF0
         * —— 待逐行还原 */
        CTX_Q(GuestCtx, 31) += 8;
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    // ===== +2064（FNV 查 ListHook + 读进程链表）=====
    if (rip == g_DnzHook.NtosOffsets[13])
    {
        UINT64 v22 = Hv_ReadGuestU64(ctx, CTX_Q(GuestCtx, 20) - g_DnzHook.OffsetTable[63]);  /* Rbp - +252 */
        UINT32 v23;
        if ((v22 - 0xFFFF) <= 0x7FFFFFFF0000ULL)
        {
            v23 = Hv_ReadGuestU32(ctx, v22 + 44);
        }
        else
        {
            v23 = 0;
        }
        if (DnzLookupListHookByPid(v23) == NULL)
        {
            /* 老师: Hook_LogListEntry("ListHook", v23, a2) —— 日志，简化 */
        }
        else
        {
            /* 老师: 自旋锁 + Hv_ReadProcessListFromGuest —— 待逐行还原 */
            while (InterlockedCompareExchange(&g_DnzHook.SyncStateLock, 1, 0) == 1)
            {
                _mm_pause();
            }
            InterlockedExchange(&g_DnzHook.SyncStateLock, 0);
        }
        CTX_Q(GuestCtx, 19) -= 8;                        /* Rsp -= 8 */
        Hv_WriteGuestU64(ctx, CTX_Q(GuestCtx, 19), CTX_Q(GuestCtx, 18));  /* 写 Rsp = Rbx */
        CTX_Q(GuestCtx, 31) += 2;
        __vmx_vmwrite(GUEST_RIP, CTX_Q(GuestCtx, 31));
        return TRUE;
    }

    return FALSE;
}

/* ============ 跨核同步（老师: HV_EptSwapHookOnViolation 原样） ============ */

BOOLEAN
DnzSyncFlipBegin(
    _In_ ULONG  CpuNumber,
    _In_ UINT64 TimeoutTsc
    )
{
    UINT64 tscStart;
    LONGLONG budget;
    UNREFERENCED_PARAMETER(TimeoutTsc);

    //
    // 老师: 状态非 0 -> 等它变 2（内层 1000 次 mfence/pause + 外层 8×预算 TSC 限时）
    //
    budget = 8 * g_DnzHook.SwapBudgetTsc;
    tscStart = __rdtsc();

    if (g_DnzHook.Sync.State != 0)
    {
        if (budget != 0)
        {
            do
            {
                ULONG i;
                for (i = 0; i < 0x3E8; i++)
                {
                    if (g_DnzHook.Sync.State == 2)
                    {
                        break;
                    }
                    _mm_mfence();
                    _mm_pause();
                }
            } while (g_DnzHook.Sync.State != 2 && (__rdtsc() - tscStart) < (UINT64)budget);
        }
        if (g_DnzHook.Sync.State != 2)
        {
            return FALSE;   /* 超时放弃（老师: 防自己卡死） */
        }
    }

    //
    // 状态 -> 1（进入翻镜子），记下是谁
    //
    InterlockedExchange(&g_DnzHook.Sync.State, 1);
    InterlockedExchange(&g_DnzHook.Sync.FlipCpu, (LONG)CpuNumber);
    return TRUE;
}

VOID
DnzSyncFinish(
    VOID
    )
{
    UINT64 tscStart;
    LONGLONG budget;

    //
    // 老师原样：单步完成 -> 状态置 2；内层 1000 次 + 外层 8×预算 TSC 限时
    // 等状态变 2（跨核同步点）；然后归零 + lfence
    //
    tscStart = __rdtsc();
    budget = 8 * g_DnzHook.SwapBudgetTsc;

    InterlockedExchange(&g_DnzHook.Sync.State, 2);

    if (budget != 0)
    {
        do
        {
            ULONG i;
            for (i = 0; i < 0x3E8; i++)
            {
                if (g_DnzHook.Sync.State == 2)
                {
                    break;
                }
                _mm_mfence();
                _mm_pause();
            }
        } while (g_DnzHook.Sync.State != 2 && (__rdtsc() - tscStart) < (UINT64)budget);
    }

    InterlockedExchange(&g_DnzHook.Sync.State, 0);
    _mm_lfence();
}

VOID
DnzSyncRecordSwap(
    VOID
    )
{
    //
    // 老师: *(a1+24656) = *(a1+6427312) - 当前TSC（记录点 - 现在）
    //
    InterlockedExchange64(&g_DnzHook.Sync.LastSwapTsc,
                          g_DnzHook.SwapRecordPoint - __rdtsc());
    InterlockedIncrement(&g_DnzHook.Sync.SwapCount);
}

/* ============ 注册/注销 ============ */

NTSTATUS
DnzRegisterProc(
    _In_ ULONG Pid
    )
{
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

    //
    // g_Hook_GuestCr3OrCtx：PID + CR3（CR3 用当前线程的；更准的版本应通过
    // EPROCESS.DirectoryTableBase 读，教学骨架从简）
    //
    g_DnzHook.GuestCtx.Pid = Pid;
    g_DnzHook.GuestCtx.Cr3 = (UINT64)__readcr3();
    g_DnzHook.GuestCtx.Pad = 0;

    //
    // 往 ListHook 链表加节点（老师: ACE_LookupListHookByPid 查的链表）
    //
    DnzListHookAdd(Pid, (UINT64)process, 0, 0);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

NTSTATUS
DnzUnregisterAll(
    VOID
    )
{
    RtlZeroMemory(&g_DnzHook.GuestCtx, sizeof(g_DnzHook.GuestCtx));
    RtlZeroMemory(g_DnzHook.NtosOffsets, sizeof(g_DnzHook.NtosOffsets));
    RtlZeroMemory(g_DnzHook.OffsetTable, sizeof(g_DnzHook.OffsetTable));
    RtlZeroMemory(g_DnzHook.Buckets, sizeof(g_DnzHook.Buckets));
    RtlZeroMemory(g_DnzHook.Nodes, sizeof(g_DnzHook.Nodes));
    return STATUS_SUCCESS;
}

NTSTATUS
DnzRegisterRip(
    _In_ ULONG64 Rip
    )
{
    ULONG i;

    //
    // 对应老师 g_Hook_NtosOffsetsCtx：RIP 偏移表槽
    //
    for (i = 0; i < DNZ_NTOS_OFFSETS_MAX; i++)
    {
        if (g_DnzHook.NtosOffsets[i] == 0)
        {
            g_DnzHook.NtosOffsets[i] = Rip;
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
    g_DnzHook.SwapBudgetTsc = 4096;   /* 老师: 8×预算里的预算值 */
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
