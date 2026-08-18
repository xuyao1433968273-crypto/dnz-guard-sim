/*++
 * dnz_teacher.c — 老师 8 个子函数逐行还原 + 全部下级 helper。
 *
 * 还原依据（老师 IDA 分析资料，全部有伪代码出处）：
 *   sub_140168A70 / sub_140176310 / sub_140179540 / sub_140179790 /
 *   sub_14017BAF0 / sub_140187B90 / sub_140187E60 / sub_1401881D0
 *
 * 下级 helper 同样按老师伪代码实现（sub_140166D10 / 1401687E0 / 14016B1C0 /
 * 14016B300 / 14016B410 / 1401755B0 / 140175D20 / 1401757E0 / 140175AA0 /
 * 140176080 / 140176110 / 140176B60 / 140176FD0 / 1401764F0 / 140178FB0 /
 * 140179340 / 14017B030 / 14017B600 / 140180A80 / 140180D20 / 140181890 /
 * 140184D90 / 14018C6B0 / 14018CC80 / 1401E98D0 / 1401E9D70 / 14014FEE0 /
 * 1401769B0 / Hook_LookupByPid / Hook_LogListEntry / HV_HandlePendingEvent /
 * HV_FlushOrSyncAfterRegister）。
 *
 * 文档化偏差：
 *   1) 老师的 Mem_HeapAlloc / 桶扩容 -> 静态节点池 + 固定 64 桶（节点布局原样）
 *   2) g_Wddm_DisableOverlay = 1 -> 走直接页表走查路径（我们的 Hv_* 原语）
 *   3) sub_14016B540 的 Esp_ApplyGuestProloguePatch -> 返回原地址
 *   4) 原认为"出处不全"的 sub_1401944D0 / Hv_ReadProcessListFromGuest /
 *      sub_140175230 / sub_14017B160 / HV_HandlePendingEvent（含 sub_1400661D0 /
 *      sub_140066580 / sub_140065C80）全部在 all_functions_raw.jsonl 里找到
 *      完整伪代码，已逐行还原（不再有结构桩）。
 * --*/

#include <intrin.h>
#include "dnz_teacher.h"
#include "dnz_hook.h"
#include "dnz_guest.h"

DNZ_TEACHER_STATE g_TState;

/* 内核驱动不链接 CRT；用到浮点（老师伪代码里的 double 比较）会引 _fltused，
 * 标准做法：自己提供一个（.rdata 段，值无所谓）。 */
#pragma section(".rdata$T", read)
__declspec(allocate(".rdata$T")) const int _fltused = 0;

/* ================= 便捷宏 ================= */

#define TCTX          ((UINT64)&g_DnzHook.GuestCtx)          /* g_Hook_GuestCr3OrCtx */
#define OT(byteOff)   (g_DnzHook.OffsetTable[(byteOff) / 4]) /* g_Hook_OffsetTable DWORD */
#define TG_PTR_OK(v)  ((UINT64)((v) - 0xFFFF) <= 0x7FFFFFFF0000ULL) /* 老师 0xFFFF..0x7FFF... 合法指针区间 */

/* ================= guest 读写薄封装（老师 Hv_* 原语） ================= */

static UINT64 TgReadU64(UINT64 Va) { return Hv_ReadGuestU64(TCTX, Va); }
static UINT32 TgReadU32(UINT64 Va) { return Hv_ReadGuestU32(TCTX, Va); }
static UINT16 TgReadU16(UINT64 Va) { return Hv_ReadGuestU16(TCTX, Va); }
static UINT8  TgReadU8(UINT64 Va)  { return Hv_ReadGuestU8(TCTX, Va); }

static VOID
TgReadBytes(
    _In_ UINT64 Va,
    _Out_ PVOID Dst,
    _In_ ULONG  Len
    )
{
    Hv_ReadGuestBytes(TCTX, Dst, Va, Len);
}

static VOID
TgWriteBytes(
    _In_ UINT64 Va,
    _In_ const void* Src,
    _In_ ULONG  Len
    )
{
    Hv_WriteGuestBytes(TCTX, Va, Src, Len);
}

/* ================= FNV-1a ================= */

static UINT64
TgFnv8(
    _In_ UINT64 Key
    )
{
    /* 老师原样：8 字节，低位字节先 */
    UINT64 h = DNZ_FNV_BASIS;
    UINT32 i;

    for (i = 0; i < 8; i++)
    {
        h = DNZ_FNV_PRIME * ((UINT8)(Key >> (8 * i)) ^ h);
    }
    return h;
}

static UINT64
TgFnvStr(
    _In_ const UINT8* Str
    )
{
    UINT64 h = DNZ_FNV_BASIS;

    while (*Str != 0)
    {
        h = DNZ_FNV_PRIME * ((UINT8)(*Str) ^ h);
        Str++;
    }
    return h;
}

/* ================= 哈希链表机制（老师桶/哨兵/链尾链头语义） =================
 * 桶项 +0 = 链尾，+8 = 链头；空桶两者 = 哨兵。
 * 节点：+0 prev / +8 next / +16 key（QWORD 或 DWORD）/ +24 data... */

static VOID
TgListInit(
    _In_ PDNZ_TLIST T
    )
{
    ULONG i;

    RtlZeroMemory(T, sizeof(*T));
    T->Sentinel = (UINT64)&T->SentinelBuf[0];
    T->SentinelBuf[0] = T->Sentinel;
    T->SentinelBuf[1] = T->Sentinel;
    T->Mask = DNZ_TLIST_BUCKETS - 1;
    T->LoadFactor = 0x3F800000ULL;   /* 1.0f */
    for (i = 0; i < DNZ_TLIST_BUCKETS; i++)
    {
        T->BucketNext[i] = T->Sentinel;
        T->BucketPrev[i] = T->Sentinel;
    }
}

static UINT8*
TgPoolAlloc(
    _In_ PUINT8 Pool,
    _In_ ULONG  NodeSize,
    _In_ ULONG  Count
    )
{
    /* 老师 Mem_HeapAllocRaw：从 size-class 堆分配 + 清零（静态池已移除，
     * 节点全部走老师堆 —— 见 dnz_heap.c） */
    UNREFERENCED_PARAMETER(Pool);
    UNREFERENCED_PARAMETER(Count);
    return (UINT8*)DnzHeapAllocRaw(NodeSize);
}

static VOID
TgPoolFree(
    _In_ PUINT8 Node,
    _In_ ULONG  NodeSize
    )
{
    /* 老师 Mem_HeapFree(ptr, size) */
    DnzHeapFree(Node, NodeSize);
}

static UINT8*
TgListFindKey(
    _In_ PDNZ_TLIST T,
    _In_ ULONG  BucketIdx,
    _In_ UINT64 Key,
    _In_ BOOLEAN QwordKey
    )
{
    UINT8* sentinel = (UINT8*)T->Sentinel;
    UINT8* head = (UINT8*)T->BucketPrev[BucketIdx];
    UINT8* tail = (UINT8*)T->BucketNext[BucketIdx];
    UINT8* cur = head;

    if (cur == sentinel)
    {
        return NULL;
    }
    if (QwordKey ? (*(UINT64*)(cur + 16) == Key)
                 : (*(UINT32*)(cur + 16) == (UINT32)Key))
    {
        return cur;
    }
    while (cur != tail)
    {
        cur = *(UINT8**)(cur + 8);
        if (QwordKey ? (*(UINT64*)(cur + 16) == Key)
                     : (*(UINT32*)(cur + 16) == (UINT32)Key))
        {
            return cur;
        }
    }
    return NULL;
}

static UINT8*
TgListFind8(
    _In_ PDNZ_TLIST T,
    _In_ UINT64 Key
    )
{
    return TgListFindKey(T, (ULONG)(TgFnv8(Key) & T->Mask), Key, TRUE);
}

static UINT8*
TgListFindPid(
    _In_ PDNZ_TLIST T,
    _In_ UINT32 Pid
    )
{
    return TgListFindKey(T, (ULONG)(DnzFnv1a(Pid) & T->Mask), (UINT64)Pid, FALSE);
}

static VOID
TgListInsert(
    _In_ PDNZ_TLIST T,
    _In_ ULONG  BucketIdx,
    _In_ PUINT8 Node
    )
{
    UINT8* sentinel = (UINT8*)T->Sentinel;
    UINT8* tail = (UINT8*)T->BucketNext[BucketIdx];
    UINT8* tailNext;

    /* 老师原样：插到链尾后面（v8 = 链尾或哨兵，v24 = v8->next） */
    tailNext = (tail == sentinel) ? (UINT8*)T->SentinelBuf[1] : *(UINT8**)(tail + 8);
    *(UINT8**)(Node + 0) = tail;
    *(UINT8**)(Node + 8) = tailNext;
    *(UINT8**)(tailNext + 0) = Node;
    *(UINT8**)(tail + 8) = Node;
    T->BucketNext[BucketIdx] = (UINT64)Node;          /* 新链尾 */
    if (tail == sentinel)
    {
        T->BucketPrev[BucketIdx] = (UINT64)Node;      /* 空桶：链头也是它 */
    }
    T->Count++;
}

static UINT8*
TgListRemove(
    _In_ PDNZ_TLIST T,
    _In_ UINT64 Key,
    _In_ BOOLEAN QwordKey
    )
{
    ULONG idx = (ULONG)((QwordKey ? TgFnv8(Key) : DnzFnv1a((UINT32)Key)) & T->Mask);
    UINT8* sentinel = (UINT8*)T->Sentinel;
    UINT8* head = (UINT8*)T->BucketPrev[idx];
    UINT8* tail = (UINT8*)T->BucketNext[idx];
    UINT8* cur = head;
    UINT8* prev;
    UINT8* next;
    BOOLEAN match;

    if (cur == sentinel)
    {
        return NULL;
    }
    match = QwordKey ? (*(UINT64*)(cur + 16) == Key)
                     : (*(UINT32*)(cur + 16) == (UINT32)Key);
    if (!match)
    {
        while (cur != tail)
        {
            cur = *(UINT8**)(cur + 8);
            match = QwordKey ? (*(UINT64*)(cur + 16) == Key)
                             : (*(UINT32*)(cur + 16) == (UINT32)Key);
            if (match)
            {
                break;
            }
        }
        if (!match)
        {
            return NULL;
        }
    }

    prev = *(UINT8**)(cur + 0);
    next = *(UINT8**)(cur + 8);
    *(UINT8**)(next + 0) = prev;
    *(UINT8**)(prev + 8) = next;

    /* 老师 sub_14018CC80：链头被删 -> 链头 = 下一个（单节点 -> 哨兵）；
     * 链尾被删 -> 链尾 = 上一个 */
    if (head == cur)
    {
        T->BucketPrev[idx] = (next == sentinel) ? T->Sentinel : (UINT64)next;
    }
    if (tail == cur)
    {
        T->BucketNext[idx] = (prev == sentinel) ? T->Sentinel : (UINT64)prev;
    }
    T->Count--;
    return cur;
}

/* ================= 列表封装 ================= */

static UINT8*
DnzNameListInsert(
    _In_ UINT32 Pid,
    _In_ UINT64 NameHash
    )
{
    UINT8* node = TgListFindPid(&g_TState.NameList, Pid);

    if (node != NULL)
    {
        return node;
    }
    node = TgPoolAlloc(NULL, 0x20, 0);
    if (node == NULL)
    {
        return NULL;
    }
    *(UINT32*)(node + 16) = Pid;
    *(UINT64*)(node + 24) = NameHash;
    TgListInsert(&g_TState.NameList,
                 (ULONG)(DnzFnv1a(Pid) & g_TState.NameList.Mask),
                 node);
    return node;
}

static UINT8*
DnzEventQueueInsert(
    _In_ UINT64 Key
    )
{
    UINT8* node = TgListFind8(&g_TState.EventQueue, Key);

    if (node != NULL)
    {
        return node;
    }
    node = TgPoolAlloc(NULL, 0x28, 0);
    if (node == NULL)
    {
        return NULL;
    }
    *(UINT64*)(node + 16) = Key;
    TgListInsert(&g_TState.EventQueue,
                 (ULONG)(TgFnv8(Key) & g_TState.EventQueue.Mask),
                 node);
    return node;
}

static VOID
DnzXlateInsert(
    _In_ UINT64 Key,
    _In_ UINT64 Data0,
    _In_ UINT64 Data1
    )
{
    UINT8* node = TgListFind8(&g_TState.XlateCache, Key);

    if (node != NULL)
    {
        *(UINT64*)(node + 24) = Data0;
        *(UINT64*)(node + 32) = Data1;
        return;
    }
    node = TgPoolAlloc(NULL, 0x28, 0);
    if (node == NULL)
    {
        return;
    }
    *(UINT64*)(node + 16) = Key;
    *(UINT64*)(node + 24) = Data0;
    *(UINT64*)(node + 32) = Data1;
    TgListInsert(&g_TState.XlateCache,
                 (ULONG)(TgFnv8(Key) & g_TState.XlateCache.Mask),
                 node);
}

static UINT8*
DnzEntity1Insert(
    _In_ UINT64 Key
    )
{
    UINT8* node = TgListFind8(&g_TState.Entity1, Key);

    if (node != NULL)
    {
        return node;
    }
    node = TgPoolAlloc(NULL, 0x70, 0);
    if (node == NULL)
    {
        return NULL;
    }
    *(UINT64*)(node + 16) = Key;
    TgListInsert(&g_TState.Entity1,
                 (ULONG)(TgFnv8(Key) & g_TState.Entity1.Mask),
                 node);
    return node;
}

static UINT8*
DnzEntity0Insert(
    _In_ UINT64 Key
    )
{
    UINT8* node = TgListFind8(&g_TState.Entity0, Key);

    if (node != NULL)
    {
        return node;
    }
    node = (UINT8*)DnzHeapAllocAligned(21616 + 24);   /* >=0x1000：走大块区对齐分配 */
    if (node == NULL)
    {
        return NULL;
    }
    *(UINT64*)(node + 16) = Key;
    TgListInsert(&g_TState.Entity0,
                 (ULONG)(TgFnv8(Key) & g_TState.Entity0.Mask),
                 node);
    return node;
}

/* ================= 通用叶子 helper ================= */

/* sub_140176810：读 guest QWORD（指针） */
static UINT64
DnzSub_140176810(
    _In_ UINT64 Va
    )
{
    return TgReadU64(Va);
}

/* sub_1401769B0：读 guest WORD（名字长度字段） */
static UINT16
DnzSub_1401769B0(
    _In_ UINT64 Va
    )
{
    return TgReadU16(Va);
}

/* sub_1401E9D70：在 a1 里找子串 a2（老师原样：返回匹配位置或 NULL） */
static PUINT8
DnzSub_1401E9D70(
    _In_ PUINT8 A1,
    _In_ PUINT8 A2
    )
{
    UINT8* v4;
    UINT64 v5;
    UINT64 v6;
    UINT8* v7;
    UINT8* v8;

    if (A1 == NULL || A2 == NULL)
    {
        return NULL;
    }
    if (*A2 == 0)
    {
        return A1;
    }
    v4 = A2;
    do
    {
        ++v4;
    } while (*v4 != 0);
    v5 = (UINT64)(v4 - A2);
    if (*A1 == 0)
    {
        return NULL;
    }
    v6 = v5;
    v7 = A2;
    v8 = A1;
    if (v5 != 0)
    {
        while (v8 != A2)
        {
            while (1)
            {
                --v6;
                if (*A1 == 0 || *A1 != *v7)
                {
                    break;
                }
                ++A1;
                ++v7;
                if (v6 == 0)
                {
                    return v8;
                }
            }
            if (v6 == (UINT64)-1 || *A1 == *v7)
            {
                break;
            }
            A1 = ++v8;
            if (*v8 == 0)
            {
                return NULL;
            }
            v6 = v5;
            v7 = A2;
        }
    }
    return v8;
}

/* sub_1401E98D0：不区分大小写的字符串比较（老师原样，返回差值） */
static INT64
DnzSub_1401E98D0(
    _In_ PUINT8 A1,
    _In_ PUINT8 A2
    )
{
    UINT8* v2;
    UINT8* v3;
    UINT8 i;
    UINT8 v6;
    UINT8 v7;
    UINT8 v8;
    UINT8 v9;

    v2 = A2;
    v3 = A1;
    if (A1 == A2)
    {
        return 0;
    }
    if (A1 == NULL)
    {
        return 0xFFFFFFFFLL;
    }
    if (A2 == NULL)
    {
        return 1;
    }
    for (i = *A1; i != 0; ++v2)
    {
        v6 = *v2;
        if (*v2 == 0)
        {
            break;
        }
        v7 = (UINT8)(i + 32);
        if ((UINT8)(i - 65) > 0x19u)
        {
            v7 = i;
        }
        if ((UINT8)(v6 - 65) <= 0x19u)
        {
            v6 = (UINT8)(v6 + 32);
        }
        if (v7 != v6)
        {
            return v7 - (INT64)v6;
        }
        i = *++v3;
    }
    v8 = *v3;
    if ((UINT8)(*v3 - 65) <= 0x19u)
    {
        v8 = (UINT8)(v8 + 32);
    }
    v9 = *v2;
    if ((UINT8)(*v2 - 65) <= 0x19u)
    {
        v9 = (UINT8)(v9 + 32);
    }
    return v8 - (INT64)v9;
}

/* sub_14014FEE0：UTF-16 -> UTF-8 转换（老师原样，含代理对） */
static UINT32
DnzSub_14014FEE0(
    _In_  PUINT16 A1,
    _In_  INT     A2,
    _Out_ PUINT8  A3,
    _In_  INT     A4
    )
{
    UINT32 v8;
    INT v9;
    INT v10;
    INT v12;
    UINT32 v14;
    INT v15;
    INT v17;
    INT v19;
    UINT32 v21;
    UINT32 v22;
    PUINT8 v23;
    INT v24;
    UINT32 v25;
    UINT8 v26;
    UINT32 v27;
    INT v28;
    UINT8 v29;
    UINT32 v30;
    UINT32 v31;

    if (A1 == NULL || A2 < 0)
    {
        if (A3 != NULL && A4 > 0)
        {
            *A3 = 0;
        }
        return 0;
    }
    v8 = 0;
    v9 = 1;
    v10 = 0;
    if (A2 > 0)
    {
        INT v11 = 0;
        do
        {
            v12 = A1[v11];
            if ((UINT16)v12 == 0)
            {
                break;
            }
            ++v10;
            if ((UINT16)v12 < 0xD800u || (UINT16)v12 > 0xDBFFu)
            {
                if ((UINT16)(v12 + 9216) <= 0x3FFu)
                {
                    return 0;
                }
                v14 = A1[v11++];
            }
            else
            {
                if (v10 >= A2)
                {
                    return 0;
                }
                v12 = A1[v11 + 1];
                if ((UINT16)(v12 + 9216) > 0x3FFu)
                {
                    return 0;
                }
                v14 = ((UINT32)v12 << 10) + (UINT32)v12 - 56613888;
                ++v10;
                v11 += 2;
            }
            if (v14 > 0x7F)
            {
                if (v14 > 0x7FF)
                {
                    if (v14 > 0xFFFF)
                    {
                        if (v14 > 0x10FFFF)
                        {
                            return 0;
                        }
                        v15 = 4;
                    }
                    else
                    {
                        v15 = 3;
                    }
                }
                else
                {
                    v15 = 2;
                }
            }
            else
            {
                v15 = 1;
            }
            if (v9 > 0x7FFFFFFF - v15)
            {
                return 0;
            }
            v9 += v15;
        } while (v10 < A2);
    }
    if (A3 == NULL)
    {
        return (UINT32)v9;
    }
    if (A4 < v9)
    {
        if (A4 > 0)
        {
            *A3 = 0;
        }
        return 0;
    }
    v17 = 0;
    if (A2 > 0)
    {
        INT v18 = 0;
        do
        {
            v19 = A1[v18];
            if ((UINT16)v19 == 0)
            {
                break;
            }
            ++v17;
            if ((UINT16)v19 < 0xD800u || (UINT16)v19 > 0xDBFFu)
            {
                if ((UINT16)(v19 + 9216) <= 0x3FFu)
                {
                    return 0;
                }
                v21 = A1[v18++];
            }
            else
            {
                if (v17 >= A2)
                {
                    return 0;
                }
                v19 = A1[v18 + 1];
                if ((UINT16)(v19 + 9216) > 0x3FFu)
                {
                    return 0;
                }
                v21 = ((UINT32)v19 << 10) + (UINT32)v19 - 56613888;
                ++v17;
                v18 += 2;
            }
            v22 = v8 + 1;
            v23 = &A3[v8];
            if (v21 > 0x7F)
            {
                v24 = (INT)v22;
                v25 = v8 + 2;
                v26 = (UINT8)((v21 & 0x3F) | 0x80);
                v27 = v21 >> 6;
                if (v21 > 0x7FF)
                {
                    v28 = (INT)v25;
                    v29 = (UINT8)((v27 & 0x3F) | 0x80);
                    v30 = v21 >> 12;
                    v31 = v25 + 1;
                    if (v21 > 0xFFFF)
                    {
                        *v23 = (UINT8)(((v21 >> 18) & 7) | 0xF0);
                        A3[v24] = (UINT8)((v30 & 0x3F) | 0x80);
                        A3[v28] = v29;
                        A3[v31] = v26;
                        v8 = v31 + 1;
                    }
                    else
                    {
                        *v23 = (UINT8)((v30 & 0xF) | 0xE0);
                        A3[v24] = v29;
                        A3[v28] = v26;
                        v8 = v31;
                    }
                }
                else
                {
                    *v23 = (UINT8)((v27 & 0x1F) | 0xC0);
                    A3[v22] = v26;
                    v8 = v22 + 1;
                }
            }
            else
            {
                *v23 = (UINT8)v21;
                ++v8;
            }
        } while (v17 < A2);
    }
    A3[v8] = 0;
    return v8;
}

/* sub_1401757E0：UTF-16 缓冲按长度解密（老师原样，WORD 异或） */
static VOID
DnzSub_1401757E0(
    _In_ UINT32 A2
    )
{
    UINT32 i;

    if (*(UINT16*)&g_TState.Utf16Buf[0] == 0)
    {
        return;
    }
    for (i = 0; i < A2; i += 2)
    {
        UINT16 key;
        switch (A2 % 9)
        {
        case 0:  key = (UINT16)(A2 + (A2 & 0x1F) + 128) | 0x7F; break;
        case 1:  key = (UINT16)(A2 + (A2 ^ 0xDF) + 128) | 0x7F; break;
        case 2:  key = (UINT16)(A2 + (A2 | 0xCF) + 128) | 0x7F; break;
        case 3:  key = (UINT16)(33 * A2 + 128) | 0x7F; break;
        case 4:  key = (UINT16)(A2 + (A2 >> 2) + 128) | 0x7F; break;
        case 5:  key = (UINT16)(3 * A2 + 133) | 0x7F; break;
        case 6:  key = (UINT16)(A2 + ((4 * A2) | 5) + 128) | 0x7F; break;
        case 7:  key = (UINT16)(A2 + ((A2 >> 4) | 7) + 128) | 0x7F; break;
        case 8:  key = (UINT16)(A2 + (A2 ^ 0xC) + 128) | 0x7F; break;
        default: key = (UINT16)(A2 + (A2 ^ 0x40) + 128) | 0x7F; break;
        }
        ((UINT16*)&g_TState.Utf16Buf[0])[i / 2] ^= key;
    }
}

/* sub_140175AA0：字节缓冲按长度解密（老师原样，BYTE 异或） */
static VOID
DnzSub_140175AA0(
    _In_ UINT32 A2
    )
{
    UINT32 i;

    if (g_TState.Utf16Buf[0] == 0)
    {
        return;
    }
    for (i = 0; i < A2; i++)
    {
        UINT8 key;
        switch (A2 % 9)
        {
        case 0:  key = (UINT8)(A2 + (A2 & 0x1F) + 0x80) | 0x7F; break;
        case 1:  key = (UINT8)(A2 + (A2 ^ 0xDF) + 0x80) | 0x7F; break;
        case 2:  key = (UINT8)(A2 + (A2 | 0xCF) + 0x80) | 0x7F; break;
        case 3:  key = (UINT8)(33 * A2 + 0x80) | 0x7F; break;
        case 4:  key = (UINT8)(A2 + (A2 >> 2) + 0x80) | 0x7F; break;
        case 5:  key = (UINT8)(2 * A2 + A2 - 123) | 0x7F; break;
        case 6:  key = (UINT8)(A2 + ((4 * A2) | 5) + 0x80) | 0x7F; break;
        case 7:  key = (UINT8)(A2 + ((A2 >> 4) | 7) + 0x80) | 0x7F; break;
        case 8:  key = (UINT8)(A2 + (A2 ^ 0xC) + 0x80) | 0x7F; break;
        default: key = (UINT8)(A2 + (A2 ^ 0x40) + 0x80) | 0x7F; break;
        }
        g_TState.Utf16Buf[i] ^= key;
    }
}

/* sub_140175D20：读 guest UTF-16/字节串到静态缓冲（老师原样） */
static UINT64
DnzSub_140175D20(
    _In_  UINT64 A1,
    _Out_ PUINT8 A2,
    _Out_ PUINT16 A3
    )
{
    UINT16 v6 = DnzSub_1401769B0(A1);
    UINT64 v10;
    UINT32 v11;

    if (v6 == 0)
    {
        *(UINT16*)&g_TState.Utf16Buf[0] = 0;
        return (UINT64)&g_TState.Utf16Buf[0];
    }
    v10 = v6 >> 6;
    v11 = (UINT32)v10;

    if (v6 & 1)
    {
        /* UTF-16：拷 2*v10 字节 */
        TgReadBytes(A1 + 2, g_TState.Utf16Buf, (ULONG)(2 * v10));
        if (OT(272) != 0)
        {
            UINT32 i;
            UINT16 key = g_TState.Utf16Key;
            if (*(UINT16*)&g_TState.Utf16Buf[0] != 0)
            {
                for (i = 0; i < v11; i++)
                {
                    ((UINT16*)&g_TState.Utf16Buf[0])[i] ^= key;
                }
            }
        }
        else
        {
            DnzSub_1401757E0(v11);
        }
        ((UINT16*)&g_TState.Utf16Buf[0])[v11] = 0;
        *A2 = 1;
        *A3 = (UINT16)v11;
    }
    else
    {
        /* 字节串：拷 v10 字节 */
        TgReadBytes(A1 + 2, g_TState.Utf16Buf, (ULONG)v10);
        if (OT(272) != 0)
        {
            UINT32 i;
            UINT8 key = (UINT8)g_TState.Utf16Key;
            if (g_TState.Utf16Buf[0] != 0)
            {
                for (i = 0; i < v11; i++)
                {
                    g_TState.Utf16Buf[i] ^= key;
                }
            }
        }
        else
        {
            DnzSub_140175AA0(v11);
        }
        g_TState.Utf16Buf[v11] = 0;
        *A2 = 0;
        *A3 = (UINT16)v11;
    }
    return (UINT64)&g_TState.Utf16Buf[0];
}

/* sub_140176080：读游戏内进程名（二级表 + UTF-16 -> UTF-8 到 NameBuf） */
static UINT64
DnzSub_140176080(
    _In_ UINT32 Pid
    )
{
    UINT32 v2 = OT(16);
    UINT64 v3 = DnzSub_140176810(g_TState.NtosBase + v2 + 8 * ((UINT64)Pid >> 18) + 8);
    UINT8  v5;
    UINT16 v6;
    UINT64 result = DnzSub_140175D20(v3 + 2 * (Pid & 0x3FFFF), &v5, &v6);

    if (v5 != 0)
    {
        DnzSub_14014FEE0((PUINT16)result, v6, g_TState.NameBuf, 4096);
        return (UINT64)g_TState.NameBuf;
    }
    return result;
}

/* sub_140176110：进程名 + "_C_" 截断（老师原样） */
static const char*
DnzSub_140176110(
    _In_ UINT32 Pid
    )
{
    UINT64 v2;
    PUINT8 v3;

    if (Pid == 0)
    {
        return "NULL0";
    }
    v2 = DnzSub_140176080(Pid);
    v3 = DnzSub_1401E9D70((PUINT8)v2, (PUINT8)"_C_");
    if (v3 != NULL)
    {
        v3[2] = 0;
    }
    return (const char*)v2;
}

/* sub_140176B60：进程名哈希表 find-or-insert（节点 0x20：+16 DWORD pid / +24 hash） */
static VOID
DnzSub_140176B60(
    _In_ UINT32 Pid,
    _In_ UINT64 Hash
    )
{
    (VOID)DnzNameListInsert(Pid, Hash);
}

/* sub_140176FD0：事件队列 find-or-insert（节点 0x28：+16 key / +24 data0 / +32 dword data1） */
static UINT8*
DnzSub_140176FD0(
    _In_ UINT64 Key
    )
{
    return DnzEventQueueInsert(Key);
}

/* sub_1401764F0：翻译缓存 find-or-insert（节点 0x28，data 16 字节） */
static VOID
DnzSub_1401764F0(
    _In_ UINT64 Key,
    _In_ const UINT64* Data16
    )
{
    DnzXlateInsert(Key, Data16[0], Data16[1]);
}

/* sub_140178FB0：PID 状态表查找（节点 0x20：+16 DWORD pid / +24 QWORD data） */
static UINT8
DnzSub_140178FB0(
    _In_ UINT32 Pid,
    _Out_ PUINT64 Out
    )
{
    UINT8* node;
    UINT8 r = 0;

    if (Pid == 0 || Out == NULL)
    {
        return 0;
    }
    while (InterlockedCompareExchange(&g_TState.LockPid, 1, 0) == 1)
    {
        _mm_pause();
    }
    node = TgListFindPid(&g_TState.PidState, Pid);
    if (node != NULL)
    {
        r = 1;
        *Out = *(UINT64*)(node + 24);
    }
    InterlockedExchange(&g_TState.LockPid, 0);
    return r;
}

/* sub_140180A80：实体表 1 查找（返回节点或哨兵） */
static VOID
DnzSub_140180A80(
    _Out_ PUINT64 Out,
    _In_  UINT64 Key
    )
{
    UINT8* node = TgListFind8(&g_TState.Entity1, Key);

    *Out = (node != NULL) ? (UINT64)node : g_TState.Entity1.Sentinel;
}

/* sub_140181890：实体表 1 find-or-insert（Out[0] = 节点，Out[1] = 新插入标志） */
static VOID
DnzSub_140181890(
    _Out_ PUINT64 Out,
    _In_  UINT64 Key
    )
{
    UINT8* node = TgListFind8(&g_TState.Entity1, Key);

    if (node != NULL)
    {
        Out[0] = (UINT64)node;
        Out[1] = 0;
        return;
    }
    node = DnzEntity1Insert(Key);
    if (node == NULL)
    {
        Out[0] = 0;
        Out[1] = 0;
        return;
    }
    Out[0] = (UINT64)node;
    Out[1] = 1;
}

/* sub_140180D20：实体表 0 find-or-insert（数据区 21616 字节清零） */
VOID
DnzSub_140180D20(
    _Out_ PUINT64 Out,
    _In_  UINT64 Key
    )
{
    UINT8* node = TgListFind8(&g_TState.Entity0, Key);

    if (node != NULL)
    {
        Out[0] = (UINT64)node;
        Out[1] = 0;
        return;
    }
    node = DnzEntity0Insert(Key);
    if (node == NULL)
    {
        Out[0] = 0;
        Out[1] = 0;
        return;
    }
    Out[0] = (UINT64)node;
    Out[1] = 1;
}

/* sub_14018CC80：事件状态表 find-remove（返回是否删掉） */
static UINT64
DnzSub_14018CC80(
    _In_ UINT64 Key
    )
{
    UINT8* node = TgListRemove(&g_TState.EventState, Key, TRUE);

    if (node == NULL)
    {
        return 0;
    }
    TgPoolFree(node, 0x28);
    return 1;
}

/* sub_140184D90：实体数组寻址（OT(32) = 每槽元素数，OT(36) = 元素大小） */
static UINT64
DnzSub_140184D90(
    _In_ UINT64 A2,
    _In_ UINT32 A3
    )
{
    UINT64 result = TgReadU64(A2 + 8 * (A3 / OT(32)));

    if (result != 0)
    {
        return DnzSub_140176810(result + OT(36) * (A3 % OT(32)));
    }
    return result;
}

/* sub_140166D10：读 guest 16 字节（自瞄用） */
static VOID
DnzSub_140166D10(
    _Out_ PUINT64 Out,
    _In_  UINT64 Va
    )
{
    if (Va > 0x10000)
    {
        TgReadBytes(Va, Out, 16);
    }
    else
    {
        Out[0] = 0;
        Out[1] = 0;
    }
}

/* sub_14018C6B0：读 guest 8 字节 */
static VOID
DnzSub_14018C6B0(
    _Out_ PUINT64 Out,
    _In_  UINT64 Va
    )
{
    if (Va > 0x10000)
    {
        TgReadBytes(Va, Out, 8);
    }
    else
    {
        *Out = 0;
    }
}

/* sub_14015D2D0：读 guest 4 字节（低 32 位 = float 位模式） */
static double
DnzSub_14015D2D0(
    _In_ UINT64 Va
    )
{
    UINT32 v = 0;
    double r;

    if (Va > 0x10000)
    {
        TgReadBytes(Va, &v, 4);
    }
    *(UINT64*)&r = (UINT64)v;
    return r;
}

/* sub_14016B1C0：写 guest 1 字节 */
static VOID
DnzSub_14016B1C0(
    _In_ UINT64 Va,
    _In_ UINT8  Val
    )
{
    if ((UINT64)(Va - 0x10000) <= 0x7FFFFFFEFFFEULL)
    {
        TgWriteBytes(Va, &Val, 1);
    }
}

/* sub_14016B300：写 guest 8 字节 */
static UINT64
DnzSub_14016B300(
    _In_ UINT64 Va,
    _In_ UINT64 Val
    )
{
    if ((UINT64)(Va - 0x10000) > 0x7FFFFFFEFFFEULL)
    {
        return 0;
    }
    TgWriteBytes(Va, &Val, 8);
    return 1;
}

/* sub_14016B410：写 guest 12 字节（3 个 float） */
static UINT64
DnzSub_14016B410(
    _In_ UINT64 Va,
    _In_ const void* Src
    )
{
    if ((UINT64)(Va - 0x10000) > 0x7FFFFFFEFFFEULL)
    {
        return 0;
    }
    TgWriteBytes(Va, Src, 12);
    return 1;
}

/* sub_14017B030：从 guest 读字符串（带长度头） */
static VOID
DnzSub_14017B030(
    _Out_ PUINT8 A1,
    _In_  UINT64 A2,
    _In_  UINT64 A3
    )
{
    UINT64 v3;
    UINT64 GuestU64;
    UINT64 v7;

    if (A1 == NULL)
    {
        return;
    }
    *A1 = 0;
    v3 = A3;
    if ((UINT64)(A3 - 0xFFFF) <= 0x7FFFFFFF0000ULL)
    {
        GuestU64 = TgReadU64(A3 + 16);
        v7 = TgReadU64(v3 + 24);
        if (GuestU64 - 1 <= 0xFFF)
        {
            if (v7 > 0xF)
            {
                v3 = TgReadU64(v3);
            }
            if ((UINT64)(v3 - 0xFFFF) <= 0x7FFFFFFF0000ULL)
            {
                if (GuestU64 >= A2)
                {
                    GuestU64 = A2 - 1;
                }
                if (v3 > 0x10000)
                {
                    TgReadBytes(v3, A1, (ULONG)GuestU64);
                    A1[GuestU64] = 0;
                    return;
                }
            }
        }
    }
    *A1 = 0;
}

/* sub_1401687E0：读 guest 1280 字节并向后扫描 mov [rsp+imm8],rcx / add rcx,8 特征 */
static UINT64
DnzSub_1401687E0(
    _In_ UINT64 A1
    )
{
    UINT64 result = OT(132);
    UINT8 v19[1280];
    UINT64 v3;
    INT64 v10;
    INT64 v11;

    if ((UINT32)result != 0)
    {
        return result;
    }
    result = g_TState.Ntos2000;
    if ((UINT32)result != 0)
    {
        return result;
    }
    v3 = A1 - 1280;
    if ((UINT64)(A1 - 1280) <= 0x10000)
    {
        return 0;
    }

    TgReadBytes(v3, v19, 1280);

    v10 = 1272;
    v11 = 1272;
    while (v19[v11] != 0x48 ||
           v19[v11 + 1] != 0x89 ||
           v19[v11 + 2] != 0x4C ||
           v19[v11 + 3] != 0x24 ||
           v19[v11 + 5] != 0x48 ||
           v19[v11 + 6] != 0x83 ||
           v19[v11 + 7] != 0xC1)
    {
        --v10;
        if (--v11 < 0)
        {
            InterlockedCompareExchange(&g_TState.CntBF70, 0, 1);
            return 0;
        }
    }
    result = (UINT64)(UINT8)v19[v10 + 4] + 8;
    g_TState.Ntos2000 = (UINT32)result;
    return result;
}

/* sub_14016B540 的两条真身路径（老师原样）：
 *   1) g_Sys_ConfigFlags+216 != 0（NtApi 钩子启用，sub_14018D350 置 1）
 *      -> sub_1401196F0：把 128 字节上下文帧写到 guest 栈 + 改 guest RIP/RSP
 *         到 handler（替身模拟返回机制，对应我们 DnzDispatchNtApi 尾部的
 *         VMCS 写回）
 *   2) 否则 -> Esp_ApplyGuestProloguePatch：往 guest 函数 prologue 写 E9 跳板 */

/* 老师 sub_1401196F0（641 字节）：guest 上下文重定向。
 * 差异（文档化）：老师操作每核 vcpu ctx（qword_148287008 槽）+
 * HV_SaveGprContext/RestoreSavedHostState；我们用 VMCS 写回等价。 */
static UINT64
DnzSub_1401196F0(
    _In_ UINT64 A1,
    _In_ UINT64 A2,
    _In_ UINT64 A3,
    _In_ UINT64 A4
    )
{
    UINT64 guestRsp = 0;
    UINT64 frameVa;
    UINT8  frame[128];

    /* 老师: v16 = (v13 & ~0xF) - 200，v13 = 当前 guest RSP（vcpu ctx +152 槽） */
    __vmx_vmread(GUEST_RSP, &guestRsp);
    frameVa = (guestRsp & ~0xF) - 200;

    /* v29 帧：v29[0] = qword_14828E008（目标 RIP），其余清零 */
    RtlZeroMemory(frame, sizeof(frame));
    *(UINT64*)&frame[0] = A2;
    Hv_WriteGuestBytes(TCTX, frameVa, frame, 128);

    /* 老师: v11[31]=a2(RIP)、v11[19]=v16(RSP)。我们写回 VMCS，
     * 执行重定向与 DnzDispatchNtApi 尾部的统一写回等价。 */
    __vmx_vmwrite(GUEST_RIP, A2);
    __vmx_vmwrite(GUEST_RSP, frameVa);

    UNREFERENCED_PARAMETER(A1);
    UNREFERENCED_PARAMETER(A3);
    UNREFERENCED_PARAMETER(A4);
    return A2;   /* 老师返回 v27[15]（vcpu ctx Rax 槽）；我们映射为翻译目标 */
}

/* 老师 Esp_ApplyGuestProloguePatch（1103 字节）：往 guest prologue 写 E9 跳板。
 * 差异（文档化）：老师按 vcpu 状态选 g_HookedRip_PresentA/B/C；我们写
 * 标准 E9 rel32 到目标，返回目标地址。 */
static UINT64
DnzEspApplyGuestProloguePatch(
    _In_ UINT64 A1,
    _In_ UINT64 A2,
    _In_ UINT64 A3
    )
{
    UINT8  patch[5];
    INT32  rel;
    UINT64 target;

    UNREFERENCED_PARAMETER(A3);
    target = (A2 != 0) ? A2 : A1;

    /* E9 rel32：目标 - (跳板地址 + 5) */
    patch[0] = 0xE9;
    rel = (INT32)(target - (A1 + 5));
    RtlCopyMemory(&patch[1], &rel, 4);
    Hv_WriteGuestBytes(TCTX, A1, patch, 5);
    return target;
}

/* sub_14016B540：prologue patch 分派（老师真身原样） */
static UINT64
DnzSub_14016B540(
    _In_ UINT64 A1,
    _In_ UINT64 A2,
    _In_ UINT64 A3
    )
{
    /* 老师: if (*(BYTE*)(g_Sys_ConfigFlags+216) != 0)
     *          return sub_1401196F0(A1, A1, A2, A3, 0,0,0,0,0, v4);
     *        else
     *          return Esp_ApplyGuestProloguePatch(A1, *(qword_1402707B8),
     *                 A1, A2, A3, 0,0,0,0,0, v5,v6,v7,v8); */
    if (g_TState.ConfigFlags[216] != 0)
    {
        return DnzSub_1401196F0(A1, A1, A2, A3);
    }
    return DnzEspApplyGuestProloguePatch(A1, A2, A3);
}

/* sub_1401755B0：指针翻译 + 缓存（老师原样结构） */
static UINT64
DnzSub_1401755B0(
    _In_ UINT64 A1
    )
{
    UINT64 GuestU64 = TgReadU64(A1);
    UINT8* node;

    if (g_TState.Ntos2130 == 0)
    {
        return GuestU64 & 0x7FFFFFFFFFFFULL;
    }
    if (GuestU64 <= 0x7FFFFFFFFFFFULL)
    {
        return GuestU64;
    }

    node = TgListFind8(&g_TState.XlateCache, A1);
    if (node != NULL && *(UINT64*)(node + 24) == GuestU64)
    {
        return *(UINT64*)(node + 32);
    }

    {
        UINT64 v9 = DnzSub_14016B540(g_TState.NtosBase + OT(176), A1 - 400, 0);
        UINT64 data[2];
        data[0] = GuestU64;
        data[1] = v9;
        DnzSub_1401764F0(A1, data);
        return v9;
    }
}

/* sub_140179340：从 guest 读实体快照到 96 字节缓冲（老师原样逐字段） */
static VOID
DnzSub_140179340(
    _In_  UINT64 A1,
    _Out_ PUINT8 A2
    )
{
    UINT64 v4;
    UINT32 GuestU32;
    UINT32 v7;
    UINT64 GuestU64;
    UINT32 v11;
    UINT32 v13;
    UINT64 v15;
    UINT64 v17;
    UINT32 v19;
    UINT32 v21;
    UINT32 v23;
    UINT32 v25;
    UINT32 v27;
    UINT32 v29;
    UINT32 v31;
    UINT64 v33;
    UINT64 result;
    UINT32 v36;
    UINT32 v38;

    if ((UINT32)TgReadU32(A1 + 76) == 200 &&
        TG_PTR_OK((v4 = TgReadU64(A1 + 64))))
    {
        GuestU32 = TgReadU32(v4 + 16);
        *(UINT32*)(A2 + 20) = GuestU32;
        v7 = TgReadU32(v4 + 20);
        *(UINT32*)(A2 + 16) = v7;
        GuestU64 = TgReadU64(v4 + 24);
        *(UINT32*)(A2 + 28) = (UINT32)GuestU64;
        v11 = TgReadU32(v4 + 32);
        *(UINT32*)(A2 + 56) = v11;
        v13 = TgReadU32(v4 + 36);
        *(UINT32*)(A2 + 60) = v13;
        v15 = DnzSub_140176810(v4 + 48);
        *(UINT64*)(A2 + 48) = v15;
        v17 = DnzSub_140176810(v4 + 56);
        *(UINT64*)(A2 + 32) = v17;
        v19 = TgReadU32(v4 + 68);
        *(UINT32*)(A2 + 24) = v19;
        v21 = TgReadU32(v4 + 80);
        *(UINT32*)(A2 + 80) = v21;
        v23 = TgReadU32(v4 + 84);
        *(UINT32*)(A2 + 72) = v23;
        v25 = TgReadU32(v4 + 88);
        *(UINT32*)(A2 + 64) = v25;
        v27 = TgReadU32(v4 + 92);
        *(UINT32*)(A2 + 84) = v27;
        v29 = TgReadU32(v4 + 96);
        *(UINT32*)(A2 + 76) = v29;
        v31 = TgReadU32(v4 + 100);
        *(UINT32*)(A2 + 68) = v31;
        v33 = DnzSub_140176810(v4 + 120);
        *(UINT64*)(A2 + 40) = v33;
        result = DnzSub_140176810(v4 + 128);
        *(UINT32*)(A2 + 12) = (UINT32)result;
        *(UINT8*)A2 = 1;
    }
    else
    {
        v36 = TgReadU32(A1 + 24);
        *(UINT32*)(A2 + 20) = v36;
        v38 = TgReadU32(A1 + 32);
        *(UINT32*)(A2 + 16) = v38;
        result = TgReadU64(A1 + 48);
        *(UINT32*)(A2 + 28) = (UINT32)result;
        *(UINT8*)A2 = 1;
    }
}

/* sub_14017B600：读 guest 子实体快照到 184 字节缓冲（老师原样逐字段） */
static VOID
DnzSub_14017B600(
    _In_ UINT64 A1,
    _In_ UINT64 A2
    )
{
    UINT64 GuestU64;
    UINT64 v16;
    UINT32 GuestU32;
    UINT32 v20;
    UINT32 v22;
    UINT8  GuestU8;
    UINT64 v26;
    UINT32 v28;
    UINT32 v30;
    UINT32 v32;
    UINT32 v34;
    UINT8  v36;
    UINT8  v38;
    UINT64 v40;
    UINT64 v41;
    UINT64 v42;
    UINT32 v44;
    UINT32 v46;
    UINT32 v48;
    UINT32 v50;
    UINT32 v52;
    UINT64 v54;
    UINT64 v56;
    UINT64 v58;
    UINT64 v60;
    UINT32 v62;
    UINT32 v64;

    if (A2 != 0 && TG_PTR_OK(A1))
    {
        RtlZeroMemory((PVOID)A2, 184);
        *(UINT8*)A2 = 1;
        GuestU64 = TgReadU64(A1 + 40);
        DnzSub_14017B030((PUINT8)(A2 + 16), 0x40, GuestU64);
        v16 = TgReadU64(A1 + 48);
        *(UINT64*)(A2 + 8) = v16;
        GuestU32 = TgReadU32(A1 + 56);
        *(UINT32*)(A2 + 88) = GuestU32;
        v20 = TgReadU32(A1 + 60);
        *(UINT32*)(A2 + 80) = v20;
        v22 = TgReadU32(A1 + 64);
        *(UINT32*)(A2 + 92) = v22;
        GuestU8 = TgReadU8(A1 + 68);
        *(UINT32*)(A2 + 84) = GuestU8;
        v26 = DnzSub_140176810(A1 + 72);
        *(UINT64*)(A2 + 112) = v26;
        v28 = TgReadU32(A1 + 88);
        *(UINT32*)(A2 + 96) = v28;
        v30 = TgReadU32(A1 + 92);
        *(UINT32*)(A2 + 100) = v30;
        v32 = TgReadU32(A1 + 96);
        *(UINT32*)(A2 + 104) = v32;
        v34 = TgReadU32(A1 + 100);
        *(UINT32*)(A2 + 172) = v34;
        v36 = TgReadU8(A1 + 105);
        *(UINT8*)(A2 + 176) = (v36 != 0) ? 1 : 0;
        v38 = TgReadU8(A1 + 108);
        *(UINT8*)(A2 + 177) = (v38 != 0) ? 1 : 0;

        if ((UINT32)TgReadU32(A1 + 124) == 20 &&
            (v40 = TgReadU64(A1 + 112), TG_PTR_OK(v40)))
        {
            v41 = v40;
            v42 = DnzSub_140176810(v40 + 64);
            *(UINT64*)(A2 + 112) = v42;
            v44 = (UINT32)DnzSub_140176810(v41 + 72);
            *(UINT32*)(A2 + 92) = v44;
            v46 = TgReadU32(v41 + 80);
            *(UINT32*)(A2 + 160) = v46;
            v48 = TgReadU32(v41 + 88);
            *(UINT32*)(A2 + 96) = v48;
            v50 = TgReadU32(v41 + 92);
            *(UINT32*)(A2 + 100) = v50;
            v52 = TgReadU32(v41 + 96);
            *(UINT32*)(A2 + 104) = v52;
            v54 = DnzSub_140176810(v41 + 104);
            *(UINT64*)(A2 + 136) = v54;
            v56 = DnzSub_140176810(v41 + 112);
            *(UINT64*)(A2 + 128) = v56;
            v58 = DnzSub_140176810(v41 + 120);
            *(UINT64*)(A2 + 120) = v58;
            v60 = TgReadU64(v41 + 128);
            *(UINT64*)(A2 + 152) = v60;
            v62 = TgReadU32(v41 + 140);
            *(UINT32*)(A2 + 164) = v62;
            v64 = TgReadU32(v41 + 152);
            *(UINT32*)(A2 + 168) = v64;
            *(UINT64*)(A2 + 144) = DnzSub_140176810(v41 + 232);
        }
        else
        {
            *(UINT64*)(A2 + 120) = *(UINT64*)(A2 + 112);
        }
    }
}

/* sub_1401E98D0 包装：和配置字符串比（老师: sub_1401E98D0(v10, g_Sys_ConfigFlags + 240)） */
static UINT32
DnzSub_1401E98D0Cfg(
    _In_ const UINT8* A1
    )
{
    return (UINT32)DnzSub_1401E98D0((PUINT8)A1, &g_TState.ConfigFlags[240]);
}

/* Hook_LogListEntry（老师原样：计数 + 探测性 guest 读，不产生输出） */
VOID
DnzHookLogListEntry(
    _In_ const char* Name,
    _In_ UINT32 Pid,
    _In_ UINT64 A3
    )
{
    LONGLONG v4;
    UINT64 v5;

    while (InterlockedCompareExchange(&g_TState.LockList, 1, 0) == 1)
    {
        _mm_pause();
    }
    InterlockedExchange(&g_TState.LockList, 0);

    if (g_TState.LogEnable != 0 || (Pid & 0xF0000000) == 0xA0000000)
    {
        v4 = (LONGLONG)InterlockedIncrement(&g_TState.LogCount);
        if (v4 <= 16 || v4 == 50 * (v4 / 50))
        {
            if (A3 != 0 && (v5 = *(UINT64*)(A3 + 128), TG_PTR_OK(v5)))
            {
                TgReadU32(v5 + 40);
            }
            else if (A3 == 0)
            {
                return;
            }
            TgReadU64(*(UINT64*)(A3 + 160) - OT(252));
        }
    }
    UNREFERENCED_PARAMETER(Name);
}

/* HV_FlushOrSyncAfterRegister：老师原样空函数 */
static VOID
DnzHvFlushOrSyncAfterRegister(
    VOID
    )
{
}

/* ================= 老师事件队列 flush 机制 =================
 * HV_HandlePendingEvent 原样还原。老师的队列是 raw 堆结构（a1[1]=链头、
 * a1[2]=计数、a1[3]=桶基址、a1[4]=容量指针、a1[6]=掩码、a1[7]=容量），
 * 我们映射到 DNZ_TLIST（静态池，文档化偏差）。老师的逻辑：
 *   计数 != 0 -> 容量够（a1[7]>>3 <= 计数）全清（sub_140066580 释放全链 +
 *   sub_140065C80 memset 清桶区）；容量不够只清到链头（sub_1400661D0）。
 * 静态池下节点数恒 <= 池容量 -> 恒走"全清"路径；"部分清"分支等价（都释放回池）。
 * Mem_HeapFree -> 节点 +0 置 0 = 空闲标记（TgPoolAlloc 判据）。 */

/* 池释放：老师 Mem_HeapFree 语义（事件队列/状态表节点 = 0x28） */
static VOID
DnzPoolFreeNode(
    _In_ UINT64 P
    )
{
    DnzHeapFree((void*)P, 0x28);
}

/* sub_140066580：释放整条链表（老师原样：从链头沿 next 走，逐个释放） */
static VOID
DnzSub_140066580(
    _In_ UINT64 A1,
    _In_ UINT64* A2
    )
{
    UINT64* v2;
    UINT64* v3;

    UNREFERENCED_PARAMETER(A1);
    v2 = A2;
    if (v2 != NULL)
    {
        do
        {
            v3 = (UINT64*)*v2;
            DnzPoolFreeNode((UINT64)v2);
            v2 = v3;
        } while (v3 != NULL);
    }
}

/* sub_140065C80：memset 填充（老师原样：成块填 + 剩余逐个填） */
static UINT64
DnzSub_140065C80(
    _In_ UINT64* A1,
    _In_ UINT64* A2,
    _In_ UINT64* A3
    )
{
    UINT64 result = 0;
    UINT64* v5 = A1;
    UINT64 v6 = ((UINT64)((PUINT8)A2 - (PUINT8)A1 + 7) >> 3);

    if (A1 > A2)
    {
        v6 = 0;
    }
    if (v6 >= 2)
    {
        result = *A3;
        if (v5 > A3 || &A1[v6 - 1] < A3)
        {
            UINT64 v8 = 8 * (v6 & 0xFFFFFFFFFFFFFFFEULL);
            RtlFillMemory(v5, (SIZE_T)v8, (UCHAR)*A3);
            v5 = (UINT64*)((PUINT8)v5 + v8);
        }
    }
    for (; v5 != A2; ++v5)
    {
        result = *A3;
        *v5 = *A3;
    }
    return result;
}

/* HV_HandlePendingEvent：事件积压处理（老师原样逻辑，适配 DNZ_TLIST）。
 * 容量够全清，不够只清到链头；静态池下恒走全清路径。 */
static VOID
DnzHvHandlePendingEvent(
    _In_ PDNZ_TLIST List
    )
{
    ULONG i;
    UINT64 savedSentinel;
    UINT64 sentinelBuf[2];

    if (List->Count == 0)
    {
        return;
    }

    /* 老师: sub_140066580 释放整条链（所有桶） */
    for (i = 0; i < DNZ_TLIST_BUCKETS; i++)
    {
        UINT8* cur = (UINT8*)List->BucketPrev[i];
        UINT8* tail = (UINT8*)List->BucketNext[i];
        UINT8* sentinel = (UINT8*)List->Sentinel;

        while (cur != NULL && cur != sentinel)
        {
            UINT8* next = *(UINT8**)(cur + 8);
            DnzPoolFreeNode((UINT64)cur);
            if (cur == tail)
            {
                break;
            }
            cur = next;
        }
        List->BucketPrev[i] = List->Sentinel;
        List->BucketNext[i] = List->Sentinel;
    }

    /* 老师: 重置链头为自引用 + 计数归零 + memset 清桶区（sub_140065C80） */
    savedSentinel = List->Sentinel;
    sentinelBuf[0] = savedSentinel;
    sentinelBuf[1] = savedSentinel;
    List->SentinelBuf[0] = savedSentinel;
    List->SentinelBuf[1] = savedSentinel;
    List->Count = 0;
}


/* Hook_LookupByPid（ACE_LookupListHookByPid）：ListHook 链表 find + 拷数据 + 删节点 */
UINT8
DnzHookLookupRemoveByPid(
    _In_ UINT32 Pid,
    _Out_ PUINT64 Out24
    )
{
    UINT64 hash;
    ULONG bucket;
    PDNZ_LIST_NODE head;
    PDNZ_LIST_NODE prev;
    PDNZ_LIST_NODE cur;
    UINT8 found = 0;

    if (Pid == 0 || Out24 == NULL)
    {
        return 0;
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
            Out24[0] = cur->Data[0];
            Out24[1] = cur->Data[1];
            Out24[2] = cur->Data[2];
            RtlZeroMemory(cur, sizeof(*cur));
            found = 1;
            break;
        }
        prev = cur;
        cur = cur->Next;
    }

    InterlockedExchange(&g_DnzHook.ListLock, 0);
    return found;
}

/* sub_1401944D0：配置检查（老师原样：FNV 哈希黑名单集合判断）。
 * 返回 1 = 该哈希不在黑名单（启用），0 = 命中黑名单（禁用）。 */
UINT8
DnzSub_1401944D0(
    _In_ UINT64 A1
    )
{
    UINT64 v1;
    UINT64 v2;

    if (A1 > 0x438094203LL)
    {
        if (A1 > 0x438A1D881LL)
        {
            if (A1 != 0x438A1D882LL && A1 - 0x46BE46787LL > 1)
            {
                return (A1 != 0x46BE46794LL) ? 1 : 0;
            }
            return 0;
        }
        if (A1 != 0x438A1D881LL)
        {
            switch (A1)
            {
                case 0x438094208uLL:
                case 0x43809420AuLL:
                case 0x43809420BuLL:
                case 0x43809420DuLL:
                case 0x43809420EuLL:
                case 0x43809420FuLL:
                case 0x438094211uLL:
                case 0x438094212uLL:
                case 0x438094214uLL:
                case 0x438094215uLL:
                case 0x438094218uLL:
                case 0x438094219uLL:
                case 0x43809421AuLL:
                case 0x43809421BuLL:
                case 0x43809421CuLL:
                case 0x43809421DuLL:
                case 0x438094220uLL:
                case 0x438094221uLL:
                case 0x438094222uLL:
                case 0x438094225uLL:
                case 0x43809422BuLL:
                case 0x43809422EuLL:
                case 0x43809422FuLL:
                case 0x438094232uLL:
                case 0x438094238uLL:
                case 0x438094239uLL:
                case 0x43809423AuLL:
                case 0x43809423BuLL:
                case 0x43809423FuLL:
                case 0x438094244uLL:
                case 0x438094246uLL:
                case 0x438094248uLL:
                case 0x438094249uLL:
                    return 0;
                default:
                    return 1;
            }
        }
        return 0;
    }
    if (A1 != 0x438094203LL)
    {
        v1 = A1 - 0x435A6E803LL;
        if (v1 > 0x10)
        {
            return 1;
        }
        v2 = 68101;   /* 0x10A05：bitmap，bit N = A1 == 0x435A6E803 + N 在黑名单 */
        if (!_bittest64((const LONG64*)&v2, (LONG)v1))
        {
            return 1;
        }
    }
    return 0;
}

/* sub_140175230：翻译缓存 find-or-insert（老师原样：qword_14DB95C90 计数保护）。
 * a1 = key（8 字节 FNV），a2 = 16 字节 data（+0 = data0，+8 低 4 字节 = data1）。
 * 语义：计数非 -1 且 CAS 递增成功 → 桶内找 key；命中更新 +24/+32 并递减返回；
 * 未命中递减后走 LABEL_14：CAS 拿独占（0→-1）成功 → 事件队列插入 + 写 data。 */
UINT64
DnzSub_140175230(
    _In_ UINT64 Key,
    _In_ const UINT64* Data16
    )
{
    UINT64 result;
    LONGLONG v2;
    UINT8* node;

    if (g_TState.XlateCounter == -1)
    {
        goto LABEL_14;
    }
    v2 = g_TState.XlateCounter;
    if (v2 != InterlockedCompareExchange64(&g_TState.XlateCounter, v2 + 1, v2))
    {
        goto LABEL_14;
    }

    node = TgListFind8(&g_TState.XlateCache, Key);
    if (node != NULL)
    {
        /* 命中：节点 +24 = data0，+32 = data1（dword） */
        *(UINT64*)(node + 24) = Data16[0];
        *(UINT32*)(node + 32) = (UINT32)Data16[1];
        InterlockedDecrement64(&g_TState.XlateCounter);
        return (UINT64)(UINT32)Data16[1];
    }
    InterlockedDecrement64(&g_TState.XlateCounter);

LABEL_14:
    result = InterlockedCompareExchange64(&g_TState.XlateCounter, -1, 0);
    if (result == 0)
    {
        UINT64 data0 = Data16[0];
        UINT32 data1 = (UINT32)Data16[1];

        /* 老师: sub_140176FD0(事件队列 find-or-insert) -> 节点 +24/+32 写 data */
        node = DnzSub_140176FD0(Key);
        if (node != NULL)
        {
            *(UINT64*)(node + 24) = data0;
            *(UINT32*)(node + 32) = data1;
        }
        g_TState.XlateCounter = 0;
    }
    return result;
}

/* sub_14017B160：EPROCESS 摘要填充（老师原样）。a1 = guest EPROCESS 指针，
 * a2 = 344 字节输出结构。 */
VOID
DnzSub_14017B160(
    _In_ UINT64 A1,
    _In_ UINT64 A2
    )
{
    UINT64 v2;
    UINT64 v8;
    UINT64 v48;

    if (A2 != 0)
    {
        /* 清零 344 字节结构（老师原样按字段写 0） */
        *(UINT16*)(A2 + 0) = 0;
        *(UINT8*)(A2 + 2) = 0;
        RtlZeroMemory((PVOID)(A2 + 136), 192);
        *(UINT32*)(A2 + 272) = 0;
        *(UINT32*)(A2 + 320) = 0;
        if (A2 != -328)
        {
            *(UINT8*)(A2 + 328) = 0;
            *(UINT64*)(A2 + 332) = 0;
            *(UINT32*)(A2 + 340) = 0;
        }

        if (TG_PTR_OK(A1))
        {
            UINT64 GuestU64;
            UINT64 v7;
            UINT32 GuestU32;

            v2 = A2 + 136;
            *(UINT8*)A2 = 1;
            GuestU64 = TgReadU64(A1 + 64);
            DnzSub_14017B030((PUINT8)(A2 + 2), 0x80, GuestU64);
            v7 = TgReadU64(A1 + 72);
            v8 = v7;
            if (v2 != 0 && TG_PTR_OK(v7))
            {
                GuestU32 = TgReadU32(v7 + 16);
                *(UINT32*)v2 = GuestU32;
                *(UINT32*)(v2 + 4) = TgReadU32(v8 + 20);
                *(UINT32*)(v2 + 8) = TgReadU32(v8 + 24);
                *(UINT32*)(v2 + 12) = TgReadU32(v8 + 28);
                *(UINT32*)(v2 + 16) = TgReadU32(v8 + 32);
                *(UINT32*)(v2 + 20) = TgReadU32(v8 + 36);
                *(UINT64*)(v2 + 24) = TgReadU64(v8 + 40);
                *(UINT64*)(v2 + 32) = DnzSub_140176810(v8 + 48);
                *(UINT32*)(v2 + 40) = TgReadU32(v8 + 56);
            }
            *(UINT32*)(A2 + 184) = TgReadU32(A1 + 96);
            *(UINT32*)(A2 + 188) = TgReadU32(A1 + 100);
            *(UINT32*)(A2 + 192) = TgReadU8(A1 + 104);
            *(UINT32*)(A2 + 196) = TgReadU32(A1 + 108);
            *(UINT64*)(A2 + 200) = TgReadU64(A1 + 112);
            *(UINT64*)(A2 + 208) = TgReadU64(A1 + 120);
            *(UINT64*)(A2 + 216) = TgReadU64(A1 + 128);
            *(UINT64*)(A2 + 240) = DnzSub_140176810(A1 + 160);
            *(UINT64*)(A2 + 232) = DnzSub_140176810(A1 + 168);
            *(UINT8*)(A2 + 224) = (TgReadU8(A1 + 188) != 0) ? 1 : 0;
            *(UINT8*)(A2 + 225) = (TgReadU8(A1 + 189) == 1) ? 1 : 0;
            if ((UINT32)TgReadU32(A1 + 252) == 20)
            {
                v48 = TgReadU64(A1 + 240);
                if (TG_PTR_OK(v48))
                {
                    *(UINT64*)(A2 + 248) = DnzSub_140176810(v48 + 64);
                    *(UINT64*)(A2 + 256) = DnzSub_140176810(v48 + 72);
                    *(UINT32*)(A2 + 264) = TgReadU32(v48 + 88);
                    *(UINT32*)(A2 + 268) = TgReadU32(v48 + 92);
                    *(UINT32*)(A2 + 272) = TgReadU32(v48 + 96);
                    *(UINT64*)(A2 + 296) = DnzSub_140176810(v48 + 104);
                    *(UINT64*)(A2 + 280) = DnzSub_140176810(v48 + 112);
                    *(UINT64*)(A2 + 288) = DnzSub_140176810(v48 + 120);
                    if (*(UINT64*)(A2 + 208) == 0)
                    {
                        *(UINT64*)(A2 + 208) = TgReadU64(v48 + 128);
                    }
                    *(UINT32*)(A2 + 312) = TgReadU32(v48 + 140);
                    *(UINT32*)(A2 + 316) = TgReadU32(v48 + 152);
                    *(UINT32*)(A2 + 320) = TgReadU32(v48 + 200);
                    *(UINT64*)(A2 + 304) = DnzSub_140176810(v48 + 232);
                }
            }
        }
    }
}

/* ACE_ReadProcessListFromGuest：读 guest 进程列表（老师原样）。a1 = 列表头指针，
 * a2 = 输出缓冲（头 16 字节 + 1080 字节 × 20 条目）。 */
VOID
Hv_ReadProcessListFromGuest(
    _In_ UINT64 A1,
    _In_ UINT64 A2
    )
{
    UINT32 v2 = 0;
    UINT32 v6;
    UINT32 v8;
    UINT8  v10;
    UINT32 v11;
    UINT64 v12;
    UINT64 v13;
    UINT64 v14;
    UINT64 v15;
    UINT64 v16;
    UINT64 v17;

    if (A2 != 0)
    {
        *(UINT16*)(A2 + 1) = 1;
        *(UINT8*)A2 = 0;
        *(UINT32*)(A2 + 12) = 0;
        *(UINT8*)(A2 + 3) = 0;
        if (TG_PTR_OK(A1) && (UINT32)TgReadU32(A1 + 40) == 0)
        {
            *(UINT8*)A2 = 1;
            v6 = TgReadU32(A1 + 44);
            *(UINT32*)(A2 + 4) = v6;
            v8 = TgReadU32(A1 + 52);
            *(UINT32*)(A2 + 8) = v8;
            v10 = TgReadU8(A1 + 56);
            *(UINT8*)(A2 + 3) = (v10 != 0) ? 1 : 0;
            if (!v10)
            {
                v11 = TgReadU32(A1 + 24);
                v12 = A1 + 32;
                if ((INT32)v11 < 0)
                {
                    TgReadU64(v12);
                    return;
                }
                if ((INT32)v11 <= 20)
                {
                    v13 = TgReadU64(v12);
                    if ((INT32)v11 <= 0)
                    {
                        return;
                    }
                }
                else
                {
                    v11 = 20;
                    v13 = TgReadU64(v12);
                }
                v14 = v13 + 8;
                v15 = v13 - 0xFFFF;
                do
                {
                    if (v15 <= 0x7FFFFFFF0000ULL)
                    {
                        v16 = TgReadU64(v14);
                        if (TG_PTR_OK(v16))
                        {
                            DnzSub_14017B160(v16, A2 + 1080LL * *(INT32*)(A2 + 12) + 16);
                            v17 = *(INT32*)(A2 + 12);
                            if (*(UINT8*)(1080 * (UINT32)v17 + A2 + 16) != 0)
                            {
                                *(UINT32*)(A2 + 12) = (UINT32)(v17 + 1);
                            }
                        }
                    }
                    v2++;
                    v14 += 8;
                } while (v2 < v11);
            }
        }
    }
}

/* ================= 8 个子函数 ================= */

/* sub_140187B90：条件跳转模拟（+1960）—— Rcx+504 读指针，查事件状态表，
 * EFlags.ZF 决定 Rip 前移 22（ZF=0）或 2（ZF=1） */
UINT64
DnzSub_140187B90(
    _In_ UINT64* A2
    )
{
    PUINT8 A1 = (PUINT8)A2;
    UINT64 v2;
    UINT64 GuestU64;
    UINT64 v4;
    UINT64 v5;
    UINT8  v6;
    UINT64 v7;
    UINT64 v8;
    UINT64 v11;
    UINT64 v12;
    double v13;
    UINT64 v14;
    UINT64 v15;
    UINT8  v16;
    UINT64 result;
    UINT64 v18;

    v2 = *(UINT64*)(A1 + 128) + OT(504);
    g_TState.LastRead0 = *(UINT64*)(A1 + 128);
    GuestU64 = TgReadU64(v2);
    g_TState.LastRead1 = GuestU64;
    g_TState.Flag3D5 = 0;
    v4 = GuestU64;
    if (!TG_PTR_OK(GuestU64))
    {
        v6 = 1;
        goto L22;
    }

    v18 = GuestU64;
    v5 = g_TState.Ntos1840;
    v6 = (GuestU64 == v5) ? 1 : 0;
    v7 = DnzSub_1401755B0(GuestU64 + OT(476));
    v8 = v7 - 0xFFFF;
    if ((UINT64)(v7 - 0xFFFF) > 0x7FFFFFFF0000ULL)
    {
        v8 = 1;
        g_TState.Flag3D5 = 1;
        if (g_TState.ConfigFlags[221] != 0)
        {
            v6 = 1;
            goto L15;
        }
    }
    else
    {
        v8 = 0;
        g_TState.Flag3D5 = 0;
    }

    if (v4 != v5)
    {
        if ((UINT8)v8 != 0 ||
            (g_TState.ConfigFlags[377] == 0 ||
             (UINT32)TgReadU32(v7 + OT(640)) != g_TState.Ntos1896) &&
            (g_TState.ConfigFlags[378] == 0 ||
             (UINT32)TgReadU32(v7 + OT(644)) != g_TState.Ntos1900))
        {
            v11 = DnzSub_1401755B0(v4 + OT(552));
            if (!TG_PTR_OK(v11))
            {
                goto L22;
            }
            v12 = DnzSub_1401755B0(v11 + OT(556));
            if (!TG_PTR_OK(v12))
            {
                goto L22;
            }
            v13 = DnzSub_14015D2D0(v12 + OT(560));
            if (g_TState.ConfigFlags[220] == 0 || *(float*)&v13 > 0.0f)
            {
                goto L22;
            }
        }
        v6 = 1;
    }

L15:
    while (InterlockedCompareExchange(&g_TState.LockEvent, 1, 0) == 1)
    {
        _mm_pause();
    }
    DnzSub_14018CC80(v18);
    InterlockedExchange(&g_TState.LockEvent, 0);

L22:
    v14 = *(UINT64*)(A1 + 152);
    g_TState.Flag3D4 = v6;
    v15 = TgReadU64(v14);
    if ((UINT64)(v15 - g_TState.NtosBase) >= 0x18000000)
    {
        InterlockedCompareExchange(&g_TState.CntC044, 0, 1);
    }
    v16 = (*(UINT32*)(A1 + 68) & 0x40) == 0;   /* ZF 位 */
    g_TState.LastRead2 = v15;
    result = 22;
    if (v16 == 0)
    {
        result = 2;
    }
    *(UINT64*)(A1 + 248) += result;
    return result;
}

/* sub_140187E60：登记事件 + 武器编号检查（+1968） */
VOID
DnzSub_140187E60(
    _In_ UINT64* A2
    )
{
    UINT64 v2;
    UINT64 GuestU64;
    UINT8  v5;
    UINT8  v6;
    UINT8  v7;
    UINT32 v8;
    UINT32 v9;
    const char* v10;
    UINT64 v11;
    UINT64 v12;
    INT64  v13;
    float  v14;
    UINT64 v15;
    UINT32 v16;
    UINT8* v17;
    UINT64 v18[2];

    Hv_WriteGuestU64(TCTX, A2[19] + 32, A2[24]);
    v2 = A2[19];
    A2[31] += 5;
    GuestU64 = TgReadU64(v2);
    if ((UINT64)(GuestU64 - g_TState.NtosBase) >= 0x18000000)
    {
        InterlockedCompareExchange(&g_TState.CntC040, 0, 1);
    }
    v5 = g_TState.ConfigFlags[219];
    if (g_TState.ConfigFlags[218] != 0 && g_TState.ConfigFlags[660] != 0)
    {
        v6 = 1;
    }
    else
    {
        v6 = 0;
        if (v5 == 0)
        {
            return;
        }
    }

    if ((UINT64)(GuestU64 - g_TState.LastRead2) <= 0x2000 && g_TState.Flag3D4 == 0)
    {
        UINT64 v21 = 0;
        DnzSub_14018C6B0(&v21, A2[16] + 88);
        v7 = 0;
        v8 = g_TState.Ntos1984;
        if (v8 != 0)
        {
            v7 = ((UINT32)v21 == v8) ? 1 : 0;
            if ((UINT32)v21 != v8 && v5 != 0 && (UINT32)v21 != 0xFFFFFFFF)
            {
                DnzSub_140176110((UINT32)v21);
            }
        }
        else
        {
            v9 = (UINT32)v21;
            if ((UINT32)v21 == 0xFFFFFFFF)
            {
                v10 = "INVALID";
            }
            else
            {
                v10 = DnzSub_140176110((UINT32)v21);
            }
            if (g_TState.ConfigFlags[240] != 0 &&
                DnzSub_1401E98D0Cfg((const UINT8*)v10) == 0)
            {
                g_TState.Ntos1984 = v9;
                while (InterlockedCompareExchange(&g_TState.LockEvent, 1, 0) == 1)
                {
                    _mm_pause();
                }
                DnzHvHandlePendingEvent(&g_TState.EventQueue);
                v7 = 1;
                InterlockedExchange(&g_TState.LockEvent, 0);
            }
        }

        if (v6 != 0 && v7 != 0)
        {
            v11 = g_TState.Ntos1928;
            v12 = 0;
            v13 = 0;
            if (v11 == 0x436D8150BLL)
            {
                v14 = *(float*)&g_TState.ConfigFlags[236];
            }
            else
            {
                v12 = v11 - 0x4E44B2883LL;
                if (v12 <= 9 && (v13 = 577, _bittest64(&v13, (UINT8)v12)))
                {
                    v14 = *(float*)&g_TState.ConfigFlags[236];
                }
                else if (g_TState.Flag3D5 != 0)
                {
                    v14 = *(float*)&g_TState.ConfigFlags[232];
                }
                else
                {
                    v14 = *(float*)&g_TState.ConfigFlags[228];
                }
            }
            {
                UINT64 v14v = 0;
                memcpy(&v14v, &v14, 4);
                Hv_WriteGuestPtr(TCTX, A2[23], v14v);
            }
            TgReadBytes(A2[17] + 16, v18, 16);
            while (InterlockedCompareExchange(&g_TState.LockEvent, 1, 0) == 1)
            {
                _mm_pause();
            }
            v15 = v18[0];
            v16 = (UINT32)v18[1];
            v17 = DnzSub_140176FD0(g_TState.LastRead1);
            if (v17 != NULL)
            {
                *(UINT64*)(v17 + 24) = v15;
                *(UINT32*)(v17 + 32) = v16;
            }
            InterlockedExchange(&g_TState.LockEvent, 0);
        }

        if (v5 != 0)
        {
            DnzHvFlushOrSyncAfterRegister();
        }
    }
}

/* sub_1401881D0：事件状态表查找 + 击杀计数写入（+1976） */
UINT64
DnzSub_1401881D0(
    _In_ UINT64* A2
    )
{
    UINT64 v2;
    UINT32 v3;
    UINT32 GuestU32;
    UINT64 GuestU64;
    UINT64 v5;
    UINT64 v7;
    UINT8* v8;
    UINT8* v9;
    UINT64 v10;
    UINT32 v11;
    UINT64 v13;
    UINT32 v14;
    UINT64 v15;
    UINT8 result;

    if (g_TState.ConfigFlags[218] == 0 ||
        g_TState.ConfigFlags[660] == 0 ||
        g_TState.Ntos1984 == 0)
    {
        goto L25;
    }

    v2 = A2[19];
    v3 = OT(160);
    GuestU32 = TgReadU32(v2 + v3 + 112);
    if (GuestU32 != 0)
    {
        GuestU64 = TgReadU64(g_TState.NtosBase + OT(20));
        if (!TG_PTR_OK(GuestU64))
        {
            v5 = 0;
        }
        else
        {
            v7 = DnzSub_140184D90(GuestU64, GuestU32);
            v5 = TG_PTR_OK(v7) ? v7 : 0;
        }
    }
    else
    {
        v5 = 0;
    }

    v15 = v5;
    v13 = 0;
    v14 = 0;
    while (InterlockedCompareExchange(&g_TState.LockEvent, 1, 0) == 1)
    {
        _mm_pause();
    }
    v8 = TgListFind8(&g_TState.EventState, v5);
    v9 = (v8 != NULL) ? v8 : (UINT8*)g_TState.EventState.Sentinel;
    if (v9 == (UINT8*)g_TState.EventState.Sentinel)
    {
        InterlockedExchange(&g_TState.LockEvent, 0);
    }
    else
    {
        v10 = *(UINT64*)(v9 + 24);
        v11 = *(UINT32*)(v9 + 32);
        InterlockedExchange(&g_TState.LockEvent, 0);
        DnzSub_14018C6B0(&v15, v2 + v3 + 128);
        if ((UINT32)v15 == g_TState.Ntos1984)
        {
            v13 = v10;
            v14 = v11;
            DnzSub_14016B410(v2 + v3 + 36, &v13);
        }
    }

L25:
    result = TgReadU8(OT(160) + 1 + A2[19]);
    A2[31] += 8;
    A2[15] = result;
    return result;
}

/* sub_140168A70：自瞄（+2024） */
UINT64
DnzSub_140168A70(
    _In_ UINT64* A2
    )
{
    UINT64 result = 0;
    UINT64 GuestU64;
    UINT64 v37 = 0;
    INT32  v38 = 0;
    UINT32 v6 = 0;
    UINT8  v7;
    UINT8  v39;
    UINT64 v17;
    UINT64 v18;
    INT32  v19 = 0;
    UINT32 v20 = 0;
    UINT32 i;
    float* f;

    Hv_WriteGuestU64(TCTX, A2[19] + 16, A2[17]);
    A2[31] += 5;

    if (g_TState.Aim.Target[0] != 0.0f ||
        g_TState.Aim.Target[1] != 0.0f ||
        g_TState.Aim.Target[2] != 0.0f)
    {
        {
            UINT64 tmp[2];
            DnzSub_140166D10(tmp, A2[17]);
            v37 = tmp[0];
            v38 = (INT32)tmp[1];
        }
        if (v37 != 0 && v38 > 0)
        {
            if ((g_TState.Aim.VectorFlag & 1) == 0)
            {
                g_TState.Aim.Vector[0] = 0;
                g_TState.Aim.VectorFlag |= 1;
                g_TState.Aim.Vector[2] = 0;
                g_TState.Aim.Vector[1] = 0;
            }
            GuestU64 = TgReadU64(A2[19]);
            {
                UINT64 v4 = GuestU64 - g_TState.NtosBase;

                g_TState.Aim.FlagB4 = (v4 >= 0x18000000) ? 1 : 0;
                if (v4 < 0x18000000)
                {
                    float xyz[4];
                    UINT64 t796 = OT(796), t788 = OT(788), t792 = OT(792);
                    UINT64 t800 = OT(800), t804 = OT(804);
                    UINT64 v24 = A2[16];
                    UINT64 v25 = v24 + t796 + t788;
                    UINT64 v26 = v24 + t796 + t792;
                    float inv;
                    UINT64 v28 = 0x3F8000003F800000ULL;

                    TgReadBytes(g_TState.Aim.ReadPtr, xyz, 16);
                    {
                        float dx = g_TState.Aim.Target[0] - xyz[0];
                        float dy = g_TState.Aim.Target[1] - xyz[1];
                        float dz = g_TState.Aim.Target[2] - xyz[2];
                        __m128 s = _mm_sqrt_ss(_mm_set_ss(dx * dx + dy * dy + dz * dz));
                        inv = 1.0f / _mm_cvtss_f32(s);
                    }
                    g_TState.Aim.Vector[0] = inv * (g_TState.Aim.Target[0] - xyz[0]);
                    g_TState.Aim.Vector[1] = inv * (g_TState.Aim.Target[1] - xyz[1]);
                    g_TState.Aim.Vector[2] = inv * (g_TState.Aim.Target[2] - xyz[2]);
                    DnzSub_14016B1C0(v25 + t800, 1);
                    DnzSub_14016B1C0(v26 + t800, 1);
                    DnzSub_14016B300(v25 + t804, v28);
                    DnzSub_14016B300(v26 + t804, v28);
                    goto L25;
                }
            }
            InterlockedCompareExchange(&g_TState.CntBF68, 0, 1);
            v6 = 0;
            v7 = (v38 == 1) ? 1 : 0;
            v39 = v7;
            if (v38 == 1)
            {
                v6 = (UINT32)g_TState.Aim.Counter0;
                result = (UINT32)++g_TState.Aim.Counter0;
                if (v6 >= 5)
                {
                    return result;
                }
                if (v6 != 0)
                {
                    goto L15;
                }
            }
            else
            {
                /* v8 = true（v38 != 1 时） */
            }

            {
                float xyz[4];
                UINT64 t796 = OT(796), t788 = OT(788), t792 = OT(792);
                UINT64 t800 = OT(800), t804 = OT(804);
                UINT64 v12 = A2[16];
                UINT64 v13 = v12 + t796 + t788;
                UINT64 v14 = v12 + t796 + t792;
                float inv;
                UINT64 v16 = 0x3F8000003F800000ULL;

                TgReadBytes(g_TState.Aim.ReadPtr, xyz, 16);
                {
                    float dx = g_TState.Aim.Target[0] - xyz[0];
                    float dy = g_TState.Aim.Target[1] - xyz[1];
                    float dz = g_TState.Aim.Target[2] - xyz[2];
                    __m128 s = _mm_sqrt_ss(_mm_set_ss(dx * dx + dy * dy + dz * dz));
                    inv = 1.0f / _mm_cvtss_f32(s);
                }
                g_TState.Aim.Vector[0] = inv * (g_TState.Aim.Target[0] - xyz[0]);
                g_TState.Aim.Vector[1] = inv * (g_TState.Aim.Target[1] - xyz[1]);
                g_TState.Aim.Vector[2] = inv * (g_TState.Aim.Target[2] - xyz[2]);
                DnzSub_14016B1C0(v13 + t800, 1);
                DnzSub_14016B1C0(v14 + t800, 1);
                DnzSub_14016B300(v13 + t804, v16);
                DnzSub_14016B300(v14 + t804, v16);
            }
            v7 = v39;

L15:
            if (v7 != 0)
            {
                result = DnzSub_1401687E0(GuestU64);
                if ((UINT32)result == 0)
                {
                    return result;
                }
                if (v6 == 0)
                {
                    v17 = TgReadU64(A2[19] + (UINT32)result);
                    InterlockedCompareExchange(&g_TState.CntBF6C, 0, 1);
                    v18 = TgReadU64(v17 + OT(136));
                    InterlockedCompareExchange(&g_TState.CntBF74, 0, 1);
                    v19 = (INT32)((0x5851F42D4C957F2DLL * v18 + 0x14057B7EF767814FLL) % 5LL);
                    g_TState.Aim.Spin[0] = (UINT32)v19;
                    result = 5 * ((v19 + 1) / 5);
                    v20 = (UINT32)((v19 + 1) % 5);
                    g_TState.Aim.Spin[1] = v20;
                }
                else
                {
                    v19 = (INT32)g_TState.Aim.Spin[0];
                    v20 = g_TState.Aim.Spin[1];
                }
                if (v6 == v20)
                {
                    UINT64 v32[2];
                    float nv[3];
                    TgReadBytes(v37, v32, 16);
                    f = (float*)v32;
                    nv[0] = (f[0] - g_TState.Aim.Vector[0]) + f[0];
                    nv[1] = (f[1] - g_TState.Aim.Vector[1]) + f[1];
                    nv[2] = (f[2] - g_TState.Aim.Vector[2]) + f[2];
                    DnzSub_14016B410(v37, nv);
                    goto L27;
                }
                if (v6 != (UINT32)v19)
                {
                    return result;
                }
            }

L25:
            ++g_TState.Aim.Counter1;
            if (v38 > 0)
            {
                i = 0;
                do
                {
                    float nv[3];
                    nv[0] = g_TState.Aim.Vector[0];
                    nv[1] = g_TState.Aim.Vector[1];
                    nv[2] = g_TState.Aim.Vector[2];
                    DnzSub_14016B410(v37 + 12 * i, nv);
                    i++;
                } while (i < (UINT32)v38);
            }

L27:
            A2[19] += 8;
            A2[31] = GuestU64;
            return result;
        }
    }
    return result;
}

/* sub_140176310：进程名 FNV 哈希查找/缓存（+2032 分支内部） */
UINT64
DnzSub_140176310(
    _In_ UINT64 A1
    )
{
    UINT32 GuestU32;
    UINT8* node;
    const char* v11;
    PUINT8 v12;
    UINT64 v18;

    GuestU32 = TgReadU32(A1 + OT(268));
    if (GuestU32 == 0)
    {
        return 0;
    }

    node = TgListFindPid(&g_TState.NameList, GuestU32);
    if (node != NULL)
    {
        return *(UINT64*)(node + 24);
    }

    if (GuestU32 != 0)
    {
        v11 = (const char*)DnzSub_140176080(GuestU32);
        v12 = DnzSub_1401E9D70((PUINT8)v11, (PUINT8)"_C_");
        if (v12 != NULL)
        {
            v12[2] = 0;
        }
    }
    else
    {
        v11 = "NULL0";
    }

    v18 = TgFnvStr((const UINT8*)v11);
    DnzSub_140176B60(GuestU32, v18);
    return v18;
}

/* sub_140179540：实体表 1 更新（+2048） */
UINT64
DnzSub_140179540(
    _In_ UINT64* A2
    )
{
    UINT64 GuestU64;
    UINT32 GuestU32;
    UINT64 v26 = 0;
    UINT64 v5;
    UINT8  v18[96];
    UINT64 v27;
    UINT64 v11;
    UINT64 v13;

    GuestU64 = TgReadU64(A2[20] - OT(252));
    if (TG_PTR_OK(GuestU64))
    {
        GuestU32 = TgReadU32(GuestU64 + 44);
    }
    else
    {
        GuestU32 = 0;
    }

    if (DnzSub_140178FB0(GuestU32, &v26) != 0)
    {
        while (InterlockedCompareExchange(&g_TState.LockPid, 1, 0) == 1)
        {
            _mm_pause();
        }
        v5 = v26;
        RtlZeroMemory(v18, sizeof(v18));
        if (v26 != 0)
        {
            while (InterlockedCompareExchange(&g_TState.LockEntity, 1, 0) == 1)
            {
                _mm_pause();
            }
            v27 = 0;
            DnzSub_140180A80(&v27, v26);
            if (v27 != g_TState.Entity1.Sentinel)
            {
                memcpy(v18, (PVOID)(v27 + 24), 80);
            }
            InterlockedExchange(&g_TState.LockEntity, 0);
        }

        DnzSub_140179340(A2[16], v18);
        if (*(UINT8*)v18 != 0)
        {
            v26 = v5;
            if (v5 != 0)
            {
                while (InterlockedCompareExchange(&g_TState.LockEntity, 1, 0) == 1)
                {
                    _mm_pause();
                }
                {
                    UINT64 out[2];
                    DnzSub_140181890(out, v26);
                    v11 = out[0];
                    v13 = (v11 != 0) ? v11 : 0;
                    if (v13 != 0)
                    {
                        memcpy((PVOID)(v13 + 24), v18, 80);
                    }
                }
                InterlockedExchange(&g_TState.LockEntity, 0);
            }
        }
        InterlockedExchange(&g_TState.LockPid, 0);
    }

    A2[19] -= 8;
    Hv_WriteGuestU64(TCTX, A2[19], A2[18]);
    A2[31] += 2;
    return 0;
}

/* sub_140179790：实体表 1 更新 + 击杀信息（+2056） */
UINT64
DnzSub_140179790(
    _In_ UINT64* A2
    )
{
    UINT64 GuestU64;
    UINT32 GuestU32;
    UINT64 v4;
    UINT64 v5;
    UINT64 v6;
    UINT64 v8;
    UINT8  v15[96];
    UINT64 v17 = 0;
    UINT64 v18 = 0;
    UINT64 v19 = 0;
    UINT32 v10_4;   /* DWORD1(v15) */
    UINT32 v10_8;   /* DWORD2(v15) */

    GuestU64 = TgReadU64(A2[20] - OT(252));
    if (TG_PTR_OK(GuestU64))
    {
        GuestU32 = TgReadU32(GuestU64 + 44);
    }
    else
    {
        GuestU32 = 0;
    }

    if (DnzSub_140178FB0(GuestU32, &v17) != 0)
    {
        while (InterlockedCompareExchange(&g_TState.LockPid, 1, 0) == 1)
        {
            _mm_pause();
        }
        v4 = TgReadU64(A2[16] + 32);
        if (TG_PTR_OK(v4))
        {
            v5 = TgReadU64(v4 + 8);
            if (TG_PTR_OK(v5))
            {
                v6 = v17;
                v18 = v17;
                RtlZeroMemory(v15, sizeof(v15));
                v17 = 0;
                if (v18 != 0)
                {
                    while (InterlockedCompareExchange(&g_TState.LockEntity, 1, 0) == 1)
                    {
                        _mm_pause();
                    }
                    v19 = 0;
                    DnzSub_140180A80(&v19, v18);
                    if (v19 != g_TState.Entity1.Sentinel)
                    {
                        memcpy(v15, (PVOID)(v19 + 24), 80);
                    }
                    InterlockedExchange(&g_TState.LockEntity, 0);
                }
                v10_4 = TgReadU32(v5 + 128);
                v10_8 = TgReadU32(v5 + 248);
                *(UINT32*)(v15 + 4) = v10_4;
                *(UINT32*)(v15 + 8) = v10_8;
                v18 = v6;
                if (v6 != 0)
                {
                    while (InterlockedCompareExchange(&g_TState.LockEntity, 1, 0) == 1)
                    {
                        _mm_pause();
                    }
                    {
                        UINT64 out[2];
                        DnzSub_140181890(out, v18);
                        v8 = (out[0] != 0) ? out[0] : 0;
                        if (v8 != 0)
                        {
                            memcpy((PVOID)(v8 + 24), v15, 80);
                        }
                    }
                    InterlockedExchange(&g_TState.LockEntity, 0);
                }
            }
        }
        InterlockedExchange(&g_TState.LockPid, 0);
    }

    A2[19] -= 8;
    Hv_WriteGuestU64(TCTX, A2[19], A2[18]);
    A2[31] += 2;
    return 0;
}

/* sub_14017BAF0：DetailHook 处理（+2072） */
UINT64
DnzSub_14017BAF0(
    _In_ UINT64* A2
    )
{
    UINT64 GuestU64;
    UINT32 GuestU32;
    UINT64 out24[3] = { 0, 0, 0 };
    UINT64 out[2];
    UINT64 v6node;
    UINT64 v7;
    INT32  v8;
    UINT64 v27;
    UINT64 v9;
    UINT64 v10;
    UINT32 v16;
    UINT64 v17;
    UINT64 v18;
    UINT32 v19;
    UINT64 v20;
    UINT64 v21;
    UINT64 v22;
    UINT32 v23;

    GuestU64 = TgReadU64(A2[20] - OT(252));
    if (TG_PTR_OK(GuestU64))
    {
        GuestU32 = TgReadU32(GuestU64 + 44);
    }
    else
    {
        GuestU32 = 0;
    }

    /* 老师: v26(_OWORD) = 拷出的前 16 字节，v27 = 第 3 个 QWORD（槽位索引）；
     * 实体表 0 的 key = v26 + 8 = 第 2 个 QWORD */
    if (DnzHookLookupRemoveByPid(GuestU32, out24) == 0 || (UINT32)out24[0] != 1)
    {
        DnzHookLogListEntry("DetailHook", GuestU32, (UINT64)A2);
        goto L30;
    }

    while (InterlockedCompareExchange(&g_TState.LockDetail, 1, 0) == 1)
    {
        _mm_pause();
    }
    DnzSub_140180D20(out, out24[1]);
    v6node = (out[0] != 0) ? out[0] : 0;
    v7 = v6node + 24;
    v27 = (INT64)out24[2];   /* 槽位索引 */

    if ((INT32)v27 >= 0)
    {
        v8 = (INT32)*(UINT32*)(v6node + 36);
        if (v8 >= 0)
        {
            if (v8 > 20)
            {
                v8 = 20;
            }
        }
        else
        {
            v8 = 0;
        }
        if ((INT32)v27 < v8)
        {
            v9 = A2[16];
            v10 = v7 + 1080 * (INT32)v27 + 344;
            if (v10 != 0 && TG_PTR_OK(v9) && (UINT32)TgReadU32(v9 + 40) == 0)
            {
                *(UINT8*)v10 = 1;
                *(UINT32*)(v10 + 4) = TgReadU32(v9 + 44);
                *(UINT32*)(v10 + 8) = TgReadU8(v9 + 48);
                *(UINT32*)(v10 + 12) = 0;
                v16 = TgReadU32(v9 + 24);
                v17 = v9 + 32;
                if ((INT32)v16 >= 0)
                {
                    if ((INT32)v16 <= 4)
                    {
                        v18 = TgReadU64(v17);
                        v19 = 0;
                        if (v16 <= 0)
                        {
                            goto L28;
                        }
                    }
                    else
                    {
                        v16 = 4;
                        v18 = TgReadU64(v17);
                        v19 = 0;
                    }
                    v20 = v18 + 8;
                    v21 = v18 - 0xFFFF;
                    do
                    {
                        if (v21 <= 0x7FFFFFFF0000ULL)
                        {
                            v22 = TgReadU64(v20);
                            if (TG_PTR_OK(v22))
                            {
                                DnzSub_14017B600(v22, v10 + 184 * *(INT32*)(v10 + 12) + 16);
                                v23 = *(UINT32*)(v10 + 12);
                                if (*(UINT8*)(184 * v23 + v10 + 16) != 0)
                                {
                                    *(UINT32*)(v10 + 12) = v23 + 1;
                                }
                            }
                        }
                        v19++;
                        v20 += 8;
                    } while (v19 < v16);
                    goto L28;
                }
                TgReadU64(v17);
            }
        }
    }
L28:
    InterlockedExchange(&g_TState.LockDetail, 0);
L30:
    A2[19] -= 8;
    Hv_WriteGuestU64(TCTX, A2[19], A2[18]);
    A2[31] += 2;
    return 0;
}

/* ================= 初始化 ================= */

VOID
DnzTeacherInit(
    VOID
    )
{
    RtlZeroMemory(&g_TState, sizeof(g_TState));
    TgListInit(&g_TState.NameList);
    TgListInit(&g_TState.EventQueue);
    TgListInit(&g_TState.EventState);
    TgListInit(&g_TState.PidState);
    TgListInit(&g_TState.XlateCache);
    TgListInit(&g_TState.Entity1);
    TgListInit(&g_TState.Entity0);

    /* 老师堆初始化（Mem_HeapAlloc 的 9MB 小对象区 + 128MB 大块区） */
    DnzHeapInit();
}
