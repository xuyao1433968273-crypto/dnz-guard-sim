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
 *   4) sub_1401944D0 / Hv_ReadProcessListFromGuest / sub_140175230 /
 *      HV_HandlePendingEvent 的事件处理 -> 结构桩（出处不全，不编造）
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
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        PUINT8 n = Pool + (UINT64)i * NodeSize;
        if (*(UINT64*)(n + 0) == 0)   /* 空闲标记：prev == 0 */
        {
            RtlZeroMemory(n, NodeSize);
            return n;
        }
    }
    return NULL;
}

static VOID
TgPoolFree(
    _In_ PUINT8 Node
    )
{
    *(UINT64*)(Node + 0) = 0;
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
    node = TgPoolAlloc(&g_TState.NamePool[0][0], 0x20, 32);
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
    node = TgPoolAlloc(&g_TState.EventPool[0][0], 0x28, 16);
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
    node = TgPoolAlloc(&g_TState.XlatePool[0][0], 0x28, 16);
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
    node = TgPoolAlloc(&g_TState.Entity1Pool[0][0], 0x70, 16);
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
    node = TgPoolAlloc(&g_TState.Entity0Pool[0][0], 21616 + 24, 4);
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
    TgPoolFree(node);
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

/* sub_14016B540：prologue patch 未移植（文档化：返回原地址） */
static UINT64
DnzSub_14016B540(
    _In_ UINT64 A1,
    _In_ UINT64 A2,
    _In_ UINT64 A3
    )
{
    /* 老师: Esp_ApplyGuestProloguePatch / sub_1401196F0 —— 本移植不安装
     * prologue 跳板，返回原目标地址（偏差文档化） */
    UNREFERENCED_PARAMETER(A2);
    UNREFERENCED_PARAMETER(A3);
    return A1;
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

/* HV_HandlePendingEvent：事件积压处理（结构桩：清空事件队列，出处不全不编造） */
static VOID
DnzHvHandlePendingEvent(
    _In_ PDNZ_TLIST List
    )
{
    ULONG i;

    for (i = 0; i < DNZ_TLIST_BUCKETS; i++)
    {
        UINT8* head = (UINT8*)List->BucketPrev[i];
        UINT8* tail = (UINT8*)List->BucketNext[i];
        UINT8* cur = head;

        while (cur != NULL && cur != (UINT8*)List->Sentinel)
        {
            UINT8* next = *(UINT8**)(cur + 8);
            if (head == cur)
            {
                List->BucketPrev[i] = (next == (UINT8*)List->Sentinel) ? List->Sentinel : (UINT64)next;
            }
            if (tail == cur)
            {
                List->BucketNext[i] = List->Sentinel;
            }
            *(UINT8**)(cur + 0) = 0;   /* 释放回池 */
            List->Count--;
            cur = next;
            if (cur == (UINT8*)List->Sentinel)
            {
                break;
            }
        }
    }
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

/* sub_1401944D0：配置检查子函数（出处不全，结构桩返回 1=启用） */
UINT8
DnzSub_1401944D0(
    _In_ UINT64 A1
    )
{
    UNREFERENCED_PARAMETER(A1);
    return 1;
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
    g_TState.WddmDisableOverlay = 1;   /* 走直接页表走查路径（偏差文档化） */
}
