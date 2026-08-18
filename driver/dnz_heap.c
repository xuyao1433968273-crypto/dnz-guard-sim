/* dnz_heap.c —— 老师 Mem_HeapAlloc / Mem_HeapFree 的逐行移植
 *
 * 出处：all_functions_raw.jsonl
 *   Mem_HeapAlloc      0x140133E10（653 字节，size-class 分箱 + bump + best-fit）
 *   Mem_HeapFree       0x1400029F0（139 字节，对齐头/区域判定）
 *   Mem_HeapFreeLocal  0x1401340A0（713 字节，bin 回推 + 空闲链表插入合并）
 *   Mem_HeapAllocAligned 0x140002AA0（137 字节，大分配带 -8 对齐头）
 *   Mem_HeapAllocRaw   0x140134370（143 字节，分配 + 清零）
 *
 * 结构（与老师一致）：
 *   小对象区 9MB（qword_14D2952A0..qword_14DB952A0）：
 *     6 个 size-class bin（每 bin 16 字节 { head, count }，128 位 CAS 栈）
 *     bump 游标 qword_14DB95300（上限 9437184）
 *     节点：+0 next / +8 class / +16 magic 0x42494E414C4C4F43（"COLLABIN"），
 *     返回块 + 32 字节
 *   大块区 128MB（qword_14027F000..qword_14827F000）：
 *     best-fit 空闲链表 g_PreAllocFreeListHead（+0 size / +8 next / +16 magic）
 *     块头 24 字节，返回块 + 24；分裂剩余块保留在链上
 *   释放：小对象回 bin（magic CAS 校验），大块按地址插入 + 前后合并
 *
 * 与老师差异（文档化）：
 *   1) 尺寸可经宏调整（默认老师原尺寸 9MB / 128MB）
 *   2) 老师在 .bss 里预分配；我们同样静态数组
 *   3) 老师的 HV_Dispatch OOM 上报（0x3678656）我们不移植（返回 NULL）
 *   4) Mem_HeapFreeTracked（host 池路径）不移植：本驱动分配全部来自
 *      小对象区/大块区，恒走 FreeLocal
 *   5) 哨兵检查 v8 == -32 不移植（我们的区基址不可能出现该值）
 */
#include <intrin.h>
#include "dnz_heap.h"

#define DNZ_HEAP_SMALL_LIMIT  9437184          /* 老师 bump 游标上限 = 9MB */
#define DNZ_HEAP_MAGIC_COLLABIN  0x42494E414C4C4F43ULL  /* 小对象分配中 */
#define DNZ_HEAP_MAGIC_BINFREE   0x42494E4652454544ULL  /* 小对象已释放 */
#define DNZ_HEAP_MAGIC_PREALLOC  0x505245414C4C4F43ULL  /* 大块分配中 */
#define DNZ_HEAP_MAGIC_PREFREE   0x5052454652454544ULL  /* 大块已释放 */

/* 小对象区（9MB）+ 大块区（128MB），静态 .bss 等价 */
static __declspec(align(16)) UINT8 g_HeapSmall[DNZ_HEAP_SMALL_SIZE];
static __declspec(align(16)) UINT8 g_HeapLarge[DNZ_HEAP_LARGE_SIZE];

/* 6 个 size-class：v4 = bsr(v2-1)-4 落在 0..5（v2 <= 512），
 * class 值 = 对齐后大小（推导自 FreeLocal 的 bsr(class-1)-4 反查） */
static const UINT64 g_SizeClass[6] = { 32, 64, 128, 256, 512, 1024 };

/* size-class bin：每 bin 16 字节 { head(low), count(high) }，128 位 CAS */
static __declspec(align(16)) volatile LONGLONG g_Bins[6][2];

/* bump 游标（qword_14DB95300） */
static volatile LONGLONG g_BumpCursor;

/* 统计（老师 g_PreAllocBinStats / qword_140270630 / 140270828 / 140270858） */
static volatile LONGLONG g_BinStats;
static volatile LONGLONG g_FreedBytes;
static volatile LONGLONG g_BinAlloc[6];
static volatile LONGLONG g_BinFree[6];

/* 大块区空闲链表 + 锁（g_PreAllocFreeListHead / g_PreAllocListLock） */
static volatile LONG  g_FreeListLock;
static UINT64         g_FreeListHead;

VOID
DnzHeapInit(
    VOID
    )
{
    ULONG i;

    RtlZeroMemory(g_HeapSmall, sizeof(g_HeapSmall));
    RtlZeroMemory(g_HeapLarge, sizeof(g_HeapLarge));
    RtlZeroMemory((PVOID)g_Bins, sizeof(g_Bins));
    g_BumpCursor = 0;
    g_FreeListHead = 0;
    g_FreeListLock = 0;
    g_BinStats = 0;
    g_FreedBytes = 0;
    for (i = 0; i < 6; i++)
    {
        g_BinAlloc[i] = 0;
        g_BinFree[i] = 0;
    }
}

/* 从 size-class bin 弹出一个空闲节点（128 位 CAS Treiber 栈，老师原样） */
static UINT8*
HeapBinPop(
    _In_ ULONG Bin
    )
{
    volatile LONGLONG* bin = g_Bins[Bin];
    LONGLONG cmp[2];
    LONGLONG cur[2];
    UINT8*   head;
    UINT8*   next;

    /* 读当前 { head, count } */
    cmp[0] = 0;
    cmp[1] = 0;
    _InterlockedCompareExchange128(bin, 0, 0, cmp);
    head = (UINT8*)cmp[0];

    if (head == NULL)
    {
        return NULL;
    }

    cur[0] = cmp[0];
    cur[1] = cmp[1];

    for (;;)
    {
        next = *(UINT8**)head;                 /* head->next */
        cmp[0] = cur[0];
        cmp[1] = cur[1];
        /* 尝试 { head->next, count+1 } 换入 { head, count } */
        if (_InterlockedCompareExchange128(bin,
                                           cur[1] + 1,   /* exchange high = count+1 */
                                           (LONGLONG)next, /* exchange low = head->next */
                                           cmp))
        {
            break;                             /* 成功：pop 出 head */
        }
        head = (UINT8*)cmp[0];                 /* 失败：读最新 head */
        cur[0] = cmp[0];
        cur[1] = cmp[1];
        if (head == NULL)
        {
            return NULL;
        }
    }
    return head;
}

/* 把节点推回 size-class bin（128 位 CAS，老师原样） */
static VOID
HeapBinPush(
    _In_ ULONG Bin,
    _In_ UINT8* Node
    )
{
    volatile LONGLONG* bin = g_Bins[Bin];
    LONGLONG cmp[2];
    LONGLONG cur[2];

    cmp[0] = 0;
    cmp[1] = 0;
    _InterlockedCompareExchange128(bin, 0, 0, cmp);   /* 读当前 */

    for (;;)
    {
        *(UINT64*)Node = (UINT64)cmp[0];              /* 节点 +0 = 旧 head */
        cur[0] = cmp[0];
        cur[1] = cmp[1];
        if (_InterlockedCompareExchange128(bin,
                                           cmp[1] + 1,   /* count+1 */
                                           (LONGLONG)Node, /* 新 head = 节点 */
                                           cur))
        {
            break;
        }
        cmp[0] = cur[0];
        cmp[1] = cur[1];
    }
}

/* 初始化小对象节点头（LABEL_15）并返回数据指针（块 + 32） */
static UINT8*
HeapSmallNodeInit(
    _In_ UINT8* Block,
    _In_ ULONG  Bin
    )
{
    *(UINT64*)(Block + 0) = 0;                        /* +0 next = 0 */
    *(UINT64*)(Block + 8) = g_SizeClass[Bin];         /* +8 class */
    *(UINT64*)(Block + 16) = DNZ_HEAP_MAGIC_COLLABIN; /* +16 magic */
    _InterlockedExchangeAdd64(&g_BinStats, (LONGLONG)g_SizeClass[Bin]);
    _InterlockedIncrement64(&g_BinAlloc[Bin]);
    return Block + 32;                                /* 返回 v8 + 4（QWORD） */
}

/* 大块区 best-fit 分配（LABEL_16，老师原样） */
static UINT8*
HeapLargeAlloc(
    _In_ UINT64 AlignedSize
    )
{
    UINT64* v18 = NULL;     /* 前驱 */
    UINT64* v19;            /* 游标 */
    UINT64* v20 = NULL;     /* best-fit 块 */
    UINT64* v21 = NULL;     /* best-fit 前驱 */
    UINT64  v22 = (UINT64)-1;
    UINT64  v23;
    UINT64* v24;
    UINT8*  result = NULL;

    while (_InterlockedCompareExchange(&g_FreeListLock, 1, 0) == 1)
    {
        _mm_pause();
    }
    _InterlockedExchangeAdd64(&g_BinStats, (LONGLONG)AlignedSize);  /* g_PreAllocTotalAlloc */

    v19 = (UINT64*)g_FreeListHead;
    if (v19 != NULL)
    {
        do
        {
            if (*v19 >= AlignedSize)
            {
                v23 = *v19 - AlignedSize;
                if (v20 == NULL || v23 < v22)
                {
                    v20 = v19;
                    v21 = v18;
                    v22 = *v19 - AlignedSize;
                    if (v23 == 0)
                    {
                        break;
                    }
                }
            }
            v18 = v19;
            v19 = (UINT64*)v19[1];
        }
        while (v19 != NULL);

        if (v20 != NULL)
        {
            if (*v20 < AlignedSize + 32)
            {
                /* 整块用掉：从链上摘除 */
                if (v21 != NULL)
                {
                    v21[1] = v20[1];
                }
                else
                {
                    g_FreeListHead = v20[1];
                }
                v20[1] = 0;
            }
            else
            {
                /* 分裂：剩余块留在链上 */
                v24 = (UINT64*)((UINT8*)v20 + AlignedSize + 24);
                *v24 = *v20 - AlignedSize - 24;
                v24[1] = v20[1];
                v24[2] = DNZ_HEAP_MAGIC_PREFREE;
                *v20 = AlignedSize;
                v20[1] = 0;
                if (v21 != NULL)
                {
                    v21[1] = (UINT64)v24;
                }
                else
                {
                    g_FreeListHead = (UINT64)v24;
                }
            }
            v20[2] = DNZ_HEAP_MAGIC_PREALLOC;
            result = (UINT8*)v20 + 24;               /* 返回 v20 + 3（QWORD） */
        }
    }

    _InterlockedExchange(&g_FreeListLock, 0);
    return result;
}

void*
DnzHeapAlloc(
    _In_ UINT64 Size
    )
{
    UINT64  v2;
    UINT32  v3;
    UINT32  v4;
    UINT64  v12;
    LONGLONG v13;
    LONGLONG v14;
    LONGLONG v15;
    LONGLONG v16;
    UINT8*  v8;
    UINT8*  block;

    if (Size == 0)
    {
        return NULL;
    }

    v2 = (Size + 7) & ~7ULL;
    _BitScanReverse64((unsigned long*)&v3, v2 - 1);
    v4 = v3 - 4;

    if (v4 <= 5)
    {
        /* 小对象：先试 size-class bin */
        v8 = HeapBinPop(v4);
        if (v8 != NULL)
        {
            return HeapSmallNodeInit(v8, v4);
        }

        /* bin 空：从 9MB 区 bump（qword_14DB95300 上限 9437184） */
        v12 = (g_SizeClass[v4] + 47) & ~0xFULL;
        v13 = _InterlockedCompareExchange64(&g_BumpCursor, 0, 0);
        v14 = v13 + (LONGLONG)v12;
        v15 = v13;
        if (v13 + (LONGLONG)v12 <= DNZ_HEAP_SMALL_LIMIT)
        {
            while (v15 != _InterlockedCompareExchange64(&g_BumpCursor, v14, v15))
            {
                v16 = _InterlockedCompareExchange64(&g_BumpCursor, 0, 0);
                v14 = v16 + (LONGLONG)v12;
                v15 = v16;
                if (v16 + (LONGLONG)v12 > DNZ_HEAP_SMALL_LIMIT)
                {
                    goto large_path;
                }
            }
            block = (UINT8*)&g_HeapSmall[0] + v15;
            if (block != NULL)
            {
                return HeapSmallNodeInit(block, v4);
            }
        }
    }

large_path:
    return HeapLargeAlloc(v2);
}

void*
DnzHeapAllocRaw(
    _In_ UINT64 Size
    )
{
    void* p;

    p = DnzHeapAlloc(Size);
    if (p == NULL)
    {
        return NULL;
    }
    RtlZeroMemory(p, Size);
    return p;
}

void*
DnzHeapAllocAligned(
    _In_ UINT64 Size
    )
{
    UINT64 raw;
    UINT64 result;

    if (Size == 0)
    {
        return 0;
    }
    if (Size < 0x1000)
    {
        return DnzHeapAllocRaw(Size);
    }
    if (Size + 39 < Size)
    {
        return 0;
    }
    raw = (UINT64)DnzHeapAllocRaw(Size + 39);
    if (raw == 0)
    {
        return 0;
    }
    result = (raw + 39) & ~0x1FULL;
    *(UINT64*)(result - 8) = raw;   /* 对齐头：-8 存原始指针 */
    return (void*)result;
}

/* 小对象释放：回 bin（老师原样，magic CAS 校验） */
static VOID
HeapSmallFree(
    _In_ UINT8* Block
    )
{
    UINT64 class;
    ULONG  i;
    UINT32 v9;
    UINT32 v10;

    class = *(UINT64*)(Block + 8);
    for (i = 0; i < 6; i++)
    {
        if (class == g_SizeClass[i])
        {
            break;
        }
    }
    if (i == 6)
    {
        return;
    }
    _BitScanReverse64((unsigned long*)&v9, class - 1);
    v10 = v9 - 4;
    if (v10 > 5)
    {
        return;
    }
    /* magic COLLABIN -> BINFREE（CAS 校验，防双释放） */
    if (_InterlockedCompareExchange64((volatile LONGLONG*)(Block + 16),
                                      DNZ_HEAP_MAGIC_BINFREE,
                                      DNZ_HEAP_MAGIC_COLLABIN) != DNZ_HEAP_MAGIC_COLLABIN)
    {
        return;
    }
    _InterlockedExchangeAdd64(&g_FreedBytes, (LONGLONG)class);
    _InterlockedIncrement64(&g_BinFree[v10]);
    HeapBinPush(v10, Block);
}

/* 大块释放：按地址插入空闲链表 + 前后合并（老师原样） */
static VOID
HeapLargeFree(
    _In_ UINT8* Block
    )
{
    UINT64 size;
    UINT64* v7;
    UINT64* v8;
    UINT64* v5;

    v5 = (UINT64*)(Block - 24);   /* 块头 */
    size = *v5;
    if (size == 0 || (size & 7) != 0 || size > 0x7FFFFE8)
    {
        return;
    }

    while (_InterlockedCompareExchange(&g_FreeListLock, 1, 0) == 1)
    {
        _mm_pause();
    }
    _InterlockedExchangeAdd64(&g_FreedBytes, (LONGLONG)size);   /* g_PreAllocTotalFree */
    v7 = (UINT64*)g_FreeListHead;
    v8 = NULL;
    *(UINT64*)(v5 + 2) = DNZ_HEAP_MAGIC_PREFREE;

    if (v7 != NULL)
    {
        do
        {
            if ((UINT64)v7 >= (UINT64)v5)
            {
                break;
            }
            v8 = v7;
            v7 = (UINT64*)v7[1];
        }
        while (v7 != NULL);

        /* 与前驱合并 */
        if (v8 != NULL && (UINT8*)v8 + *v8 + 24 == (UINT8*)v5)
        {
            v5 = v8;
            *v8 += size + 24;
        }
        else
        {
            *(UINT64*)(v5 + 1) = (UINT64)v7;
            if (v8 != NULL)
            {
                v8[1] = (UINT64)v5;
            }
            else
            {
                g_FreeListHead = (UINT64)v5;
            }
        }
        /* 与后继合并 */
        if (v7 != NULL && (UINT8*)v5 + *v5 + 24 == (UINT8*)v7)
        {
            *v5 += *v7 + 24;
            *(UINT64*)(v5 + 1) = v7[1];
        }
    }
    else
    {
        *(UINT64*)(v5 + 1) = 0;
        g_FreeListHead = (UINT64)v5;
    }
    *(UINT64*)(v5 + 2) = DNZ_HEAP_MAGIC_PREFREE;
    _InterlockedExchange(&g_FreeListLock, 0);
}

VOID
DnzHeapFree(
    _In_ void*  Ptr,
    _In_ UINT64 Size
    )
{
    UINT8* a1 = (UINT8*)Ptr;

    /* Mem_HeapFree 原样：size >= 0x1000 时走对齐头（a1-8 存原始指针） */
    if (Size >= 0x1000)
    {
        if ((UINT64)(a1 - *(UINT64*)(a1 - 8) - 8) > 0x1F)
        {
            return;   /* sub_1401E98C0 的等价物：非法指针，静默返回 */
        }
        a1 = (UINT8*)*(UINT64*)(a1 - 8);
    }

    if (a1 == NULL)
    {
        return;
    }

    /* 区域判定：小对象区（头在 -32）/ 大块区（头在 -24） */
    if ((UINT8*)a1 >= &g_HeapSmall[0] && (UINT8*)a1 < &g_HeapSmall[0] + DNZ_HEAP_SMALL_SIZE)
    {
        UINT8* hdr = a1 - 32;
        if (hdr >= &g_HeapSmall[0] &&
            hdr + 31 < &g_HeapSmall[0] + DNZ_HEAP_SMALL_SIZE &&
            a1 != (UINT8*)&g_HeapSmall[0] + 32)
        {
            if (*(UINT64*)(hdr + 16) == DNZ_HEAP_MAGIC_COLLABIN)
            {
                HeapSmallFree(hdr);
                return;
            }
        }
        return;
    }
    if ((UINT8*)a1 >= &g_HeapLarge[0] && (UINT8*)a1 < &g_HeapLarge[0] + DNZ_HEAP_LARGE_SIZE)
    {
        UINT8* hdr = a1 - 24;
        if (hdr >= &g_HeapLarge[0] &&
            hdr + 23 < &g_HeapLarge[0] + DNZ_HEAP_LARGE_SIZE &&
            *(UINT64*)(hdr + 16) == DNZ_HEAP_MAGIC_PREALLOC)
        {
            HeapLargeFree(hdr);
        }
        return;
    }
    /* 老师这里走 Mem_HeapFreeTracked（host 池）；本驱动分配全来自上述两区，
     * 落到这里说明指针不是我们分配的（文档化偏差 4） */
}
