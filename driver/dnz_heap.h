/* dnz_heap.h —— 老师 Mem_HeapAlloc/Mem_HeapFree 的逐行移植
 *
 * 老师堆结构（Mem_HeapAlloc 0x140133E10 / Mem_HeapFree 0x1400029F0 /
 * Mem_HeapFreeLocal 0x1401340A0，伪代码出处 engine_ref/heap_full.md）：
 *
 *   小对象区：qword_14D2952A0 .. qword_14DB952A0（9MB 静态区）
 *     - 6 个 size-class 分箱（每箱 16 字节 { head, count }，128 位 CAS 栈）
 *     - class 表 qword_14022A9E8 = { 32, 64, 128, 256, 512, 1024 }
 *     - bump 游标 qword_14DB95300（CAS 递增，上限 9437184 = 9MB）
 *     - 节点：+0 next / +8 class / +16 magic 0x42494E414C4C4F43，数据在 +32
 *   大块区：qword_14027F000 .. qword_14827F000（128MB 静态区）
 *     - best-fit 空闲链表 g_PreAllocFreeListHead + 前后合并
 *     - 块头 24 字节：+0 size / +8 next / +16 magic 0x505245414C4C4F43（PREALLOC）
 *     - 分配中 magic = PREALLOC，释放后 = 0x5052454652454544（PREFREE）
 *   释放：Mem_HeapFree(a1, size)，size >= 0x1000 时带对齐头（a1-8 存原始指针）。
 *
 * 与老师的差异（仅尺寸，结构/算法/magic 全部原样）：
 *   老师的小对象区/大块区在 .bss 里预分配 9MB+128MB；我们同样静态预分配，
 *   尺寸可经宏调整（默认老师原尺寸）。*/
#ifndef _DNZ_HEAP_H_
#define _DNZ_HEAP_H_

/* SimpleVisor 环境：完整 WDK 头（与 dnz_guest.h 一致，确保 LONGLONG 等类型） */
#include <ntddk.h>

/* 老师原尺寸：小对象区 9MB、大块区 128MB（.bss，加载时按需提交） */
#define DNZ_HEAP_SMALL_SIZE  (9 * 1024 * 1024)
#define DNZ_HEAP_LARGE_SIZE  (128 * 1024 * 1024)

VOID   DnzHeapInit(VOID);

/* Mem_HeapAlloc */
void*  DnzHeapAlloc(ULONG64 Size);

/* Mem_HeapAllocRaw：分配 + 清零 */
void*  DnzHeapAllocRaw(ULONG64 Size);

/* Mem_HeapAllocAligned：>=0x1000 时带对齐头（-8 存原始指针） */
void*  DnzHeapAllocAligned(ULONG64 Size);

/* Mem_HeapFree(a1, size) */
VOID   DnzHeapFree(void* Ptr, ULONG64 Size);

#endif /* _DNZ_HEAP_H_ */
