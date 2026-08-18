#pragma once
#include "dnz_types.h"

/*
 * 页框池模块 —— 对应老师代码：
 *   Mem_PoolAlloc           (0x1401339c0) 池分配
 *   Mem_HeapFreeTracked     (0x140133bc0) 归还跟踪
 *   以及 HV_EptSplitLargePage / HV_EptMapGuestAccess 里
 *   用 g_HvGlobalState+6316032/6316040/5791744/5267456 的池操作。
 */

/* 物理内存访问（读写） */
uint8_t *dnz_phys_base(void);
uint64_t dnz_phys_size(void);

/* 池分配：返回物理帧号（-1 失败）。等价于老师: pool_frames[pool_next++]，并置满零 */
int64_t dnz_pool_alloc_frame(void);
/* 池分配：返回直接映射虚拟地址（页表页用） */
void   *dnz_pool_alloc_page(void);
/* 归还跟踪：把帧号放回池（模型只做计数回退+清零） */
void    dnz_pool_free_frame(uint64_t frame);
/* 内存读写助手：物理地址读写 */
void    dnz_phys_write(uint64_t phys, const void *src, size_t n);
void    dnz_phys_read(uint64_t phys, void *dst, size_t n);
