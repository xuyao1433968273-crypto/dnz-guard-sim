#include "dnz_pool.h"
#include <string.h>

/* 模拟物理内存：64MB（全局，dnz_phys_ptr 直接指向它） */
uint8_t g_dnz_phys[DNZ_PHYS_SIZE];

uint8_t *dnz_phys_base(void) { return g_dnz_phys; }
uint64_t dnz_phys_size(void) { return DNZ_PHYS_SIZE; }

/* 池分配物理帧：
 * 老师代码：*(g+6316032)=v10+1 推进计数，帧号取 *(g+8*v10+5791744)。
 * 模型：把池子看成"低地址起的连续物理页"，分配即取 pool_next 号帧。 */
int64_t dnz_pool_alloc_frame(void)
{
    if (g_dnz.pool_next >= g_dnz.pool_limit) {
        /* 池满：老师代码写 *(*(g+6317688)+24744) = 2147484434 (=0x80000212) 并返回 0 */
        if (g_dnz.vcpu) g_dnz.vcpu->exit_flags = 0x80000212ULL;
        return -1;
    }
    uint64_t idx = g_dnz.pool_next++;
    g_dnz.pool_frames[idx] = idx;   /* 模型里帧号 = 池序号 */
    /* 新页清零（老师代码用 memset64 填 7 表示 present；分配页表页后由调用方填） */
    memset(dnz_phys_ptr(idx << 12), 0, DNZ_PAGE_SIZE);
    return (int64_t)idx;
}

void *dnz_pool_alloc_page(void)
{
    int64_t f = dnz_pool_alloc_frame();
    if (f < 0) return NULL;
    /* 返回指向模型物理数组的地址（老师: 直接映射地址） */
    uint64_t va = (uint64_t)(uintptr_t)g_dnz_phys + ((uint64_t)f << 12);
    g_dnz.pool_va[g_dnz.pool_next - 1] = va;
    return (void *)(uintptr_t)va;
}

void dnz_pool_free_frame(uint64_t frame)
{
    /* 模型：归还 = 清零该页并把计数回退（不真正维护空闲链） */
    if (g_dnz.pool_next > 0) {
        g_dnz.pool_next--;
        memset(dnz_phys_ptr(frame << 12), 0, DNZ_PAGE_SIZE);
    }
}

void dnz_phys_write(uint64_t phys, const void *src, size_t n)
{
    if (phys + n > DNZ_PHYS_SIZE) return;
    memcpy(g_dnz_phys + phys, src, n);
}

void dnz_phys_read(uint64_t phys, void *dst, size_t n)
{
    if (phys + n > DNZ_PHYS_SIZE) return;
    memcpy(dst, g_dnz_phys + phys, n);
}
