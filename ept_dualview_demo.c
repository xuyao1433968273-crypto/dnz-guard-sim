/*
 * ept_dualview_demo.c —— EPT 双视图原理演示（教学用）
 * ====================================================
 * 纯软件模拟，不加载驱动、不碰虚拟化硬件、不针对任何反作弊。
 *
 * 用 Intel SDM 28.2 里真实的 EPT 数据结构（PML4/PDPT/PD/PT 四层表、
 * 8 字节表项）演示三件事：
 *
 *   1. 大页拆分：把 2MB 大页拆成 512 个 4KB 小页（驱动里叫 HV_EptSplitLargePage）
 *   2. 双视图：  同一块物理页，两个观察者看到不同内容（驱动里叫 HV_EptInstallHook）
 *   3. 访问分派：房东拦截每次访问，决定给谁看哪一面（驱动里叫 HV_EptSwapHookOnViolation）
 *
 * 编译运行（Windows 用 gcc / MinGW 也行）：
 *     gcc -o demo ept_dualview_demo.c && ./demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 * 真实的 EPT 表项结构（Intel SDM Vol 3C 28.2.2 的 EPT PTE）
 * 和驱动里 HV_LookupEptEntry 操作的 *v17 是同一类东西
 * ============================================================ */
typedef union EptEntry {
    unsigned long long raw;                  /* 整 8 字节 */
    struct {
        unsigned long long r    : 1;        /* bit 0  可读 */
        unsigned long long w    : 1;        /* bit 1  可写 */
        unsigned long long x    : 1;        /* bit 2  可执行 */
        unsigned long long mem_type : 3;    /* bit 3-5 内存类型(6=WB) */
        unsigned long long ign_pat : 1;     /* bit 6 */
        unsigned long long page_size : 1;   /* bit 7  1=2MB大页, 0=4KB */
        unsigned long long avl  : 3;        /* bit 8-10 软件可用位 */
        unsigned long long pfn  : 36;       /* bit 12-47 物理页框号 */
        unsigned long long supv : 1;        /* bit 51 */
        unsigned long long      : 11;
        unsigned long long nx   : 1;        /* bit 63 不可执行 */
    } b;
} EptEntry;

#define PT_ENTRIES 512          /* 每张表 512 项 */
#define PAGE_4K   4096          /* 4KB 小页 */
#define PAGE_2M   (2 * 1024 * 1024)  /* 2MB 大页 */
#define PAGE_SHIFT 12

/* ============================================================
 * 模拟物理内存：一块"干净页" + 一块"改过页"，内容不同
 * ============================================================ */
static unsigned char phys_clean_page[PAGE_4K];     /* 干净页：全是 0xCC */
static unsigned char phys_modified_page[PAGE_4K];  /* 改过页：全是 0xAA */

/* 模拟一个 2MB 物理区域，演示用 */
static unsigned char phys_region[PAGE_2M];

/* ============================================================
 * 四层 EPT 表（和硬件里一模一样）
 *   PML4 -> PDPT -> PD -> PT（最后一级才是 4KB 页）
 * ============================================================ */
static EptEntry g_pml4[PT_ENTRIES];
static EptEntry g_pdpt[PT_ENTRIES];
static EptEntry g_pd[PT_ENTRIES];     /* 这层先当 2MB 大页用 */
static EptEntry g_pt[PT_ENTRIES];     /* 拆成 4KB 后指向小页 */

/* ============================================================
 * 工具：做一条表项
 * ============================================================ */
static EptEntry make_pte(unsigned long long pfn, int page_size,
                         int read, int write, int exec) {
    EptEntry e;
    memset(&e, 0, sizeof(e));
    e.b.r = read;
    e.b.w = write;
    e.b.x = exec;
    e.b.mem_type = 6;            /* WB 回写 */
    e.b.page_size = page_size;   /* 1 = 大页(2MB)，0 = 小页(4KB) */
    e.b.pfn = pfn;
    return e;
}

/* 把物理地址换算成 pfn（页框号 = 地址 >> 12） */
static unsigned long long addr_to_pfn(void *p) {
    return (unsigned long long)p >> PAGE_SHIFT;
}

/* ============================================================
 * 第 1 步：搭好表。把一个 2MB 区域先映射成"大页"。
 * ============================================================ */
static void build_2mb_mapping(void) {
    /* PML4[0] -> PDPT[0] -> PD[0] 一条链，指向 2MB 大页 */
    g_pml4[0] = make_pte(addr_to_pfn(g_pdpt), 0, 1, 1, 1);
    g_pdpt[0] = make_pte(addr_to_pfn(g_pd), 0, 1, 1, 1);
    /* PD[0] 直接当 2MB 大页，指向 phys_region */
    g_pd[0] = make_pte(addr_to_pfn(phys_region), 1, 1, 1, 1);
}

/* ============================================================
 * 第 2 步：拆大页（对应驱动 HV_EptSplitLargePage）
 * 把 PD[0] 这个 2MB 大页项，替换成指向一张 PT 表，
 * PT 表里 512 项各自映射 4KB。
 * ============================================================ */
static void split_large_page(void) {
    unsigned long long base_pfn = addr_to_pfn(phys_region);
    int i;

    /* PD[0] 不再是大页，改成指向 PT 表（下一级） */
    g_pd[0] = make_pte(addr_to_pfn(g_pt), 0, 1, 1, 1);

    /* PT 里 512 项，每项映射 phys_region 里的一页 4KB */
    for (i = 0; i < PT_ENTRIES; i++) {
        g_pt[i] = make_pte(base_pfn + i, 0, 1, 1, 1);
    }
    printf("[拆大页] 2MB 大页已拆成 512 个 4KB 小页\n");
}

/* ============================================================
 * 工具：在 EPT 里查某一项（对应驱动 HV_LookupEptEntry）
 * 返回指向表项的指针，调用者可以直接改写它（就是改 pfn）
 * ============================================================ */
static EptEntry *lookup_ept_entry(unsigned long long gpa) {
    int idx = (int)((gpa >> 12) & 0x1FF);   /* 4KB 页内偏移取第 9 位 */
    return &g_pt[idx];                      /* 简化：只走 PT 层 */
}

/* ============================================================
 * 第 3 步：装双视图（对应驱动 HV_EptInstallHook）
 * 把第 0 页（gpa = 0）的映射从"原内容"改成"改过页"，
 * 但保留一份"干净页"的 pfn 备用——翻镜子时换回来。
 * ============================================================ */
static unsigned long long g_clean_pfn;   /* 记下干净页的 pfn */
static unsigned long long g_modified_pfn;/* 改过页的 pfn */

static void install_dual_view(void) {
    EptEntry *e = lookup_ept_entry(0);
    g_clean_pfn = e->b.pfn;                       /* 原来指向的区域 */
    g_modified_pfn = addr_to_pfn(phys_modified_page);

    /* 改写表项：pfn 指向"改过页"，游戏看到的就是它 */
    e->b.pfn = g_modified_pfn;
    printf("[装双视图] 房间 0 现在游戏看到的是【改过页】\n");
}

/* ============================================================
 * 第 4 步：有人访问时的分派（对应驱动 HV_EptSwapHookOnViolation）
 * 房东看"谁来访问"：
 *   - 观察者 B（保安类）来 -> 翻镜子，改成干净页，查完再翻回来
 *   - 观察者 A（住户类）来 -> 直接给改过页
 * ============================================================ */
static void access_page(int observer) {
    EptEntry *e = lookup_ept_entry(0);
    unsigned char *view;

    if (observer == 0) {
        /* 住户访问：直接给改过页 */
        view = phys_modified_page;
        printf("   [住户] 读房间 0，看到内容：0x%02X 0x%02X 0x%02X ...（改过页）\n",
               view[0], view[1], view[2]);
    } else {
        /* 保安访问：翻镜子给干净页，查完翻回来 */
        e->b.pfn = g_clean_pfn;              /* 翻：换成干净页 */
        view = phys_clean_page;
        printf("   [保安] 读房间 0，看到内容：0x%02X 0x%02X 0x%02X ...（干净页！一切正常）\n",
               view[0], view[1], view[2]);
        e->b.pfn = g_modified_pfn;           /* 翻回来：恢复改过页 */
        printf("          保安走了，房东把镜子翻回来，房间恢复改过页\n");
    }
}

/* ============================================================
 * 主流程：把整个故事演一遍
 * ============================================================ */
int main(void) {
    int i;

    /* 准备内容：干净页全是 0xCC，改过页全是 0xAA，区域全是 0x55 */
    memset(phys_clean_page, 0xCC, sizeof(phys_clean_page));
    memset(phys_modified_page, 0xAA, sizeof(phys_modified_page));
    memset(phys_region, 0x55, sizeof(phys_region));

    printf("======================================================\n");
    printf("      EPT 双视图原理演示（纯软件模拟，不针对任何人）\n");
    printf("======================================================\n\n");

    build_2mb_mapping();
    split_large_page();
    install_dual_view();

    printf("\n--- 场景 1：住户使用房间 ---\n");
    for (i = 0; i < 3; i++)
        access_page(0);            /* 住户：每次看到的都是改过页 */

    printf("\n--- 场景 2：保安查房（每秒都在查）---\n");
    for (i = 0; i < 2; i++)
        access_page(1);            /* 保安：每次看到的都是干净页 */

    printf("\n--- 场景 3：保安走了，住户继续用 ---\n");
    access_page(0);

    printf("\n======================================================\n");
    printf(" 原理一句话：同一块物理页，房东靠改写 EPT 表项\n");
    printf(" （换 pfn），让不同观察者看到不同内容。\n");
    printf(" 这就是驱动里 HV_EptInstallHook / HV_EptSwapHookOnViolation\n");
    printf(" 在硬件上干的事——本程序用软件把它演了一遍。\n");
    printf("======================================================\n");
    return 0;
}
