/*
 * hv_ept_hook_model.c —— EPT 钩子机制模型（教学版）
 * ====================================================
 * 按照老师驱动（IDA 分析）里 HV_Ept* 系列函数的【真实结构和逻辑】，
 * 用软件模型实现。纯软件模拟，不加载驱动、不碰虚拟化硬件、不针对任何人。
 *
 * 函数与老师驱动的对应关系：
 *   hv_ept_lookup                   -> HV_LookupEptEntry          (0x140115220)
 *   hv_ept_split_large_page         -> HV_EptSplitLargePage       (0x140115400)
 *   hv_ept_install_hook             -> HV_EptInstallHook          (0x140115980)
 *   hv_ept_remove_hook              -> HV_EptRemoveHook           (0x140115ac0)
 *   hv_ept_hide_pages               -> HV_EptHidePages            (0x140115c20)
 *   hv_ept_unhide_pages             -> HV_EptUnhidePages          (0x140115e10)
 *   hv_ept_swap_hook_on_violation   -> HV_EptSwapHookOnViolation  (0x140116f90)
 *   hv_after_ept_violation          -> HV_AfterEptViolation       (0x140116ed0)
 *   hv_dispatch_exit_handlers       -> HV_DispatchExitHandlers_Ept(0x1401171c0)
 *
 * 编译：gcc -O2 -o hv_ept hv_ept_hook_model.c && ./hv_ept
 * 或 VS 开发者命令行：cl hv_ept_hook_model.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t  u8;

/* ================================================================
 * 1. 数据结构 —— 和老师驱动/Intel SDM 28.2 一致
 * ================================================================ */

/* EPT 表项（8 字节）：R/W/X 权限、内存类型、大页位、pfn（物理页框号）
 * 老师驱动 HV_LookupEptEntry 返回的 *v17 就是改这个东西 */
typedef union EptEntry {
    u64 raw;
    struct {
        u64 r         : 1;   /* bit0  可读 */
        u64 w         : 1;   /* bit1  可写 */
        u64 x         : 1;   /* bit2  可执行 */
        u64 mem_type  : 3;   /* bit3-5 内存类型，6=WB */
        u64 ign_pat   : 1;   /* bit6 */
        u64 page_size : 1;   /* bit7  1=2MB大页，0=4KB页 */
        u64 avl       : 3;   /* bit8-10 软件可用位 */
        u64 pfn       : 36;  /* bit12-47 物理页框号 */
        u64            : 12;
        u64 nx        : 1;   /* bit63 不可执行 */
    } b;
} EptEntry;

#define PT_ENTRIES 512
#define PAGE_4K    4096u
#define PAGE_2M    (2u * 1024u * 1024u)
#define PAGE_SHIFT 12

/* 钩子记录：老师驱动里每个被 hook 的页对应一条这样的记录
 * （state 对应 IDA 里 *(a1+6427304)，last_swap 对应 *(a1+24656)） */
typedef struct {
    u64  gpa;             /* 被 hook 的客户机地址 */
    u64  clean_pfn;       /* 干净页 pfn（翻镜子时换回来） */
    u64  modified_pfn;    /* 改过页 pfn（平时给住户看） */
    int  state;           /* 0=闲 1=翻面中 2=干完了（跨核信号） */
    int  flags;           /* HOOK_* 位 */
    u64  expected_ticks;  /* 预期耗时（防时间差用的基准） */
    u64  last_swap_delta; /* 本次实际耗时记账 */
} HookEntry;

#define HOOK_DUAL_VIEW    0x1
#define HOOK_FIRST_TOUCH  0x2
#define HOOK_HIDDEN       0x4

#define MAX_HOOKS 16

/* 每次 VM-exit 的"来者材料"：对应老师驱动分派器里的 exit info 缓冲区 */
typedef struct {
    u32 reason;          /* 退出原因：1=EPT violation */
    u32 rip;             /* 客人在哪个位置被拦 */
    u64 gpa;             /* 碰的是哪个地址 */
    u32 observer;        /* 0=住户 1=保安（认人的材料之一） */
    u32 magic;           /* 0x52695269="RiRi" -> 走拆页重定向路径 */
} ExitInfo;

#define EXIT_REASON_EPT_VIOLATION 1
#define MAGIC_RIRI 0x52695269u
#define HYPERCALL_MAGIC 0x3467103u

/* 每 vCPU 状态：对应老师驱动里那棵大结构 a1（我们只留关键字段） */
typedef struct {
    EptEntry *pml4;               /* EPT 根表 */
    HookEntry hooks[MAX_HOOKS];
    int  hook_count;
    u64  exit_state;              /* 对应 *(a1+6427304) */
    u64  status_flags;            /* 对应 *(a1+24588) */
    u64  last_swap_delta;         /* 对应 *(a1+24656) */
    int  use_real_vmx;            /* 对应 g_UseRealVmxInstr */
    int  scan_count;              /* 保安查了多少次 */
} VcpuState;

/* ================================================================
 * 2. 模拟物理内存
 * ================================================================ */
#define PHYS_PAGES 64
static u8  g_phys[PHYS_PAGES][PAGE_4K];   /* 64 页物理内存 */
static u64 g_next_pfn = 1;                /* 从 1 开始分配 pfn */

static u64 phys_alloc_pfn(void) { return g_next_pfn++; }
static u8 *pfn_to_va(u64 pfn)   { return g_phys[pfn]; }

/* 往某一页填内容 */
static void fill_page(u64 pfn, u8 val) {
    memset(pfn_to_va(pfn), val, PAGE_4K);
}

/* ================================================================
 * 3. 4 层 EPT 走查 —— hv_ept_lookup（对应 HV_LookupEptEntry）
 *    返回指向目标页表项的指针，调用者直接改它（改 pfn）就是换视图
 * ================================================================ */
static EptEntry make_pte(u64 pfn, int page_size, int r, int w, int x) {
    EptEntry e; memset(&e, 0, sizeof(e));
    e.b.r = r; e.b.w = w; e.b.x = x;
    e.b.mem_type = 6;
    e.b.page_size = page_size;
    e.b.pfn = pfn;
    return e;
}

static EptEntry *ept_next_level(EptEntry *table, int idx) {
    /* 表项指向下一级表：pfn 就是下一级表的地址 */
    return (EptEntry *)(pfn_to_va(table[idx].b.pfn));
}

static EptEntry *hv_ept_lookup(VcpuState *s, u64 gpa) {
    int idx4 = (int)((gpa >> 39) & 0x1FF);
    int idx3 = (int)((gpa >> 30) & 0x1FF);
    int idx2 = (int)((gpa >> 21) & 0x1FF);
    int idx1 = (int)((gpa >> 12) & 0x1FF);

    EptEntry *pml4 = s->pml4;
    if (!(pml4[idx4].b.pfn)) return NULL;
    EptEntry *pdpt = ept_next_level(pml4, idx4);
    if (!(pdpt[idx3].b.pfn)) return NULL;
    EptEntry *pd = ept_next_level(pdpt, idx3);

    /* PD 层可能是 2MB 大页，也可能是下一级 PT 表 */
    if (pd[idx2].b.page_size)
        return &pd[idx2];
    EptEntry *pt = ept_next_level(pd, idx2);
    return &pt[idx1];
}

/* ================================================================
 * 4. 拆大页 —— hv_ept_split_large_page（对应 HV_EptSplitLargePage）
 * ================================================================ */
static void hv_ept_split_large_page(VcpuState *s, u64 gpa) {
    int idx4 = (int)((gpa >> 39) & 0x1FF);
    int idx3 = (int)((gpa >> 30) & 0x1FF);
    int idx2 = (int)((gpa >> 21) & 0x1FF);

    EptEntry *pdpt = ept_next_level(s->pml4, idx4);
    EptEntry *pd   = ept_next_level(pdpt, idx3);
    EptEntry *big  = &pd[idx2];

    if (!big->b.page_size) return;              /* 已经是 4KB 了 */

    /* 分配一张 PT 表（占用一页物理内存当表用） */
    u64 pt_pfn = phys_alloc_pfn();
    EptEntry *pt = (EptEntry *)pfn_to_va(pt_pfn);
    /* 教学简化：所有小页指向同一物理页（真实硬件是连续 2MB 物理内存） */
    for (int i = 0; i < PT_ENTRIES; i++)
        pt[i] = make_pte(big->b.pfn, 0, 1, 1, 1);

    /* PD 项从"大页"改成"指向 PT 表" */
    *big = make_pte(pt_pfn, 0, 1, 1, 1);
    printf("[拆大页] gpa=0x%llx: 2MB 大页 -> 512 个 4KB 小页\n", gpa);
}

/* ================================================================
 * 5. 装钩子/卸钩子 —— 双视图的核心
 *    install: 把 EPT 表项 pfn 指到"改过页"，并记下"干净页"备用
 *    remove : 把 pfn 换回干净页
 * ================================================================ */
static int hv_ept_install_hook(VcpuState *s, u64 gpa, u64 modified_pfn) {
    EptEntry *e = hv_ept_lookup(s, gpa);
    if (!e) return -1;
    HookEntry *h = &s->hooks[s->hook_count];
    h->gpa = gpa;
    h->clean_pfn = e->b.pfn;                    /* 记下原本（干净）的 pfn */
    h->modified_pfn = modified_pfn;
    h->state = 0;
    h->flags = HOOK_DUAL_VIEW | HOOK_FIRST_TOUCH;
    h->expected_ticks = 100;                    /* 预期翻面耗时基准 */
    h->last_swap_delta = 0;
    s->hook_count++;

    e->b.pfn = modified_pfn;                    /* 表项指向改过页 */
    printf("[装钩子] gpa=0x%llx 双视图: 住户看到[改过页], 保安看到[干净页]\n", gpa);
    return 0;
}

static void hv_ept_remove_hook(VcpuState *s, u64 gpa) {
    EptEntry *e = hv_ept_lookup(s, gpa);
    if (!e) return;
    for (int i = 0; i < s->hook_count; i++) {
        if (s->hooks[i].gpa == gpa) {
            e->b.pfn = s->hooks[i].clean_pfn;   /* 换回干净页 */
            /* 从表里摘掉这条记录 */
            for (int j = i; j < s->hook_count - 1; j++)
                s->hooks[j] = s->hooks[j + 1];
            s->hook_count--;
            printf("[卸钩子] gpa=0x%llx 已还原为干净页\n", gpa);
            return;
        }
    }
}

/* ================================================================
 * 6. 藏页/放页 —— hv_ept_hide_pages / unhide（对应 HV_EptHidePages）
 *    藏 = 把表项的 R/W/X 全清掉（表项"不可见"，访问会触发 violation）
 * ================================================================ */
static void hv_ept_hide_pages(VcpuState *s, u64 gpa, int count) {
    for (int i = 0; i < count; i++) {
        EptEntry *e = hv_ept_lookup(s, gpa + i * PAGE_4K);
        if (e) { e->b.r = 0; e->b.w = 0; e->b.x = 0; }
    }
    printf("[藏页] gpa=0x%llx 起 %d 页: 表项清空, 访问会触发 violation\n", gpa, count);
}

static void hv_ept_unhide_pages(VcpuState *s, u64 gpa, int count) {
    for (int i = 0; i < count; i++) {
        EptEntry *e = hv_ept_lookup(s, gpa + i * PAGE_4K);
        if (e) { e->b.r = 1; e->b.w = 1; e->b.x = 1; }
    }
    printf("[放页] gpa=0x%llx 起 %d 页: 已恢复可见\n", gpa, count);
}

/* ================================================================
 * 7. 翻镜子 —— hv_ept_swap_hook_on_violation（对应 HV_EptSwapHookOnViolation）
 *    忠实还原 IDA 里的三段逻辑：
 *      分支1: 首次触碰标记 -> 卸钩子再装钩子（完整翻面）
 *      分支2: exit_state != 0 -> 跨核等待(state==2) + 预算限时 + 计时记账
 *      分支3: 否则置一个标志位
 * ================================================================ */
static u64 rdtsc_now(void) {
    /* 模拟 CPU 秒表（TSC）：真实驱动里是 __rdtsc() */
    static u64 fake = 0;
    fake += 40;               /* 每次"翻面"大约 40 个假时钟周期 */
    return fake;
}

static void hv_ept_swap_hook_on_violation(VcpuState *s, HookEntry *h) {
    /* ---- 分支 1：首次触碰 -> 完整翻面（卸掉再装，改过版<->干净版互换） ---- */
    if (h->flags & HOOK_FIRST_TOUCH) {
        h->flags &= ~HOOK_FIRST_TOUCH;
        hv_ept_remove_hook(s, h->gpa);
        hv_ept_install_hook(s, h->gpa, h->modified_pfn);
        s->hooks[s->hook_count - 1].flags &= ~HOOK_FIRST_TOUCH; /* 首次翻面完成 */
        return;   /* 之后进入 hv_after_ept_violation 由分派器统一走 */
    }

    /* ---- 分支 2：exit_state != 0 -> 等待"干完了"信号，带预算限时 ---- */
    if (s->exit_state) {
        u64 t0 = rdtsc_now();
        u64 budget = 8ull * 100;               /* 8 * 预算周期 */
        /* 内层 0x3E8 次暂停 + 外层预算限时（对应 IDA 的 do/while 双重循环） */
        do {
            for (int i = 0; i < 0x3E8; i++) {
                if (s->exit_state == 2) break; /* 别的核干完了 */
                /* _mm_mfence(); _mm_pause(); 内存栅栏+暂停 */
            }
        } while (s->exit_state != 2 && rdtsc_now() - t0 < budget);

        s->exit_state = 0;
        u64 actual = rdtsc_now() - t0;
        /* 计时记账：对应 IDA 的 *(a1+24656) = 预期 - 实际
         * 目的：翻面慢了会露时间差，记账用于校准 */
        h->last_swap_delta = h->expected_ticks - actual;
        s->last_swap_delta = h->last_swap_delta;
        printf("   [计时] 本次翻面实际 %llu tick, 记账 delta=%lld (防时间差用)\n",
               actual, (long long)h->last_swap_delta);
        return;
    }

    /* ---- 分支 3：空闲状态 -> 置标志 ---- */
    s->status_flags |= 0x100000u;
}

/* ================================================================
 * 8. 收尾 —— hv_after_ept_violation（对应 HV_AfterEptViolation）
 *    把被碰页的内容从客户机拷贝一份，埋"跳板"（这里是打印演示），
 *    然后让访问者看到拷贝（干净版）
 * ================================================================ */
static void hv_after_ept_violation(VcpuState *s, u64 gpa) {
    EptEntry *e = hv_ept_lookup(s, gpa);
    if (!e) return;
    u8 buf[16];
    memcpy(buf, pfn_to_va(e->b.pfn), sizeof(buf));   /* 拷贝被碰页内容 */
    /* 埋跳板：真实驱动写 HV_Vmmcall_IretStub 的地址，这里仅示意 */
    printf("   [收尾] 已拷贝被碰页内容(前4字节 %02X %02X %02X %02X), 埋好跳板\n",
           buf[0], buf[1], buf[2], buf[3]);
}

/* ================================================================
 * 9. 出口处理分派 —— hv_dispatch_exit_handlers（对应 HV_DispatchExitHandlers_Ept）
 *    门口逻辑：切 host CR3 -> 逐个问登记表里的处理者 -> 认领则停
 *    magic RiRi -> 走 EPT 拆页重定向；没人认领 -> 注入 hypercall
 * ================================================================ */
typedef int (*ExitHandler)(VcpuState *, ExitInfo *);

static ExitHandler g_exit_handler_table[8];
static int g_exit_handler_count = 0;

static int hv_register_exit_handler(ExitHandler fn) {
    if (g_exit_handler_count >= 8) return -1;
    g_exit_handler_table[g_exit_handler_count++] = fn;
    return 0;
}

static u64 hv_translate_guest_va(VcpuState *s, u64 gpa) {
    return gpa;   /* 教学模型里 GPA==HPA，真实驱动走 HV_TranslateGuestVa */
}

static int hv_dispatch_exit_handlers(VcpuState *s, ExitInfo *info) {
    int handled = 0;

    if (!g_exit_handler_count) {
        s->status_flags = 2147484419u;         /* 对应 LABEL_19 的错误码 */
        return 0;
    }

    /* 切 host CR3（真实驱动 __writecr3(host_cr3)），模型里不需要真切 */

    /* 逐个问处理者：认领了(返回非0)就停 */
    for (int i = 0; i < g_exit_handler_count; i++) {
        if (g_exit_handler_table[i](s, info)) { handled = 1; break; }
    }

    /* magic RiRi -> EPT 拆页重定向（对应 IDA 里 v25[1]==0x52695269 分支） */
    if (handled && info->magic == MAGIC_RIRI) {
        u64 pa = hv_translate_guest_va(s, info->gpa);
        EptEntry *e = hv_ept_lookup(s, pa);
        if (e) {
            /* 重定向：把表项 pfn 指到翻译后的物理页（拆页/换视图） */
            u64 new_pfn = pa >> PAGE_SHIFT;
            e->b.pfn = new_pfn;
            s->status_flags |= 0x100u;
            printf("[分派] magic=RiRi -> EPT 项已重定向到 pfn=0x%llx\n", new_pfn);
        }
        return 1;
    }

    /* 没人认领 -> 注入 hypercall（对应 IDA 的 g_EncryptedVmcallTarget / 0x3467103） */
    if (!handled) {
        s->status_flags = HYPERCALL_MAGIC;
        printf("[分派] 无人认领 -> 向客户机注入 hypercall 0x%x\n", HYPERCALL_MAGIC);
    }
    return handled;
}

/* ================================================================
 * 10. 处理者 1：EPT violation（翻镜子）
 * ================================================================ */
static int ept_violation_handler(VcpuState *s, ExitInfo *info) {
    if (info->reason != EXIT_REASON_EPT_VIOLATION) return 0;

    for (int i = 0; i < s->hook_count; i++) {
        HookEntry *h = &s->hooks[i];
        if (h->gpa != (info->gpa & ~(u64)(PAGE_4K - 1))) continue;

        printf("[door] EPT violation @ gpa=0x%llx rip=0x%x observer=%d\n",
               info->gpa, info->rip, info->observer);

        if (info->observer == 1) {
            /* ---- 保安来查 -> 翻镜子，给干净页，查完翻回来 ---- */
            /* 模拟跨核信号：另一个核"正在翻面"，置 exit_state=1，稍后=2 */
            s->exit_state = 1;
            s->exit_state = 2;

            hv_ept_swap_hook_on_violation(s, h);   /* 翻镜子 */
            hv_after_ept_violation(s, h->gpa);     /* 收尾 */

            /* 翻镜子时给保安看干净页：把表项临时换成干净 pfn */
            EptEntry *e = hv_ept_lookup(s, h->gpa);
            e->b.pfn = h->clean_pfn;
            s->scan_count++;
            printf("   [保安] 看到: %02X %02X %02X ... (干净页, 一切正常)\n",
                   pfn_to_va(h->clean_pfn)[0], pfn_to_va(h->clean_pfn)[1],
                   pfn_to_va(h->clean_pfn)[2]);
            e->b.pfn = h->modified_pfn;            /* 保安走了，翻回来 */

            info->magic = MAGIC_RIRI;              /* 让分派器走重定向路径 */
            return 1;
        } else {
            /* ---- 住户访问 -> 替身模拟：给改过页的内容 ---- */
            printf("   [住户] 替身模拟: 读到 %02X %02X %02X ... (改过页)\n",
                   pfn_to_va(h->modified_pfn)[0], pfn_to_va(h->modified_pfn)[1],
                   pfn_to_va(h->modified_pfn)[2]);
            return 1;
        }
    }
    return 0;
}

/* ================================================================
 * 11. 处理者 2：NT API 钩子（对应 Hook_NtApi_VmExitHandler）
 *     认人：先查"是不是被关注进程"（PID/CR3 匹配），再按 RIP 对照表
 * ================================================================ */
static u64 g_hook_guest_cr3;   /* 被关注进程的 CR3（对应 g_Hook_GuestCr3OrCtx） */

static int hook_ntapi_handler(VcpuState *s, ExitInfo *info) {
    (void)s;
    /* 认人第一关：当前进程的 CR3 是不是被关注的那个 */
    u64 cur_cr3 = 0x9999;      /* 模拟当前进程 CR3 */
    if (cur_cr3 != g_hook_guest_cr3)
        return 0;              /* 不是被关注进程 -> 不认领 */
    /* 认人第二关：RIP 命中黑名单（这里放一个"目标函数"地址） */
    if (info->rip == 0x7777) {
        printf("[door] 命中黑名单 API @ rip=0x%x -> 替身模拟执行\n", info->rip);
        info->magic = MAGIC_RIRI;
        return 1;
    }
    return 0;
}

/* ================================================================
 * 12. 住户/保安访问入口（模拟硬件 VM-exit）
 * ================================================================ */
static void guest_access(VcpuState *s, int observer, u64 gpa, u32 rip) {
    ExitInfo info;
    memset(&info, 0, sizeof(info));
    info.gpa = gpa;
    info.rip = rip;

    EptEntry *e = hv_ept_lookup(s, gpa);

    /* 被钩子保护的页：访问必触发 violation（真实机制：钩子让页产生陷阱） */
    for (int i = 0; i < s->hook_count; i++) {
        if (s->hooks[i].gpa == (gpa & ~(u64)(PAGE_4K - 1))) {
            info.observer = observer;
            info.reason = EXIT_REASON_EPT_VIOLATION;
            hv_dispatch_exit_handlers(s, &info);
            return;
        }
    }

    if (!e || !(e->b.r || e->b.w || e->b.x)) {
        /* 访问不可见页 -> EPT violation */
        info.observer = observer;
        info.reason = EXIT_REASON_EPT_VIOLATION;
        hv_dispatch_exit_handlers(s, &info);
        if (observer == 0)
            printf("   [住户] 访问被藏页 -> 触发 violation\n");
        return;
    }

    /* 可访问的页：住户看当前表项指向的内容 */
    u8 *view = pfn_to_va(e->b.pfn);
    if (observer == 0)
        printf("   [住户] 读 gpa=0x%llx: %02X %02X %02X ...\n",
               gpa, view[0], view[1], view[2]);
    else
        printf("   [保安] 读 gpa=0x%llx: %02X %02X %02X ...\n",
               gpa, view[0], view[1], view[2]);
}

/* ================================================================
 * 13. main —— 把老师驱动的流程演一遍
 * ================================================================ */
int main(void) {
    VcpuState s;
    memset(&s, 0, sizeof(s));
    s.use_real_vmx = 1;

    /* 分配 EPT 根表 + 中间层 */
    u64 pml4_pfn = phys_alloc_pfn();
    u64 pdpt_pfn = phys_alloc_pfn();
    u64 pd_pfn   = phys_alloc_pfn();
    s.pml4 = (EptEntry *)pfn_to_va(pml4_pfn);
    EptEntry *pdpt = (EptEntry *)pfn_to_va(pdpt_pfn);
    EptEntry *pd   = (EptEntry *)pfn_to_va(pd_pfn);
    memset(s.pml4, 0, PAGE_4K);
    memset(pdpt, 0, PAGE_4K);
    memset(pd, 0, PAGE_4K);

    /* 映射一个 2MB 区域（PD[0] 用大页） */
    u64 region_pfn = phys_alloc_pfn();
    fill_page(region_pfn, 0x55);               /* 区域内容 */
    s.pml4[0] = make_pte(pdpt_pfn, 0, 1, 1, 1);
    pdpt[0]   = make_pte(pd_pfn, 0, 1, 1, 1);
    pd[0]     = make_pte(region_pfn, 1, 1, 1, 1);

    /* 分配并准备 干净页(0xCC) 和 改过页(0xAA) */
    u64 clean_pfn = phys_alloc_pfn();
    u64 mod_pfn   = phys_alloc_pfn();
    fill_page(clean_pfn, 0xCC);
    fill_page(mod_pfn, 0xAA);

    printf("=====================================================\n");
    printf("  EPT 钩子机制模型（按老师驱动 HV_Ept* 函数结构）\n");
    printf("  纯软件模拟，不针对任何人\n");
    printf("=====================================================\n\n");

    /* 登记处理者（对应 Hook_InstallAll 注册 exit handler） */
    hv_register_exit_handler(ept_violation_handler);
    hv_register_exit_handler(hook_ntapi_handler);
    g_hook_guest_cr3 = 0x9999;

    /* 1. 拆大页 */
    hv_ept_split_large_page(&s, 0);

    /* 2. 在 gpa=0x1000 装双视图钩子（住户看到改过页） */
    hv_ept_install_hook(&s, 0x1000, mod_pfn);

    /* 3. 藏一页 gpa=0x2000 */
    hv_ept_hide_pages(&s, 0x2000, 1);

    printf("\n--- 场景1: 住户访问（看到改过页）---\n");
    guest_access(&s, 0, 0x1000, 0x1111);

    printf("\n--- 场景2: 保安查房（翻镜子, 看到干净页）---\n");
    for (int i = 0; i < 3; i++) {
        printf("  第 %d 轮查房:\n", i + 1);
        guest_access(&s, 1, 0x1000, 0x2222);
    }

    printf("\n--- 场景3: 住户访问被藏页（触发 violation）---\n");
    guest_access(&s, 0, 0x2000, 0x3333);

    printf("\n--- 场景4: NT API 命中黑名单（替身执行）---\n");
    {
        ExitInfo info = {0};
        info.reason = 0; info.rip = 0x7777; info.gpa = 0x4000;
        hv_dispatch_exit_handlers(&s, &info);
    }

    printf("\n=====================================================\n");
    printf(" 总结: 保安查了 %d 次房, 每次看到的都是干净页\n", s.scan_count);
    printf(" 计时记账: last_swap_delta=%lld (防时间差用)\n",
           (long long)s.last_swap_delta);
    printf("=====================================================\n");
    return 0;
}
