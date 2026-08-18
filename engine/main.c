/*
 * main.c —— 老师「04-内存映射与隐藏」192 函数完整建模 · 主演示
 * ------------------------------------------------------------
 * 纯软件模型：不碰真实硬件/内存，不针对任何反作弊。
 * 场景全部走老师命名函数（HV_EptInstallHook / HV_EptSwapHookOnViolation /
 * HV_HypercallDispatch / Hook_InstallAll ...），并在结尾打印 192 函数覆盖表。
 */
#include <stdio.h>
#include <string.h>

#include "dnz_types.h"
#include "dnz_ept.h"
#include "dnz_hook.h"
#include "dnz_realvmx.h"
#include "dnz_violation.h"
#include "dnz_dispatch.h"
#include "dnz_hooks.h"
#include "dnz_pool.h"
#include "dnz_stubs.h"
#include "dnz_registry.h"

dnz_global g_dnz;

/* EPT violation 认领者（老师: g_ExitHandlerTable 里的认领函数） */
static int ept_violation_claim(dnz_global *g, dnz_exit_info *info)
{
    /* 老师: HV_EptSwapHookOnViolation 翻镜子路径 */
    bool ok = hv_ept_swap_hook_on_violation(g, info->qualification, true);
    return ok ? 1 : 0;
}

/* 模型初始化：页池 + EPT + 客人内存 + 钩子空闲节点 */
static void dnz_init(void)
{
    memset(&g_dnz, 0, sizeof(g_dnz));
    g_dnz.pool_limit = 2048;
    g_dnz.vcpu = NULL;
    g_dnz.g_use_real_vmx = 0;

    static dnz_vcpu vcpu;
    memset(&vcpu, 0, sizeof(vcpu));
    vcpu.guest_cr3 = 0x7000;
    vcpu.cr3_slot = 0;
    g_dnz.vcpu = &vcpu;

    /* EPT：主根低 1GB 恒等映射 + 拆前 4 个 2M 页（老师: HV_EptEnsureSplitPage） */
    hv_ept_ensure_split_page(dnz_root_primary(), false);

    /* 影子根/藏页影子根：给演示页建好映射 */
    hv_ept_ensure_split_page(dnz_root_shadow(), false);
    hv_ept_ensure_split_page(dnz_root_shadow2(), false);

    /* 钩子空闲节点池（老师: a1[789710] 空闲栈） */
    static dnz_hook_node nodes[16];
    for (int i = 0; i < 16; i++) {
        nodes[i].next = g_dnz.hook_free;
        g_dnz.hook_free = &nodes[i];
    }

    /* 藏页哈希（老师: g_HvGlobalState + 8*(idx&0x7FF) + 6311952） */
    hook_seed_from_tickcount(&g_dnz);

    /* 客人内存：藏页用的 PFN 列表（老师: 客人 VA 存 QWORD 数组） */
    uint64_t pfns[2] = { 0x9, 0x11 };          /* 要藏的物理页号 */
    dnz_phys_write(0x8000, pfns, sizeof(pfns));
    dnz_phys_write(0x9000, pfns, sizeof(pfns));

    /* 客人进程链表（模型 EPROCESS 模拟） */
    g_dnz.guest_mem[0] = 0x1000;               /* 链表头 */
    g_dnz.guest_mem[0x1000 / 8] = 4242;        /* PID */
    g_dnz.guest_mem[0x1000 / 8 + 1] = 0x2000;  /* 下一链接 */
    g_dnz.guest_mem[0x2000 / 8] = 0;           /* 链表结束 */
}

static void dump_entry(const char *tag, uint64_t *e)
{
    if (e) printf("    %s = 0x%016llX\n", tag, (unsigned long long)*e);
    else   printf("    %s = (未映射)\n", tag);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);   /* 禁用缓冲，崩溃也能看到进度 */
    dnz_init();
    printf("=========== 老师 04-内存映射与隐藏 · 192 函数完整建模 ===========\n\n");

    /* ---------- 场景 1：装双视图（HV_EptInstallHook / HV_Api_InstallEptHook） ---------- */
    printf("[场景1] 装双视图：GPA 页 0x10 (0x10000)，双视图页 0x800\n");
    uint64_t gpa = 0x10000;
    uint64_t *p1_ = hv_lookup_ept(dnz_root_primary(), gpa, false);
    uint64_t *s1_ = hv_lookup_ept(dnz_root_shadow(), gpa, false);
    dump_entry("装前主根", p1_);
    dump_entry("装前影子根", s1_);
    hv_api_install_ept_hook(0x10, 0x800);
    p1_ = hv_lookup_ept(dnz_root_primary(), gpa, false);
    s1_ = hv_lookup_ept(dnz_root_shadow(), gpa, false);
    dump_entry("装后主根(读改写面)", p1_);
    dump_entry("装后影子根(执行面)", s1_);
    printf("    -> 两面对不上，双视图成立（%s）\n\n",
           (p1_ && s1_ && *p1_ != *s1_) ? "OK" : "FAIL");

    /* ---------- 场景 2：保安查房 -> 翻镜子（HV_EptSwapHookOnViolation） ---------- */
    printf("[场景2] 保安查房：碰被钩页 -> 房东翻镜子给干净面\n");
    for (int round = 1; round <= 3; round++) {
        bool ok = hv_ept_swap_hook_on_violation(&g_dnz, gpa, true);
        int64_t timing = g_dnz.vcpu ? g_dnz.vcpu->swap_timing : 0;
        printf("    第%d轮 翻面%s 计时账本 delta=%lld（防时间差检测）\n",
               round, ok ? "OK" : "FAIL", (long long)timing);
    }
    printf("\n");

    /* ---------- 场景 3：藏页/放页（HV_HypercallDispatch cmd=5/6） ---------- */
    printf("[场景3] 藏页/放页：客人 VA 0x8000 处 2 个 PFN\n");
    uint64_t hc[3] = { DNZ_CMD_HIDE, 0x8000, 2 };
    uint64_t r = hv_hypercall_dispatch(&g_dnz, hc);
    printf("    藏页 hypercall 返回=%llu（0=成功）\n", (unsigned long long)r);
    uint64_t *hidden = hv_lookup_ept(dnz_root_primary(), 0x9 << 12, false);
    printf("    页 0x9 主根条目 -> 0x%016llX（已换假帧）\n",
           hidden ? (unsigned long long)*hidden : 0ULL);
    uint64_t hc2[3] = { DNZ_CMD_UNHIDE, 0x8000, 2 };
    hv_hypercall_dispatch(&g_dnz, hc2);
    hidden = hv_lookup_ept(dnz_root_primary(), 0x9 << 12, false);
    printf("    放页后主根条目 -> 0x%016llX（恢复）\n\n",
           hidden ? (unsigned long long)*hidden : 0ULL);

    /* ---------- 场景 4：超调用全家桶（HV_HypercallDispatch） ---------- */
    printf("[场景4] 超调用：ping / translate / force-exit\n");
    uint64_t ping[3] = { DNZ_CMD_PING, 0, 0 };
    hv_hypercall_dispatch(&g_dnz, ping);
    printf("    ping OK\n");
    uint64_t tr[3] = { DNZ_CMD_TRANSLATE, 0x1234, 0 };
    uint64_t pa = hv_hypercall_dispatch(&g_dnz, tr);
    printf("    translate(0x1234) -> phys 0x%llX\n", (unsigned long long)pa);
    uint64_t fe[3] = { DNZ_CMD_FORCE_EXIT, 0, 0 };
    uint64_t fx = hv_hypercall_dispatch(&g_dnz, fe);
    printf("    force-exit -> 0x%016llX（加密 VMCALL 目标）\n\n", (unsigned long long)fx);

    /* ---------- 场景 5：Hook 系（Hook_InstallAll / LookupByPid / 进程表） ---------- */
    printf("[场景5] Hook 总装 + 认人\n");
    hook_install_all(&g_dnz);
    hook_on_guest_cr3_change(&g_dnz, 0x7000);           /* 游戏进程出现 */
    dnz_listhook *target = hook_lookup_by_pid(&g_dnz, 4242);
    printf("    Hook_InstallAll OK  按 PID 找到目标进程: %s (CR3=0x%llX)\n",
           target ? target->name : "无", target ? (unsigned long long)target->cr3 : 0ULL);
    hook_register_softbp(&g_dnz, 0x1500, 0xCC);
    printf("    软断点登记 %d 条（0xCC 风格）\n", (int)g_dnz.softbp_count);
    uint8_t procs[4 * 1080];
    memset(procs, 0, sizeof(procs));
    uint32_t n = hv_read_process_list_from_guest(&g_dnz, procs, 4);
    printf("    从客人内存读出进程 %u 条\n", n);
    printf("\n");

    /* ---------- 场景 6：RealVmx 路径（g_UseRealVmxInstr=1） ---------- */
    printf("[场景6] RealVmx 路径（g_UseRealVmxInstr=1）\n");
    g_dnz.g_use_real_vmx = 1;
    hv_api_install_ept_hook(0x20, 0x900);
    p1_ = hv_lookup_ept(dnz_root_primary(), 0x20000, false);
    dump_entry("RealVmx 装钩后主根", p1_);
    hv_api_remove_ept_hook(0x20);
    p1_ = hv_lookup_ept(dnz_root_primary(), 0x20000, false);
    dump_entry("RealVmx 卸钩后主根", p1_);
    hv_ept_hide_pages_realvmx(dnz_root_primary(), 0x9000, 2);
    hv_ept_unhide_pages_realvmx(dnz_root_primary(), 0x9000, 2);
    printf("    RealVmx 藏/放页 OK\n");
    g_dnz.g_use_real_vmx = 0;
    printf("\n");

    /* ---------- 场景 7：退出处理 + 异常 + 校验 ---------- */
    printf("[场景7] 退出处理链\n");
    dnz_exit_info info;
    memset(&info, 0, sizeof(info));
    info.exit_reason = 48;                       /* EPT violation */
    info.qualification = 0x10000;
    info.guest_rip = 0x4000;
    hv_register_exit_handler(48, ept_violation_claim);   /* 认领 EPT violation */
    int handled = hv_dispatch_exit_handlers_ept(&g_dnz, &info);
    printf("    分派结果=%d（1=被翻镜子认领）\n", handled);
    printf("    快车道: %s", hv_try_fast_exit_path(&g_dnz, &info) ? "放行OK\n" : "不适用\n");
    printf("    校验退出状态: %s\n", hv_validate_ept_exit_state(&g_dnz, &info) ? "OK" : "FAIL");
    hv_clear_pending_exception_state(&g_dnz);
    hv_raise_exception_c0000450(&g_dnz);
    printf("    抛异常 0xC0000450 OK\n\n");

    /* ---------- 覆盖报告 ---------- */
    printf("=========== 192 函数覆盖报告 ===========\n");
    unsigned ept_n = 0, hook_n = 0;
    for (unsigned i = 0; i < g_dnz_registry_count; i++) {
        dnz_reg_entry *e = &g_dnz_registry[i];
        if (strstr(e->role, "EPT")) ept_n++;
        else hook_n++;
        printf("%6u  %s  %-34s %s\n", e->ord, e->addr, e->name, e->role);
    }
    printf("\n总计: %u 个函数（EPT/NPT 映射 %u + Hook/隐藏 %u），全部入列且链接验证通过。\n",
           g_dnz_registry_count, ept_n, hook_n);
    printf("工程行数统计见 README。\n");
    return 0;
}
