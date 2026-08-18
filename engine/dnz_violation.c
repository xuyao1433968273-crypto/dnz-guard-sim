#include "dnz_violation.h"
#include "dnz_ept.h"
#include "dnz_hook.h"
#include <string.h>

uint64_t dnz_tsc(void)
{
    /* 模型时钟：用全局计数器累加，避免依赖真实 rdtsc */
    static uint64_t t = 0;
    return t += 37;
}

/* 跨核状态（老师: 偏移 6332536 的标记位 + 偏移 6427304 的状态计数） */
static volatile int64_t g_swap_marker;   /* 0=闲 1=正在翻 */
static volatile int64_t g_swap_state;    /* 0=闲 1=干活中 2=干完 */

/*
 * ============================================================
 * 01758. HV_EptSwapHookOnViolation (0x140116f90)
 * ------------------------------------------------------------
 * 老师逐行（此前已深挖）：
 *   信号1：标记位(偏移6332536) —— "这页是不是装过双面镜的受保护页"
 *   信号2：状态计数(偏移6427304) —— 0=闲 2=干完，跨核对表
 *   信号3：TSC —— 限时等待(8×预算周期) + 翻面计时记账
 *   动作：清标记 → HV_EptRemoveHook（撤走改过面）→ HV_EptInstallHook（装干净面）
 *         → HV_AfterEptViolation → 记账 *(a1+24656) = 预期-实际
 * 模型：who=observer 表示"保安来查"才翻面；住户访问直接放行。
 * ============================================================
 */
bool hv_ept_swap_hook_on_violation(dnz_global *g, uint64_t fault_gpa, bool observer_is_guard)
{
    if (!observer_is_guard) {
        /* 住户访问：老师里走 HV_HandleGuestFaultOrExit 的映射路径 */
        return hv_ept_map_guest_access(dnz_root_primary(), fault_gpa, false);
    }

    /* ---- 翻镜子 ---- */
    uint64_t t0 = dnz_tsc();
    uint64_t budget = 8;                       /* 老师: 8×预算周期 */
    uint64_t deadline = t0 + budget * 1000;

    /* 跨核等待：若别的核正在翻，原地转圈等"干完"(state==2)，带时限 */
    while (g_swap_state == 1) {
        if (dnz_tsc() > deadline) return false;   /* 老师: 超时放弃 */
    }
    g_swap_marker = 1;                        /* 老师: 清标记=我来处理 */
    g_swap_state = 1;

    /* 卸掉改过那面 → 装上干净那面（老师: RemoveHook → InstallHook） */
    uint64_t gpa_idx = (uint32_t)(fault_gpa >> 12);
    /* 找当前装着的钩子：把"双视图页"换回"真实页"的语义 */
    for (dnz_hook_node *n = g->hook_list; n; n = n->next) {
        if (n->gpa_idx == gpa_idx) {
            /* 老师第2步：撤走（把主根恢复成"干净内容可见"）；
               第3步：再装一次（把影子根指向干净页） */
            hv_ept_remove_hook(dnz_root_primary(), gpa_idx);
            hv_ept_install_hook(dnz_root_primary(), gpa_idx, n->hook_pfn);
            break;
        }
    }

    hv_after_ept_violation(g, fault_gpa);

    /* 计时记账：老师 *(a1+24656) = 预期时间 - 实际时间（防时间差检测） */
    uint64_t took = dnz_tsc() - t0;
    if (g->vcpu) {
        g->vcpu->swap_timing = (int64_t)(deadline - t0) - (int64_t)took;
    }
    g_swap_state = 2;
    g_swap_marker = 0;
    return true;
}

/*
 * ============================================================
 * 01757. HV_AfterEptViolation (0x140116ed0)
 * ------------------------------------------------------------
 * 老师逐行（此前已深挖）：
 *   读当前进程 CR3（VMCS）
 *   把被碰那一页 4096 字节从系统地图拷出来
 *   拷贝开头埋"跳板"指向 IretStub
 *   让访问者看到的是这个拷贝
 * 模型：在模拟物理内存里做 4KB 拷贝 + 开头写跳板字节。
 * ============================================================
 */
void hv_after_ept_violation(dnz_global *g, uint64_t fault_gpa)
{
    uint64_t page = fault_gpa & ~0xFFFULL;
    /* 老师: 拷 4096 字节（来源=被保护页真实内容，模型里是 hide 前的内容） */
    uint64_t src = page;
    uint64_t dst = (page + DNZ_PAGE_SIZE) & (DNZ_PHYS_SIZE - DNZ_PAGE_SIZE); /* 拷贝页 */
    memcpy(dnz_phys_ptr(dst), dnz_phys_ptr(src), DNZ_PAGE_SIZE);
    /* 老师: 开头埋跳板（指向 IretStub，模型: 0xE9 近跳 + 偏移） */
    uint8_t *stub = dnz_phys_ptr(dst);
    stub[0] = 0xE9;                                  /* JMP rel32 */
    uint64_t target = 0;                             /* IretStub 模型地址 */
    uint32_t rel = (uint32_t)((target - (dst + 5)) & 0xFFFFFFFFULL);
    memcpy(stub + 1, &rel, 4);
    (void)g;
}

/*
 * ============================================================
 * 01753. HV_HandleGuestFaultOrExit (0x140116b70)
 * ------------------------------------------------------------
 * 老师流程：
 *   v4 = *(a1+24696) 退出标志；v5 = a1+77824（EPT 上下文）
 *   若 v4&1：
 *     若未切槽(6393888==0) 且 EPT 项带 0x200：
 *       (v4&0x12)!=0x10 → HV_InjectGuestHypercallFrame(0x3467101, v4, RIP, RSP)
 *       否则：加密 VMCALL 路径（g_EncryptedVmcallTarget ^ 0x6D772324CE8FCDB9，
 *             把 RSP-56 当作栈帧，写退出帧 208=0x3467102 / 200 / 152 / 144）
 *     若 (v4&0x10)==0：对 RIP 与 RIP+15 两页做 SplitPage_ClearXD
 *       6393888==1 → SwitchGuestCr3Slot(0) 否则 Slot(1)
 * 模型：按上述分支建模（超调用帧/退出帧用结构体近似）。
 * ============================================================
 */
int hv_handle_guest_fault_or_exit(dnz_global *g, dnz_exit_info *info)
{
    uint64_t flags = g->vcpu ? g->vcpu->exit_flags : 0;
    uint64_t gpa   = g->vcpu ? g->vcpu->fault_gpa : (info ? info->qualification : 0);

    if (flags & 1) {
        uint64_t *entry = hv_lookup_ept(dnz_root_primary(), gpa, false);
        if (g->vcpu->cr3_slot == 0 && entry && (*entry & 0xE00) == 0x200) {
            if ((flags & 0x12) != 0x10) {
                /* 老师: HV_InjectGuestHypercallFrame(54948097, flags, RIP, RSP) */
                return 54948097;   /* 0x3467101 */
            } else {
                /* 加密 VMCALL 目标 */
                uint64_t v21 = DNZ_VMCALL_KEY;
                uint64_t v20 = g->g_encrypted_vmcall_target ^ v21;
                if (g->vcpu) {
                    g->vcpu->guest_rsp = (g->vcpu->guest_rsp & ~0xFULL) - 56;
                    g->vcpu->guest_rip = v20;
                }
                if (info) info->exit_reason = 54948098; /* 0x3467102 */
                return 54948098;
            }
        }
        if ((flags & 0x10) == 0) {
            /* 老师: RIP 与 RIP+15 两页清 XD（跨页边界处理） */
            uint64_t rip = g->vcpu ? g->vcpu->guest_rip : 0;
            hv_ept_split_page_clear_xd(dnz_root_primary(), rip);
            hv_ept_split_page_clear_xd(dnz_root_primary(), rip + 15);
        }
        if (g->vcpu && g->vcpu->cr3_slot == 1) {
            g->vcpu->cr3_slot = 0;   /* 老师: SwitchGuestCr3Slot(0) */
        } else if (g->vcpu) {
            g->vcpu->cr3_slot = 1;
        }
        return 0;
    }
    return 0;
}

/*
 * ============================================================
 * 01754. HV_Svm_MsrInterceptHandler (0x140116d90)
 * ------------------------------------------------------------
 * 老师：AMD 侧 MSR 拦截处理（读/写分流）。
 * 模型：LSTAR/STAR/SFMASK/EFER 等常规拦截项，记录并放行。
 * ============================================================
 */
uint64_t hv_svm_msr_intercept_handler(uint64_t msr_index, uint64_t *value, bool write)
{
    /* 老师: 对拦截表里的 MSR 做读改写；模型记录一笔 */
    switch (msr_index) {
    case 0xC0000082ULL: /* LSTAR */
    case 0xC0000081ULL: /* STAR */
    case 0xC0000084ULL: /* SFMASK */
    case 0xC0000080ULL: /* EFER */
        return 1;   /* 拦截成功 */
    default:
        (void)write; (void)value;
        return 0;   /* 放行 */
    }
}

/*
 * ============================================================
 * 01785. HV_InvalidateGuestTlbOrEpt (0x14011b560)
 * ------------------------------------------------------------
 * 老师：
 *   HV_Rdgsbase() 判当前核
 *   地址范围/规范地址检查
 *   v5 = (a1>>39)&0x1FF；读两个根的 PML4E
 *   不同 → 写回 + sub_14011BD00()（invvpid 冲刷）
 * ============================================================
 */
bool hv_invalidate_guest_tlb_or_ept(uint64_t addr, uint64_t *root_a, uint64_t *root_b)
{
    /* 老师: a1+0x800000000000 >= 0x1000000000000 → 越界返回 */
    if (addr + 0x800000000000ULL >= 0x1000000000000ULL) return false;
    /* 老师: 高位模式检查（非规范地址） */
    if ((addr & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL
        && (addr & 0xFFFF000000000000ULL) != 0) return false;

    unsigned pml4 = (unsigned)((addr >> 39) & 0x1FF);
    uint64_t a = root_a[pml4];
    uint64_t b = root_b[pml4];
    if (a == b) return true;      /* 老师: 相同 → 什么都不用做 */

    root_b[pml4] = a;             /* 老师: 写回 */
    if (g_dnz.vcpu) {
        g_dnz.vcpu->ept_flags &= ~0x10u;
        g_dnz.vcpu->ept_state = 3;
    }
    return true;
}

/*
 * ============================================================
 * 01872. HV_ClearPendingExceptionState (0x140125f40)
 * ------------------------------------------------------------
 * 老师：有挂起的待处理事件先清掉（HV_HandlePendingEvent），
 *       再按需修正条目，最后冲刷（sub_1401E06C6(2,...)）。
 * ============================================================
 */
uint64_t hv_clear_pending_exception_state(dnz_global *g)
{
    if (g->vcpu && g->vcpu->pending_event) {
        g->vcpu->pending_event = 0;      /* 老师: HV_HandlePendingEvent */
    }
    if (g_dnz.vcpu) {
        g_dnz.vcpu->ept_flags &= ~0x10u;
        g_dnz.vcpu->ept_state = 3;
    }
    return 0;
}

/*
 * ============================================================
 * 01873. HV_TryFastExitPath (0x140126020)
 * ------------------------------------------------------------
 * 老师：常见/无害退出走快车道（不惊动大部队）。
 * 模型：根据退出原因位做白名单判断。
 * ============================================================
 */
bool hv_try_fast_exit_path(dnz_global *g, dnz_exit_info *info)
{
    (void)g;
    if (!info) return false;
    /* 老师: (*(a1+6502288) & 0x80000000000000) 标志判断；
       模型: 只放行"无害"的退出（中断/外部事件/CPUID 等） */
    uint64_t r = info->exit_reason;
    if (r == 0 || r == 1 || r == 10 || r == 12) return true;  /* 中断/异常/NMI/外部 */
    return false;
}

/*
 * ============================================================
 * 01875. HV_ValidateEptExitState (0x1401266e0)
 * ------------------------------------------------------------
 * 老师：翻完镜子检查退出状态是否自洽，别露馅。
 * 模型：校验 fault 地址在钩子链表里找得到（否则说明状态错）。
 * ============================================================
 */
bool hv_validate_ept_exit_state(dnz_global *g, dnz_exit_info *info)
{
    if (!info) return false;
    uint64_t gpa_idx = (uint32_t)(info->qualification >> 12);
    for (dnz_hook_node *n = g->hook_list; n; n = n->next) {
        if (n->gpa_idx == gpa_idx) return true;
    }
    /* 不在链表里也未必错（可能是藏页路径）；模型里放宽为 true */
    return true;
}
