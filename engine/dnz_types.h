/*
 * dnz_types.h — 老师样本「04-内存映射与隐藏」192 函数完整建模工程 · 类型与全局定义
 * ---------------------------------------------------------------------------
 * 建模依据：D:\CodexWork\ReverseLabV3\teacher_function_by_function_20260813\output
 *           all_functions_index_cn.csv + line_by_line_cn\LINE_*.md（逐行大白话）
 *
 * 原则：
 *   1. 所有 192 个函数全部入列，命名函数忠实建模，sub_ 函数按分析给出的
 *      角色/调用关系逐个建模（VMProtect 加密区按结构桩 + 文档标注）。
 *   2. 纯软件模型：不碰真实硬件、不碰真实内存、不针对任何反作弊。
 *   3. 老师代码里的魔数偏移（6316032/5791744/789710 等）在注释里保留对应关系。
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* 可移植原子 CAS（模型里的跨核锁/状态计数用） */
static inline int64_t dnz_cas(volatile int64_t *dst, int64_t cmp, int64_t val)
{
#ifdef _MSC_VER
    return _InterlockedCompareExchange64(dst, val, cmp);
#else
    return __sync_val_compare_and_swap(dst, cmp, val);
#endif
}

/* ============ 模拟硬件常量（对应老师代码里的魔数） ============ */

/* 物理内存直接映射基址：老师代码里访问物理页用 +0x7F8000000000 寻址 */
#define DNZ_DIRECT_MAP_BASE    0x7F8000000000ULL
/* 物理内存大小（模型用 64MB，够放 EPT 页表 + 演示数据） */
#define DNZ_PHYS_SIZE          (64ULL * 1024 * 1024)
/* 页面大小 */
#define DNZ_PAGE_SIZE          0x1000ULL
#define DNZ_LARGE_PAGE_SIZE    0x200000ULL      /* 2MB 大页 */
#define DNZ_EPT_ENTRIES        512              /* 每级 512 项 */

/* 超调用魔数（HV_HypercallDispatch 里校验 *a2 > 0x69695269 判错） */
#define DNZ_MAGIC_HYPERCALL    0x69695269ULL
#define DNZ_ERR_RETURN         0x6969696969696969ULL

/* 超调用命令号（分析注释原文） */
#define DNZ_CMD_PING           0x1LL
#define DNZ_CMD_HOST_ENTER     0x2LL
#define DNZ_CMD_EPT_HOOK_SET   0x3LL   /* 装双视图 */
#define DNZ_CMD_EPT_HOOK_CLR   0x4LL   /* 卸双视图 */
#define DNZ_CMD_HIDE           0x5LL   /* 藏页 */
#define DNZ_CMD_UNHIDE         0x6LL   /* 放页 */
#define DNZ_CMD_COPY           0xCLL   /* 拷贝 */
#define DNZ_CMD_TRANSLATE      0xDLL   /* 翻译客户机地址 */
#define DNZ_CMD_TRANSLATE2     0xELL
#define DNZ_CMD_FORCE_EXIT     0xFLL   /* 强制退出 */

/* 加密 VMCALL 目标（HandleGuestFaultOrExit 里 XOR 魔数） */
#define DNZ_VMCALL_KEY         0x6D772324CE8FCDB9ULL

/* ============ EPT 页表项位（Intel 手册） ============ */
#define EPT_PRESENT      0x1ULL
#define EPT_RW           0x2ULL
#define EPT_X            0x4ULL
#define EPT_UC           0x0000000000000000ULL  /* bit2-3 = 0: uncacheable */
#define EPT_WC           0x20000000000000ULL
#define EPT_WT           0x40000000000000ULL
#define EPT_WB           0x60000000000000ULL
#define EPT_XD           (1ULL << 63)
#define EPT_PFN_MASK     0x000FFFFFFFFFF000ULL
#define EPT_ADDR_MASK    0xFFFFFFFFFF000ULL     /* 老师代码用 0xFFFFFFFFFF000 */

/* ============ 结构体（字段名可读，注释保留老师偏移） ============ */

/* EPT 双视图钩子节点（HV_EptInstallHook 里 v7 处的 16 字节节点：
 *   [0]  next 指针          （老师: *(_QWORD*)v7）
 *   [8]  gpa 页号 (dword)   （老师: *(_DWORD*)(v7+8) = a2）
 *   [12] hook 页号 (dword)  （老师: *(_DWORD*)(v7+12) = a3） */
typedef struct dnz_hook_node {
    struct dnz_hook_node *next;
    uint32_t              gpa_idx;   /* 客户机物理页号 */
    uint32_t              hook_pfn;  /* 假页/双视图页物理帧号 */
} dnz_hook_node;

/* 软断点钩子表项（Hook_RegisterSoftBp 往 ACE hook 表里登记的东西） */
typedef struct dnz_softbp_entry {
    uint64_t target;      /* 要拦的客户机地址 */
    uint64_t fake;        /* 替身地址 */
    uint8_t  opcode;      /* 常为 0xCC */
    uint8_t  active;
    uint32_t pid_filter;
} dnz_softbp_entry;

/* 进程钩子表项（Hook_LookupByPid / Hv_ReadProcessListFromGuest 用的 ListHook） */
typedef struct dnz_listhook {
    struct dnz_listhook *next;
    uint32_t             pid;
    uint64_t             cr3;
    uint64_t             eprocess;
    char                 name[16];
} dnz_listhook;

/* 客户机退出信息（HV_DispatchExitHandlers_Ept 递给认领者的 1232 字节袋子，
 *  模型里只保留分析确认过的字段） */
typedef struct dnz_exit_info {
    uint64_t exit_reason;       /* VM-exit 原因 */
    uint64_t guest_rip;         /* 客人在哪个位置被拦 */
    uint64_t guest_cr3;         /* 谁的地址地图 */
    uint64_t qualification;     /* 退出限定字（EPT violation 时是 fault 地址等） */
    uint32_t cs_rpl;            /* 内核态还是用户态 */
    uint32_t access_type;       /* 读/写/执行 */
    uint64_t rflags;
    uint64_t rsp;
    uint64_t rcx, rdx, rbx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rax;
    uint8_t  buf[1152];         /* 凑满 1232 字节的原始袋子（模型保留） */
} dnz_exit_info;

/* 每核 VCPU 上下文（老师代码里 a1 = 全局态，+6317688 处是当前核状态指针；
 * 字段偏移见注释） */
typedef struct dnz_vcpu {
    uint64_t guest_cr3;         /* 老师: +25936  = 当前进程页目录基址 */
    uint64_t guest_cr0;         /* +25944 */
    uint64_t guest_rflags;      /* +25968 */
    uint64_t guest_rip;         /* +25976 */
    uint64_t guest_rsp;         /* +26072 */
    uint64_t guest_rax;         /* +26080 */
    uint32_t cs_sel;            /* +25600 (sub_1401E06DB 读的 16 位选择子) */
    uint32_t ss_sel;            /* +25632 */
    uint32_t ds_sel;            /* +25648 */
    uint32_t ctrl_flags;        /* +24588: 控制位（分析: & 0xFFFFFBBD | 2） */
    uint32_t ept_flags;         /* +24768: EPT 指针域，bit4 = "需要冲刷 EPT" */
    uint8_t  ept_state;         /* +24668: 3 = 冲刷后状态 */
    int64_t  swap_timing;       /* +24656: 翻镜子计时账本（预期-实际） */
    uint64_t exit_flags;        /* +24696: 退出标志 */
    uint64_t fault_gpa;         /* +24704: EPT violation 地址 */
    uint32_t cr3_slot;          /* +6393888: CR3 槽位标记（0/1） */
    dnz_exit_info *exit_frame;  /* +6426688: 退出帧指针 */
    uint64_t pending_event;     /* +6512648: 待处理事件 */
    uint64_t vmcs_shadow_base;  /* 影子 VMCS 基址（模型） */
} dnz_vcpu;

/* 全局状态（老师代码里 g_HvGlobalState 指向的大结构；字段偏移见注释） */
typedef struct dnz_global {
    /* --- 页框池（HV_EptSplitLargePage / HV_EptMapGuestAccess 分配页用） --- */
    uint64_t pool_next;         /* 老师: +6316032 = 已分配计数 */
    uint64_t pool_limit;        /* 老师: +6316040 = 上限 */
    uint64_t pool_frames[4096]; /* 老师: +5791744 + 8*i = 物理帧号表 */
    uint64_t pool_va[4096];     /* 老师: +5267456 + 8*i = 虚拟地址表 */
    uint8_t  pool_use_phys;     /* 老师: +6317712 = 是否用物理帧映射 */

    /* --- 藏页哈希表（HV_EptHidePages: g_HvGlobalState + 8*(idx&0x7FF) + 6311952） --- */
    uint64_t hide_hash[2048];

    /* --- 钩子计数（HV_RemoveEptHook_Wrapper 遍历用） --- */
    uint32_t hook_count;        /* 老师: +6332448 */

    /* --- 当前核状态 --- */
    dnz_vcpu *vcpu;             /* 老师: +6317688 指向每核状态 */

    /* --- EPT 上下文（每个 VCPU 一套，老师代码里 a1 = EPT ctx） --- */
    uint64_t ept_primary[512];  /* 主 EPT 根（PML4） */
    uint64_t ept_shadow[512];   /* 影子根（老师: a1+263680） */
    uint64_t ept_shadow2[512];  /* 藏页影子根（老师: a1+2109440） */
    dnz_hook_node *hook_list;   /* 老师: a1[789709] = 钩子链表头 */
    dnz_hook_node *hook_free;   /* 老师: a1[789710] = 空闲节点栈 */

    /* --- 软断点表 & 进程表 --- */
    dnz_softbp_entry softbps[64];
    uint32_t         softbp_count;
    dnz_listhook    *list_buckets[256];  /* g_Hook_ListBuckets */
    uint64_t         list_sentinel;      /* g_Hook_ListSentinel */
    uint64_t         hook_offset_table[64]; /* g_Hook_OffsetTable */

    /* --- 开关 --- */
    uint8_t g_use_real_vmx;     /* g_UseRealVmxInstr: 1=真 VMX 指令路径 */
    uint64_t g_encrypted_vmcall_target; /* g_EncryptedVmcallTarget */

    /* --- 演示用客户机 "进程" 模拟 --- */
    uint64_t guest_mem[4096];   /* 客人内存（4K QWORDs = 32KB） */
    uint64_t guest_pid;
    uint64_t guest_cr3;
} dnz_global;

/* 退出处理认领者（HV_DispatchExitHandlers_Ept 的 g_ExitHandlerTable 登记表） */
typedef int (*dnz_exit_handler_fn)(dnz_global *g, dnz_exit_info *info);
typedef struct dnz_exit_handler {
    uint32_t             reason;
    dnz_exit_handler_fn  fn;
} dnz_exit_handler;

/* ============ 全局实例（模型单例） ============ */
extern dnz_global g_dnz;

/* ============ 模型工具函数 ============ */

/* 模型物理内存（全局数组，dnz_pool.c 里定义）。
 * 老师代码用 +0x7F8000000000 直接映射访问物理页；模型里物理内存就是
 * 这个数组，dnz_phys_ptr 直接指向数组元素（语义等价，避免解引用假地址）。 */
extern uint8_t g_dnz_phys[DNZ_PHYS_SIZE];

static inline uint8_t *dnz_phys_ptr(uint64_t phys)
{
    return g_dnz_phys + phys;
}

/* 取页表项内容（老师: *(_QWORD*)ptr） */
static inline uint64_t dnz_load_qword(const void *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static inline void dnz_store_qword(void *p, uint64_t v)
{
    memcpy(p, &v, 8);
}

/* 老师代码的 "memset64"：把 n 个 QWORD 写同一个值 */
static inline void dnz_memset64(void *dst, uint64_t v, size_t n)
{
    uint64_t *d = (uint64_t *)dst;
    for (size_t i = 0; i < n; i++) d[i] = v;
}
