#include "dnz_hooks.h"
#include "dnz_dispatch.h"
#include <string.h>

/* 老师: FNV-1a 常量 */
#define FNV_PRIME  0x100000001B3ULL
#define FNV_OFFSET 0xCBF29CE484222325ULL

uint64_t dnz_fnv1a(const uint8_t *data, size_t len)
{
    uint64_t h = FNV_OFFSET;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= FNV_PRIME;
    }
    return h;
}

/* 模型: 全局钩子锁（老师: qword_14D292998 / 0x14C292908 / qword_14DB95CB0 等） */
static volatile int64_t g_hook_lock;

/*
 * ============================================================
 * 01606. Hook_OnGuestCr3Change (0x1400fd390)
 * ------------------------------------------------------------
 * 老师：换进程看门狗。加锁 → v2 = a2 & 0xFFFFFFFFFF000（CR3 基址）
 *       → 查表（sub_1400FF350）→ 解锁 → 分派（sub_1400FD450）
 * 模型：CR3 变 → 若匹配目标进程则记下 GuestCr3OrCtx，否则清掉。
 * ============================================================
 */
void hook_on_guest_cr3_change(dnz_global *g, uint64_t new_cr3)
{
    while (dnz_cas(&g_hook_lock, 0, 1) == 1) { /* 自旋 */ }
    uint64_t cr3_base = new_cr3 & 0xFFFFFFFFFF000ULL;   /* 老师: v2 */

    if (cr3_base != 0 && cr3_base == (g->guest_cr3 & 0xFFFFFFFFFF000ULL)) {
        g->guest_cr3 = cr3_base;   /* 老师: 记录到 g_Hook_GuestCr3OrCtx */
    } else if (cr3_base != 0) {
        /* 不是目标进程：老师 return 0 不干活 */
    }
    dnz_cas(&g_hook_lock, 1, 0);
}

/*
 * ============================================================
 * 02285. Hook_SeedFromTickCount (0x140167a10)
 * ------------------------------------------------------------
 * 老师：拿系统配置/时间字节做 FNV-1a 长链哈希（逐字节 0x100000001B3 展开）。
 * 模型：对配置字符串做 FNV-1a，结果写进哈希表偏移（hide_hash）。
 * ============================================================
 */
void hook_seed_from_tickcount(dnz_global *g)
{
    /* 老师: g_Sys_ConfigFlags + 16 起逐字节哈希 */
    const uint8_t cfg[16] = { 0x44, 0x4E, 0x5A, 0x48, 0x56, 0x50, 0x52, 0x4F,
                              0x42, 0x45, 0x53, 0x45, 0x32, 0x30, 0x32, 0x36 };
    uint64_t h = dnz_fnv1a(cfg, sizeof(cfg));
    /* 老师: 把种子写进藏页哈希（模型） */
    for (int i = 0; i < 2048; i++) g->hide_hash[i] = 0x100 + (i * 3) + (uint32_t)(h & 0xFF);
}

/*
 * ============================================================
 * 02316. Hook_InitEnv (0x14016ca70)
 * ------------------------------------------------------------
 * 老师：加锁 → 数字转字符串 → 注册进全局表（sub_14011BDD0）
 *       → 解锁。初始化 hook 运行环境。
 * 模型：建偏移表（g_Hook_OffsetTable）、设目标进程。
 * ============================================================
 */
void hook_init_env(dnz_global *g)
{
    while (dnz_cas(&g_hook_lock, 0, 1) == 1) { }
    /* 老师: 偏移表 g_Hook_OffsetTable（+252 等偏移由 Hook_LogListEntry 用） */
    for (int i = 0; i < 64; i++) g->hook_offset_table[i] = 0x20 + (uint64_t)i * 8;
    g->guest_pid = 0;
    dnz_cas(&g_hook_lock, 1, 0);
}

/*
 * ============================================================
 * 02411. Hook_LookupByPid (0x14017abc0)
 * ------------------------------------------------------------
 * 老师注释：FNV-1a hash lookup of ListHook by PID; remove node if found
 * 流程：加锁 → FNV-1a(PID) → 桶 → 遍历找匹配 → 摘链 → 解锁
 * ============================================================
 */
dnz_listhook *hook_lookup_by_pid(dnz_global *g, uint32_t pid)
{
    while (dnz_cas(&g_hook_lock, 0, 1) == 1) { }

    uint8_t p[4] = { (uint8_t)pid, (uint8_t)(pid >> 8), (uint8_t)(pid >> 16), (uint8_t)(pid >> 24) };
    uint64_t h = dnz_fnv1a(p, 4);
    unsigned bucket = (unsigned)(h & 0xFF);

    dnz_listhook *prev = NULL, *cur = g->list_buckets[bucket];
    while (cur) {
        if (cur->pid == pid) break;
        prev = cur;
        cur = cur->next;
    }
    if (cur) {                       /* 老师: 命中就摘链 */
        if (prev) prev->next = cur->next;
        else      g->list_buckets[bucket] = cur->next;
        cur->next = NULL;
    }
    dnz_cas(&g_hook_lock, 1, 0);
    return cur;
}

/*
 * ============================================================
 * 02413. Hook_LogListEntry (0x14017aea0)
 * ------------------------------------------------------------
 * 老师：加锁 → 计数器 +1 → 条件满足时 Hv_ReadGuestU32/U64 读客人
 *       内存记录（+40 处 PID、偏移表+252 处等）。
 * 模型：命中计数 +1，读客人 PID。
 * ============================================================
 */
void hook_log_list_entry(dnz_global *g, dnz_listhook *h, uint64_t guest_va)
{
    while (dnz_cas(&g_hook_lock, 0, 1) == 1) { }
    (void)guest_va;
    if (h) {
        /* 老师: Hv_ReadGuestU32(g_Hook_GuestCr3OrCtx, v5+40) —— 读进程 PID */
        h->pid = h->pid; /* 模型里已填好 */
    }
    dnz_cas(&g_hook_lock, 1, 0);
}

/*
 * ============================================================
 * 02417. Hv_ReadProcessListFromGuest (0x14017b970)
 * ------------------------------------------------------------
 * 老师：从客人进程链表头开始，沿 ActiveProcessLinks 走：
 *   +40 = PID，+24/+16 = 链表/名字，每条 1080 字节填进输出数组。
 * 模型：客人内存里预置 2 条进程记录，逐个填出。
 * ============================================================
 */
uint32_t hv_read_process_list_from_guest(dnz_global *g, uint8_t *out_entries, uint32_t max)
{
    uint32_t n = 0;
    /* 模型：客人内存低地址预置的 EPROCESS 模拟（见 dnz_main 初始化） */
    uint64_t head = g->guest_mem[0];                 /* 链表头 */
    uint64_t cur = head;
    for (uint32_t i = 0; i < 64 && cur; i++) {
        uint64_t pid = g->guest_mem[cur / 8];        /* 老师: 读客人 +40 */
        if (pid == 0) break;
        if (n < max) {
            /* 老师: sub_14017B160(v16, a2 + 1080*idx + 16) */
            memcpy(out_entries + 1080ULL * n + 16, &pid, 8);
            n++;
        }
        cur = g->guest_mem[(cur / 8) + 1];           /* 下一链接 */
    }
    return n;
}

/*
 * ============================================================
 * 02477. Hook_RegisterSoftBp (0x140185b50)
 * ------------------------------------------------------------
 * 老师注释：Register soft-BP style hook entry (a2 often 0xCC) into ACE hook table
 * 流程：加锁 → 查重（0xCCCCCCCCCCCCCCCD*((xmmword-qword)>>3) 表长）→
 *       追加登记 → 解锁。
 * ============================================================
 */
bool hook_register_softbp(dnz_global *g, uint64_t target, uint8_t opcode)
{
    while (dnz_cas(&g_hook_lock, 0, 1) == 1) { }

    for (uint32_t i = 0; i < g->softbp_count; i++) {   /* 老师: 查重 */
        if (g->softbps[i].target == target) {
            dnz_cas(&g_hook_lock, 1, 0);
            return false;
        }
    }
    if (g->softbp_count >= 64) {
        dnz_cas(&g_hook_lock, 1, 0);
        return false;
    }
    dnz_softbp_entry *e = &g->softbps[g->softbp_count++];
    e->target = target;
    e->fake   = 0;                    /* 老师: 由后续 patch 填 */
    e->opcode = opcode;
    e->active = 1;
    e->pid_filter = (uint32_t)g->guest_pid;
    dnz_cas(&g_hook_lock, 1, 0);
    return true;
}

/* 模型: 安装进程钩子（Hook_LookupByPid 的上游，也往桶里放） */
dnz_listhook *hook_install_process_hook(dnz_global *g, uint32_t pid, uint64_t cr3, uint64_t eprocess)
{
    static dnz_listhook nodes[16];
    static uint32_t node_idx = 0;
    if (node_idx >= 16) return NULL;

    dnz_listhook *n = &nodes[node_idx++];
    n->pid = pid;
    n->cr3 = cr3 & 0xFFFFFFFFFF000ULL;
    n->eprocess = eprocess;
    memcpy(n->name, "dnz_target", 11);

    uint8_t p[4] = { (uint8_t)pid, (uint8_t)(pid >> 8), (uint8_t)(pid >> 16), (uint8_t)(pid >> 24) };
    unsigned bucket = (unsigned)(dnz_fnv1a(p, 4) & 0xFF);
    n->next = g->list_buckets[bucket];
    g->list_buckets[bucket] = n;

    if (!g->guest_pid) {
        g->guest_pid = pid;
        g->guest_cr3 = n->cr3;
    }
    return n;
}

/*
 * ============================================================
 * 02497. Hook_InstallAll (0x1401891d0) —— 9699 字节总装
 * ------------------------------------------------------------
 * 老师调用链（分析原文节选）：
 *   Hook_InitEnv → Hook_SeedFromTickCount → Hook_OnGuestCr3Change(注册) →
 *   HV_RegisterExitHandler → Hook_RegisterSoftBp(多组) →
 *   Hook_InstallNtApi_Set1/Set2 → Esp_ApplyGuestProloguePatch → ...
 * 模型：按顺序把命名函数全走一遍（软断点用 0xCC）。
 * ============================================================
 */
void hook_install_all(dnz_global *g)
{
    hook_init_env(g);
    hook_seed_from_tickcount(g);

    /* 老师: 注册退出处理（HV_RegisterExitHandler） */
    /* 门口登记表由 dnz_main 统一注册，这里补软断点路径 */

    /* 老师: Hook_RegisterSoftBp 一组（0xCC 软断点，目标=客人内存区） */
    hook_register_softbp(g, 0x1000, 0xCC);
    hook_register_softbp(g, 0x2000, 0xCC);
    hook_register_softbp(g, 0x3000, 0xCC);

    /* 老师: 安装进程钩子（等游戏出现时由 CR3 看门狗认领） */
    hook_install_process_hook(g, 4242, 0x7000, 0x5000);
}
