#pragma once
#include "dnz_types.h"

/*
 * Hook 系（认人/安装）模块 —— 对应老师代码：
 *   01606 Hook_OnGuestCr3Change      0x1400fd390  换进程看门狗
 *   02285 Hook_SeedFromTickCount     0x140167a10  FNV-1a 播种哈希
 *   02316 Hook_InitEnv               0x14016ca70  初始化环境/注册表
 *   02411 Hook_LookupByPid           0x14017abc0  FNV-1a 查 PID（找到就摘链）
 *   02413 Hook_LogListEntry          0x14017aea0  记录钩子命中
 *   02417 Hv_ReadProcessListFromGuest 0x14017b970 遍历客人进程表
 *   02477 Hook_RegisterSoftBp        0x140185b50  登记软断点(0xCC)钩子
 *   02497 Hook_InstallAll            0x1401891d0  总装（9699 字节大函数）
 */

/* FNV-1a（老师: prime 0x100000001B3, offset 0xCBF29CE484222325） */
uint64_t dnz_fnv1a(const uint8_t *data, size_t len);

/* 01606：客人换进程（CR3 变化）时被叫 */
void hook_on_guest_cr3_change(dnz_global *g, uint64_t new_cr3);

/* 02285：用系统时间播种哈希表 */
void hook_seed_from_tickcount(dnz_global *g);

/* 02316：初始化环境（建立偏移表、注册表） */
void hook_init_env(dnz_global *g);

/* 02411：按 PID 在哈希桶里查 ListHook；命中摘链返回 */
dnz_listhook *hook_lookup_by_pid(dnz_global *g, uint32_t pid);

/* 02413：记录一条钩子命中日志（模型: 计数） */
void hook_log_list_entry(dnz_global *g, dnz_listhook *h, uint64_t guest_va);

/* 02417：从客人内存遍历进程链表，填 entry 数组（老师: a2+1080*i+16） */
uint32_t hv_read_process_list_from_guest(dnz_global *g, uint8_t *out_entries, uint32_t max);

/* 02477：登记软断点钩子（a2 常为 0xCC） */
bool hook_register_softbp(dnz_global *g, uint64_t target, uint8_t opcode);

/* 02497：总装（按老师调用链顺序） */
void hook_install_all(dnz_global *g);

/* 模型：查找/安装客人进程钩子（Hook_LookupByPid 的上游） */
dnz_listhook *hook_install_process_hook(dnz_global *g, uint32_t pid, uint64_t cr3, uint64_t eprocess);
