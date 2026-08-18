/*++
 * dnz_ept.h — 真实 EPT 双视图钩子模块（叠在 SimpleVisor 骨架上）。
 *
 * 对应老师 IDA 分析：
 *   01738 HV_LookupEptEntry           0x140115220  四层 EPT 走查
 *   01739 HV_EptSplitLargePage        0x140115400  2MB 大页拆 512×4K
 *   01742 HV_EptInstallHook           0x140115980  装双视图
 *   01743 HV_EptRemoveHook            0x140115ac0  卸双视图
 *   01758 HV_EptSwapHookOnViolation   0x140116F90  翻镜子（换面 + 计时 + 跨核同步）
 *   01757 HV_AfterEptViolation        0x140116ed0  收尾
 *
 * 设计（教学骨架）：
 *   - 每核 EPT 用 SimpleVisor 的恒等映射（2MB 大页）打底
 *   - 装钩时把目标页所在 2MB 大页拆成 512 个 4K 页（EptPt 表）
 *   - 目标 4K 页平时 EPT 项 = 无权限（Read/Write/Execute 全 0）→ 任何访问都触发
 *     EPT violation（EXIT_REASON_EPT_VIOLATION = 48）
 *   - violation 处理（翻镜子）：
 *       认人（DnzRecognizeAccessor 按 CR3）→ 决定给哪张脸
 *       住户（被钩进程）→ 临时改成指向假页（钩子面，放"改过"的内容）
 *       其他人（保安/无关）→ 临时改成指向真页（干净面）
 *       然后开 MTF 单步（执行一条指令后立刻再 VM-exit）→ 下个 exit 恢复原状
 *   - 翻镜子带计时账本 + 跨核同步（TSC 限时等待）
 * --*/

#pragma once
#include <ntddk.h>
#include "shv_x.h"

/* EPT violation 退出限定字：bit0-47 = faulting GPA */
#define DNZ_EPT_VIOLATION_GPA_MASK  0x0000FFFFFFFFF000ULL

/* EPT 页权限组合 */
#define DNZ_EPT_NO_ACCESS   0ULL                /* 全部无权限 -> 触发 violation */
#define DNZ_EPT_RWX         (1ULL | 2ULL | 4ULL) /* R|W|X */

/* 拆页：把目标 2MB 大页拆成 512 个 4K 页（老师: HV_EptSplitLargePage）
 * 返回拆页用的 PT 表索引，失败返回 -1。 */
LONG
DnzEptSplitLargePage(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa,
    _Out_ PUINT32 PtIndex,
    _Out_ PUINT32 PteIndex
    );

/* 装双视图钩子：a2 = 被钩客户机物理页（4K 对齐），
 * a3 = 假页（钩子视图）物理帧号，a4 = 真页（干净视图）物理帧号。
 * 对应老师: HV_EptInstallHook。 */
NTSTATUS
DnzEptInstallHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa,
    _In_ UINT64 FakePfn,
    _In_ UINT64 CleanPfn
    );

/* 卸双视图钩子：恢复原 2MB 大页（老师: HV_EptRemoveHook） */
VOID
DnzEptRemoveHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    );

/* 翻镜子（老师: HV_EptSwapHookOnViolation）：
 *   在 EPT violation 时调用。guest_cr3 = 访问者 CR3。
 *   返回 TRUE 表示已换面并开了 MTF（下个 exit 由 DnzEptFinishFlip 收尾）。 */
BOOLEAN
DnzEptHandleViolation(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 FaultGpa
    );

/* MTF 单步后的收尾：恢复 EPT 项为无权限，关 MTF，记计时账本
 * （老师: HV_AfterEptViolation + *(a1+24656) 计时）。 */
VOID
DnzEptFinishFlip(
    _In_ PSHV_VP_DATA VpData
    );

/* EPT 走查（老师: HV_LookupEptEntry）：返回 4K 页的 PTE 指针（在 EptPt 表里），
 * 找不到返回 NULL。 */
PVMX_PTE
DnzEptLookup4k(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    );

/* 找到被钩页（返回 EptHooks 里的槽位，找不到返回 -1） */
LONG
DnzEptFindHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    );
