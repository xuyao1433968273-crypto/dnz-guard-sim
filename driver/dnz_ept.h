/*++
 * dnz_ept.h — 真实 EPT 双视图钩子模块（双根架构，叠在 SimpleVisor 骨架上）。
 *
 * 对应老师 IDA 分析：
 *   01738 HV_LookupEptEntry           0x140115220  四层 EPT 走查
 *   01739 HV_EptSplitLargePage        0x140115400  2MB 大页拆 512×4K
 *   01742 HV_EptInstallHook           0x140115980  装双视图（建主根/影子根）
 *   01743 HV_EptRemoveHook            0x140115ac0  卸双视图
 *   01758 HV_EptSwapHookOnViolation   0x140116F90  翻镜子（换面 + 计时 + 跨核同步）
 *   01757 HV_AfterEptViolation        0x140116ed0  收尾
 *
 * 双根设计（老师：家里两堵墙，保安进来把海报墙推开给他看白墙）：
 *   - 主根   MainView   ：被钩页 → 假页（FakePfn，改过版），RWX 常驻
 *   - 影子根 ShadowView ：被钩页 → 真页（CleanPfn，干净版），RWX 常驻
 *   - 触发根 FaultView  ：被钩页 → 无权限（默认 EPTP），任何访问都触发
 *     EPT violation（EXIT_REASON_EPT_VIOLATION = 48）
 *   - 翻镜子 = 切换视图：VMCS EPTP 改成主根/影子根 + INVEPT，**不动页表**
 *   - 认人（CR3）+ RIP 黑名单决定给哪张脸；开 MTF 单步执行一条指令，
 *     下个 exit（MTF）把 EPTP 切回触发根收尾
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

/* 初始化三个视图（主根/影子根/触发根）。必须在 ShvVmxEptInitialize 之后、
 * ShvVmxSetupVmcsForVp 之前调用（VMCS 默认 EPTP 要用 FaultView）。 */
VOID
DnzEptViewsInit(
    _In_ PSHV_VP_DATA VpData
    );

/* 装双视图钩子：a2 = 被钩客户机物理页（4K 对齐），
 * a3 = 假页（钩子面/主根）物理帧号，a4 = 真页（干净面/影子根）物理帧号。
 * 对应老师: HV_EptInstallHook。三个视图同步建好，翻镜子只切 EPTP。 */
NTSTATUS
DnzEptInstallHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa,
    _In_ UINT64 FakePfn,
    _In_ UINT64 CleanPfn
    );

/* 卸双视图钩子：三个视图恢复（2MB 大页 / 共享基底）（老师: HV_EptRemoveHook） */
VOID
DnzEptRemoveHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    );

/* 翻镜子（老师: HV_EptSwapHookOnViolation + ACE_NtApiHook_ExitHandler）：
 *   在 EPT violation 时调用。GuestCtx = guest 寄存器帧（PCONTEXT，a2）。
 *   流程（老师原样）：
 *     第一招认人（PID 对比）→ 不是被钩进程：切影子根（干净面）+ MTF
 *     第二招认人（RIP 偏移表）→ 命中：DnzDispatchNtApi 模拟 API，RIP 前移
 *     都没命中 → 切主根（假页）+ MTF
 *   返回 TRUE 表示已处理（切视图 + MTF，或已模拟 API）。 */
BOOLEAN
DnzEptHandleViolation(
    _In_ PSHV_VP_DATA VpData,
    _In_ PCONTEXT GuestCtx,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestRip,
    _In_ UINT64 FaultGpa
    );

/* MTF 单步后的收尾：EPTP 切回触发根，关 MTF，记计时账本
 * （老师: HV_AfterEptViolation + *(a1+24656) 计时）。 */
VOID
DnzEptFinishFlip(
    _In_ PSHV_VP_DATA VpData
    );

/* 找到被钩页（返回 EptHooks 里的槽位，找不到返回 -1） */
LONG
DnzEptFindHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    );
