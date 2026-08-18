/*++
 * dnz_ept.c — 双根 EPT 双视图钩子（视图初始化 / 装钩 / 卸钩 / 翻镜子 / MTF 收尾）。
 *
 * 对应老师 IDA 分析：
 *   HV_EptSplitLargePage        (0x140115400)  2MB 拆 512×4K
 *   HV_EptInstallHook           (0x140115980)  装双视图（主根/影子根）
 *   HV_EptSwapHookOnViolation   (0x140116F90)  翻镜子 = 切视图（改 EPTP）
 *   HV_AfterEptViolation        (0x140116ed0)  收尾（切回触发根）
 *
 * 双根原理（老师：两堵墙，保安进来推开海报墙给他看白墙）：
 *   主根/影子根两张完整地图，被钩页分别指向假页/真页（RWX 常驻）；
 *   默认 EPTP 是触发根（被钩页无权限），任何访问先触发 violation，
 *   认人（CR3 + RIP 黑名单）后把 EPTP 切到对应视图 + MTF 单步，
 *   一条指令执行完，下个 exit 把 EPTP 切回触发根。全程不改页表。
 *
 * 运行环境：装/卸钩在 DISPATCH_LEVEL（KeGenericCallDpc 广播到每核）；
 *           翻镜子在 VM-exit handler（MAX_IRQL，只用原子 + __rdtsc）。
 * --*/

#include <ntddk.h>
#include "dnz_ept.h"
#include "dnz_hook.h"

#ifndef STATUS_ALREADY_EXISTS
#define STATUS_ALREADY_EXISTS ((NTSTATUS)0xC0000035L)
#endif

extern PSHV_VP_DATA* ShvGlobalData;
extern VOID AsmInvEpt(UINT64 Type, UINT64* EptpDescriptor); /* shvosx64.asm */

#define EPT_IDX_PML4(gpa)  (((gpa) >> 39) & 0x1FF)
#define EPT_IDX_PDPT(gpa)  (((gpa) >> 30) & 0x1FF)
#define EPT_IDX_PD(gpa)    (((gpa) >> 21) & 0x1FF)
#define EPT_IDX_PT(gpa)    (((gpa) >> 12) & 0x1FF)

#define DNZ_MAX_HOOKS 8
#define DNZ_EPT_WALK_LENGTH 3

/* INVEPT 描述符（16 字节：EPTP + 保留，必须整块传） */
typedef struct _DNZ_INVEPT_DESC
{
    UINT64 Eptp;
    UINT64 Reserved;
} DNZ_INVEPT_DESC;

/* 单上下文失效：翻镜子切视图后，刷掉目标视图的 TLB 缓存 */
static
VOID
DnzInvEptSingle(
    _In_ UINT64 Eptp
    )
{
    DNZ_INVEPT_DESC desc;
    desc.Eptp = Eptp;
    desc.Reserved = 0;
    AsmInvEpt(0, (UINT64*)&desc);
}

/* 全局失效：装/卸钩改页表后，刷所有视图 */
static
VOID
DnzInvEptGlobal(
    VOID
    )
{
    DNZ_INVEPT_DESC desc;
    desc.Eptp = 0;
    desc.Reserved = 0;
    AsmInvEpt(1, (UINT64*)&desc);
}

/* ================= 三视图初始化（老师: HV_EptInstallHook 的主根/影子根） ================= */

VOID
DnzEptViewsInit(
    _In_ PSHV_VP_DATA VpData
    )
{
    PDNZ_EPT_VIEW views[3];
    UINT32 i, v;
    UINT64 pfn;

    views[0] = &VpData->MainView;
    views[1] = &VpData->ShadowView;
    views[2] = &VpData->FaultView;

    for (v = 0; v < 3; v++)
    {
        PDNZ_EPT_VIEW view = views[v];

        RtlZeroMemory(view->Pml4, sizeof(view->Pml4));
        RtlZeroMemory(view->Pdpt, sizeof(view->Pdpt));
        RtlZeroMemory(view->Pde, sizeof(view->Pde));
        RtlZeroMemory(view->Pt, sizeof(view->Pt));
        for (i = 0; i < DNZ_MAX_HOOKS; i++)
        {
            view->CloneRegion[i] = -1;
            view->PtKey[i] = -1;
        }

        // PML4[0] -> 本视图的 PDPT
        pfn = (UINT64)MmGetPhysicalAddress(view->Pdpt).QuadPart >> 12;
        view->Pml4[0].Read = 1;
        view->Pml4[0].Write = 1;
        view->Pml4[0].Execute = 1;
        view->Pml4[0].PageFrameNumber = pfn;

        // PDPT[i] -> 共享基底 Epde[i]（SimpleVisor 的 2MB 恒等映射，永不被改）
        for (i = 0; i < PDPTE_ENTRY_COUNT; i++)
        {
            pfn = (UINT64)MmGetPhysicalAddress(&VpData->Epde[i][0]).QuadPart >> 12;
            view->Pdpt[i].Read = 1;
            view->Pdpt[i].Write = 1;
            view->Pdpt[i].Execute = 1;
            view->Pdpt[i].PageFrameNumber = pfn;
        }

        // EPTP：walk length = 3（4 层），内存类型 = WB
        pfn = (UINT64)MmGetPhysicalAddress(view->Pml4).QuadPart >> 12;
        view->EptpValue = (pfn << 12) | (DNZ_EPT_WALK_LENGTH << 3) | MTRR_TYPE_WB;
    }
}

/* ================= 装钩（老师: HV_EptInstallHook） ================= */

/* 找同 1GB 区域已有的克隆槽（三个视图同槽），没有返回 -1 */
static
LONG
DnzFindCloneForRegion(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT32 Region
    )
{
    ULONG k;
    for (k = 0; k < VpData->EptHookCount; k++)
    {
        if (VpData->EptHooks[k].Installed &&
            EPT_IDX_PDPT(VpData->EptHooks[k].Gpa) == Region)
        {
            return VpData->EptHooks[k].CloneIdx;
        }
    }
    return -1;
}

/* 找同 2MB 页已有的拆页 PT 槽（三个视图同槽），没有返回 -1 */
static
LONG
DnzFindPtForPage(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT32 Region,
    _In_ UINT32 Pd
    )
{
    ULONG k;
    for (k = 0; k < VpData->EptHookCount; k++)
    {
        if (VpData->EptHooks[k].Installed &&
            EPT_IDX_PDPT(VpData->EptHooks[k].Gpa) == Region &&
            EPT_IDX_PD(VpData->EptHooks[k].Gpa) == Pd)
        {
            return VpData->EptHooks[k].PtIdx;
        }
    }
    return -1;
}

/* 分配区域克隆槽：三个视图同槽（都空闲才可用） */
static
LONG
DnzAllocCloneSlot(
    _In_ PSHV_VP_DATA VpData,
    _In_ LONG Region
    )
{
    LONG s;
    for (s = 0; s < DNZ_MAX_HOOKS; s++)
    {
        if (VpData->MainView.CloneRegion[s] == -1 &&
            VpData->ShadowView.CloneRegion[s] == -1 &&
            VpData->FaultView.CloneRegion[s] == -1)
        {
            VpData->MainView.CloneRegion[s] = Region;
            VpData->ShadowView.CloneRegion[s] = Region;
            VpData->FaultView.CloneRegion[s] = Region;
            return s;
        }
    }
    return -1;
}

/* 分配拆页 PT 槽：三个视图同槽 */
static
LONG
DnzAllocPtSlot(
    _In_ PSHV_VP_DATA VpData,
    _In_ LONG Key
    )
{
    LONG s;
    for (s = 0; s < DNZ_MAX_HOOKS; s++)
    {
        if (VpData->MainView.PtKey[s] == -1 &&
            VpData->ShadowView.PtKey[s] == -1 &&
            VpData->FaultView.PtKey[s] == -1)
        {
            VpData->MainView.PtKey[s] = Key;
            VpData->ShadowView.PtKey[s] = Key;
            VpData->FaultView.PtKey[s] = Key;
            return s;
        }
    }
    return -1;
}

LONG
DnzEptFindHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    )
{
    ULONG h;
    for (h = 0; h < VpData->EptHookCount; h++)
    {
        if (VpData->EptHooks[h].Installed &&
            VpData->EptHooks[h].Gpa == (Gpa & ~0xFFFULL))
        {
            return (LONG)h;
        }
    }
    return -1;
}

NTSTATUS
DnzEptInstallHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa,
    _In_ UINT64 FakePfn,
    _In_ UINT64 CleanPfn
    )
{
    UINT32 region, pd, ptEntry;
    LONG slot, cloneIdx, ptIdx;
    BOOLEAN cloneNew, ptNew;
    UINT64 basePfn2m;
    UINT32 n, v;
    PDNZ_EPT_VIEW views[3];

    Gpa &= ~0xFFFULL;

    if (DnzEptFindHook(VpData, Gpa) >= 0)
    {
        return STATUS_ALREADY_EXISTS;
    }
    if (VpData->EptHookCount >= DNZ_MAX_HOOKS)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    region  = EPT_IDX_PDPT(Gpa);
    pd      = EPT_IDX_PD(Gpa);
    ptEntry = EPT_IDX_PT(Gpa);

    //
    // 复用同区域克隆 / 同 2MB 页 PT；没有就在三个视图里同槽分配
    //
    cloneIdx = DnzFindCloneForRegion(VpData, region);
    cloneNew = FALSE;
    if (cloneIdx < 0)
    {
        cloneIdx = DnzAllocCloneSlot(VpData, (LONG)region);
        if (cloneIdx < 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        cloneNew = TRUE;
    }

    ptIdx = DnzFindPtForPage(VpData, region, pd);
    ptNew = FALSE;
    if (ptIdx < 0)
    {
        ptIdx = DnzAllocPtSlot(VpData, (LONG)((region << 9) | pd));
        if (ptIdx < 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ptNew = TRUE;
    }

    views[0] = &VpData->MainView;
    views[1] = &VpData->ShadowView;
    views[2] = &VpData->FaultView;

    if (cloneNew)
    {
        //
        // 新克隆：从共享基底 Epde[region] 拷一份（仍是 2MB 大页），
        // 视图 Pdpt[region] 改指向自己的克隆——这就是"第二套地图"的分叉点
        //
        for (v = 0; v < 3; v++)
        {
            PDNZ_EPT_VIEW view = views[v];
            RtlCopyMemory(view->Pde[cloneIdx], VpData->Epde[region],
                          sizeof(view->Pde[cloneIdx]));
            view->Pdpt[region].AsUlonglong = 0;
            view->Pdpt[region].Read = 1;
            view->Pdpt[region].Write = 1;
            view->Pdpt[region].Execute = 1;
            view->Pdpt[region].PageFrameNumber =
                (UINT64)MmGetPhysicalAddress(&view->Pde[cloneIdx][0]).QuadPart >> 12;
        }
    }

    if (ptNew)
    {
        //
        // 新 PT：把该 2MB 页拆成 512×4K（真实页），克隆里 PDE 指向这张 PT
        // （老师: HV_EptSplitLargePage）
        //
        basePfn2m = VpData->Epde[region][pd].PageFrameNumber;   /* 共享基底 2MB PFN */
        for (v = 0; v < 3; v++)
        {
            PDNZ_EPT_VIEW view = views[v];
            RtlZeroMemory(view->Pt[ptIdx], PAGE_SIZE);
            for (n = 0; n < PTE_ENTRY_COUNT; n++)
            {
                view->Pt[ptIdx][n].Read = 1;
                view->Pt[ptIdx][n].Write = 1;
                view->Pt[ptIdx][n].Execute = 1;
                view->Pt[ptIdx][n].PageFrameNumber = basePfn2m * 512 + n;
            }
            view->Pde[cloneIdx][pd].AsUlonglong = 0;
            view->Pde[cloneIdx][pd].Read = 1;
            view->Pde[cloneIdx][pd].Write = 1;
            view->Pde[cloneIdx][pd].Execute = 1;
            view->Pde[cloneIdx][pd].PageFrameNumber =
                (UINT64)MmGetPhysicalAddress(&view->Pt[ptIdx][0]).QuadPart >> 12;
        }
    }

    //
    // 按视图角色设置被钩 4K 项——三张图就此不同：
    //   主根    -> 假页（FakePfn，住户看"改过版"）
    //   影子根  -> 真页（CleanPfn，保安看"干净版"）
    //   触发根  -> 无权限（默认 EPTP，任何访问触发 violation）
    //
    VpData->MainView.Pt[ptIdx][ptEntry].AsUlonglong = 0;
    VpData->MainView.Pt[ptIdx][ptEntry].Read = 1;
    VpData->MainView.Pt[ptIdx][ptEntry].Write = 1;
    VpData->MainView.Pt[ptIdx][ptEntry].Execute = 1;
    VpData->MainView.Pt[ptIdx][ptEntry].PageFrameNumber = FakePfn;

    VpData->ShadowView.Pt[ptIdx][ptEntry].AsUlonglong = 0;
    VpData->ShadowView.Pt[ptIdx][ptEntry].Read = 1;
    VpData->ShadowView.Pt[ptIdx][ptEntry].Write = 1;
    VpData->ShadowView.Pt[ptIdx][ptEntry].Execute = 1;
    VpData->ShadowView.Pt[ptIdx][ptEntry].PageFrameNumber = CleanPfn;

    VpData->FaultView.Pt[ptIdx][ptEntry].AsUlonglong = DNZ_EPT_NO_ACCESS;

    //
    // 记录钩子状态
    //
    slot = (LONG)VpData->EptHookCount;
    VpData->EptHooks[slot].Gpa = Gpa;
    VpData->EptHooks[slot].CleanPfn = CleanPfn;
    VpData->EptHooks[slot].FakePfn = FakePfn;
    VpData->EptHooks[slot].CloneIdx = cloneIdx;
    VpData->EptHooks[slot].PtIdx = ptIdx;
    VpData->EptHooks[slot].PteIndex = ptEntry;
    VpData->EptHooks[slot].Installed = TRUE;
    VpData->EptHooks[slot].InFlip = FALSE;
    VpData->EptHookCount++;

    //
    // 三张图都变了，全局刷 EPT TLB
    //
    DnzInvEptGlobal();
    return STATUS_SUCCESS;
}

/* ================= 卸钩（老师: HV_EptRemoveHook） ================= */

VOID
DnzEptRemoveHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    )
{
    LONG slot = DnzEptFindHook(VpData, Gpa);
    UINT32 region, pd;
    LONG cloneIdx, ptIdx;
    BOOLEAN pageHasOther, regionHasOther;
    ULONG k, v;
    PDNZ_EPT_VIEW views[3];

    if (slot < 0)
    {
        return;
    }

    region  = EPT_IDX_PDPT(Gpa);
    pd      = EPT_IDX_PD(Gpa);
    cloneIdx = VpData->EptHooks[slot].CloneIdx;
    ptIdx    = VpData->EptHooks[slot].PtIdx;

    //
    // 摘掉记录（最后一个挪过来填空位）
    //
    VpData->EptHooks[slot].Installed = FALSE;
    VpData->EptHookCount--;
    if ((ULONG)slot < VpData->EptHookCount)
    {
        VpData->EptHooks[slot] = VpData->EptHooks[VpData->EptHookCount];
    }

    //
    // 还有别的钩子占着这个 2MB 页 / 1GB 区域吗？
    //
    pageHasOther = FALSE;
    regionHasOther = FALSE;
    for (k = 0; k < VpData->EptHookCount; k++)
    {
        if (VpData->EptHooks[k].Installed)
        {
            if (EPT_IDX_PDPT(VpData->EptHooks[k].Gpa) == region)
            {
                regionHasOther = TRUE;
            }
            if (EPT_IDX_PDPT(VpData->EptHooks[k].Gpa) == region &&
                EPT_IDX_PD(VpData->EptHooks[k].Gpa) == pd)
            {
                pageHasOther = TRUE;
            }
        }
    }

    views[0] = &VpData->MainView;
    views[1] = &VpData->ShadowView;
    views[2] = &VpData->FaultView;

    if (!pageHasOther)
    {
        //
        // 这个 2MB 页没钩子了：克隆里 PDE 恢复成 2MB 大页（从共享基底取），
        // 释放 PT 槽
        //
        for (v = 0; v < 3; v++)
        {
            PDNZ_EPT_VIEW view = views[v];
            view->Pde[cloneIdx][pd].AsUlonglong = VpData->Epde[region][pd].AsUlonglong;
            view->PtKey[ptIdx] = -1;
            RtlZeroMemory(view->Pt[ptIdx], PAGE_SIZE);
        }
    }

    if (!regionHasOther)
    {
        //
        // 这个区域没钩子了：视图 Pdpt[region] 恢复指向共享基底，释放克隆槽
        //
        for (v = 0; v < 3; v++)
        {
            PDNZ_EPT_VIEW view = views[v];
            view->Pdpt[region].AsUlonglong = 0;
            view->Pdpt[region].Read = 1;
            view->Pdpt[region].Write = 1;
            view->Pdpt[region].Execute = 1;
            view->Pdpt[region].PageFrameNumber =
                (UINT64)MmGetPhysicalAddress(&VpData->Epde[region][0]).QuadPart >> 12;
            view->CloneRegion[cloneIdx] = -1;
            RtlZeroMemory(view->Pde[cloneIdx], sizeof(view->Pde[cloneIdx]));
        }
    }

    DnzInvEptGlobal();
}

/* ================= 翻镜子（老师: HV_EptSwapHookOnViolation） =================
 *
 * EPT violation 到来时（默认 EPTP = 触发根，被钩页无权限）：
 *   1. 找钩子槽位
 *   2. 认人（CR3）：住户 -> 主根（假页）；其他人 -> 影子根（真页）
 *   3. 切视图：VMCS EPTP 改成目标根 + INVEPT（**不动页表**）
 *   4. 开 MTF（Monitor Trap Flag）：VM-entry 后执行一条指令就再 VM-exit
 *   5. 下个 exit（MTF）由 DnzEptFinishFlip 收尾：EPTP 切回触发根 + 关 MTF
 */

BOOLEAN
DnzEptHandleViolation(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestRip,
    _In_ UINT64 FaultGpa
    )
{
    LONG slot;
    INT who;
    BOOLEAN ripHit, flipToClean;
    PDNZ_EPT_VIEW view;
    UINT64 tscBefore, tscAfter;
    LARGE_INTEGER msr;

    slot = DnzEptFindHook(VpData, FaultGpa);
    if (slot < 0)
    {
        return FALSE;   /* 不是我们的钩子页，正常放行 */
    }

    //
    // 认人两招（老师: Hook_NtApi_VmExitHandler）：
    //   第一招：查 PID（CR3）——不是被钩进程就 return 0
    //   第二招：拿 guest RIP 对黑名单——命中才"干活"（翻到钩子面/模拟 API）
    // 只有"住户 + RIP 命中黑名单"才看假页；其他一切情况看真页（干净面）。
    //
    who = DnzRecognizeAccessor(GuestCr3);
    if (who == 0)
    {
        flipToClean = TRUE;     /* 不是被钩进程 -> 影子根（真页） */
    }
    else
    {
        ripHit = DnzRipInBlacklist(GuestRip);
        flipToClean = ripHit ? FALSE : TRUE;
    }

    //
    // 跨核同步：抢翻镜子权（TSC 限时等待，老师: 8×预算周期）
    //
    tscBefore = __rdtsc();
    if (!DnzSyncFlipBegin(KeGetCurrentProcessorNumberEx(NULL), 8 * 4096))
    {
        return FALSE;   /* 超时放弃（不该发生，教学骨架） */
    }

    //
    // 翻镜子 = 切视图：VMCS EPTP 指向主根（假页）或影子根（真页）
    // 页表一个字都不改——这就是"双根"和"单根换项"的本质区别
    //
    view = flipToClean ? &VpData->ShadowView : &VpData->MainView;
    __vmx_vmwrite(EPT_POINTER, view->EptpValue);
    DnzInvEptSingle(view->EptpValue);

    VpData->EptHooks[slot].FlipState = flipToClean ? TRUE : FALSE;
    VpData->EptHooks[slot].InFlip = TRUE;
    VpData->EptHooks[slot].FlipToClean = flipToClean;

    //
    // 开 MTF：SECONDARY_VM_EXEC_CONTROL bit 27（MONITOR_TRAP_FLAG）
    // VM-entry 后执行一条指令 -> VM-exit（reason 37），我们在那里收尾。
    //
    msr.QuadPart = 0;
    __vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (SIZE_T*)&msr.QuadPart);
    msr.QuadPart |= 0x08000000ULL;   /* SECONDARY_EXEC_MONITOR_TRAP_FLAG */
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, msr.QuadPart);
    VpData->MtfActive = 1;

    //
    // 计时账本（老师: *(a1+24656) = 预期 - 实际）
    //
    tscAfter = __rdtsc();
    VpData->SwapExpectedTsc = 4096;   /* 预算：4096 ticks */
    VpData->LastSwapTsc = VpData->SwapExpectedTsc - (tscAfter - tscBefore);
    DnzSyncRecordSwap(VpData->SwapExpectedTsc, tscAfter - tscBefore);

    //
    // 收尾由下个 exit（MTF）做
    //
    return TRUE;
}

VOID
DnzEptFinishFlip(
    _In_ PSHV_VP_DATA VpData
    )
{
    LARGE_INTEGER msr;
    ULONG h;

    //
    // 关 MTF
    //
    msr.QuadPart = 0;
    __vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (SIZE_T*)&msr.QuadPart);
    msr.QuadPart &= ~0x08000000ULL;
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, msr.QuadPart);
    VpData->MtfActive = 0;

    //
    // 切回触发根（默认），刷 TLB——下个访问再次触发 violation，重新认人
    //
    __vmx_vmwrite(EPT_POINTER, VpData->FaultView.EptpValue);
    DnzInvEptSingle(VpData->FaultView.EptpValue);

    //
    // 清翻镜子标记——双根的好处：没有页表要恢复，视图是预置好的
    //
    for (h = 0; h < VpData->EptHookCount; h++)
    {
        VpData->EptHooks[h].InFlip = FALSE;
    }

    //
    // 翻完，释放跨核同步锁
    //
    DnzSyncFlipEnd();
}
