/*++
 * dnz_ept.c — 真实 EPT 双视图钩子（拆页 / 装钩 / 翻镜子 / MTF 单步收尾）。
 *
 * 对应老师 IDA 分析：
 *   HV_EptSplitLargePage        (0x140115400)  2MB 拆 512×4K
 *   HV_EptInstallHook           (0x140115980)  装双视图
 *   HV_EptSwapHookOnViolation   (0x140116F90)  翻镜子
 *   HV_AfterEptViolation        (0x140116ed0)  收尾
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
extern VOID AsmInvEpt(UINT64 Type, UINT64* EptpValue); /* shvosx64.asm */

#define EPT_IDX_PML4(gpa)  (((gpa) >> 39) & 0x1FF)
#define EPT_IDX_PDPT(gpa)  (((gpa) >> 30) & 0x1FF)
#define EPT_IDX_PD(gpa)    (((gpa) >> 21) & 0x1FF)
#define EPT_IDX_PT(gpa)    (((gpa) >> 12) & 0x1FF)

/* 取当前核的 VP 数据 */
static
PSHV_VP_DATA
DnzGetCurrentVp(
    VOID
    )
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    return ShvGlobalData[cpu];
}

/* ================= 拆页（老师: HV_EptSplitLargePage） ================= */

LONG
DnzEptSplitLargePage(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa,
    _Out_ PUINT32 PtIndex,
    _Out_ PUINT32 PteIndex
    )
{
    UINT32 pdptIdx, pdIdx, ptIdx, i;
    UINT64 pdePhys;
    VMX_LARGE_PDE pde;
    PVOID ptTable;
    PVMX_PTE pt;
    UINT64 pfnBase;

    pdptIdx = EPT_IDX_PDPT(Gpa);
    pdIdx   = EPT_IDX_PD(Gpa);
    ptIdx   = EPT_IDX_PT(Gpa);

    //
    // 先确认这是 2MB 大页（SimpleVisor 的恒等映射全是大页）
    //
    pde.AsUlonglong = VpData->Epde[pdptIdx][pdIdx].AsUlonglong;
    if (pde.Large == 0)
    {
        //
        // 已经是 4K 页表了（可能之前拆过）——只给出索引
        //
        *PtIndex = 0;
        *PteIndex = ptIdx;
        return 0;
    }

    //
    // 找一张空闲的 EptPt 表
    //
    for (i = 0; i < 8; i++)
    {
        BOOLEAN used = FALSE;
        ULONG h;
        for (h = 0; h < VpData->EptHookCount; h++)
        {
            if (VpData->EptHooks[h].PtIndex == i)
            {
                used = TRUE;
                break;
            }
        }
        if (!used)
        {
            break;
        }
    }
    if (i == 8)
    {
        return -1;   /* 没有空闲拆页表 */
    }

    ptTable = &VpData->EptPt[i][0];
    RtlZeroMemory(ptTable, PAGE_SIZE);
    pt = (PVMX_PTE)ptTable;

    //
    // 把 2MB 大页拆成 512 个 4K 页，全部 RWX，PFN = 大页PFN*512 + n
    //
    pfnBase = pde.PageFrameNumber * 512;   /* 2MB 页 PFN -> 4K 页 PFN 基数 */
    for (UINT32 n = 0; n < 512; n++)
    {
        pt[n].Read = 1;
        pt[n].Write = 1;
        pt[n].Execute = 1;
        pt[n].PageFrameNumber = pfnBase + n;
    }

    //
    // 把 PDE 从"2MB 大页"改成"指向 4K 页表"
    //
    pdePhys = (UINT64)MmGetPhysicalAddress(ptTable).QuadPart;
    VpData->Epde[pdptIdx][pdIdx].AsUlonglong = 0;
    VpData->Epde[pdptIdx][pdIdx].Read = 1;
    VpData->Epde[pdptIdx][pdIdx].Write = 1;
    VpData->Epde[pdptIdx][pdIdx].Execute = 1;
    VpData->Epde[pdptIdx][pdIdx].PageFrameNumber = pdePhys >> 12;

    *PtIndex = i;
    *PteIndex = ptIdx;
    return 0;
}

/* ================= 走查（老师: HV_LookupEptEntry） ================= */

PVMX_PTE
DnzEptLookup4k(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa
    )
{
    UINT32 pdptIdx, pdIdx, ptIdx, h;
    VMX_LARGE_PDE pde;

    pdptIdx = EPT_IDX_PDPT(Gpa);
    pdIdx   = EPT_IDX_PD(Gpa);
    ptIdx   = EPT_IDX_PT(Gpa);

    //
    // 找哪张 EptPt 表被这个 PDE 使用：通过 EptHooks 里的记录
    //
    for (h = 0; h < VpData->EptHookCount; h++)
    {
        if (VpData->EptHooks[h].Installed &&
            EPT_IDX_PDPT(VpData->EptHooks[h].Gpa) == pdptIdx &&
            EPT_IDX_PD(VpData->EptHooks[h].Gpa) == pdIdx &&
            EPT_IDX_PT(VpData->EptHooks[h].Gpa) == ptIdx)
        {
            return &VpData->EptPt[VpData->EptHooks[h].PtIndex][ptIdx];
        }
    }

    //
    // 不在钩子里——检查 PDE 是否已拆（非大页）。拆过但没钩子记录的（比如
    // 同 2MB 页里第二个钩子）需要扫所有 EptPt 表。教学骨架：钩子少，直接全扫。
    //
    pde.AsUlonglong = VpData->Epde[pdptIdx][pdIdx].AsUlonglong;
    if (pde.Large == 0)
    {
        UINT32 i;
        for (i = 0; i < 8; i++)
        {
            PVMX_PTE pt = &VpData->EptPt[i][0];
            if (pt[ptIdx].AsUlonglong != 0)
            {
                return &pt[ptIdx];
            }
        }
    }
    return NULL;
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

/* ================= 装钩（老师: HV_EptInstallHook） ================= */

NTSTATUS
DnzEptInstallHook(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 Gpa,
    _In_ UINT64 FakePfn,
    _In_ UINT64 CleanPfn
    )
{
    UINT32 ptIdx, pteIdx;
    LONG slot;
    PVMX_PTE pte;
    ULONG h;

    Gpa &= ~0xFFFULL;

    if (DnzEptFindHook(VpData, Gpa) >= 0)
    {
        return STATUS_ALREADY_EXISTS;
    }
    if (VpData->EptHookCount >= 8)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // 拆页
    //
    if (DnzEptSplitLargePage(VpData, Gpa, &ptIdx, &pteIdx) < 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    slot = (LONG)VpData->EptHookCount;
    h = (ULONG)slot;

    //
    // 记录钩子状态
    //
    VpData->EptHooks[h].Gpa = Gpa;
    VpData->EptHooks[h].CleanPfn = CleanPfn;
    VpData->EptHooks[h].FakePfn = FakePfn;
    VpData->EptHooks[h].PtIndex = ptIdx;
    VpData->EptHooks[h].PteIndex = pteIdx;
    VpData->EptHooks[h].SplitPdeIndex = EPT_IDX_PD(Gpa);

    //
    // 保存原 PTE，然后把目标页改成"无权限"——任何访问都触发 EPT violation
    //
    pte = &VpData->EptPt[ptIdx][pteIdx];
    VpData->EptHooks[h].OriginalPte = pte->AsUlonglong;
    pte->AsUlonglong = DNZ_EPT_NO_ACCESS;
    VpData->EptHooks[h].Installed = TRUE;
    VpData->EptHooks[h].InFlip = FALSE;
    VpData->EptHookCount++;

    //
    // 刷 EPT TLB（改了页表必须 INVEPT）
    //
    { UINT64 e = 0; AsmInvEpt(0, &e); }
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
    PVMX_PTE pte;
    UINT32 pdptIdx, pdIdx;

    if (slot < 0)
    {
        return;
    }

    pte = &VpData->EptPt[VpData->EptHooks[slot].PtIndex]
                       [VpData->EptHooks[slot].PteIndex];
    pte->AsUlonglong = VpData->EptHooks[slot].OriginalPte;

    //
    // 恢复 2MB 大页（把 PDE 改回大页，SimpleVisor 原样）
    //
    pdptIdx = EPT_IDX_PDPT(Gpa);
    pdIdx   = EPT_IDX_PD(Gpa);
    VpData->Epde[pdptIdx][pdIdx].AsUlonglong = 0;
    VpData->Epde[pdptIdx][pdIdx].Read = 1;
    VpData->Epde[pdptIdx][pdIdx].Write = 1;
    VpData->Epde[pdptIdx][pdIdx].Execute = 1;
    VpData->Epde[pdptIdx][pdIdx].Large = 1;
    VpData->Epde[pdptIdx][pdIdx].PageFrameNumber =
        (VpData->EptHooks[slot].OriginalPte == 0)
            ? 0
            : (VpData->EptHooks[slot].OriginalPte & 0x000FFFFFFFFFF000ULL) >> 21;

    //
    // 摘掉记录（把最后一个挪过来填空位）
    //
    VpData->EptHooks[slot].Installed = FALSE;
    VpData->EptHookCount--;
    if ((ULONG)slot < VpData->EptHookCount)
    {
        VpData->EptHooks[slot] = VpData->EptHooks[VpData->EptHookCount];
    }

    { UINT64 e = 0; AsmInvEpt(0, &e); }
}

/* ================= 翻镜子（老师: HV_EptSwapHookOnViolation） =================
 *
 * EPT violation 到来时：
 *   1. 找钩子槽位
 *   2. 认人（CR3）：住户 -> 看假页（钩子面）；其他人 -> 看真页（干净面）
 *   3. 临时把 EPT 项改成指向目标页（RWX）
 *   4. 开 MTF（Monitor Trap Flag）：VM-entry 后执行一条指令就再 VM-exit
 *   5. 下个 exit（MTF）由 DnzEptFinishFlip 收尾：恢复无权限 + 关 MTF + 计时
 */

BOOLEAN
DnzEptHandleViolation(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 FaultGpa
    )
{
    LONG slot;
    PVMX_PTE pte;
    INT who;
    UINT64 targetPfn;
    BOOLEAN flipToClean;
    UINT64 tscBefore, tscAfter;
    LARGE_INTEGER msr;

    slot = DnzEptFindHook(VpData, FaultGpa);
    if (slot < 0)
    {
        return FALSE;   /* 不是我们的钩子页，正常放行 */
    }

    //
    // 认人（老师: Hook_NtApi_VmExitHandler 的 PID/CR3 检查）
    //
    who = DnzRecognizeAccessor(GuestCr3);
    flipToClean = (who != 1);   /* 住户看假页，其他（保安/无关）看真页 */

    //
    // 跨核同步：抢翻镜子权（TSC 限时等待，老师: 8×预算周期）
    //
    tscBefore = __rdtsc();
    if (!DnzSyncFlipBegin(KeGetCurrentProcessorNumberEx(NULL), 8 * 4096))
    {
        return FALSE;   /* 超时放弃（不该发生，教学骨架） */
    }

    pte = &VpData->EptPt[VpData->EptHooks[slot].PtIndex]
                       [VpData->EptHooks[slot].PteIndex];
    targetPfn = flipToClean
                    ? VpData->EptHooks[slot].CleanPfn
                    : VpData->EptHooks[slot].FakePfn;

    //
    // 换面：临时改成 RWX 指向目标页
    //
    pte->AsUlonglong = 0;
    pte->Read = 1;
    pte->Write = 1;
    pte->Execute = 1;
    pte->PageFrameNumber = targetPfn;

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

    //
    // 恢复所有在翻的钩子：把 EPT 项改回"无权限"，关 MTF
    //
    for (ULONG h = 0; h < VpData->EptHookCount; h++)
    {
        if (VpData->EptHooks[h].InFlip)
        {
            PVMX_PTE pte = &VpData->EptPt[VpData->EptHooks[h].PtIndex]
                                         [VpData->EptHooks[h].PteIndex];
            pte->AsUlonglong = DNZ_EPT_NO_ACCESS;
            VpData->EptHooks[h].InFlip = FALSE;
        }
    }

    //
    // 关 MTF
    //
    msr.QuadPart = 0;
    __vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (SIZE_T*)&msr.QuadPart);
    msr.QuadPart &= ~0x08000000ULL;
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, msr.QuadPart);
    VpData->MtfActive = 0;

    //
    // 翻完，释放跨核同步锁
    //
    DnzSyncFlipEnd();

    //
    // 刷 EPT TLB
    //
    { UINT64 e = 0; AsmInvEpt(0, &e); }
}
