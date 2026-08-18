/*++
 * dnz_guest.c — guest 内存读写实现。
 *
 * 老师 IDA 分析：
 *   HV_TranslateGuestVa_Present (0x14011c2a0)
 *   Hv_ReadGuestU64 / Hv_ReadGuestU32 / Hv_ReadGuestBytes
 *   Hv_WriteGuestU64 / Hv_WriteGuestPtr
 *
 * 真硬件要点：
 *   - DirectMapBase：DriverEntry（PASSIVE）时 MmGetVirtualForPhysical(物理0)
 *     记下 direct map 基址；之后在 root 模式（MAX_IRQL）直接 基址+物理地址
 *     读写 guest 物理内存，不需要映射/解锁。
 *   - 地址翻译：guest CR3 -> PML4 -> PDPT -> PD -> PT，逐级用 direct map
 *     读 guest 页表项，处理 1GB（PS 在 PDPT）/ 2MB（PS 在 PD）大页。
 * --*/

#include "dnz_guest.h"

/* Windows 直接映射区基址（约 0xFFFFF68000000000，运行时探测） */
static UINT64 DnzDirectMapBase;

VOID
DnzGuestInit(
    VOID
    )
{
    PHYSICAL_ADDRESS pa;

    //
    // 物理地址 0 的虚拟映射 = direct map 基址（Windows 每进程页表都含这段映射，
    // root 模式下 host CR3 = SYSTEM 进程页表，direct map 有效）
    //
    pa.QuadPart = 0;
    DnzDirectMapBase = (UINT64)MmGetVirtualForPhysical(pa);
}

/* ===== 物理内存读写（MAX_IRQL 可用） ===== */

UINT64
DnzReadPhys64(
    _In_ UINT64 Phys
    )
{
    return *(volatile UINT64*)(DnzDirectMapBase + Phys);
}

UINT32
DnzReadPhys32(
    _In_ UINT64 Phys
    )
{
    return *(volatile UINT32*)(DnzDirectMapBase + Phys);
}

UINT8
DnzReadPhys8(
    _In_ UINT64 Phys
    )
{
    return *(volatile UINT8*)(DnzDirectMapBase + Phys);
}

VOID
DnzWritePhys(
    _In_ UINT64 Phys,
    _In_ UINT64 Value,
    _In_ ULONG  Size
    )
{
    if (Size == 8)
    {
        *(volatile UINT64*)(DnzDirectMapBase + Phys) = Value;
    }
    else if (Size == 4)
    {
        *(volatile UINT32*)(DnzDirectMapBase + Phys) = (UINT32)Value;
    }
    else if (Size == 2)
    {
        *(volatile UINT16*)(DnzDirectMapBase + Phys) = (UINT16)Value;
    }
    else if (Size == 1)
    {
        *(volatile UINT8*)(DnzDirectMapBase + Phys) = (UINT8)Value;
    }
}

/* ===== 客户机虚拟地址 -> 物理（老师: HV_TranslateGuestVa_Present） ===== */

#define GUEST_PTE_PRESENT  0x1ULL
#define GUEST_PTE_PS       0x80ULL
#define GUEST_PTE_PFN_MASK 0x000FFFFFFFFFF000ULL

BOOLEAN
Hv_TranslateGuestVa_Present(
    _In_  UINT64 GuestCr3,
    _In_  UINT64 Va,
    _Out_ PUINT64 PhysOut
    )
{
    UINT64 pml4Base, pml4e, pdpte, pde, pte;
    UINT64 pfn;

    if (PhysOut == NULL)
    {
        return FALSE;
    }

    pml4Base = GuestCr3 & GUEST_PTE_PFN_MASK;

    // PML4
    pml4e = DnzReadPhys64(pml4Base + ((Va >> 39) & 0x1FF) * 8);
    if (!(pml4e & GUEST_PTE_PRESENT))
    {
        return FALSE;
    }

    // PDPT
    pdpte = DnzReadPhys64((pml4e & GUEST_PTE_PFN_MASK) + ((Va >> 30) & 0x1FF) * 8);
    if (!(pdpte & GUEST_PTE_PRESENT))
    {
        return FALSE;
    }
    if (pdpte & GUEST_PTE_PS)
    {
        // 1GB 大页
        pfn = (pdpte & 0x000FFFFFC0000000ULL);   /* PFN(18)<<30 */
        *PhysOut = pfn + (Va & 0x3FFFFFFFULL);
        return TRUE;
    }

    // PD
    pde = DnzReadPhys64((pdpte & GUEST_PTE_PFN_MASK) + ((Va >> 21) & 0x1FF) * 8);
    if (!(pde & GUEST_PTE_PRESENT))
    {
        return FALSE;
    }
    if (pde & GUEST_PTE_PS)
    {
        // 2MB 大页
        pfn = (pde & 0x000FFFFFFFE00000ULL);     /* PFN(27)<<21 */
        *PhysOut = pfn + (Va & 0x1FFFFFULL);
        return TRUE;
    }

    // PT
    pte = DnzReadPhys64((pde & GUEST_PTE_PFN_MASK) + ((Va >> 12) & 0x1FF) * 8);
    if (!(pte & GUEST_PTE_PRESENT))
    {
        return FALSE;
    }

    *PhysOut = (pte & GUEST_PTE_PFN_MASK) + (Va & 0xFFFULL);
    return TRUE;
}

/* ===== 老师原样 guest 读写（Ctx = g_Hook_GuestCr3OrCtx，前 8 字节 = CR3） ===== */

UINT64
Hv_ReadGuestU64(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va
    )
{
    UINT64 phys;

    if (Hv_TranslateGuestVa_Present(*(PUINT64)(Ctx + 8), Va, &phys))
    {
        return DnzReadPhys64(phys);
    }
    return 0;
}

UINT32
Hv_ReadGuestU32(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va
    )
{
    UINT64 phys;

    if (Hv_TranslateGuestVa_Present(*(PUINT64)(Ctx + 8), Va, &phys))
    {
        return DnzReadPhys32(phys);
    }
    return 0;
}

VOID
Hv_ReadGuestBytes(
    _In_  UINT64 Ctx,
    _Out_ PVOID  Dst,
    _In_  UINT64 Va,
    _In_  ULONG  Len
    )
{
    UINT64 phys;
    PUINT8 dst = (PUINT8)Dst;
    ULONG i;

    for (i = 0; i < Len; i++)
    {
        if (Hv_TranslateGuestVa_Present(*(PUINT64)(Ctx + 8), Va + i, &phys))
        {
            dst[i] = DnzReadPhys8(phys);
        }
        else
        {
            dst[i] = 0;
        }
    }
}

VOID
Hv_WriteGuestU64(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va,
    _In_ UINT64 Val
    )
{
    UINT64 phys;

    if (Hv_TranslateGuestVa_Present(*(PUINT64)(Ctx + 8), Va, &phys))
    {
        DnzWritePhys(phys, Val, 8);
    }
}

VOID
Hv_WriteGuestPtr(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va,
    _In_ UINT64 Val
    )
{
    UINT64 phys;

    if (Hv_TranslateGuestVa_Present(*(PUINT64)(Ctx + 8), Va, &phys))
    {
        DnzWritePhys(phys, Val, 8);
    }
}
