/*++
 * dnz_guest.h — guest 内存读写（老师: Hv_ReadGuestU64 / Hv_WriteGuestU64 /
 * Hv_TranslateGuestVa_Present）。叠在 SimpleVisor 骨架上。
 *
 * 老师 IDA 分析：
 *   HV_TranslateGuestVa_Present (0x14011c2a0)  客户机虚拟地址 -> 物理
 *   Hv_ReadGuestU64 / Hv_ReadGuestU32 / Hv_ReadGuestBytes / Hv_WriteGuestU64
 *   / Hv_WriteGuestPtr —— ACE_NtApiHook_ExitHandler 里每个分支的替身模拟都要用
 *
 * 实现要点（真硬件可跑）：
 *   - root 模式（MAX_IRQL）读客户机物理内存，靠 Windows 直接映射区
 *     （direct map，物理地址 + DirectMapBase），DriverEntry 时用
 *     MmGetVirtualForPhysical(物理0) 记下基址，之后任意 IRQL 可读写
 *   - guest 虚拟地址 -> 物理：用 guest CR3 走 4 级页表（每级表项通过
 *     direct map 从 guest 物理内存读），处理 1GB/2MB 大页
 * --*/

#pragma once
#include <ntddk.h>

/* direct map 基址初始化（DriverEntry / DnzDeviceInit 里调一次） */
VOID
DnzGuestInit(
    VOID
    );

/* 物理内存读写（MAX_IRQL 可用：direct map 直读） */
UINT64
DnzReadPhys64(
    _In_ UINT64 Phys
    );

UINT32
DnzReadPhys32(
    _In_ UINT64 Phys
    );

UINT8
DnzReadPhys8(
    _In_ UINT64 Phys
    );

VOID
DnzWritePhys(
    _In_ UINT64 Phys,
    _In_ UINT64 Value,
    _In_ ULONG  Size
    );

/* 客户机虚拟地址 -> 物理（老师: HV_TranslateGuestVa_Present）。
 * GuestCr3 = guest CR3（值即 PML4 物理地址）。返回 TRUE 且 PhysOut 有效。 */
BOOLEAN
Hv_TranslateGuestVa_Present(
    _In_  UINT64 GuestCr3,
    _In_  UINT64 Va,
    _Out_ PUINT64 PhysOut
    );

/* ===== 老师原样 guest 读写（Ctx = g_Hook_GuestCr3OrCtx，含 CR3） ===== */

UINT64
Hv_ReadGuestU64(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va
    );

UINT32
Hv_ReadGuestU32(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va
    );

VOID
Hv_ReadGuestBytes(
    _In_  UINT64 Ctx,
    _Out_ PVOID  Dst,
    _In_  UINT64 Va,
    _In_  ULONG  Len
    );

VOID
Hv_WriteGuestU64(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va,
    _In_ UINT64 Val
    );

VOID
Hv_WriteGuestPtr(
    _In_ UINT64 Ctx,
    _In_ UINT64 Va,
    _In_ UINT64 Val
    );
