/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shv_x.h

Abstract:

    This header defines the externally visible structures and functions of the
    Simple Hyper Visor which are visible between the OS layer and SimpleVisor.

Author:

    Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once

#include "vmx.h"

#define SHV_STATUS_SUCCESS          0
#define SHV_STATUS_NOT_AVAILABLE    -1
#define SHV_STATUS_NO_RESOURCES     -2
#define SHV_STATUS_NOT_PRESENT      -3

#define _1GB                        (1 * 1024 * 1024 * 1024)
#define _2MB                        (2 * 1024 * 1024)

struct _SHV_CALLBACK_CONTEXT;

typedef
void
SHV_CPU_CALLBACK (
    struct _SHV_CALLBACK_CONTEXT* Context
    );
typedef SHV_CPU_CALLBACK *PSHV_CPU_CALLBACK;

typedef struct _SHV_SPECIAL_REGISTERS
{
    UINT64 Cr0;
    UINT64 Cr3;
    UINT64 Cr4;
    UINT64 MsrGsBase;
    UINT16 Tr;
    UINT16 Ldtr;
    UINT64 DebugControl;
    UINT64 KernelDr7;
    KDESCRIPTOR Idtr;
    KDESCRIPTOR Gdtr;
} SHV_SPECIAL_REGISTERS, *PSHV_SPECIAL_REGISTERS;

typedef struct _SHV_MTRR_RANGE
{
    UINT32 Enabled;
    UINT32 Type;
    UINT64 PhysicalAddressMin;
    UINT64 PhysicalAddressMax;
} SHV_MTRR_RANGE, *PSHV_MTRR_RANGE;

/* 双根视图（老师: HV_EptInstallHook 里的主根/影子根）。
 * 每视图一套独立页表，只在被钩区域与共享基底（Epml4/Epdpt/Epde）不同。
 * DECLSPEC_ALIGN(PAGE_SIZE) 保证每张表物理 4KB 对齐（MM 取物理地址用）。
 * CloneRegion = 区域克隆覆盖的 1GB 区域号（PDPT 索引），-1 = 空闲；
 * PtKey = 拆页 PT 覆盖的 2MB 页键 (region<<9|pd)，-1 = 空闲。 */
typedef struct _DNZ_EPT_VIEW
{
    UINT64  EptpValue;               /* 算好的 EPTP 值（VMCS EPT_POINTER 直接写） */
    LONG    CloneRegion[8];          /* 8 个区域克隆槽 */
    LONG    PtKey[8];                /* 8 个拆页 PT 槽 */
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_EPML4E Pml4[PML4E_ENTRY_COUNT];      /* 1 pg */
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_PDPTE Pdpt[PDPTE_ENTRY_COUNT];       /* 1 pg */
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_LARGE_PDE Pde[8][PDE_ENTRY_COUNT];   /* 8 pg */
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_PTE Pt[8][PTE_ENTRY_COUNT];          /* 8 pg */
} DNZ_EPT_VIEW, *PDNZ_EPT_VIEW;

typedef struct _SHV_VP_DATA
{
    union
    {
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 ShvStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            SHV_SPECIAL_REGISTERS SpecialRegisters;
            CONTEXT ContextFrame;
            UINT64 SystemDirectoryTableBase;
            LARGE_INTEGER MsrData[17];
            SHV_MTRR_RANGE MtrrData[16];
            UINT64 VmxOnPhysicalAddress;
            UINT64 VmcsPhysicalAddress;
            UINT64 MsrBitmapPhysicalAddress;
            UINT64 EptPml4PhysicalAddress;
            UINT32 EptControls;
        };
    };

    /* ===== 老师工程细节：双根 EPT（主根/影子根）+ 触发根（dnz_ept.c 用） =====
     *
     * 老师驱动是"双根"：手里同时攥着两套完整地图——
     *   主根 MainView   ：被钩页 → 假页（FakePfn，"改过版"，住户/游戏看）
     *   影子根 ShadowView：被钩页 → 真页（CleanPfn，"干净版"，保安/外人看）
     * 翻镜子 = 切换视图（改 VMCS EPTP），不是改页表。
     * 另配一个"触发根" FaultView：被钩页 → 无权限，作为默认 EPTP，
     * 任何访问都触发 EPT violation，我们才能认出是谁、决定给哪张脸。
     *
     * 结构（省内存版"两套地图"）：
     *   共享基底 Epml4/Epdpt/Epde（SimpleVisor 的 2MB 恒等映射，永不被改）
     *   每个视图只带自己的 Pml4/Pdpt + 区域克隆 Pde[8] + 拆页 PT 表 Pt[8]
     *   视图 Pdpt[i] 默认指向共享 Epde[i]，有钩子的区域才指向自己的克隆。
     */
    DECLSPEC_ALIGN(PAGE_SIZE) DNZ_EPT_VIEW MainView;
    DECLSPEC_ALIGN(PAGE_SIZE) DNZ_EPT_VIEW ShadowView;
    DECLSPEC_ALIGN(PAGE_SIZE) DNZ_EPT_VIEW FaultView;
    /* 每核双视图钩子状态（最多 8 个） */
    struct _DNZ_VP_EPT_STATE {
        UINT64  Gpa;              /* 被钩的客户机物理页（4K 对齐） */
        UINT64  CleanPfn;         /* 干净视图物理帧号（影子根） */
        UINT64  FakePfn;          /* 钩子视图物理帧号（主根） */
        LONG    CloneIdx;         /* 区域克隆槽（三个视图同槽） */
        LONG    PtIdx;            /* 拆页 PT 槽（三个视图同槽） */
        UINT32  PteIndex;         /* PT 表内索引 */
        BOOLEAN Installed;
        BOOLEAN InFlip;           /* 正在翻镜子（MTF 单步中） */
        BOOLEAN FlipToClean;      /* 本次翻到干净面(影子根)还是钩子面(主根) */
        BOOLEAN FlipState;        /* 当前面向谁：FALSE=住户(假页) TRUE=保安(真页) */
    } EptHooks[8];
    UINT32  EptHookCount;
    UINT32  MtfActive;            /* 是否开了 MTF 单步 */
    UINT64  LastSwapTsc;          /* 本核翻镜子耗时账本（老师: +24656） */
    UINT64  SwapExpectedTsc;
    volatile long  SyncLocal;     /* 本核跨核同步镜像 */
    /* ===== 老师工程细节结束 ===== */

    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 MsrBitmap[PAGE_SIZE];
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_EPML4E Epml4[PML4E_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_PDPTE Epdpt[PDPTE_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_LARGE_PDE Epde[PDPTE_ENTRY_COUNT][PDE_ENTRY_COUNT];

    DECLSPEC_ALIGN(PAGE_SIZE) VMX_VMCS VmxOn;
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_VMCS Vmcs;
} SHV_VP_DATA, *PSHV_VP_DATA;

/* 大小断言已移除（与 WDK C_ASSERT 冲突） */

VOID
_sldt (
    _In_ UINT16* Ldtr
    );

VOID
_ltr (
    _In_ UINT16 Tr
    );

VOID
_str (
    _In_ UINT16* Tr
    );

VOID
__lgdt (
    _In_ VOID* Gdtr
    );

INT32
ShvLoad (
    VOID
    );

VOID
ShvUnload (
    VOID
    );