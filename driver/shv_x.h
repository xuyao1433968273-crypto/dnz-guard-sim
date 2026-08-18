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

    /* ===== 老师工程细节：EPT 拆页表 + 双视图钩子状态（dnz_ept.c 用） ===== */
    /* 每核 8 张 4KB 页表，供拆 2MB 大页用（每张覆盖 512 个 4K 页 = 2MB） */
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_PTE EptPt[8][PTE_ENTRY_COUNT];
    /* 每核双视图钩子状态（最多 8 个） */
    struct _DNZ_VP_EPT_STATE {
        UINT64  Gpa;              /* 被钩的客户机物理页（4K 对齐） */
        UINT64  CleanPfn;         /* 干净视图物理帧号 */
        UINT64  FakePfn;          /* 钩子视图物理帧号 */
        UINT32  PtIndex;          /* 用哪张 EptPt 表 */
        UINT32  PteIndex;         /* PT 表内索引 */
        UINT64  OriginalPde;      /* 拆页前保存的 2MB PDE 原值（卸钩恢复用） */
        UINT64  OriginalPte;      /* 拆页后目标 4K 项原值 */
        UINT32  SplitPdeIndex;    /* 拆页时改的 PDE 索引 */
        BOOLEAN Installed;
        BOOLEAN InFlip;           /* 正在翻镜子（MTF 单步中） */
        BOOLEAN FlipToClean;      /* 本次翻到干净面还是钩子面 */
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