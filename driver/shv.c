/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shv.c

Abstract:

    This module implements the Driver Entry/Unload for the Simple Hyper Visor,
    plus the DnzVisor device object and IOCTL dispatch (EPT dual-view hooks).

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#include <ntddk.h>
#include "shv.h"
#include "dnz_ept.h"
#include "dnz_hook.h"
#include "dnz_guest.h"

/* KeGenericCallDpc 三件套原型（WDK 头有时不导出，手工声明） */
NTKERNELAPI VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
NTKERNELAPI VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

#define DNZ_IOCTL_BASE    0x800
#define DNZ_IOCTL_REGISTER_PROC   CTL_CODE(FILE_DEVICE_UNKNOWN, DNZ_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DNZ_IOCTL_UNREGISTER_ALL CTL_CODE(FILE_DEVICE_UNKNOWN, DNZ_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DNZ_IOCTL_INSTALL_HOOK   CTL_CODE(FILE_DEVICE_UNKNOWN, DNZ_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DNZ_IOCTL_REMOVE_HOOK    CTL_CODE(FILE_DEVICE_UNKNOWN, DNZ_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DNZ_IOCTL_TEST           CTL_CODE(FILE_DEVICE_UNKNOWN, DNZ_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DNZ_IOCTL_REGISTER_RIP   CTL_CODE(FILE_DEVICE_UNKNOWN, DNZ_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 用户态 <-> 内核 IOCTL 数据结构 */
typedef struct _DNZ_IOCTL_HOOK {
    UINT64 Gpa;      /* 被钩客户机物理页 */
    UINT64 FakePfn;  /* 假页（钩子面）物理帧号 */
    UINT64 CleanPfn; /* 真页（干净面）物理帧号 */
} DNZ_IOCTL_HOOK, *PDNZ_IOCTL_HOOK;

/* 每核广播上下文：给每个核的 EPT 装同一个钩子 */
typedef struct _DNZ_DPC_HOOK_CTX {
    UINT64 Gpa;
    UINT64 FakePfn;
    UINT64 CleanPfn;
    LONG   ResultCount;
    NTSTATUS Status;
} DNZ_DPC_HOOK_CTX, *PDNZ_DPC_HOOK_CTX;

extern PSHV_VP_DATA* ShvGlobalData;

static VOID
DnzDpcInstallHook(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PDNZ_DPC_HOOK_CTX ctx = (PDNZ_DPC_HOOK_CTX)DeferredContext;
    PSHV_VP_DATA vp;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    vp = ShvGlobalData[KeGetCurrentProcessorNumberEx(NULL)];
    if (vp != NULL)
    {
        ctx->Status = DnzEptInstallHook(vp, ctx->Gpa, ctx->FakePfn, ctx->CleanPfn);
        if (NT_SUCCESS(ctx->Status))
        {
            InterlockedIncrement(&ctx->ResultCount);
        }
    }
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID
DnzDpcRemoveHook(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PDNZ_DPC_HOOK_CTX ctx = (PDNZ_DPC_HOOK_CTX)DeferredContext;
    PSHV_VP_DATA vp;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    vp = ShvGlobalData[KeGetCurrentProcessorNumberEx(NULL)];
    if (vp != NULL)
    {
        DnzEptRemoveHook(vp, ctx->Gpa);
    }
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

NTSTATUS
DnzDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code)
    {
    case DNZ_IOCTL_REGISTER_PROC:
        if (inLen >= sizeof(ULONG))
        {
            status = DnzRegisterProc(*(PULONG)inBuf);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case DNZ_IOCTL_REGISTER_RIP:
        if (inLen >= sizeof(ULONG64))
        {
            status = DnzRegisterRip(*(PULONG64)inBuf);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case DNZ_IOCTL_UNREGISTER_ALL:
        status = DnzUnregisterAll();
        break;

    case DNZ_IOCTL_INSTALL_HOOK:
        if (inLen >= sizeof(DNZ_IOCTL_HOOK))
        {
            DNZ_DPC_HOOK_CTX ctx;
            PDNZ_IOCTL_HOOK hk = (PDNZ_IOCTL_HOOK)inBuf;
            ctx.Gpa = hk->Gpa;
            ctx.FakePfn = hk->FakePfn;
            ctx.CleanPfn = hk->CleanPfn;
            ctx.ResultCount = 0;
            ctx.Status = STATUS_SUCCESS;
            KeGenericCallDpc(DnzDpcInstallHook, &ctx);
            status = ctx.Status;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case DNZ_IOCTL_REMOVE_HOOK:
        if (inLen >= sizeof(UINT64))
        {
            DNZ_DPC_HOOK_CTX ctx;
            ctx.Gpa = *(PULONG64)inBuf;
            ctx.ResultCount = 0;
            ctx.Status = STATUS_SUCCESS;
            KeGenericCallDpc(DnzDpcRemoveHook, &ctx);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case DNZ_IOCTL_TEST:
        {
            /* 简单自检：报告翻镜子次数和最近耗时 */
            ULONG64 out[2];
            out[0] = (ULONG64)g_DnzHook.Sync.SwapCount;
            out[1] = (ULONG64)g_DnzHook.Sync.LastSwapTsc;
            if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(out))
            {
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, out, sizeof(out));
                Irp->IoStatus.Information = sizeof(out);
            }
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
DnzCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID
ShvUnload (
    VOID
    )
{
    //
    // Attempt to exit VMX root mode on all logical processors. This will
    // broadcast an interrupt which will execute the callback routine in
    // parallel on the LPs.
    //
    // Note that if SHV is not loaded on any of the LPs, this routine will not
    // perform any work, but will not fail in any way.
    //
    ShvOsRunCallbackOnProcessors(ShvVpUnloadCallback, NULL);

    //
    // Indicate unload
    //
    ShvOsDebugPrint("The SHV has been uninstalled.\n");
}

INT32
ShvLoad (
    VOID
    )
{
    SHV_CALLBACK_CONTEXT callbackContext;

    //
    // Attempt to enter VMX root mode on all logical processors. This will
    // broadcast a DPC interrupt which will execute the callback routine in
    // parallel on the LPs. Send the callback routine the physical address of
    // the PML4 of the system process, which is what this driver entrypoint
    // should be executing in.
    //
    callbackContext.Cr3 = __readcr3();
    callbackContext.FailureStatus = SHV_STATUS_SUCCESS;
    callbackContext.FailedCpu = -1;
    callbackContext.InitCount = 0;
    ShvOsRunCallbackOnProcessors(ShvVpLoadCallback, &callbackContext);

    //
    // Check if all LPs are now hypervised. Return the failure code of at least
    // one of them. 
    //
    // Note that each VP is responsible for freeing its VP data on failure.
    //
    if (callbackContext.InitCount != ShvOsGetActiveProcessorCount())
    {
        ShvOsDebugPrint("The SHV failed to initialize (0x%lX) Failed CPU: %d\n",
                        callbackContext.FailureStatus, callbackContext.FailedCpu);
        return callbackContext.FailureStatus;
    }

    //
    // Indicate success.
    //
    ShvOsDebugPrint("The SHV has been installed.\n");
    return SHV_STATUS_SUCCESS;
}

NTSTATUS
DnzDeviceInit (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\DnzVisor");
    UNICODE_STRING symLink    = RTL_CONSTANT_STRING(L"\\DosDevices\\DnzVisor");
    PDEVICE_OBJECT deviceObject = NULL;

    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            0,
                            FALSE,
                            &deviceObject);
    if (NT_SUCCESS(status))
    {
        status = IoCreateSymbolicLink(&symLink, &deviceName);
    }
    if (NT_SUCCESS(status))
    {
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DnzCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DnzCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DnzDeviceControl;
        deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    }

    DnzGuestInit();   /* direct map 基址（guest 物理内存读写用） */
    DnzHookInit();
    return status;
}

VOID
DnzDeviceCleanup (
    VOID
    )
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\DnzVisor");
    IoDeleteSymbolicLink(&symLink);
    DnzHookCleanup();
}
