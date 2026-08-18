# -*- coding: utf-8 -*-
# 把 RIP 黑名单接进翻镜子决策：
#   1) dnz_hook.h   加 DnzRipInBlacklist 声明
#   2) dnz_hook.c   实现 DnzRipInBlacklist（老师: RIP == 偏移表逐个对）
#   3) dnz_ept.h    改 DnzEptHandleViolation 签名（加 GuestRip 参数）
#   4) dnz_ept.c    认人升级：只有"住户 + RIP 命中黑名单"才看假页（钩子面）
#   5) shvvmxhv.c   EPT violation 分支读 GUEST_RIP 传进去
import io

# ============ 1) dnz_hook.h: 加声明 ============
p = r"D:/dnz_guard_sim/driver/dnz_hook.h"
with io.open(p, "r", encoding="utf-8", errors="replace") as f:
    txt = f.read()

old = """/* 跨核同步（老师: 翻镜子里的 spin-wait + TSC 限时） */
BOOLEAN
DnzSyncFlipBegin("""
new = """/* RIP 黑名单命中检查（老师: Hook_NtApi_VmExitHandler 第二招——
 * 拿 guest RIP 去对 g_Hook_NtosOffsetsCtx 的偏移表，命中才处理） */
BOOLEAN
DnzRipInBlacklist(
    _In_ UINT64 GuestRip
    );

/* 跨核同步（老师: 翻镜子里的 spin-wait + TSC 限时） */
BOOLEAN
DnzSyncFlipBegin("""
assert txt.count(old) == 1, "hook.h anchor"
txt = txt.replace(old, new)
with io.open(p, "w", encoding="utf-8", newline="\n") as f:
    f.write(txt)
print("dnz_hook.h: DnzRipInBlacklist declared")

# ============ 2) dnz_hook.c: 实现 ============
p = r"D:/dnz_guard_sim/driver/dnz_hook.c"
with io.open(p, "r", encoding="utf-8", errors="replace") as f:
    txt = f.read()

old = """/* ============ 跨核同步（老师: 翻镜子里的 spin-wait + TSC 超时） ============ */
"""
new = """/* ============ RIP 黑名单（老师: Hook_NtApi_VmExitHandler 第二招） ============ */

BOOLEAN
DnzRipInBlacklist(
    _In_ UINT64 GuestRip
    )
{
    ULONG i;

    //
    // 老师逻辑：拿 guest RIP 去和登记表（g_Hook_NtosOffsetsCtx 的十几个偏移）
    // 逐个对，RIP == 偏移 N 的位置就按 N 的处理方式模拟那个 API。
    // 教学骨架：直接对比绝对 RIP（IOCTL 注册的黑名单）。
    //
    for (i = 0; i < DNZ_MAX_RIP_BLACKLIST; i++)
    {
        if (g_DnzHook.Rips[i].Active &&
            g_DnzHook.Rips[i].Rip == GuestRip)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============ 跨核同步（老师: 翻镜子里的 spin-wait + TSC 超时） ============ */
"""
assert txt.count(old) == 1, "hook.c anchor"
txt = txt.replace(old, new)
with io.open(p, "w", encoding="utf-8", newline="\n") as f:
    f.write(txt)
print("dnz_hook.c: DnzRipInBlacklist implemented")

# ============ 3) dnz_ept.h: 改签名 ============
p = r"D:/dnz_guard_sim/driver/dnz_ept.h"
with io.open(p, "r", encoding="utf-8", errors="replace") as f:
    txt = f.read()

old = """BOOLEAN
DnzEptHandleViolation(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 FaultGpa
    );"""
new = """BOOLEAN
DnzEptHandleViolation(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestRip,
    _In_ UINT64 FaultGpa
    );"""
assert txt.count(old) == 1, "ept.h anchor"
txt = txt.replace(old, new)
with io.open(p, "w", encoding="utf-8", newline="\n") as f:
    f.write(txt)
print("dnz_ept.h: signature updated")

# ============ 4) dnz_ept.c: 认人升级 ============
p = r"D:/dnz_guard_sim/driver/dnz_ept.c"
with io.open(p, "r", encoding="utf-8", errors="replace") as f:
    txt = f.read()

old = """BOOLEAN
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
"""
new = """BOOLEAN
DnzEptHandleViolation(
    _In_ PSHV_VP_DATA VpData,
    _In_ UINT64 GuestCr3,
    _In_ UINT64 GuestRip,
    _In_ UINT64 FaultGpa
    )
{
    LONG slot;
    PVMX_PTE pte;
    INT who;
    BOOLEAN ripHit;
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
    // 认人两招（老师: Hook_NtApi_VmExitHandler）：
    //   第一招：查 PID（CR3）——不是被钩进程就 return 0
    //   第二招：拿 guest RIP 对黑名单——命中才"干活"（翻到钩子面/模拟 API）
    // 只有"住户 + RIP 命中黑名单"才看假页；其他一切情况看真页（干净面）。
    //
    who = DnzRecognizeAccessor(GuestCr3);
    if (who == 0)
    {
        //
        // 不是被钩进程——老师代码里这里 return 0，直接放行（看真页）
        //
        flipToClean = TRUE;
    }
    else
    {
        ripHit = DnzRipInBlacklist(GuestRip);
        if (ripHit)
        {
            //
            // 住户 + RIP 命中黑名单：翻到钩子面（假页），模拟这个 API
            //
            flipToClean = FALSE;
        }
        else
        {
            //
            // 住户但 RIP 没命中：不是要拦的 API，正常放行（看真页）
            //
            flipToClean = TRUE;
        }
    }
"""
assert txt.count(old) == 1, "ept.c handle violation anchor"
txt = txt.replace(old, new)
with io.open(p, "w", encoding="utf-8", newline="\n") as f:
    f.write(txt)
print("dnz_ept.c: recognition upgraded (PID + RIP blacklist)")

# ============ 5) shvvmxhv.c: 读 GUEST_RIP 传进去 ============
p = r"D:/dnz_guard_sim/driver/shvvmxhv.c"
with io.open(p, "r", encoding="utf-8", errors="replace") as f:
    txt = f.read()

old = """    case EXIT_REASON_EPT_VIOLATION:
    {
        UINT64 qualification = 0;
        UINT64 guestCr3 = 0;
        UINT64 faultGpa;

        __vmx_vmread(EXIT_QUALIFICATION, &qualification);
        __vmx_vmread(GUEST_CR3, &guestCr3);
        faultGpa = qualification & DNZ_EPT_VIOLATION_GPA_MASK;

        if (DnzEptHandleViolation(VpData, guestCr3, faultGpa))"""
new = """    case EXIT_REASON_EPT_VIOLATION:
    {
        UINT64 qualification = 0;
        UINT64 guestCr3 = 0;
        UINT64 guestRip = 0;
        UINT64 faultGpa;

        __vmx_vmread(EXIT_QUALIFICATION, &qualification);
        __vmx_vmread(GUEST_CR3, &guestCr3);
        __vmx_vmread(GUEST_RIP, &guestRip);
        faultGpa = qualification & DNZ_EPT_VIOLATION_GPA_MASK;

        if (DnzEptHandleViolation(VpData, guestCr3, guestRip, faultGpa))"""
assert txt.count(old) == 1, "exit handler anchor"
txt = txt.replace(old, new)
with io.open(p, "w", encoding="utf-8", newline="\n") as f:
    f.write(txt)
print("shvvmxhv.c: GUEST_RIP read and passed")
