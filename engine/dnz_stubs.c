/* ============================================================
 * dnz_stubs.c —— 老师「04-内存映射与隐藏」剩余 sub_ 函数建模
 * ------------------------------------------------------------
 * 本文件由 engine_ref/gen_stubs.py 依据逐行分析自动生成。
 * 每个函数都保留老师 IDA 地址/序号/角色/大小/调用者，
 * 内容按"调用关系 + 关键行特征"建模，可编译、可运行、可被调用。
 * VMProtect 加密区的内容老师分析也未能还原，这里给出的是
 * 围绕其已知调用图的结构模型（真实行为见命名函数模块）。
 * ============================================================ */
#include "dnz_stubs.h"
#include "dnz_ept.h"
#include "dnz_hook.h"
#include "dnz_realvmx.h"
#include "dnz_violation.h"
#include "dnz_dispatch.h"
#include "dnz_hooks.h"
#include "dnz_pool.h"
#include <string.h>

/* 模型: sub_1401E06C6(2,...) 冲刷原语 */
static uint64_t flush_model(void) { hv_clear_pending_exception_state(&g_dnz); return 0; }

/* ------------------------------------------------------------
 *     29  0x140001fb0  sub_140001FB0
 * 角色: Hook/隐藏    大小: 390 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: Mem_HeapFree(0x1400029f0) → Rtl_RegisterAtExit(0x1401036b0) → Mem_HeapAlloc(0x140133e10) → HV_Dispatch(0x1401536b0)
 * ------------------------------------------------------------ */
uint64_t sub_140001FB0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *    443  0x1400401a0  sub_1400401A0
 * 角色: EPT/NPT内存映射    大小: 906 字节
 * 谁叫它: sub_140040C10(0x140040c10)、sub_140041000(0x140041000)、sub_140041C90(0x140041c90)、Lic_ReportAppCompatCache(0x140043b40)、sub_14004AB80(0x14004ab80)、Lic_ReportNetwork(0x14004b000)、Lic_ReportServiceDrivers(0x14004c870)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → HV_MemsetGuestVa(0x140152df0)
 * ------------------------------------------------------------ */
uint64_t sub_1400401A0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    444  0x140040530  sub_140040530
 * 角色: EPT/NPT内存映射    大小: 1555 字节
 * 谁叫它: sub_140040B50(0x140040b50)、sub_140042B20(0x140042b20)、sub_140045CA0(0x140045ca0)、Lic_ReportNetwork(0x14004b000)、Lic_ReportServiceDrivers(0x14004c870)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → HV_MemsetGuestVa(0x140152df0)
 * ------------------------------------------------------------ */
uint64_t sub_140040530(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    463  0x1400448f0  sub_1400448F0
 * 角色: EPT/NPT内存映射    大小: 962 字节
 * 谁叫它: Lic_ReportServiceDrivers(0x14004c870)
 * 它叫谁: sub_1400447F0(0x1400447f0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_1400448F0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    465  0x140044e30  sub_140044E30
 * 角色: EPT/NPT内存映射    大小: 850 字节
 * 谁叫它: Lic_ReportProcesses(0x14004fa40)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → sub_14014C400(0x14014c400)
 * ------------------------------------------------------------ */
uint64_t sub_140044E30(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    466  0x140045190  sub_140045190
 * 角色: EPT/NPT内存映射    大小: 748 字节
 * 谁叫它: sub_14004D5E0(0x14004d5e0)
 * 它叫谁: Util_WideToUtf8(0x14003eac0) → sub_140053A20(0x140053a20) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_140045190(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    467  0x140045480  sub_140045480
 * 角色: EPT/NPT内存映射    大小: 661 字节
 * 谁叫它: sub_140046320(0x140046320)、sub_1400466D0(0x1400466d0)、sub_140046C40(0x140046c40)、sub_140047080(0x140047080)、sub_140047600(0x140047600)
 * 它叫谁: sub_1400525B0(0x1400525b0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → sub_1401349F0(0x1401349f0)
 * ------------------------------------------------------------ */
uint64_t sub_140045480(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    468  0x140045720  sub_140045720
 * 角色: EPT/NPT内存映射    大小: 645 字节
 * 谁叫它: sub_14004D5E0(0x14004d5e0)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → sub_1401349F0(0x1401349f0) → HV_MemsetGuestVa(0x140152df0)
 * ------------------------------------------------------------ */
uint64_t sub_140045720(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    474  0x140046320  sub_140046320
 * 角色: EPT/NPT内存映射    大小: 942 字节
 * 谁叫它: sub_1400466D0(0x1400466d0)
 * 它叫谁: Rtl_AbortStringTooLong(0x140002870) → Mem_HeapFree(0x1400029f0) → sub_140045480(0x140045480) → sub_1400525B0(0x1400525b0) → sub_140053920(0x140053920) → sub_1400608A0(0x1400608a0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10)
 * ------------------------------------------------------------ */
uint64_t sub_140046320(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    477  0x140047080  sub_140047080
 * 角色: EPT/NPT内存映射    大小: 1393 字节
 * 谁叫它: Lic_ReportQQUserData(0x140049e90)
 * 它叫谁: Rtl_AbortStringTooLong(0x140002870) → Mem_HeapFree(0x1400029f0) → sub_140045480(0x140045480) → sub_140046020(0x140046020) → sub_140046C40(0x140046c40) → sub_1400525B0(0x1400525b0) → sub_1400526D0(0x1400526d0) → sub_140053920(0x140053920)
 * ------------------------------------------------------------ */
uint64_t sub_140047080(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: EPT/NPT内存映射 —— 走查当前根，给 4K 页填条目 */
    { uint64_t *e = hv_lookup_ept(dnz_root_primary(), p1, true);
      if (!e) { hv_ept_map_guest_access(dnz_root_primary(), p1, false); e = hv_lookup_ept(dnz_root_primary(), p1, false); }
      v = e ? *e : 0; }
    return v;
}

/* ------------------------------------------------------------
 *    479  0x140047ad0  sub_140047AD0
 * 角色: EPT/NPT内存映射    大小: 1715 字节
 * 谁叫它: sub_140048660(0x140048660)
 * 它叫谁: sub_14003F470(0x14003f470) → sub_1400525B0(0x1400525b0) → sub_140087190(0x140087190) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0)
 * ------------------------------------------------------------ */
uint64_t sub_140047AD0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    492  0x14004b000  Lic_ReportNetwork
 * 角色: Hook/隐藏    大小: 3529 字节
 * 谁叫它: Lic_CollectMachineReport(0x14004fe60)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → sub_14003E7E0(0x14003e7e0) → Util_WideToUtf8(0x14003eac0) → sub_1400401A0(0x1400401a0) → sub_140040530(0x140040530) → sub_140040C10(0x140040c10) → Lic_NetEnumHelper(0x14004a8d0) → sub_14004A9A0(0x14004a9a0)
 * ------------------------------------------------------------ */
uint64_t Lic_ReportNetwork(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *    639  0x140062650  sub_140062650
 * 角色: Hook/隐藏    大小: 2447 字节
 * 谁叫它: sub_140159C30(0x140159c30)
 * 它叫谁: HV_InitAttachCore(0x14003e390) → sub_140062410(0x140062410) → sub_14012F1F0(0x14012f1f0) → Mem_HeapFreeTracked(0x140133bc0) → sub_140141000(0x140141000) → sub_14014F6A0(0x14014f6a0) → HV_Dispatch(0x1401536b0) → sub_140154100(0x140154100)
 * ------------------------------------------------------------ */
uint64_t sub_140062650(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: Mem_HeapFreeTracked */
    dnz_pool_free_frame(p1);
    return v;
}

/* ------------------------------------------------------------
 *    689  0x140068450  sub_140068450
 * 角色: EPT/NPT内存映射    大小: 2442 字节
 * 谁叫它: sub_1400695F0(0x1400695f0)
 * 它叫谁: sub_14003E7E0(0x14003e7e0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_140068450(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    739  0x140074440  sub_140074440
 * 角色: EPT/NPT内存映射    大小: 1764 字节
 * 谁叫它: sub_140074B30(0x140074b30)、sub_140075120(0x140075120)、sub_140075550(0x140075550)、sub_140075B00(0x140075b00)
 * 它叫谁: Rtl_AbortStringTooLong(0x140002870) → Util_StringAssign(0x140002930) → Mem_HeapFree(0x1400029f0) → Mem_HeapAllocAligned(0x140002aa0) → sub_140053A20(0x140053a20) → sub_140065B00(0x140065b00) → sub_14006BF40(0x14006bf40) → sub_14006C040(0x14006c040)
 * ------------------------------------------------------------ */
uint64_t sub_140074440(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: EPT/NPT内存映射 —— 走查当前根，给 4K 页填条目 */
    { uint64_t *e = hv_lookup_ept(dnz_root_primary(), p1, true);
      if (!e) { hv_ept_map_guest_access(dnz_root_primary(), p1, false); e = hv_lookup_ept(dnz_root_primary(), p1, false); }
      v = e ? *e : 0; }
    return v;
}

/* ------------------------------------------------------------
 *    771  0x14007cda0  sub_14007CDA0
 * 角色: EPT/NPT内存映射    大小: 1020 字节
 * 谁叫它: sub_14007D1A0(0x14007d1a0)、sub_14007E010(0x14007e010)
 * 它叫谁: sub_14007CCD0(0x14007ccd0) → sub_140087190(0x140087190) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_14007CDA0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    851  0x1400884b0  sub_1400884B0
 * 角色: EPT/NPT内存映射    大小: 760 字节
 * 谁叫它: sub_1400887B0(0x1400887b0)
 * 它叫谁: sub_140088AF0(0x140088af0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_1400884B0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    853  0x140088af0  sub_140088AF0
 * 角色: EPT/NPT内存映射    大小: 1863 字节
 * 谁叫它: sub_14007E010(0x14007e010)、sub_1400884B0(0x1400884b0)
 * 它叫谁: HV_FlushOrSyncAfterRegister(0x14003e1e0) → sub_14003E7E0(0x14003e7e0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0)
 * ------------------------------------------------------------ */
uint64_t sub_140088AF0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *    914  0x1400943c0  sub_1400943C0
 * 角色: EPT/NPT内存映射    大小: 2464 字节
 * 谁叫它: sub_140077F20(0x140077f20)、sub_14007F370(0x14007f370)
 * 它叫谁: sub_1400927C0(0x1400927c0) → sub_140094F80(0x140094f80) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → Mem_HeapAllocRaw(0x140134370)
 * ------------------------------------------------------------ */
uint64_t sub_1400943C0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   1096  0x1400acbc0  sub_1400ACBC0
 * 角色: Hook/隐藏    大小: 621 字节
 * 谁叫它: sub_1400AF5E0(0x1400af5e0)
 * 它叫谁: sub_14009AFA0(0x14009afa0) → sub_1400AC280(0x1400ac280) → sub_1400AC970(0x1400ac970) → HV_Dispatch(0x1401536b0)
 * ------------------------------------------------------------ */
uint64_t sub_1400ACBC0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1097  0x1400ace30  sub_1400ACE30
 * 角色: Hook/隐藏    大小: 116 字节
 * 谁叫它: sub_1400B3CD0(0x1400b3cd0)、sub_1400B3DC0(0x1400b3dc0)、sub_1400B5EC0(0x1400b5ec0)、sub_1400F6780(0x1400f6780)、sub_1400F6B00(0x1400f6b00)、sub_1400F6E80(0x1400f6e80)、sub_1400F7210(0x1400f7210)、sub_1400F75B0(0x1400f75b0)
 * 它叫谁: sub_14009B040(0x14009b040) → sub_1400AC310(0x1400ac310)
 * ------------------------------------------------------------ */
uint64_t sub_1400ACE30(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1098  0x1400aceb0  sub_1400ACEB0
 * 角色: Hook/隐藏    大小: 71 字节
 * 谁叫它: sub_1400B3DC0(0x1400b3dc0)
 * 它叫谁: sub_1400AC310(0x1400ac310) → sub_1400AF240(0x1400af240)
 * ------------------------------------------------------------ */
uint64_t sub_1400ACEB0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1168  0x1400b3cd0  sub_1400B3CD0
 * 角色: Hook/隐藏    大小: 238 字节
 * 谁叫它: sub_1400F6780(0x1400f6780)、sub_1400F6B00(0x1400f6b00)、sub_1400F6E80(0x1400f6e80)、sub_1400F7210(0x1400f7210)、sub_1400F75B0(0x1400f75b0)、sub_1400F7970(0x1400f7970)、sub_1400F7D50(0x1400f7d50)、sub_1400F8350(0x1400f8350)
 * 它叫谁: sub_1400AC4F0(0x1400ac4f0) → sub_1400ACE30(0x1400ace30)
 * ------------------------------------------------------------ */
uint64_t sub_1400B3CD0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1169  0x1400b3dc0  sub_1400B3DC0
 * 角色: Hook/隐藏    大小: 2665 字节
 * 谁叫它: sub_1400A1CF0(0x1400a1cf0)
 * 它叫谁: sub_14009B040(0x14009b040) → sub_1400AC310(0x1400ac310) → sub_1400ACE30(0x1400ace30) → sub_1400ACEB0(0x1400aceb0) → sub_1400ACF00(0x1400acf00) → sub_1400B2960(0x1400b2960) → sub_1400B3650(0x1400b3650) → sub_1400B3940(0x1400b3940)
 * ------------------------------------------------------------ */
uint64_t sub_1400B3DC0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1178  0x1400b5ec0  sub_1400B5EC0
 * 角色: Hook/隐藏    大小: 2461 字节
 * 谁叫它: sub_1400B3DC0(0x1400b3dc0)
 * 它叫谁: sub_14009B040(0x14009b040) → sub_1400A0D00(0x1400a0d00) → sub_1400AABC0(0x1400aabc0) → sub_1400AB5E0(0x1400ab5e0) → sub_1400ACE30(0x1400ace30) → sub_1400ACF00(0x1400acf00) → sub_1400AD0B0(0x1400ad0b0) → sub_1400AF390(0x1400af390)
 * ------------------------------------------------------------ */
uint64_t sub_1400B5EC0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1568  0x1400f6780  sub_1400F6780
 * 角色: Hook/隐藏    大小: 883 字节
 * 谁叫它: sub_1400E53A0(0x1400e53a0)
 * 它叫谁: sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FA8C0(0x1400fa8c0) → HV_Dispatch(0x1401536b0) → sub_1401DD760(0x1401dd760)
 * ------------------------------------------------------------ */
uint64_t sub_1400F6780(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1569  0x1400f6b00  sub_1400F6B00
 * 角色: Hook/隐藏    大小: 884 字节
 * 谁叫它: sub_1400E53A0(0x1400e53a0)
 * 它叫谁: sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FAF60(0x1400faf60) → HV_Dispatch(0x1401536b0) → sub_1401DD760(0x1401dd760)
 * ------------------------------------------------------------ */
uint64_t sub_1400F6B00(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1570  0x1400f6e80  sub_1400F6E80
 * 角色: Hook/隐藏    大小: 897 字节
 * 谁叫它: sub_1400E53A0(0x1400e53a0)
 * 它叫谁: sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FB670(0x1400fb670) → HV_Dispatch(0x1401536b0) → sub_1401DD760(0x1401dd760)
 * ------------------------------------------------------------ */
uint64_t sub_1400F6E80(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1571  0x1400f7210  sub_1400F7210
 * 角色: Hook/隐藏    大小: 922 字节
 * 谁叫它: sub_1400E53A0(0x1400e53a0)
 * 它叫谁: sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FBF80(0x1400fbf80) → HV_Dispatch(0x1401536b0) → sub_1401DD760(0x1401dd760)
 * ------------------------------------------------------------ */
uint64_t sub_1400F7210(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1572  0x1400f75b0  sub_1400F75B0
 * 角色: Hook/隐藏    大小: 946 字节
 * 谁叫它: sub_1400E53A0(0x1400e53a0)
 * 它叫谁: sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FC5C0(0x1400fc5c0) → HV_Dispatch(0x1401536b0) → sub_1401DD760(0x1401dd760)
 * ------------------------------------------------------------ */
uint64_t sub_1400F75B0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1573  0x1400f7970  sub_1400F7970
 * 角色: Hook/隐藏    大小: 979 字节
 * 谁叫它: sub_1400E53A0(0x1400e53a0)
 * 它叫谁: sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FCCE0(0x1400fcce0) → HV_Dispatch(0x1401536b0) → sub_1401DD760(0x1401dd760)
 * ------------------------------------------------------------ */
uint64_t sub_1400F7970(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1574  0x1400f7d50  sub_1400F7D50
 * 角色: Hook/隐藏    大小: 1534 字节
 * 谁叫它: sub_1400E5E70(0x1400e5e70)
 * 它叫谁: sub_1400A0D00(0x1400a0d00) → sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FA310(0x1400fa310) → sub_1400FA620(0x1400fa620) → sub_1400FA8C0(0x1400fa8c0)
 * ------------------------------------------------------------ */
uint64_t sub_1400F7D50(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1575  0x1400f8350  sub_1400F8350
 * 角色: Hook/隐藏    大小: 1540 字节
 * 谁叫它: sub_1400E5E70(0x1400e5e70)
 * 它叫谁: sub_1400A0D00(0x1400a0d00) → sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FA990(0x1400fa990) → sub_1400FACB0(0x1400facb0) → sub_1400FAF60(0x1400faf60)
 * ------------------------------------------------------------ */
uint64_t sub_1400F8350(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1576  0x1400f8960  sub_1400F8960
 * 角色: Hook/隐藏    大小: 1538 字节
 * 谁叫它: sub_1400E5E70(0x1400e5e70)
 * 它叫谁: sub_1400A0D00(0x1400a0d00) → sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FB030(0x1400fb030) → sub_1400FB3A0(0x1400fb3a0) → sub_1400FB670(0x1400fb670)
 * ------------------------------------------------------------ */
uint64_t sub_1400F8960(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1577  0x1400f8f70  sub_1400F8F70
 * 角色: Hook/隐藏    大小: 1576 字节
 * 谁叫它: sub_1400E5E70(0x1400e5e70)
 * 它叫谁: sub_1400A0D00(0x1400a0d00) → sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FB740(0x1400fb740) → sub_1400FBB80(0x1400fbb80) → sub_1400FBF80(0x1400fbf80)
 * ------------------------------------------------------------ */
uint64_t sub_1400F8F70(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1578  0x1400f95a0  sub_1400F95A0
 * 角色: Hook/隐藏    大小: 1580 字节
 * 谁叫它: sub_1400E5E70(0x1400e5e70)
 * 它叫谁: sub_1400A0D00(0x1400a0d00) → sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FC070(0x1400fc070) → sub_1400FC350(0x1400fc350) → sub_1400FC5C0(0x1400fc5c0)
 * ------------------------------------------------------------ */
uint64_t sub_1400F95A0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1579  0x1400f9bd0  sub_1400F9BD0
 * 角色: Hook/隐藏    大小: 1582 字节
 * 谁叫它: sub_1400E5E70(0x1400e5e70)
 * 它叫谁: sub_1400A0D00(0x1400a0d00) → sub_1400ACE30(0x1400ace30) → sub_1400B3CD0(0x1400b3cd0) → sub_1400E6A10(0x1400e6a10) → sub_1400FC6B0(0x1400fc6b0) → sub_1400FCA10(0x1400fca10) → sub_1400FCCE0(0x1400fcce0)
 * ------------------------------------------------------------ */
uint64_t sub_1400F9BD0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1682  0x14010b530  sub_14010B530
 * 角色: EPT/NPT内存映射    大小: 1478 字节
 * 谁叫它: sub_14010C900(0x14010c900)
 * 它叫谁: Lic_Smbios_SanitizeString(0x140109b10) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → sub_1401349F0(0x1401349f0)
 * ------------------------------------------------------------ */
uint64_t sub_14010B530(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   1684  0x14010bc10  sub_14010BC10
 * 角色: EPT/NPT内存映射    大小: 795 字节
 * 谁叫它: sub_14010C900(0x14010c900)
 * 它叫谁: Lic_Smbios_SanitizeString(0x140109b10) → sub_14010B340(0x14010b340) → sub_140114F60(0x140114f60) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0)
 * ------------------------------------------------------------ */
uint64_t sub_14010BC10(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   1687  0x14010d560  Lic_AppendPnpDevices
 * 角色: EPT/NPT内存映射    大小: 1140 字节
 * 谁叫它: Lic_AppendHwInventory(0x14010e920)
 * 它叫谁: Util_StringAppend(0x14005db00) → sub_140114F60(0x140114f60) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t Lic_AppendPnpDevices(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   1735  0x1401147a0  sub_1401147A0
 * 角色: EPT/NPT内存映射    大小: 617 字节
 * 谁叫它: sub_140114A10(0x140114a10)
 * 它叫谁: sub_140114540(0x140114540) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → HV_MemsetGuestVa(0x140152df0)
 * ------------------------------------------------------------ */
uint64_t sub_1401147A0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   1767  0x140118380  sub_140118380
 * 角色: EPT/NPT内存映射    大小: 453 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: HV_LookupEptEntry(0x140115220) → HV_HypercallDispatch(0x140117f20) → HV_TranslateGuestVa_Present(0x14011c2a0) → Esp_HookedRip_Dispatch(0x140123fe0)
 * ------------------------------------------------------------ */
uint64_t sub_140118380(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_LookupEptEntry */
    { uint64_t *e = hv_lookup_ept(dnz_root_primary(), p1, true);
      if (e) v = *e; }
    return v;
}

/* ------------------------------------------------------------
 *   1778  0x140119f40  sub_140119F40
 * 角色: EPT/NPT内存映射    大小: 783 字节
 * 谁叫它: sub_1401E0420(0x1401e0420)
 * 它叫谁: sub_140119E00(0x140119e00) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_TranslateGuestVa_Present(0x14011c2a0) → HV_Rdfsbase(0x14011fb50) → HV_EptInstallHook_RealVmx(0x140124cf0) → HV_EptRemoveHook_RealVmx(0x140124db0) → sub_14012C4F0(0x14012c4f0) → sub_140152AE0(0x140152ae0)
 * ------------------------------------------------------------ */
uint64_t sub_140119F40(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_EptInstallHook */
    { v = (uint64_t)hv_ept_install_hook(dnz_root_primary(), (uint32_t)p1, (uint32_t)p2); }
    return v;
}

/* ------------------------------------------------------------
 *   1849  0x1401237c0  sub_1401237C0
 * 角色: EPT/NPT内存映射    大小: 490 字节
 * 谁叫它: Esp_HookedRip_Dispatch(0x140123fe0)
 * 它叫谁: HV_LookupEptEntry(0x140115220) → HV_TranslateGuestVa_Present(0x14011c2a0) → sub_14011C820(0x14011c820) → HV_Rdfsbase(0x14011fb50) → sub_1401220B0(0x1401220b0) → sub_1401248E0(0x1401248e0) → Util_Memcpy(0x1401ea340)
 * ------------------------------------------------------------ */
uint64_t sub_1401237C0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_LookupEptEntry */
    { uint64_t *e = hv_lookup_ept(dnz_root_primary(), p1, true);
      if (e) v = *e; }
    return v;
}

/* ------------------------------------------------------------
 *   1890  0x140128680  sub_140128680
 * 角色: EPT/NPT内存映射    大小: 249 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: HV_ClearPendingExceptionState(0x140125f40) → sub_140127C20(0x140127c20)
 * ------------------------------------------------------------ */
uint64_t sub_140128680(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师: FNV-1a 哈希（prime 0x100000001B3） */
    { uint8_t b[8]; for (int i = 0; i < 8; i++) b[i] = (uint8_t)(p1 >> (i * 8));
      v = dnz_fnv1a(b, 8) & 0xFF; }
    /* 老师调用: HV_ClearPendingExceptionState */
    { v = (uint64_t)hv_clear_pending_exception_state(&g_dnz); }
    return v;
}

/* ------------------------------------------------------------
 *   1902  0x140129050  sub_140129050
 * 角色: EPT/NPT内存映射    大小: 890 字节
 * 谁叫它: sub_1401293D0(0x1401293d0)
 * 它叫谁: HV_TranslateGuestVa_Present(0x14011c2a0) → sub_14011C650(0x14011c650) → HV_Rdfsbase(0x14011fb50) → HV_EptInstallHook_RealVmx(0x140124cf0) → HV_EptRemoveHook_RealVmx(0x140124db0) → HV_EptHidePages_RealVmx(0x140124ea0) → HV_EptUnhidePages_RealVmx(0x1401250a0) → sub_140125260(0x140125260)
 * ------------------------------------------------------------ */
uint64_t sub_140129050(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_EptInstallHook */
    { v = (uint64_t)hv_ept_install_hook(dnz_root_primary(), (uint32_t)p1, (uint32_t)p2); }
    return v;
}

/* ------------------------------------------------------------
 *   1923  0x14012b0c0  sub_14012B0C0
 * 角色: EPT/NPT内存映射    大小: 170 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: HV_ClearPendingExceptionState(0x140125f40) → HV_CheckGuestCplAndReady(0x14012a120) → sub_14012B020(0x14012b020) → HV_VmresumeFromExit(0x14012d9f0)
 * ------------------------------------------------------------ */
uint64_t sub_14012B0C0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_ClearPendingExceptionState */
    { v = (uint64_t)hv_clear_pending_exception_state(&g_dnz); }
    return v;
}

/* ------------------------------------------------------------
 *   1953  0x14012f1f0  sub_14012F1F0
 * 角色: Hook/隐藏    大小: 1039 字节
 * 谁叫它: sub_140062650(0x140062650)
 * 它叫谁: sub_1401334B0(0x1401334b0) → HV_Dispatch(0x1401536b0) → Sys_CreateObjectByName(0x140154780) → sub_1401563C0(0x1401563c0) → Ob_RegisterCallbackOrNotify(0x1401d9bc0)
 * ------------------------------------------------------------ */
uint64_t sub_14012F1F0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   1976  0x140135c70  sub_140135C70
 * 角色: EPT/NPT内存映射    大小: 1184 字节
 * 谁叫它: sub_14003D950(0x14003d950)、sub_1401D9520(0x1401d9520)、sub_14E7FD27D(0x14e7fd27d)
 * 它叫谁: sub_14003E7E0(0x14003e7e0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_140135C70(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   1998  0x140138f20  sub_140138F20
 * 角色: EPT/NPT内存映射    大小: 2697 字节
 * 谁叫它: sub_1400620A0(0x1400620a0)、Esp_GetOrCreateFrameState(0x1400967d0)、sub_14011AB30(0x14011ab30)、sub_14011CFA0(0x14011cfa0)、sub_14011E970(0x14011e970)、sub_1401523C0(0x1401523c0)、Ob_RegisterCallbackOrNotify(0x1401d9bc0)
 * 它叫谁: sub_14003E7E0(0x14003e7e0) → sub_14003E9E0(0x14003e9e0) → sub_140051FA0(0x140051fa0) → ProcessDecryptedPacket(0x14005d800) → sub_1401034C0(0x1401034c0) → sub_140103520(0x140103520) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10)
 * ------------------------------------------------------------ */
uint64_t sub_140138F20(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   2044  0x140140c20  sub_140140C20
 * 角色: EPT/NPT内存映射    大小: 684 字节
 * 谁叫它: sub_1401523C0(0x1401523c0)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_GetGuestGsBase(0x14011cc30) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → HV_MemsetGuestVa(0x140152df0) → HV_Dispatch(0x1401536b0)
 * ------------------------------------------------------------ */
uint64_t sub_140140C20(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   2177  0x140157040  sub_140157040
 * 角色: EPT/NPT内存映射    大小: 1370 字节
 * 谁叫它: sub_140047080(0x140047080)、sub_14004EDD0(0x14004edd0)、sub_140067C00(0x140067c00)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → sub_1401349F0(0x1401349f0)
 * ------------------------------------------------------------ */
uint64_t sub_140157040(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   2190  0x140159830  sub_140159830
 * 角色: EPT/NPT内存映射    大小: 516 字节
 * 谁叫它: sub_14008A8E0(0x14008a8e0)、sub_140159C30(0x140159c30)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → sub_14011B930(0x14011b930) → HV_Rdgsbase(0x14011fb10) → sub_140154A80(0x140154a80) → sub_140156860(0x140156860) → sub_140158350(0x140158350) → sub_140159200(0x140159200) → sub_1401DFFC0(0x1401dffc0)
 * ------------------------------------------------------------ */
uint64_t sub_140159830(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   2195  0x14015aef0  sub_14015AEF0
 * 角色: Hook/隐藏    大小: 836 字节
 * 谁叫它: sub_14015B240(0x14015b240)
 * 它叫谁: sub_1401E4360(0x1401e4360) → sub_1401E8450(0x1401e8450)
 * ------------------------------------------------------------ */
uint64_t sub_14015AEF0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2196  0x14015b240  sub_14015B240
 * 角色: Hook/隐藏    大小: 597 字节
 * 谁叫它: sub_14015C420(0x14015c420)、sub_14015C740(0x14015c740)
 * 它叫谁: sub_14015AEF0(0x14015aef0) → sub_1401E4360(0x1401e4360) → sub_1401E8450(0x1401e8450)
 * ------------------------------------------------------------ */
uint64_t sub_14015B240(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2198  0x14015b960  sub_14015B960
 * 角色: Hook/隐藏    大小: 893 字节
 * 谁叫它: Hook_InstallAll(0x1401891d0)
 * 它叫谁: sub_14014C400(0x14014c400) → Util_FreeWideOrHeap(0x14014c450) → sub_14015B4A0(0x14015b4a0) → Hv_ReadGuestU32(0x14015cf60) → sub_14015D2D0(0x14015d2d0) → Hv_WriteGuestPtr(0x14015d480) → Hv_ReadGuestU64(0x14015d5c0) → sub_1401755B0(0x1401755b0)
 * ------------------------------------------------------------ */
uint64_t sub_14015B960(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2199  0x14015bce0  sub_14015BCE0
 * 角色: Hook/隐藏    大小: 1489 字节
 * 谁叫它: Hook_InstallAll(0x1401891d0)
 * 它叫谁: Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU32(0x14015cf60) → sub_14015D2D0(0x14015d2d0) → sub_14015D6D0(0x14015d6d0) → Hv_ReadGuestBytes(0x14015d900) → sub_14015DB10(0x14015db10) → sub_14015DCF0(0x14015dcf0)
 * ------------------------------------------------------------ */
uint64_t sub_14015BCE0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2222  0x14015eae0  sub_14015EAE0
 * 角色: Hook/隐藏    大小: 1636 字节
 * 谁叫它: sub_14015F150(0x14015f150)
 * 它叫谁: sub_140052310(0x140052310) → sub_1401777E0(0x1401777e0) → Util_Memcpy(0x1401ea340)
 * ------------------------------------------------------------ */
uint64_t sub_14015EAE0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2260  0x140163720  sub_140163720
 * 角色: Hook/隐藏    大小: 183 字节
 * 谁叫它: sub_140165F30(0x140165f30)
 * 它叫谁: Hv_ReadGuestU64(0x14015d5c0) → sub_140176310(0x140176310)
 * ------------------------------------------------------------ */
uint64_t sub_140163720(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2261  0x1401637e0  sub_1401637E0
 * 角色: Hook/隐藏    大小: 802 字节
 * 谁叫它: sub_140165F30(0x140165f30)、sub_140166200(0x140166200)
 * 它叫谁: sub_140166AF0(0x140166af0) → sub_1401753D0(0x1401753d0)
 * ------------------------------------------------------------ */
uint64_t sub_1401637E0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2264  0x140163ef0  sub_140163EF0
 * 角色: Hook/隐藏    大小: 1315 字节
 * 谁叫它: sub_140166690(0x140166690)
 * 它叫谁: sub_140067180(0x140067180) → sub_140163360(0x140163360) → sub_1401636C0(0x1401636c0) → sub_140163B10(0x140163b10) → sub_140167700(0x140167700) → sub_140167780(0x140167780)
 * ------------------------------------------------------------ */
uint64_t sub_140163EF0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2268  0x140164f60  sub_140164F60
 * 角色: Hook/隐藏    大小: 2348 字节
 * 谁叫它: sub_140165F30(0x140165f30)
 * 它叫谁: sub_14015D2D0(0x14015d2d0) → Hv_ReadGuestBytes(0x14015d900) → sub_1401634D0(0x1401634d0) → sub_140164650(0x140164650) → sub_140164950(0x140164950) → sub_140166D10(0x140166d10) → sub_140166EB0(0x140166eb0) → sub_1401670D0(0x1401670d0)
 * ------------------------------------------------------------ */
uint64_t sub_140164F60(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2269  0x140165890  sub_140165890
 * 角色: Hook/隐藏    大小: 591 字节
 * 谁叫它: sub_140165F30(0x140165f30)
 * 它叫谁: Hv_ReadGuestU64(0x14015d5c0) → sub_140163330(0x140163330) → sub_140163360(0x140163360) → sub_140167340(0x140167340)
 * ------------------------------------------------------------ */
uint64_t sub_140165890(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2270  0x140165ae0  sub_140165AE0
 * 角色: Hook/隐藏    大小: 267 字节
 * 谁叫它: sub_140165D30(0x140165d30)
 * 它叫谁: Rtl_AtExitListPush(0x1400ff200) → Hv_ReadGuestU64(0x14015d5c0) → sub_140166D10(0x140166d10)
 * ------------------------------------------------------------ */
uint64_t sub_140165AE0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2271  0x140165bf0  sub_140165BF0
 * 角色: Hook/隐藏    大小: 311 字节
 * 谁叫它: sub_140165BF0(0x140165bf0)、sub_140165D30(0x140165d30)
 * 它叫谁: Rtl_AtExitListPush(0x1400ff200) → Hv_ReadGuestU64(0x14015d5c0) → sub_140166D10(0x140166d10)
 * ------------------------------------------------------------ */
uint64_t sub_140165BF0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2272  0x140165d30  sub_140165D30
 * 角色: Hook/隐藏    大小: 501 字节
 * 谁叫它: sub_140166200(0x140166200)
 * 它叫谁: Rtl_AtExitListPush(0x1400ff200) → Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_140165AE0(0x140165ae0) → sub_140165BF0(0x140165bf0) → sub_140166D10(0x140166d10) → sub_140184D90(0x140184d90)
 * ------------------------------------------------------------ */
uint64_t sub_140165D30(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2273  0x140165f30  sub_140165F30
 * 角色: Hook/隐藏    大小: 714 字节
 * 谁叫它: sub_140166200(0x140166200)
 * 它叫谁: Hv_ReadGuestU64(0x14015d5c0) → sub_140163720(0x140163720) → sub_1401637E0(0x1401637e0) → sub_140164650(0x140164650) → sub_140164F60(0x140164f60) → sub_140165890(0x140165890)
 * ------------------------------------------------------------ */
uint64_t sub_140165F30(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2274  0x140166200  sub_140166200
 * 角色: Hook/隐藏    大小: 1154 字节
 * 谁叫它: sub_140166690(0x140166690)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → Mem_HeapAlloc(0x140133e10) → HV_Dispatch(0x1401536b0) → sub_1401637E0(0x1401637e0) → sub_140163B10(0x140163b10) → sub_140165D30(0x140165d30) → sub_140165F30(0x140165f30) → sub_1401755B0(0x1401755b0)
 * ------------------------------------------------------------ */
uint64_t sub_140166200(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2275  0x140166690  sub_140166690
 * 角色: Hook/隐藏    大小: 1106 字节
 * 谁叫它: Hook_InstallAll(0x1401891d0)
 * 它叫谁: sub_140066ED0(0x140066ed0) → sub_140067020(0x140067020) → sub_140067200(0x140067200) → sub_14014E4F0(0x14014e4f0) → sub_14015D2D0(0x14015d2d0) → sub_140163EF0(0x140163ef0) → sub_140166200(0x140166200) → sub_140167780(0x140167780)
 * ------------------------------------------------------------ */
uint64_t sub_140166690(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2283  0x140167780  sub_140167780
 * 角色: Hook/隐藏    大小: 400 字节
 * 谁叫它: sub_140163EF0(0x140163ef0)、sub_140166690(0x140166690)、sub_140169C10(0x140169c10)、sub_140169CD0(0x140169cd0)、sub_14016A980(0x14016a980)、sub_14016DD70(0x14016dd70)、sub_140171E10(0x140171e10)、sub_140186D90(0x140186d90)
 * 它叫谁: sub_1401E9260(0x1401e9260)
 * ------------------------------------------------------------ */
uint64_t sub_140167780(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2286  0x140167e60  sub_140167E60
 * 角色: Hook/隐藏    大小: 468 字节
 * 谁叫它: sub_14016A130(0x14016a130)
 * 它叫谁: sub_140167910(0x140167910)
 * ------------------------------------------------------------ */
uint64_t sub_140167E60(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师: FNV-1a 哈希（prime 0x100000001B3） */
    { uint8_t b[8]; for (int i = 0; i < 8; i++) b[i] = (uint8_t)(p1 >> (i * 8));
      v = dnz_fnv1a(b, 8) & 0xFF; }
    return v;
}

/* ------------------------------------------------------------
 *   2287  0x140168040  sub_140168040
 * 角色: Hook/隐藏    大小: 995 字节
 * 谁叫它: sub_14016DD70(0x14016dd70)
 * 它叫谁: sub_140167910(0x140167910)
 * ------------------------------------------------------------ */
uint64_t sub_140168040(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2289  0x1401686a0  sub_1401686A0
 * 角色: Hook/隐藏    大小: 104 字节
 * 谁叫它: sub_14016DD70(0x14016dd70)
 * 它叫谁: sub_14015D2D0(0x14015d2d0)
 * ------------------------------------------------------------ */
uint64_t sub_1401686A0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2292  0x140168a70  sub_140168A70
 * 角色: Hook/隐藏    大小: 1542 字节
 * 谁叫它: Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: Hv_WriteGuestU64(0x14015d100) → Hv_ReadGuestU64(0x14015d5c0) → Hv_ReadGuestBytes(0x14015d900) → sub_140166D10(0x140166d10) → sub_1401687E0(0x1401687e0) → sub_14016B1C0(0x14016b1c0) → sub_14016B300(0x14016b300) → sub_14016B410(0x14016b410)
 * ------------------------------------------------------------ */
uint64_t sub_140168A70(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2297  0x140169cd0  sub_140169CD0
 * 角色: Hook/隐藏    大小: 1120 字节
 * 谁叫它: sub_14016A130(0x14016a130)、sub_14016DD70(0x14016dd70)
 * 它叫谁: sub_140167780(0x140167780) → sub_140169080(0x140169080) → sub_1401696C0(0x1401696c0) → sub_1401944D0(0x1401944d0) → sub_1401E9260(0x1401e9260)
 * ------------------------------------------------------------ */
uint64_t sub_140169CD0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2298  0x14016a130  sub_14016A130
 * 角色: Hook/隐藏    大小: 504 字节
 * 谁叫它: sub_140166690(0x140166690)、sub_140186D90(0x140186d90)
 * 它叫谁: sub_140167E60(0x140167e60) → sub_140169C10(0x140169c10) → sub_140169CD0(0x140169cd0) → sub_14016B8D0(0x14016b8d0) → DnsPrint_ParsedMessage(0x140185840)
 * ------------------------------------------------------------ */
uint64_t sub_14016A130(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2299  0x14016a330  sub_14016A330
 * 角色: Hook/隐藏    大小: 983 字节
 * 谁叫它: sub_14016A980(0x14016a980)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_14016A330(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2300  0x14016a710  sub_14016A710
 * 角色: Hook/隐藏    大小: 154 字节
 * 谁叫它: sub_14016A7B0(0x14016a7b0)、sub_14016A980(0x14016a980)
 * 它叫谁: Hv_ReadGuestU64(0x14015d5c0) → sub_14016B540(0x14016b540)
 * ------------------------------------------------------------ */
uint64_t sub_14016A710(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2301  0x14016a7b0  sub_14016A7B0
 * 角色: Hook/隐藏    大小: 462 字节
 * 谁叫它: sub_14016A980(0x14016a980)
 * 它叫谁: sub_14015D2D0(0x14015d2d0) → Hv_ReadGuestU64(0x14015d5c0) → sub_14016A710(0x14016a710) → sub_14016B540(0x14016b540) → sub_1401755B0(0x1401755b0)
 * ------------------------------------------------------------ */
uint64_t sub_14016A7B0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2318  0x14016cdc0  sub_14016CDC0
 * 角色: Hook/隐藏    大小: 514 字节
 * 谁叫它: sub_140186D90(0x140186d90)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_140171410(0x140171410) → sub_140171580(0x140171580) → sub_140171800(0x140171800) → sub_1401755B0(0x1401755b0)
 * ------------------------------------------------------------ */
uint64_t sub_14016CDC0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2320  0x14016d230  sub_14016D230
 * 角色: Hook/隐藏    大小: 1409 字节
 * 谁叫它: sub_14016DD70(0x14016dd70)、sub_1401703F0(0x1401703f0)、Hook_InstallAll(0x1401891d0)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → sub_140053A20(0x140053a20) → Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_140166D10(0x140166d10) → sub_14016CD20(0x14016cd20) → sub_140170E00(0x140170e00)
 * ------------------------------------------------------------ */
uint64_t sub_14016D230(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2321  0x14016d7c0  sub_14016D7C0
 * 角色: Hook/隐藏    大小: 1019 字节
 * 谁叫它: sub_14016DBC0(0x14016dbc0)、sub_14016DD70(0x14016dd70)、sub_1401703F0(0x1401703f0)、sub_140186D90(0x140186d90)
 * 它叫谁: sub_140066ED0(0x140066ed0) → sub_140067180(0x140067180) → sub_1400CB720(0x1400cb720) → HV_Dispatch(0x1401536b0) → sub_140167700(0x140167700)
 * ------------------------------------------------------------ */
uint64_t sub_14016D7C0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2322  0x14016dbc0  sub_14016DBC0
 * 角色: Hook/隐藏    大小: 430 字节
 * 谁叫它: sub_14016DD70(0x14016dd70)、sub_1401703F0(0x1401703f0)
 * 它叫谁: sub_140138660(0x140138660) → sub_14014E4F0(0x14014e4f0) → Hv_ReadGuestU64(0x14015d5c0) → sub_14016D7C0(0x14016d7c0) → sub_1401755B0(0x1401755b0) → sub_1401939D0(0x1401939d0) → sub_140193AA0(0x140193aa0)
 * ------------------------------------------------------------ */
uint64_t sub_14016DBC0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2324  0x140170330  sub_140170330
 * 角色: Hook/隐藏    大小: 191 字节
 * 谁叫它: sub_14016DD70(0x14016dd70)、sub_1401703F0(0x1401703f0)
 * 它叫谁: Hv_ReadGuestBytes(0x14015d900) → sub_1401755B0(0x1401755b0)
 * ------------------------------------------------------------ */
uint64_t sub_140170330(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2325  0x1401703f0  sub_1401703F0
 * 角色: Hook/隐藏    大小: 2415 字节
 * 谁叫它: sub_140186D90(0x140186d90)
 * 它叫谁: sub_14014E4F0(0x14014e4f0) → sub_14015C2C0(0x14015c2c0) → sub_14015C420(0x14015c420) → sub_14015C5A0(0x14015c5a0) → sub_14015C740(0x14015c740) → Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU32(0x14015cf60) → sub_14015D2D0(0x14015d2d0)
 * ------------------------------------------------------------ */
uint64_t sub_1401703F0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2326  0x140170d60  sub_140170D60
 * 角色: Hook/隐藏    大小: 151 字节
 * 谁叫它: sub_1401703F0(0x1401703f0)
 * 它叫谁: Hv_ReadGuestU64(0x14015d5c0) → sub_1401755B0(0x1401755b0)
 * ------------------------------------------------------------ */
uint64_t sub_140170D60(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2342  0x140172be0  sub_140172BE0
 * 角色: Hook/隐藏    大小: 622 字节
 * 谁叫它: sub_140186D90(0x140186d90)
 * 它叫谁: Hv_ReadGuestU64(0x14015d5c0) → sub_1401616B0(0x1401616b0) → sub_1401619E0(0x1401619e0) → sub_140166D10(0x140166d10) → sub_140171090(0x140171090) → sub_140172AB0(0x140172ab0) → sub_140172E50(0x140172e50)
 * ------------------------------------------------------------ */
uint64_t sub_140172BE0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2343  0x140172e50  sub_140172E50
 * 角色: Hook/隐藏    大小: 144 字节
 * 谁叫它: sub_140172BE0(0x140172be0)、sub_140172EE0(0x140172ee0)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → sub_1401755B0(0x1401755b0) → sub_140176310(0x140176310) → sub_1401D2EF0(0x1401d2ef0)
 * ------------------------------------------------------------ */
uint64_t sub_140172E50(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2344  0x140172ee0  sub_140172EE0
 * 角色: Hook/隐藏    大小: 1529 字节
 * 谁叫它: sub_140186D90(0x140186d90)
 * 它叫谁: sub_140066ED0(0x140066ed0) → sub_140067020(0x140067020) → sub_1400673C0(0x1400673c0) → sub_14009CE00(0x14009ce00) → sub_14014E4F0(0x14014e4f0) → Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU64(0x14015d5c0) → sub_1401616B0(0x1401616b0)
 * ------------------------------------------------------------ */
uint64_t sub_140172EE0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2347  0x1401739e0  sub_1401739E0
 * 角色: Hook/隐藏    大小: 360 字节
 * 谁叫它: sub_140186D90(0x140186d90)
 * 它叫谁: sub_140066ED0(0x140066ed0) → sub_140067200(0x140067200) → sub_14014E4F0(0x14014e4f0) → sub_14015D2D0(0x14015d2d0) → sub_140171E10(0x140171e10)
 * ------------------------------------------------------------ */
uint64_t sub_1401739E0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2362  0x1401750b0  sub_1401750B0
 * 角色: Hook/隐藏    大小: 170 字节
 * 谁叫它: Hook_InstallAll(0x1401891d0)
 * 它叫谁: Hv_ReadGuestU8(0x14015cdc0) → Hv_WriteGuestU64(0x14015d100) → sub_14015D240(0x14015d240)
 * ------------------------------------------------------------ */
uint64_t sub_1401750B0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2370  0x140176080  sub_140176080
 * 角色: Hook/隐藏    大小: 144 字节
 * 谁叫它: sub_140172840(0x140172840)、sub_140176110(0x140176110)、sub_140176160(0x140176160)、sub_140176310(0x140176310)
 * 它叫谁: sub_14014FEE0(0x14014fee0) → sub_140175D20(0x140175d20) → sub_140176810(0x140176810)
 * ------------------------------------------------------------ */
uint64_t sub_140176080(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2372  0x140176160  sub_140176160
 * 角色: Hook/隐藏    大小: 100 字节
 * 谁叫它: sub_140184AD0(0x140184ad0)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → sub_140176080(0x140176080) → sub_1401E9D70(0x1401e9d70)
 * ------------------------------------------------------------ */
uint64_t sub_140176160(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2373  0x1401761d0  sub_1401761D0
 * 角色: Hook/隐藏    大小: 305 字节
 * 谁叫它: sub_14015B960(0x14015b960)
 * 它叫谁: sub_1400FD010(0x1400fd010) → HV_Rdgsbase(0x14011fb10) → Hv_ReadGuestU64(0x14015d5c0) → sub_14015DF90(0x14015df90)
 * ------------------------------------------------------------ */
uint64_t sub_1401761D0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2374  0x140176310  sub_140176310
 * 角色: Hook/隐藏    大小: 474 字节
 * 谁叫它: sub_14015B960(0x14015b960)、sub_140163720(0x140163720)、sub_14016DD70(0x14016dd70)、sub_140172E50(0x140172e50)、sub_140186D90(0x140186d90)、Hook_InstallAll(0x1401891d0)、Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: Mem_HeapAlloc(0x140133e10) → HV_Dispatch(0x1401536b0) → Hv_ReadGuestU32(0x14015cf60) → sub_1401625B0(0x1401625b0) → sub_140176080(0x140176080) → sub_140176B60(0x140176b60) → sub_1401E9D70(0x1401e9d70)
 * ------------------------------------------------------------ */
uint64_t sub_140176310(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2394  0x1401788e0  sub_1401788E0
 * 角色: Hook/隐藏    大小: 492 字节
 * 谁叫它: sub_140178AD0(0x140178ad0)
 * 它叫谁: sub_1401852D0(0x1401852d0)
 * ------------------------------------------------------------ */
uint64_t sub_1401788E0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2395  0x140178ad0  sub_140178AD0
 * 角色: Hook/隐藏    大小: 216 字节
 * 谁叫它: sub_1401790B0(0x1401790b0)、sub_14017BDB0(0x14017bdb0)、sub_14017BFA0(0x14017bfa0)
 * 它叫谁: sub_14016B540(0x14016b540) → sub_1401788E0(0x1401788e0) → sub_1401D6C10(0x1401d6c10)
 * ------------------------------------------------------------ */
uint64_t sub_140178AD0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2399  0x1401790b0  sub_1401790B0
 * 角色: Hook/隐藏    大小: 650 字节
 * 谁叫它: sub_14017EFC0(0x14017efc0)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → HV_Rdgsbase(0x14011fb10) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_1401777E0(0x1401777e0) → sub_1401778F0(0x1401778f0) → sub_1401779D0(0x1401779d0) → sub_140177B90(0x140177b90)
 * ------------------------------------------------------------ */
uint64_t sub_1401790B0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: Mem_HeapFreeTracked */
    dnz_pool_free_frame(p1);
    return v;
}

/* ------------------------------------------------------------
 *   2400  0x140179340  sub_140179340
 * 角色: Hook/隐藏    大小: 498 字节
 * 谁叫它: sub_140179540(0x140179540)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_140176810(0x140176810)
 * ------------------------------------------------------------ */
uint64_t sub_140179340(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2401  0x140179540  sub_140179540
 * 角色: Hook/隐藏    大小: 587 字节
 * 谁叫它: Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → Hv_WriteGuestU64(0x14015d100) → Hv_ReadGuestU64(0x14015d5c0) → sub_140178FB0(0x140178fb0) → sub_140179340(0x140179340) → sub_140180A80(0x140180a80) → sub_140181890(0x140181890)
 * ------------------------------------------------------------ */
uint64_t sub_140179540(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2402  0x140179790  sub_140179790
 * 角色: Hook/隐藏    大小: 760 字节
 * 谁叫它: Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → Hv_WriteGuestU64(0x14015d100) → Hv_ReadGuestU64(0x14015d5c0) → sub_140178FB0(0x140178fb0) → sub_140180A80(0x140180a80) → sub_140181890(0x140181890)
 * ------------------------------------------------------------ */
uint64_t sub_140179790(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2404  0x140179af0  sub_140179AF0
 * 角色: Hook/隐藏    大小: 431 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: sub_14014E4F0(0x14014e4f0)
 * ------------------------------------------------------------ */
uint64_t sub_140179AF0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2412  0x14017ad80  sub_14017AD80
 * 角色: Hook/隐藏    大小: 278 字节
 * 谁叫它: sub_14017BDB0(0x14017bdb0)、sub_14017BFA0(0x14017bfa0)
 * 它叫谁: sub_1400FF650(0x1400ff650)
 * ------------------------------------------------------------ */
uint64_t sub_14017AD80(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师: FNV-1a 哈希（prime 0x100000001B3） */
    { uint8_t b[8]; for (int i = 0; i < 8; i++) b[i] = (uint8_t)(p1 >> (i * 8));
      v = dnz_fnv1a(b, 8) & 0xFF; }
    /* 老师: 跨核原子操作（InterlockedExchange/CompareExchange） */
    { static volatile int64_t lk = 0;
      while (dnz_cas(&lk, 0, 1) == 1) { }
      dnz_cas(&lk, 1, 0); }
    return v;
}

/* ------------------------------------------------------------
 *   2415  0x14017b160  sub_14017B160
 * 角色: Hook/隐藏    大小: 1182 字节
 * 谁叫它: Hv_ReadProcessListFromGuest(0x14017b970)
 * 它叫谁: Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_140176810(0x140176810) → sub_14017B030(0x14017b030)
 * ------------------------------------------------------------ */
uint64_t sub_14017B160(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2416  0x14017b600  sub_14017B600
 * 角色: Hook/隐藏    大小: 872 字节
 * 谁叫它: sub_14017BAF0(0x14017baf0)
 * 它叫谁: Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_140176810(0x140176810) → sub_14017B030(0x14017b030) → Util_Memset(0x1401ea040)
 * ------------------------------------------------------------ */
uint64_t sub_14017B600(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2418  0x14017baf0  sub_14017BAF0
 * 角色: Hook/隐藏    大小: 703 字节
 * 谁叫它: Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU32(0x14015cf60) → Hv_WriteGuestU64(0x14015d100) → Hv_ReadGuestU64(0x14015d5c0) → Hook_LookupByPid(0x14017abc0) → Hook_LogListEntry(0x14017aea0) → sub_14017B600(0x14017b600) → sub_140180D20(0x140180d20)
 * ------------------------------------------------------------ */
uint64_t sub_14017BAF0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: Hook_LookupByPid */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1); if (h) v = h->pid; }
    return v;
}

/* ------------------------------------------------------------
 *   2419  0x14017bdb0  sub_14017BDB0
 * 角色: Hook/隐藏    大小: 488 字节
 * 谁叫它: sub_14017DDB0(0x14017ddb0)、sub_14017EFC0(0x14017efc0)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → HV_Rdgsbase(0x14011fb10) → sub_140178440(0x140178440) → sub_140178AD0(0x140178ad0) → Hook_InstallNtApi_Set2(0x140178bb0) → sub_14017AB20(0x14017ab20) → sub_14017AD80(0x14017ad80) → sub_140180D20(0x140180d20)
 * ------------------------------------------------------------ */
uint64_t sub_14017BDB0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师: 跨核原子操作（InterlockedExchange/CompareExchange） */
    { static volatile int64_t lk = 0;
      while (dnz_cas(&lk, 0, 1) == 1) { }
      dnz_cas(&lk, 1, 0); }
    return v;
}

/* ------------------------------------------------------------
 *   2420  0x14017bfa0  sub_14017BFA0
 * 角色: Hook/隐藏    大小: 814 字节
 * 谁叫它: sub_14017DDB0(0x14017ddb0)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → HV_FlushOrSyncAfterRegister(0x14003e1e0) → HV_Rdgsbase(0x14011fb10) → Util_Snprintf(0x14014e6b0) → sub_1401786F0(0x1401786f0) → sub_140178AD0(0x140178ad0) → Hook_InstallNtApi_Set2(0x140178bb0) → sub_14017AB20(0x14017ab20)
 * ------------------------------------------------------------ */
uint64_t sub_14017BFA0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2433  0x14017efc0  sub_14017EFC0
 * 角色: Hook/隐藏    大小: 5055 字节
 * 谁叫它: sub_14E8116D1(0x14e8116d1)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → sub_140053A20(0x140053a20) → sub_14009C2D0(0x14009c2d0) → sub_1400A0EA0(0x1400a0ea0) → sub_1400A7FD0(0x1400a7fd0) → sub_1400AA4B0(0x1400aa4b0) → sub_1400AB4C0(0x1400ab4c0) → sub_1400AB560(0x1400ab560)
 * ------------------------------------------------------------ */
uint64_t sub_14017EFC0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2444  0x140181310  sub_140181310
 * 角色: Hook/隐藏    大小: 752 字节
 * 谁叫它: sub_14017AB20(0x14017ab20)
 * 它叫谁: nullsub_3(0x140002790) → Mem_HeapAlloc(0x140133e10) → HV_Dispatch(0x1401536b0) → sub_140183F30(0x140183f30) → sub_1401E9C60(0x1401e9c60)
 * ------------------------------------------------------------ */
uint64_t sub_140181310(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2462  0x140183f30  sub_140183F30
 * 角色: Hook/隐藏    大小: 446 字节
 * 谁叫它: sub_140181310(0x140181310)
 * 它叫谁: nullsub_3(0x140002790) → sub_140066620(0x140066620)
 * ------------------------------------------------------------ */
uint64_t sub_140183F30(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2470  0x140184d90  sub_140184D90
 * 角色: Hook/隐藏    大小: 95 字节
 * 谁叫它: sub_140165D30(0x140165d30)、sub_1401881D0(0x1401881d0)
 * 它叫谁: Hv_ReadGuestU64(0x14015d5c0) → sub_140176810(0x140176810)
 * ------------------------------------------------------------ */
uint64_t sub_140184D90(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2471  0x140184df0  sub_140184DF0
 * 角色: Hook/隐藏    大小: 1247 字节
 * 谁叫它: sub_1401852D0(0x1401852d0)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → Util_StringAppend(0x14005db00) → sub_14007C270(0x14007c270) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140176810(0x140176810) → sub_140184AD0(0x140184ad0) → sub_1401E98C0(0x1401e98c0)
 * ------------------------------------------------------------ */
uint64_t sub_140184DF0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: Mem_HeapFreeTracked */
    dnz_pool_free_frame(p1);
    return v;
}

/* ------------------------------------------------------------
 *   2472  0x1401852d0  sub_1401852D0
 * 角色: Hook/隐藏    大小: 493 字节
 * 谁叫它: sub_1401788E0(0x1401788e0)、sub_140189000(0x140189000)、Hook_InstallAll(0x1401891d0)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_140176810(0x140176810) → sub_140184DF0(0x140184df0) → sub_1401E98C0(0x1401e98c0)
 * ------------------------------------------------------------ */
uint64_t sub_1401852D0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: Mem_HeapFreeTracked */
    dnz_pool_free_frame(p1);
    return v;
}

/* ------------------------------------------------------------
 *   2488  0x140186cb0  sub_140186CB0
 * 角色: Hook/隐藏    大小: 223 字节
 * 谁叫它: sub_140186D90(0x140186d90)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → sub_1401755B0(0x1401755b0)
 * ------------------------------------------------------------ */
uint64_t sub_140186CB0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2490  0x140187b90  sub_140187B90
 * 角色: Hook/隐藏    大小: 709 字节
 * 谁叫它: Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: Hv_ReadGuestU32(0x14015cf60) → sub_14015D2D0(0x14015d2d0) → Hv_ReadGuestU64(0x14015d5c0) → sub_1401755B0(0x1401755b0) → sub_14018CC80(0x14018cc80)
 * ------------------------------------------------------------ */
uint64_t sub_140187B90(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2491  0x140187e60  sub_140187E60
 * 角色: Hook/隐藏    大小: 870 字节
 * 谁叫它: Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: HV_FlushOrSyncAfterRegister(0x14003e1e0) → HV_HandlePendingEvent(0x140127b80) → Hv_WriteGuestU64(0x14015d100) → Hv_WriteGuestPtr(0x14015d480) → Hv_ReadGuestU64(0x14015d5c0) → Hv_ReadGuestBytes(0x14015d900) → sub_140176110(0x140176110) → sub_140176FD0(0x140176fd0)
 * ------------------------------------------------------------ */
uint64_t sub_140187E60(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2492  0x1401881d0  sub_1401881D0
 * 角色: Hook/隐藏    大小: 682 字节
 * 谁叫它: Hook_NtApi_VmExitHandler(0x1401906e0)
 * 它叫谁: Hv_ReadGuestU8(0x14015cdc0) → Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → sub_14016B410(0x14016b410) → sub_140184D90(0x140184d90) → sub_14018C6B0(0x14018c6b0)
 * ------------------------------------------------------------ */
uint64_t sub_1401881D0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2493  0x140188480  sub_140188480
 * 角色: Hook/隐藏    大小: 893 字节
 * 谁叫它: Hook_InstallAll(0x1401891d0)
 * 它叫谁: sub_14015D2D0(0x14015d2d0) → Hv_ReadGuestU64(0x14015d5c0)
 * ------------------------------------------------------------ */
uint64_t sub_140188480(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2495  0x140188dd0  sub_140188DD0
 * 角色: Hook/隐藏    大小: 553 字节
 * 谁叫它: sub_140189000(0x140189000)
 * 它叫谁: sub_14014C400(0x14014c400) → Util_FreeWideOrHeap(0x14014c450) → Hv_ReadGuestU32(0x14015cf60) → Hv_ReadGuestU64(0x14015d5c0) → Util_Memset(0x1401ea040)
 * ------------------------------------------------------------ */
uint64_t sub_140188DD0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2496  0x140189000  sub_140189000
 * 角色: Hook/隐藏    大小: 453 字节
 * 谁叫它: Hook_InstallAll(0x1401891d0)
 * 它叫谁: sub_1401852D0(0x1401852d0) → sub_140188DD0(0x140188dd0)
 * ------------------------------------------------------------ */
uint64_t sub_140189000(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2522  0x14018f3a0  sub_14018F3A0
 * 角色: Hook/隐藏    大小: 2256 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: sub_140061AD0(0x140061ad0) → sub_140078940(0x140078940) → sub_14007D1A0(0x14007d1a0) → sub_14007DC90(0x14007dc90) → sub_14007E010(0x14007e010) → sub_14007F300(0x14007f300) → sub_1400DF750(0x1400df750) → sub_14011E1D0(0x14011e1d0)
 * ------------------------------------------------------------ */
uint64_t sub_14018F3A0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2524  0x14018fd70  sub_14018FD70
 * 角色: Hook/隐藏    大小: 782 字节
 * 谁叫它: Esp_PeriodicTick(0x1401905a0)、sub_14E813ABB(0x14e813abb)、sub_14E8142E8(0x14e8142e8)
 * 它叫谁: sub_1400ACE30(0x1400ace30) → sub_1400ACF00(0x1400acf00) → sub_14018D230(0x14018d230)
 * ------------------------------------------------------------ */
uint64_t sub_14018FD70(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   2538  0x1401931e0  sub_1401931E0
 * 角色: EPT/NPT内存映射    大小: 1490 字节
 * 谁叫它: sub_14E813ABB(0x14e813abb)
 * 它叫谁: sub_1400841F0(0x1400841f0) → sub_140084CF0(0x140084cf0) → sub_140087AD0(0x140087ad0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0)
 * ------------------------------------------------------------ */
uint64_t sub_1401931E0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *   3241  0x1401d2e30  sub_1401D2E30
 * 角色: Hook/隐藏    大小: 11 字节
 * 谁叫它: sub_1401948F0(0x1401948f0)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_1401D2E30(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   3258  0x1401d4110  sub_1401D4110
 * 角色: Hook/隐藏    大小: 2384 字节
 * 谁叫它: sub_14E813345(0x14e813345)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_1401D4110(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   3262  0x1401d6bb0  sub_1401D6BB0
 * 角色: Hook/隐藏    大小: 85 字节
 * 谁叫它: sub_14E811E71(0x14e811e71)
 * 它叫谁: sub_1400FD010(0x1400fd010)
 * ------------------------------------------------------------ */
uint64_t sub_1401D6BB0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *   3278  0x1401da2c0  sub_1401DA2C0
 * 角色: EPT/NPT内存映射    大小: 674 字节
 * 谁叫它: Mem_WritePhysicalOrProbe(0x1401da570)、Ob_UnregisterCallbackOrClose(0x1401dada0)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → Rtl_AtExitListPush(0x1400ff200) → sub_140139ED0(0x140139ed0) → Util_FreeWideOrHeap(0x14014c450) → sub_1401D9E00(0x1401d9e00) → sub_1401D9F20(0x1401d9f20) → HV_RemoveEptHook_Wrapper(0x1401da0b0) → Util_Memcpy(0x1401ea340)
 * ------------------------------------------------------------ */
uint64_t sub_1401DA2C0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_RemoveEptHook_Wrapper */
    hv_remove_ept_hook_wrapper(dnz_root_primary(), true);
    return v;
}

/* ------------------------------------------------------------
 *   3280  0x1401dada0  Ob_UnregisterCallbackOrClose
 * 角色: EPT/NPT内存映射    大小: 974 字节
 * 谁叫它: Esp_GetBuffer_SoftBpFsm(0x14008d6b0)、HV_UnregisterExitHandler(0x140118870)、HV_RegisterExitHandler(0x140118970)、sub_14011E1D0(0x14011e1d0)、sub_140185E80(0x140185e80)、Esp_AttachToDwmProcess(0x14e7ea666)、sub_14E7FB5B8(0x14e7fb5b8)
 * 它叫谁: sub_14011C0D0(0x14011c0d0) → sub_14011CC00(0x14011cc00) → HV_Rdgsbase(0x14011fb10) → sub_140134490(0x140134490) → sub_140140A80(0x140140a80) → sub_1401566F0(0x1401566f0) → HV_RemoveEptHook_Wrapper(0x1401da0b0) → sub_1401DA2C0(0x1401da2c0)
 * ------------------------------------------------------------ */
uint64_t Ob_UnregisterCallbackOrClose(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_RemoveEptHook_Wrapper */
    hv_remove_ept_hook_wrapper(dnz_root_primary(), true);
    return v;
}

/* ------------------------------------------------------------
 *   3281  0x1401db170  sub_1401DB170
 * 角色: EPT/NPT内存映射    大小: 845 字节
 * 谁叫它: Esp_HookedRip_Dispatch(0x140123fe0)、sub_1401D9B40(0x1401d9b40)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → Rtl_AtExitListPush(0x1400ff200) → sub_140139ED0(0x140139ed0) → Util_FreeWideOrHeap(0x14014c450) → sub_1401D9E00(0x1401d9e00) → sub_1401D9F20(0x1401d9f20) → HV_RemoveEptHook_Wrapper(0x1401da0b0) → Util_Memcpy(0x1401ea340)
 * ------------------------------------------------------------ */
uint64_t sub_1401DB170(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_RemoveEptHook_Wrapper */
    hv_remove_ept_hook_wrapper(dnz_root_primary(), true);
    return v;
}

/* ------------------------------------------------------------
 *   3364  0x1401e06c6  sub_1401E06C6
 * 角色: EPT/NPT内存映射    大小: 6 字节
 * 谁叫它: HV_EptInstallHook_RealVmx(0x140124cf0)、HV_EptRemoveHook_RealVmx(0x140124db0)、HV_EptHidePages_RealVmx(0x140124ea0)、HV_EptUnhidePages_RealVmx(0x1401250a0)、sub_140125260(0x140125260)、HV_EptOpA_RealVmx(0x140125440)、HV_EptOpB_RealVmx(0x1401256b0)、HV_ClearPendingExceptionState(0x140125f40)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_1401E06C6(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: EPT/NPT内存映射 —— 走查当前根，给 4K 页填条目 */
    { uint64_t *e = hv_lookup_ept(dnz_root_primary(), p1, true);
      if (!e) { hv_ept_map_guest_access(dnz_root_primary(), p1, false); e = hv_lookup_ept(dnz_root_primary(), p1, false); }
      v = e ? *e : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  15680  0x1401e4360  sub_1401E4360
 * 角色: Hook/隐藏    大小: 1279 字节
 * 谁叫它: sub_14009A070(0x14009a070)、sub_1400A1CF0(0x1400a1cf0)、sub_1400C4FB0(0x1400c4fb0)、sub_1400EE000(0x1400ee000)、sub_14015ABE0(0x14015abe0)、sub_14015AEF0(0x14015aef0)、sub_14015B240(0x14015b240)、sub_1401634D0(0x1401634d0)
 * 它叫谁: sub_140138D20(0x140138d20) → __remainder_piby2d2f_forAsm(0x1401e7690) → __remainder_piby2_fma3(0x1401e7cc0) → __remainder_piby2_fma3_bdl(0x1401e7eb0)
 * ------------------------------------------------------------ */
uint64_t sub_1401E4360(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  15696  0x1401e8450  sub_1401E8450
 * 角色: Hook/隐藏    大小: 1734 字节
 * 谁叫它: sub_14009A070(0x14009a070)、sub_1400C4FB0(0x1400c4fb0)、sub_1400EE000(0x1400ee000)、sub_14015ABE0(0x14015abe0)、sub_14015AEF0(0x14015aef0)、sub_14015B240(0x14015b240)、sub_1401634D0(0x1401634d0)、sub_1401693A0(0x1401693a0)
 * 它叫谁: sub_140138D20(0x140138d20) → __remainder_piby2d2f_forC(0x1401e77e0)
 * ------------------------------------------------------------ */
uint64_t sub_1401E8450(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  15701  0x1401e98c0  sub_1401E98C0
 * 角色: EPT/NPT内存映射    大小: 10 字节
 * 谁叫它: sub_140002750(0x140002750)、Mem_HeapFree(0x1400029f0)、Mem_HeapAllocAligned(0x140002aa0)、Util_StringCtorOrCopy(0x140002b30)、sub_1400030C0(0x1400030c0)、sub_14003ED00(0x14003ed00)、sub_140040C10(0x140040c10)、sub_140041000(0x140041000)
 * 它叫谁: j_HV_RaiseException_C0000450(0x1401e9b70)
 * ------------------------------------------------------------ */
uint64_t sub_1401E98C0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_RaiseException_C0000450 */
    { v = (uint64_t)hv_raise_exception_c0000450(&g_dnz); }
    return v;
}

/* ------------------------------------------------------------
 *  15754  0x1402162f0  sub_1402162F0
 * 角色: Hook/隐藏    大小: 73 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: Mem_HeapFree(0x1400029f0) → sub_140065920(0x140065920)
 * ------------------------------------------------------------ */
uint64_t sub_1402162F0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  16943  0x14e4face1  sub_14E4FACE1
 * 角色: Hook/隐藏    大小: 451 字节
 * 谁叫它: sub_14E5F7BFF(0x14e5f7bff)、sub_14E603FD7(0x14e603fd7)
 * 它叫谁: sub_14E4B8AD9(0x14e4b8ad9) → sub_14E59A3DA(0x14e59a3da) → sub_14E664A3F(0x14e664a3f) → sub_14E6E9A28(0x14e6e9a28) → sub_14E72128E(0x14e72128e)
 * ------------------------------------------------------------ */
uint64_t sub_14E4FACE1(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  18026  0x14e53aceb  sub_14E53ACEB
 * 角色: Hook/隐藏    大小: 53 字节
 * 谁叫它: sub_14E711BA8(0x14e711ba8)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_14E53ACEB(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  20656  0x14e5d46b8  sub_14E5D46B8
 * 角色: Hook/隐藏    大小: 120 字节
 * 谁叫它: sub_14E4D64AC(0x14e4d64ac)
 * 它叫谁: sub_14E55A99A(0x14e55a99a)
 * ------------------------------------------------------------ */
uint64_t sub_14E5D46B8(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  20772  0x14e5dace3  sub_14E5DACE3
 * 角色: Hook/隐藏    大小: 242 字节
 * 谁叫它: sub_14E4E1B78(0x14e4e1b78)
 * 它叫谁: sub_14E4E29F4(0x14e4e29f4) → sub_14E4EB5C3(0x14e4eb5c3) → sub_14E5894E3(0x14e5894e3)
 * ------------------------------------------------------------ */
uint64_t sub_14E5DACE3(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  21061  0x14e5eace0  sub_14E5EACE0
 * 角色: Hook/隐藏    大小: 103 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: sub_14E64E68D(0x14e64e68d) → sub_14E6D3B25(0x14e6d3b25)
 * ------------------------------------------------------------ */
uint64_t sub_14E5EACE0(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  21612  0x14e60c974  sub_14E60C974
 * 角色: Hook/隐藏    大小: 291 字节
 * 谁叫它: sub_14E4C0901(0x14e4c0901)
 * 它叫谁: sub_14E4D079D(0x14e4d079d) → sub_14E685666(0x14e685666) → sub_14E687BE4(0x14e687be4)
 * ------------------------------------------------------------ */
uint64_t sub_14E60C974(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  22140  0x14e62ace1  sub_14E62ACE1
 * 角色: Hook/隐藏    大小: 187 字节
 * 谁叫它: sub_14E4FB6E4(0x14e4fb6e4)、sub_14E62ABA8(0x14e62aba8)
 * 它叫谁: sub_14E50562F(0x14e50562f) → sub_14E60018B(0x14e60018b) → sub_14E6CA04A(0x14e6ca04a) → sub_14E6CBF9C(0x14e6cbf9c) → sub_14E7D3538(0x14e7d3538)
 * ------------------------------------------------------------ */
uint64_t sub_14E62ACE1(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  23048  0x14e65eace  sub_14E65EACE
 * 角色: Hook/隐藏    大小: 14 字节
 * 谁叫它: sub_14E570A38(0x14e570a38)、sub_14E6B6A8C(0x14e6b6a8c)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_14E65EACE(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  23265  0x14e66ace7  sub_14E66ACE7
 * 角色: Hook/隐藏    大小: 231 字节
 * 谁叫它: 静态图未找到；可能是入口、回调、间接调用或被保护壳隐藏
 * 它叫谁: sub_14E6B3DD1(0x14e6b3dd1) → sub_14E798883(0x14e798883)
 * ------------------------------------------------------------ */
uint64_t sub_14E66ACE7(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  23831  0x14e68aace  sub_14E68AACE
 * 角色: Hook/隐藏    大小: 15 字节
 * 谁叫它: sub_14E51B997(0x14e51b997)、sub_14E786F6A(0x14e786f6a)
 * 它叫谁: sub_14E556E8B(0x14e556e8b)
 * ------------------------------------------------------------ */
uint64_t sub_14E68AACE(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  24450  0x14e6ace99  sub_14E6ACE99
 * 角色: Hook/隐藏    大小: 128 字节
 * 谁叫它: sub_14E4DB6E1(0x14e4db6e1)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_14E6ACE99(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  27512  0x14e759ace  sub_14E759ACE
 * 角色: Hook/隐藏    大小: 14 字节
 * 谁叫它: sub_14E664A3F(0x14e664a3f)、sub_14E72E636(0x14e72e636)
 * 它叫谁: 没有直接下级函数，或者通过函数指针间接调用
 * ------------------------------------------------------------ */
uint64_t sub_14E759ACE(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  28197  0x14e7827e6  sub_14E7827E6
 * 角色: Hook/隐藏    大小: 243 字节
 * 谁叫它: sub_14E4B77E3(0x14e4b77e3)、sub_14E4B83C0(0x14e4b83c0)、sub_14E4BCC3A(0x14e4bcc3a)、sub_14E4C17EF(0x14e4c17ef)、sub_14E4C81A4(0x14e4c81a4)、sub_14E4C896E(0x14e4c896e)、sub_14E4C8E6B(0x14e4c8e6b)、sub_14E4C93EF(0x14e4c93ef)
 * 它叫谁: sub_14E630ABD(0x14e630abd) → sub_14E7B9F8C(0x14e7b9f8c)
 * ------------------------------------------------------------ */
uint64_t sub_14E7827E6(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  28914  0x14e7acec8  sub_14E7ACEC8
 * 角色: Hook/隐藏    大小: 300 字节
 * 谁叫它: sub_14E5D430D(0x14e5d430d)
 * 它叫谁: sub_14E5EB5E6(0x14e5eb5e6) → sub_14E5FFD97(0x14e5ffd97) → sub_14E66A13E(0x14e66a13e) → sub_14E765453(0x14e765453)
 * ------------------------------------------------------------ */
uint64_t sub_14E7ACEC8(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师角色: Hook/隐藏 —— 查/登记钩子表 */
    { dnz_listhook *h = hook_lookup_by_pid(&g_dnz, (uint32_t)p1);
      v = h ? h->cr3 : 0; }
    return v;
}

/* ------------------------------------------------------------
 *  29908  0x14e7e61cd  sub_14E7E61CD
 * 角色: EPT/NPT内存映射    大小: 4666 字节
 * 谁叫它: sub_140087190(0x140087190)
 * 它叫谁: sub_14003E7E0(0x14003e7e0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_14E7E61CD(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *  30012  0x14e807cdb  sub_14E807CDB
 * 角色: EPT/NPT内存映射    大小: 4999 字节
 * 谁叫它: sub_1401349F0(0x1401349f0)
 * 它叫谁: sub_14003E7E0(0x14003e7e0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550)
 * ------------------------------------------------------------ */
uint64_t sub_14E807CDB(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *  30013  0x14e809062  sub_14E809062
 * 角色: EPT/NPT内存映射    大小: 4141 字节
 * 谁叫它: sub_140135400(0x140135400)
 * 它叫谁: Mem_HeapFree(0x1400029f0) → sub_14003E7E0(0x14003e7e0) → HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0)
 * ------------------------------------------------------------ */
uint64_t sub_14E809062(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}

/* ------------------------------------------------------------
 *  30031  0x14e8106bc  sub_14E8106BC
 * 角色: EPT/NPT内存映射    大小: 2155 字节
 * 谁叫它: Sys_QuerySystemInformation(0x140155350)、sub_14E811E71(0x14e811e71)
 * 它叫谁: HV_InvalidateGuestTlbOrEpt(0x14011b560) → HV_Rdgsbase(0x14011fb10) → HV_HostVmcallPath(0x140121cd0) → Mem_PoolAlloc(0x1401339c0) → Mem_HeapFreeTracked(0x140133bc0) → Mem_HeapFreeLocal(0x1401340a0) → sub_140134550(0x140134550) → HV_MemsetGuestVa(0x140152df0)
 * ------------------------------------------------------------ */
uint64_t sub_14E8106BC(uint64_t p1, uint64_t p2)
{
    uint64_t gpa = p1;
    uint64_t va  = p2;
    uint64_t sz  = 0;
    uint64_t v   = 0;
    uint64_t cmd = p1;
    uint64_t p[3] = { p1, p2, 0 };
    uint64_t msr = p1;
    uint64_t cr3 = p2;
    dnz_listhook *h = NULL;
    dnz_exit_info info; memset(&info, 0, sizeof(info));
    /* 老师调用: HV_InvalidateGuestTlbOrEpt */
    { v = (uint64_t)hv_invalidate_guest_tlb_or_ept(va, dnz_root_primary(), dnz_root_shadow()); }
    return v;
}
