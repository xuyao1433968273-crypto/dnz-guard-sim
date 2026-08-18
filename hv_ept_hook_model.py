# -*- coding: utf-8 -*-
"""
hv_ept_hook_model.py —— EPT 钩子机制模型（教学版，Python 移植）
===============================================================
与 hv_ept_hook_model.c 同构：函数名、数据结构、流程完全对应老师驱动
IDA 分析里的 HV_Ept* 系列。纯软件模拟，不碰硬件，不针对任何人。

函数对应关系（与 C 版一致）：
  hv_ept_lookup                 -> HV_LookupEptEntry          (0x140115220)
  hv_ept_split_large_page       -> HV_EptSplitLargePage       (0x140115400)
  hv_ept_install_hook           -> HV_EptInstallHook          (0x140115980)
  hv_ept_remove_hook            -> HV_EptRemoveHook           (0x140115ac0)
  hv_ept_hide_pages             -> HV_EptHidePages            (0x140115c20)
  hv_ept_swap_hook_on_violation -> HV_EptSwapHookOnViolation  (0x140116f90)
  hv_after_ept_violation        -> HV_AfterEptViolation       (0x140116ed0)
  hv_dispatch_exit_handlers     -> HV_DispatchExitHandlers_Ept(0x1401171c0)

运行：python hv_ept_hook_model.py
"""
import time

PAGE_4K = 4096
PAGE_2M = 2 * 1024 * 1024
PAGE_SHIFT = 12
PT_ENTRIES = 512

MAGIC_RIRI = 0x52695269
HYPERCALL_MAGIC = 0x3467103
EXIT_REASON_EPT_VIOLATION = 1

HOOK_DUAL_VIEW = 1
HOOK_FIRST_TOUCH = 2
HOOK_HIDDEN = 4


# ------------------------------------------------------------------
# EPT 表项（8 字节）：对应 Intel SDM 28.2 / C 版的 EptEntry union
# ------------------------------------------------------------------
class EptEntry:
    def __init__(self, pfn=0, page_size=0, r=1, w=1, x=1, mem_type=6):
        self.r = r                # bit0 可读
        self.w = w                # bit1 可写
        self.x = x                # bit2 可执行
        self.mem_type = mem_type  # bit3-5 内存类型(6=WB)
        self.page_size = page_size  # bit7 1=2MB大页, 0=4KB
        self.pfn = pfn            # bit12-47 物理页框号

    def present(self):
        return self.r or self.w or self.x


# ------------------------------------------------------------------
# 模拟物理内存：64 页
# ------------------------------------------------------------------
class PhysMem:
    def __init__(self):
        self.pages = {}
        self.next_pfn = 1

    def alloc_pfn(self):
        p = self.next_pfn
        self.next_pfn += 1
        self.pages[p] = bytearray(PAGE_4K)
        return p

    def pfn_to_va(self, pfn):
        return self.pages[pfn]

    def fill(self, pfn, val):
        self.pages[pfn] = bytearray([val] * PAGE_4K)


# ------------------------------------------------------------------
# 钩子记录：对应 C 版 HookEntry / 老师驱动的每条 hook
# ------------------------------------------------------------------
class HookEntry:
    def __init__(self, gpa, clean_pfn, modified_pfn):
        self.gpa = gpa
        self.clean_pfn = clean_pfn
        self.modified_pfn = modified_pfn
        self.state = 0           # 0=闲 1=翻面中 2=干完了（跨核信号）
        self.flags = HOOK_DUAL_VIEW | HOOK_FIRST_TOUCH
        self.expected_ticks = 100
        self.last_swap_delta = 0


# ------------------------------------------------------------------
# 每 vCPU 状态：对应 C 版 VcpuState / 老师驱动的 a1
# ------------------------------------------------------------------
class VcpuState:
    def __init__(self, phys):
        self.phys = phys
        self.pml4 = None
        self.hooks = []
        self.exit_state = 0
        self.status_flags = 0
        self.last_swap_delta = 0
        self.use_real_vmx = True
        self.scan_count = 0


# ------------------------------------------------------------------
# 伪秒表：模拟真实驱动的 __rdtsc()
# ------------------------------------------------------------------
def rdtsc_now():
    return time.perf_counter_ns() // 1000


# ------------------------------------------------------------------
# hv_ept_lookup：4 层走查，返回目标表项（对应 HV_LookupEptEntry）
# ------------------------------------------------------------------
def make_pte(pfn, page_size, r=1, w=1, x=1):
    return EptEntry(pfn=pfn, page_size=page_size, r=r, w=w, x=x)


def hv_ept_lookup(s, gpa, tables):
    idx4 = (gpa >> 39) & 0x1FF
    idx3 = (gpa >> 30) & 0x1FF
    idx2 = (gpa >> 21) & 0x1FF
    idx1 = (gpa >> 12) & 0x1FF

    pml4 = s.pml4
    if not pml4[idx4].pfn:
        return None
    pdpt = tables[pml4[idx4].pfn]
    if not pdpt[idx3].pfn:
        return None
    pd = tables[pdpt[idx3].pfn]
    if pd[idx2].page_size:
        return pd[idx2]
    pt = tables[pd[idx2].pfn]
    return pt[idx1]


# ------------------------------------------------------------------
# hv_ept_split_large_page：拆大页（对应 HV_EptSplitLargePage）
# ------------------------------------------------------------------
def hv_ept_split_large_page(s, gpa, tables):
    idx4 = (gpa >> 39) & 0x1FF
    idx3 = (gpa >> 30) & 0x1FF
    idx2 = (gpa >> 21) & 0x1FF

    pdpt = tables[s.pml4[idx4].pfn]
    pd = tables[pdpt[idx3].pfn]
    big = pd[idx2]

    if not big.page_size:
        return

    pt_pfn = s.phys.alloc_pfn()              # 分配一张 PT 表
    pt = [make_pte(big.pfn, 0) for i in range(PT_ENTRIES)]  # 教学简化：全部指向同一物理页
    tables[pt_pfn] = pt
    pd[idx2] = make_pte(pt_pfn, 0)           # PD 项指向 PT 表
    print(f"[拆大页] gpa=0x{gpa:x}: 2MB 大页 -> 512 个 4KB 小页")


# ------------------------------------------------------------------
# hv_ept_install_hook / remove：装/卸双视图（对应 HV_EptInstallHook）
# ------------------------------------------------------------------
def hv_ept_install_hook(s, gpa, modified_pfn, tables):
    e = hv_ept_lookup(s, gpa, tables)
    if e is None:
        return -1
    h = HookEntry(gpa, e.pfn, modified_pfn)
    s.hooks.append(h)
    e.pfn = modified_pfn
    print(f"[装钩子] gpa=0x{gpa:x} 双视图: 住户看到[改过页], 保安看到[干净页]")


def hv_ept_remove_hook(s, gpa, tables):
    e = hv_ept_lookup(s, gpa, tables)
    if e is None:
        return
    for i, h in enumerate(s.hooks):
        if h.gpa == gpa:
            e.pfn = h.clean_pfn
            del s.hooks[i]
            print(f"[卸钩子] gpa=0x{gpa:x} 已还原为干净页")
            return


# ------------------------------------------------------------------
# hv_ept_hide_pages：藏页（对应 HV_EptHidePages）
# ------------------------------------------------------------------
def hv_ept_hide_pages(s, gpa, count, tables):
    for i in range(count):
        e = hv_ept_lookup(s, gpa + i * PAGE_4K, tables)
        if e:
            e.r = e.w = e.x = 0
    print(f"[藏页] gpa=0x{gpa:x} 起 {count} 页: 表项清空, 访问会触发 violation")


def hv_ept_unhide_pages(s, gpa, count, tables):
    for i in range(count):
        e = hv_ept_lookup(s, gpa + i * PAGE_4K, tables)
        if e:
            e.r = e.w = e.x = 1
    print(f"[放页] gpa=0x{gpa:x} 起 {count} 页: 已恢复可见")


# ------------------------------------------------------------------
# hv_ept_swap_hook_on_violation：翻镜子（对应 HV_EptSwapHookOnViolation）
# 忠实还原 IDA 三段逻辑：首次触碰翻面 / 跨核等待+计时记账 / 置标志
# ------------------------------------------------------------------
def hv_ept_swap_hook_on_violation(s, h, tables):
    if h.flags & HOOK_FIRST_TOUCH:
        h.flags &= ~HOOK_FIRST_TOUCH
        hv_ept_remove_hook(s, h.gpa, tables)
        hv_ept_install_hook(s, h.gpa, h.modified_pfn, tables)
        s.hooks[-1].flags &= ~HOOK_FIRST_TOUCH  # 首次翻面完成，下次走计时路径
        return

    if s.exit_state:
        t0 = rdtsc_now()
        budget = 8 * 100
        for _ in range(0x3E8 * 8):            # 内层0x3E8 + 外层预算限时
            if s.exit_state == 2:
                break
            if rdtsc_now() - t0 >= budget:
                break
        s.exit_state = 0
        actual = rdtsc_now() - t0
        # 计时记账：对应 IDA *(a1+24656) = 预期 - 实际（防时间差）
        h.last_swap_delta = h.expected_ticks - actual
        s.last_swap_delta = h.last_swap_delta
        print(f"   [计时] 本次翻面实际 {actual} tick, 记账 delta={h.last_swap_delta} (防时间差用)")
        return

    s.status_flags |= 0x100000


# ------------------------------------------------------------------
# hv_after_ept_violation：收尾（对应 HV_AfterEptViolation）
# ------------------------------------------------------------------
def hv_after_ept_violation(s, gpa, tables):
    e = hv_ept_lookup(s, gpa, tables)
    if e is None:
        return
    buf = bytes(s.phys.pfn_to_va(e.pfn)[:4])
    print(f"   [收尾] 已拷贝被碰页内容(前4字节 {buf.hex(' ')}), 埋好跳板")


# ------------------------------------------------------------------
# hv_dispatch_exit_handlers：门口分派（对应 HV_DispatchExitHandlers_Ept）
# ------------------------------------------------------------------
class ExitInfo:
    def __init__(self, reason=0, rip=0, gpa=0, magic=0, observer=0):
        self.reason = reason
        self.rip = rip
        self.gpa = gpa
        self.magic = magic
        self.observer = observer  # 0=住户 1=保安


g_exit_handler_table = []


def hv_register_exit_handler(fn):
    g_exit_handler_table.append(fn)


def hv_translate_guest_va(s, gpa):
    return gpa   # 教学模型里 GPA==HPA


def hv_dispatch_exit_handlers(s, info, tables):
    if not g_exit_handler_table:
        s.status_flags = 2147484419
        return False

    handled = False
    for fn in g_exit_handler_table:
        if fn(s, info, tables):
            handled = True
            break

    if handled and info.magic == MAGIC_RIRI:
        pa = hv_translate_guest_va(s, info.gpa)
        e = hv_ept_lookup(s, pa, tables)
        if e:
            e.pfn = pa >> PAGE_SHIFT
            s.status_flags |= 0x100
            print(f"[分派] magic=RiRi -> EPT 项已重定向到 pfn=0x{e.pfn:x}")
        return True

    if not handled:
        s.status_flags = HYPERCALL_MAGIC
        print(f"[分派] 无人认领 -> 向客户机注入 hypercall 0x{HYPERCALL_MAGIC:x}")
    return handled


# ------------------------------------------------------------------
# 处理者 1：EPT violation（翻镜子）
# ------------------------------------------------------------------
def ept_violation_handler(s, info, tables):
    if info.reason != EXIT_REASON_EPT_VIOLATION:
        return False

    for h in s.hooks:
        if h.gpa != (info.gpa & ~(PAGE_4K - 1)):
            continue
        print(f"[door] EPT violation @ gpa=0x{info.gpa:x} rip=0x{info.rip:x}")

        if info.observer == 1:
            # ---- 保安来查 -> 翻镜子，给干净页，查完翻回来 ----
            s.exit_state = 1      # 模拟跨核信号：另一个核在翻面
            s.exit_state = 2
            hv_ept_swap_hook_on_violation(s, h, tables)
            hv_after_ept_violation(s, h.gpa, tables)
            view = s.phys.pfn_to_va(h.clean_pfn)
            s.scan_count += 1
            print(f"   [保安] 看到: {view[0]:02X} {view[1]:02X} {view[2]:02X} ... (干净页, 一切正常)")
            info.magic = MAGIC_RIRI
            return True
        else:
            # ---- 住户访问 -> 替身模拟：给改过页的内容 ----
            view = s.phys.pfn_to_va(h.modified_pfn)
            print(f"   [住户] 替身模拟: 读到 {view[0]:02X} {view[1]:02X} {view[2]:02X} ... (改过页)")
            return True
    return False


# ------------------------------------------------------------------
# 处理者 2：NT API 钩子（对应 Hook_NtApi_VmExitHandler）
# 认人：先查 CR3（是不是被关注进程），再按 RIP 对照黑名单
# ------------------------------------------------------------------
g_hook_guest_cr3 = 0x9999


def hook_ntapi_handler(s, info, tables):
    cur_cr3 = 0x9999   # 模拟当前进程 CR3
    if cur_cr3 != g_hook_guest_cr3:
        return False
    if info.rip == 0x7777:
        print(f"[door] 命中黑名单 API @ rip=0x{info.rip:x} -> 替身模拟执行")
        info.magic = MAGIC_RIRI
        return True
    return False


# ------------------------------------------------------------------
# guest_access：住户/保安访问入口（模拟硬件 VM-exit）
# ------------------------------------------------------------------
def guest_access(s, observer, gpa, rip, tables):
    info = ExitInfo(gpa=gpa, rip=rip, observer=observer)
    e = hv_ept_lookup(s, gpa, tables)

    # 被钩子保护的页：访问必触发 violation（真实机制：钩子让页产生陷阱）
    hooked = any(h.gpa == (gpa & ~(PAGE_4K - 1)) for h in s.hooks)

    if hooked:
        info.reason = EXIT_REASON_EPT_VIOLATION
        hv_dispatch_exit_handlers(s, info, tables)
        return

    if e is None or not e.present():
        # 普通被藏页（无钩子）-> violation，无人认领 -> 注入 hypercall
        info.reason = EXIT_REASON_EPT_VIOLATION
        hv_dispatch_exit_handlers(s, info, tables)
        if observer == 0:
            print(f"   [住户] 访问被藏页 -> 触发 violation")
        return

    view = s.phys.pfn_to_va(e.pfn)
    who = "住户" if observer == 0 else "保安"
    print(f"   [{who}] 读 gpa=0x{gpa:x}: {view[0]:02X} {view[1]:02X} {view[2]:02X} ...")


# ------------------------------------------------------------------
# main：把老师驱动的流程演一遍
# ------------------------------------------------------------------
def main():
    phys = PhysMem()
    s = VcpuState(phys)
    tables = {}

    pml4_pfn = phys.alloc_pfn()
    pdpt_pfn = phys.alloc_pfn()
    pd_pfn = phys.alloc_pfn()
    s.pml4 = [EptEntry() for _ in range(PT_ENTRIES)]
    tables[pml4_pfn] = s.pml4
    pdpt = [EptEntry() for _ in range(PT_ENTRIES)]
    tables[pdpt_pfn] = pdpt
    pd = [EptEntry() for _ in range(PT_ENTRIES)]
    tables[pd_pfn] = pd

    region_pfn = phys.alloc_pfn()
    phys.fill(region_pfn, 0x55)
    s.pml4[0] = make_pte(pdpt_pfn, 0)
    pdpt[0] = make_pte(pd_pfn, 0)
    pd[0] = make_pte(region_pfn, 1)          # 2MB 大页

    clean_pfn = phys.alloc_pfn()
    mod_pfn = phys.alloc_pfn()
    phys.fill(clean_pfn, 0xCC)
    phys.fill(mod_pfn, 0xAA)

    print("=====================================================")
    print("  EPT 钩子机制模型（按老师驱动 HV_Ept* 函数结构）")
    print("  纯软件模拟，不针对任何人")
    print("=====================================================")
    print()

    hv_register_exit_handler(ept_violation_handler)
    hv_register_exit_handler(hook_ntapi_handler)

    hv_ept_split_large_page(s, 0, tables)
    hv_ept_install_hook(s, 0x1000, mod_pfn, tables)
    hv_ept_hide_pages(s, 0x2000, 1, tables)

    print("\n--- 场景1: 住户访问钩子页（替身模拟 -> 改过页）---")
    guest_access(s, 0, 0x1000, 0x1111, tables)

    print("\n--- 场景2: 保安查房（翻镜子 -> 干净页）---")
    for i in range(3):
        print(f"  第 {i + 1} 轮查房:")
        guest_access(s, 1, 0x1000, 0x2222, tables)

    print("\n--- 场景3: 住户访问被藏页（无钩子 -> 无人认领 -> hypercall）---")
    guest_access(s, 0, 0x2000, 0x3333, tables)

    print("\n--- 场景4: NT API 命中黑名单（替身执行）---")
    hv_dispatch_exit_handlers(s, ExitInfo(rip=0x7777, gpa=0x4000), tables)

    print("\n=====================================================")
    print(f" 总结: 保安查了 {s.scan_count} 次房, 每次看到的都是干净页")
    print(f" 计时记账: last_swap_delta={s.last_swap_delta} (防时间差用)")
    print("=====================================================")


if __name__ == "__main__":
    main()
