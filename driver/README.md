# DnzVisor — 真实 EPT 双视图 hypervisor 驱动骨架（双根架构）

基于 **SimpleVisor**（Alex Ionescu 开源，MIT 风格）的 VMX 骨架打底，
叠加老师驱动（IDA 分析）的工程细节：**双根 EPT + 认人 + 翻镜子（切视图）+ 跨核同步**。

> 边界：教学/研究骨架，演示"双视图"的完整机制。不针对任何反作弊，
> 不含任何具体游戏的偏移，不包含 VMProtect 内容（那部分本来不可得）。

## 双根架构（老师：两堵墙，保安进来推开海报墙给他看白墙）

每个核有三套 EPT 视图，被钩页在三张图里指向不同内容：

| 视图 | 被钩页指向 | 谁在看 | 权限 |
|---|---|---|---|
| **主根 MainView** | 假页 FakePfn（"改过版"） | 住户（被钩进程 + RIP 命中黑名单） | RWX 常驻 |
| **影子根 ShadowView** | 真页 CleanPfn（"干净版"） | 保安/其他任何人 | RWX 常驻 |
| **触发根 FaultView** | 无权限 | **默认 EPTP**——任何访问先触发 violation | NO_ACCESS |

**翻镜子 = 切换视图**：改 VMCS `EPT_POINTER` 指向主根/影子根 + INVEPT，
**全程不改页表一个字**——三张图在装钩时就预置好了（对应老师 `HV_EptInstallHook`
建主根/影子根，`HV_EptSwapHookOnViolation` 只换 EPTP）。

省内存实现：共享基底 Epml4/Epdpt/Epde（SimpleVisor 的 2MB 恒等映射，永不被改），
每个视图只带自己的 Pml4/Pdpt + 区域克隆 Pde[8] + 拆页 PT 表 Pt[8]；
视图 Pdpt[i] 默认指向共享基底，有钩子的区域才指向自己的克隆。

## 已实现（真硬件，不是模拟）

| 层 | 内容 | 对应 SimpleVisor | 对应老师 IDA |
|---|---|---|---|
| VMX 核心 | VMXON / VMCS 全字段 / VMLAUNCH / VM-exit 循环 | shvvmx.c / shvvmxhv.c | — |
| EPT 打底 | 恒等映射（2MB 大页，MTRR 校正内存类型） | shvvmx.c `ShvVmxEptInitialize` | — |
| 三视图 | 主根/影子根/触发根，EPTP 预置 | 新增 dnz_ept.c `DnzEptViewsInit` | `HV_EptInstallHook` 的主根/影子根 |
| EPT 拆页 | 2MB 大页拆 512×4K（三视图各带 8 张 PT 表） | 新增 dnz_ept.c | `HV_EptSplitLargePage` (0x140115400) |
| 装双视图 | 三张图同步建好：主根→假页、影子根→真页、触发根→无权限 | 新增 dnz_ept.c | `HV_EptInstallHook` (0x140115980) |
| 认人第一招 | **PID 对比**：guest 当前进程 PID != g_Hook_GuestCr3OrCtx.Pid -> 放行（EPROCESS 偏移链） | 新增 dnz_hook.c | `ACE_NtApiHook_ExitHandler` (0x1401906E0) |
| 认人第二招 | **偏移表分派**：guest RIP 对 g_Hook_NtosOffsetsCtx 14 个偏移，命中哪个模拟哪个 API | 新增 dnz_hook.c | `ACE_NtApiHook_ExitHandler` 偏移表 if-else 链 |
| FNV 链表 | **ListHook FNV-1a 哈希链表**（基数 0xCBF29CE484222325，自旋锁+桶+遍历） | 新增 dnz_hook.c | `ACE_LookupListHookByPid` |
| guest 内存读写 | **direct map + 4 级页表翻译**：Hv_ReadGuest* / Hv_WriteGuest* | 新增 dnz_guest.c | `HV_TranslateGuestVa_Present` (0x14011C2A0) |
| 翻镜子 | **切换视图**：VMCS EPTP → 主根/影子根 + INVEPT，**不动页表** | 新增 dnz_ept.c | `HV_EptSwapHookOnViolation` (0x140116F90) |
| MTF 收尾 | 单步执行一条指令后 EPTP 切回触发根 + 关 MTF + INVEPT | 新增 dnz_ept.c | `HV_AfterEptViolation` (0x140116ED0) |
| 跨核同步 | 老师原样：状态非 0 等变 2（**内层 1000 次 mfence/pause + 外层 8×预算 TSC 限时**）→ 归零 + lfence | 新增 dnz_hook.c | `HV_EptSwapHookOnViolation` (0x140116F90) |
| 计时账本 | 老师原样公式：`*(a1+24656) = *(a1+6427312) - 当前TSC`（记录点 - 现在） | 新增 dnz_hook.c | `*(a1+24656)` |
| RIP 黑名单 | 可注册黑名单 RIP（教学用 0xCC 语义） | 新增 dnz_hook.c | `g_Hook_NtosOffsetsCtx` |
| 驱动入口 | 设备对象 + IOCTL + 卸载恢复（VMXOFF + GDTR/IDTR 还原 + 段修复） | shv.c / shvos.c | — |

## 翻镜子完整流程（真实 VM-exit 链路，全程不改页表）

```
住户/保安访问被钩页
   ↓ 默认 EPTP = 触发根（被钩页无权限）-> 硬件 EPT violation (exit reason 48)
HV_DispatchExitHandlers 门口
   ↓ 读 EXIT_QUALIFICATION 拿 fault GPA，读 GUEST_CR3 / GUEST_RIP
DnzEptHandleViolation
   ├─ 认人第一招：guest 进程 PID 对比 g_Hook_GuestCr3OrCtx.Pid（老师原样）
   │     不是被钩进程 -> 影子根（干净面）+ MTF（保安永远看到真页）
   ├─ 认人第二招：guest RIP 对偏移表 -> 命中则 DnzDispatchNtApi 模拟 API（RIP 前移）
   ├─ 没命中 -> 切视图：VMCS EPTP = 主根(假页) + INVEPT   ← 不碰页表
   ├─ 跨核同步：状态非 0 等变 2（内层 1000 次 mfence/pause + 外层 8×预算）
   ├─ 开 MTF（SECONDARY_VM_EXEC_CONTROL bit27）
   └─ 计时记录点：SwapRecordPoint = TSC
   ↓ VM-resume，重跑出错指令（RIP 不动），对着选定视图执行一条指令
   ↓ 硬件 MTF exit (reason 37)
DnzEptFinishFlip
   ├─ VMCS EPTP 切回触发根 + INVEPT（下个访问重新认人）
   ├─ 关 MTF
   ├─ DnzSyncFinish：状态置 2 -> 内层 1000 次 + 外层 8×预算 TSC 限时 -> 归零 + lfence
   └─ 计时账本：LastSwapTsc = 记录点 - 当前TSC（老师原公式）
   ↓ VM-resume，继续跑
```

## 目录 / 模块映射

```
D:\dnz_guard_sim\driver\
├─ DnzVisor.vcxproj      MSBuild 工程（WDK 工具集 WindowsKernelModeDriver10.0）
├─ DnzVisor.inf          安装文件（测试签名加载）
├─ shv.c                 驱动入口 + IOCTL 分发（设备 \Device\DnzVisor）
├─ shv.h / shv_x.h       核心头（VP 数据，含三视图 DNZ_EPT_VIEW + 双视图状态）
├─ shvvmx.c              VMXON / VMCS 配置 / EPT 恒等映射 / 视图初始化接入
├─ shvvmxhv.c            VM-exit 处理（EPT violation + MTF 两个 case）
├─ shvvmxhvx64.asm       汇编 VM 入口（SimpleVisor 原样）
├─ shvvp.c               每核 VP 数据管理（含 ShvGlobalData 定义）
├─ shvos.c               内核 OS 层（DPC 广播、内存、DriverEntry）
├─ shvosx64.asm          _str/_sldt/ShvVmxCleanup/RestoreContext + AsmInvEpt
├─ vmx.h                 VMX 常量 + EPT 结构（含 4KB VMX_PTE）
├─ ntint.h               SimpleVisor 自带 NT 类型（已加 WDK 兼容保护）
├─ dnz_ept.c / .h        三视图初始化 / 装钩 / 卸钩 / 翻镜子（切 EPTP）/ MTF 收尾
├─ dnz_hook.c / .h       认人（PID 对比 + 偏移表分派 + FNV 链表）/ 跨核同步（三段式）/ 计时账本
├─ dnz_teacher.c / .h    老师 8 个子函数逐行还原（sub_140187B90/E60/1881D0/168A70/
│                        179540/179790/17BAF0/176310）+ 全部下级 helper（FNV 哈希链
│                        表机制 / guest 翻译 / 自瞄状态 / 事件状态表 / 实体表 / 配置标志）
└─ dnz_guest.c / .h      guest 内存读写（direct map + 4 级页表翻译）
```

## 编译（本机已验证）

```
MSBuild DnzVisor.vcxproj /p:Configuration=Debug /p:Platform=x64
产物：D:\dnz_guard_sim\out\bin\Debug\x64\DnzVisor.sys
```

## 加载 / 测试（测试机或虚拟机，需测试签名模式）

```
bcdedit /set testsigning on        # 重启生效
sc create DnzVisor type= kernel binPath= C:\...\DnzVisor.sys
sc start DnzVisor                   # 启动即对全 CPU 执行 VMXON
```

IOCTL（用户态程序通过 \\.\DnzVisor）：
| IOCTL | 输入 | 作用 |
|---|---|---|
| REGISTER_PROC | ULONG PID | 注册"住户"进程（认人用） |
| REGISTER_RIP | ULONG64 RIP | 注册黑名单 RIP |
| INSTALL_HOOK | {Gpa, FakePfn, CleanPfn} | 给目标客户机物理页装双视图（三视图同步建，广播到每核） |
| REMOVE_HOOK | ULONG64 Gpa | 卸钩（三视图恢复 2MB 大页/共享基底） |
| TEST | — | 读翻镜子次数 + 最近耗时 |

**演示步骤**：
1. 注册一个进程为住户（它的 CR3 会被记下来）
2. 装钩：`Gpa` = 某物理页，`FakePfn` = 假页（放演示内容），`CleanPfn` = 真页
3. 住户进程在该页上命中黑名单 RIP → 切主根 → 看到假页内容
4. 其他进程访问该页 → 切影子根 → 看到真页内容（保安永远看不到假页）
5. TEST 查询翻镜子计数与耗时账本

## 已知限制（诚实说明）

- **触发根方案每次访问都翻一次镜子**（VM-exit 开销大）：这是"按访问认人 + RIP 黑名单"
  的代价——要认出"谁在访问"就得让访问先 fault。老师驱动在同款机制上做了计时校准
  掩盖延迟，本骨架只有账本、没做掩盖。
- **认人三招已对齐老师原样**：PID 对比（EPROCESS 偏移链）+ guest RIP 对
  `g_Hook_NtosOffsetsCtx` 偏移表分派（14 个偏移分支，命中哪个模拟哪个 API，RIP 前移 +
  写 guest 寄存器/栈/内存）+ FNV-1a 哈希链表（`ACE_LookupListHookByPid` 同款：基数
  0xCBF29CE484222325、质数 0x100000001B3、桶+链表+自旋锁）。8 个 stub 子函数已按
  老师伪代码逐行还原（见 dnz_teacher.c），剩余几个深层叶子（sub_1401944D0 /
  Hv_ReadProcessListFromGuest / sub_140175230）出处不全，保留为结构桩、不编造。
- **未做多核钩子状态一致性**：每核独立 EPT，装钩广播到每核；翻镜子的跨核同步
  是全局锁 + TSC 超时（老师代码同款语义），但未做跨核视图传播。
- **未模拟嵌套**（L0 底下再套一层）——那是 NestedHv2026 的事，不在这。
- **VMProtect 那 153 个加密函数**：本来就不在 IDA 能还原的范围内，骨架没有、
  也不可能有它们的真身。
