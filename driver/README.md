# DnzVisor — 真实 EPT 双视图 hypervisor 驱动骨架

基于 **SimpleVisor**（Alex Ionescu 开源，MIT 风格）的 VMX 骨架打底，
叠加老师驱动（IDA 分析）的工程细节：**认人 + 翻镜子 + 跨核同步**。

> 边界：教学/研究骨架，演示"双视图"的完整机制。不针对任何反作弊，
> 不含任何具体游戏的偏移，不包含 VMProtect 内容（那部分本来不可得）。

## 已实现（真硬件，不是模拟）

| 层 | 内容 | 对应 SimpleVisor | 对应老师 IDA |
|---|---|---|---|
| VMX 核心 | VMXON / VMCS 全字段 / VMLAUNCH / VM-exit 循环 | shvvmx.c / shvvmxhv.c | — |
| EPT 打底 | 恒等映射（2MB 大页，MTRR 校正内存类型） | shvvmx.c `ShvVmxEptInitialize` | — |
| EPT 拆页 | 2MB 大页拆 512×4K（每核 8 张 PT 表） | 新增 dnz_ept.c | `HV_EptSplitLargePage` (0x140115400) |
| 装双视图 | 目标页 EPT 项 = 无权限（任何访问触发 violation） | 新增 dnz_ept.c | `HV_EptInstallHook` (0x140115980) |
| 认人 | EPT violation 时按 **CR3** 判断访问者：住户 vs 其他 | 新增 dnz_hook.c | `Hook_NtApi_VmExitHandler` (0x1401906E0) |
| 翻镜子 | 住户→看假页；保安/其他→看真页；临时换面 + 开 MTF 单步 | 新增 dnz_ept.c | `HV_EptSwapHookOnViolation` (0x140116F90) |
| MTF 收尾 | 单步执行一条指令后恢复无权限 + 关 MTF + INVEPT | 新增 dnz_ept.c | `HV_AfterEptViolation` (0x140116ED0) |
| 跨核同步 | 翻镜子抢锁（CAS 0→1），别人在翻就 spin-wait，**TSC 限时**超时放弃 | 新增 dnz_hook.c | 翻镜子里的跨核等待 |
| 计时账本 | 每次翻镜子记录 `预期-实际` TSC（防时间差） | 新增 dnz_hook.c | `*(a1+24656) = 预期 - 实际` |
| RIP 黑名单 | 可注册黑名单 RIP（教学用 0xCC 语义） | 新增 dnz_hook.c | `g_Hook_NtosOffsetsCtx` |
| 驱动入口 | 设备对象 + IOCTL + 卸载恢复（VMXOFF + GDTR/IDTR 还原 + 段修复） | shv.c / shvos.c | — |

## 翻镜子完整流程（真实 VM-exit 链路）

```
住户/保安访问被钩页
   ↓ 硬件 EPT violation (exit reason 48)
HV_DispatchExitHandlers 门口
   ↓ 读 EXIT_QUALIFICATION 拿 fault GPA，读 GUEST_CR3
DnzEptHandleViolation
   ├─ 认人：CR3 对比进程表 → 住户(看假页) / 其他(看真页)
   ├─ 跨核同步：DnzSyncFlipBegin（CAS 抢锁，TSC 超时）
   ├─ 临时换面：EPT 项改成 RWX 指向目标页
   ├─ 开 MTF（SECONDARY_VM_EXEC_CONTROL bit27）
   └─ 计时账本：LastSwapTsc = 预期 - 实际
   ↓ VM-resume，重跑出错指令（RIP 不动）
   ↓ 硬件 MTF exit (reason 37)，一条指令执行完毕
DnzEptFinishFlip
   ├─ EPT 项恢复为无权限
   ├─ 关 MTF
   ├─ DnzSyncFlipEnd（状态 0→2）
   └─ INVEPT 刷 TLB
   ↓ VM-resume，继续跑
```

## 目录 / 模块映射

```
D:\dnz_guard_sim\driver\
├─ DnzVisor.vcxproj      MSBuild 工程（WDK 工具集 WindowsKernelModeDriver10.0）
├─ DnzVisor.inf          安装文件（测试签名加载）
├─ shv.c                 驱动入口 + IOCTL 分发（设备 \Device\DnzVisor）
├─ shv.h / shv_x.h       核心头（VP 数据，含 EPT 拆页表 + 双视图状态）
├─ shvvmx.c              VMXON / VMCS 配置 / EPT 恒等映射（SimpleVisor 原样）
├─ shvvmxhv.c            VM-exit 处理（加了 EPT violation + MTF 两个 case）
├─ shvvmxhvx64.asm       汇编 VM 入口（SimpleVisor 原样）
├─ shvvp.c               每核 VP 数据管理（含 ShvGlobalData 定义）
├─ shvos.c               内核 OS 层（DPC 广播、内存、DriverEntry）
├─ shvosx64.asm          _str/_sldt/ShvVmxCleanup/RestoreContext + AsmInvEpt
├─ vmx.h                 VMX 常量 + EPT 结构（加了 4KB VMX_PTE）
├─ ntint.h               SimpleVisor 自带 NT 类型（已加 WDK 兼容保护）
├─ dnz_ept.c / .h        EPT 拆页 / 装钩 / 卸钩 / 翻镜子 / MTF 收尾
├─ dnz_hook.c / .h       认人（CR3 对比）/ 跨核同步（TSC 限时）/ 计时账本
└─ patch*.py             改造脚本（保留备查）
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
| INSTALL_HOOK | {Gpa, FakePfn, CleanPfn} | 给目标客户机物理页装双视图（广播到每核） |
| REMOVE_HOOK | ULONG64 Gpa | 卸钩（恢复 2MB 大页） |
| TEST | — | 读翻镜子次数 + 最近耗时 |

**演示步骤**：
1. 注册一个进程为住户（它的 CR3 会被记下来）
2. 装钩：`Gpa` = 某物理页，`FakePfn` = 假页（放演示内容），`CleanPfn` = 真页
3. 住户进程访问该页 → EPT violation → 翻镜子 → 看到假页内容
4. 其他进程访问该页 → 翻镜子 → 看到真页内容
5. TEST 查询翻镜子计数与耗时账本

## 已知限制（诚实说明）

- **认人只用 CR3**：老师驱动还叠加了 RIP 黑名单判断"调用了哪个 API"，骨架里黑名单
  已注册但未接入翻镜子决策（教学演示认人主体已够）。
- **未做多核钩子状态一致性**：每核独立 EPT，装钩广播到每核；翻镜子的跨核同步
  是全局锁 + TSC 超时（老师代码同款语义），但未做跨核视图传播。
- **未模拟嵌套**（L0 底下再套一层）——那是 NestedHv2026 的事，不在这。
- **VMProtect 那 153 个加密函数**：本来就不在 IDA 能还原的范围内，骨架没有、
  也不可能有它们的真身。
