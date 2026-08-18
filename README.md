# dnz-ept-engine — 老师「04-内存映射与隐藏」192 函数完整建模

纯软件教学模型：把老师驱动里 **全部 192 个**「内存映射与隐藏」函数（IDA 分析
`04-内存映射与隐藏` 分类）逐个建模成可编译、可运行、可被调用的 C 代码。
**不碰真实硬件/内存，不针对任何反作弊**——只演示 EPT 双视图、藏页、翻镜子、
超调用分派这些公开的技术原理。

## 为什么是 192 个？

老师样本 `all_functions_index_cn.csv` 里 `04-内存映射与隐藏` 分类恰好 192 个函数：

| 角色 | 数量 | 说明 |
|---|---|---|
| EPT/NPT 内存映射 | 73 | 页表走查、拆大页、建表、装/卸双视图、藏页、翻镜子 |
| Hook/隐藏 | 119 | 认人（PID/CR3）、软断点、进程表遍历、总装 |

其中 **39 个带名字**（`HV_*`、`Hook_*`）在各自模块里**忠实建模**（逐行对照 IDA
伪代码）；其余 **153 个 `sub_XXXX`**（VMProtect 加密区，老师分析也未能还原内容）
在 `dnz_stubs.c` 里按「角色 + 调用关系 + 关键行特征」逐个建模，每个都保留
IDA 地址/序号/角色/大小/调用者。

## 工程结构（6152 行）

```
engine/
  main.c           主演示：7 个场景 + 192 函数覆盖报告
  dnz_types.h      数据结构/常量（注释保留老师魔数偏移）
  dnz_pool.c/h     页框池 + 模拟物理内存
  dnz_ept.c/h      HV_LookupEptEntry / SplitLargePage / EnsureSplitPage /
                   MapGuestAccess / SplitPage_ClearXD
  dnz_hook.c/h     HV_EptInstallHook / RemoveHook / HidePages / UnhidePages /
                   RemoveEptHook_Wrapper
  dnz_realvmx.c/h  真 VMX 路径全套（Install/Remove/Hide/Unhide/OpA/OpB + Api 入口）
  dnz_violation.c/h  HandleGuestFaultOrExit / AfterEptViolation /
                   SwapHookOnViolation / ClearPendingExceptionState /
                   TryFastExitPath / ValidateEptExitState / InvalidateGuestTlbOrEpt
  dnz_dispatch.c/h HV_HypercallDispatch / DispatchFromGuestFrame /
                   RaiseException_C0000450 / 门口分派表
  dnz_hooks.c/h    Hook_OnGuestCr3Change / LookupByPid / RegisterSoftBp /
                   InstallAll / 进程表遍历
  dnz_stubs.c/h    153 个 sub_ 函数逐个建模
  dnz_registry.c   192 函数登记表（链接期验证全覆盖）
  dnz_aliases.h    老师原名 → 模型函数 映射
engine_ref/        生成工具（依据 D 盘逐行分析自动生成 stubs/registry）
```

## 编译（用你机器上真实的 MSVC 工具链）

```bash
cd D:\dnz_guard_sim\engine
# 设好 MSVC + SDK 的 INCLUDE/LIB（见下方）后：
cl /nologo /W3 /O2 /EHsc /utf-8 /Fe:dnz_engine.exe main.c dnz_pool.c \
   dnz_ept.c dnz_hook.c dnz_realvmx.c dnz_violation.c dnz_dispatch.c \
   dnz_hooks.c dnz_stubs.c dnz_registry.c /link /subsystem:console
```

你的工具链位置（本机实测）：
- MSVC：`D:\VSBuildTools\VC\Tools\MSVC\14.44.35207`
- SDK：`D:\CodexWork\WindowsKits\10\Include\10.0.26100.0`
- LIB：MSVC `lib\x64` + SDK `Lib\10.0.26100.0\ucrt\x64` + `um\x64`

## 运行

```
dnz_engine.exe
```

输出 7 个场景（双视图装卸、保安查房翻镜子、藏页放页、超调用全家桶、
Hook 总装认人、RealVmx 路径、退出处理链）+ 192 函数覆盖报告。

## 建模依据

`D:\CodexWork\ReverseLabV3\teacher_function_by_function_20260813\output\`
（`all_functions_index_cn.csv` + `line_by_line_cn\LINE_*.md` 逐行大白话）。
`engine_ref\teacher_192_reference.md` 是 192 个函数章节的合并版。

## 诚实边界

- 39 个命名函数：**逐行对照 IDA 伪代码**建模（魔数、掩码、流程都保留）。
- 153 个 sub_：VMProtect 加密区，老师分析也只还原了调用图/角色——这里给的是
  围绕已知调用关系的结构模型，不是"还原原逻辑"。
- 这是**软件模型**：EPT 是数组模拟，不是真硬件页表。
