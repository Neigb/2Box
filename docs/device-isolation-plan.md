# 设备隔离后续方案草案

本文是 `device-isolation-todo.md` 之后的演进计划，目标：高/中频检测路径优先、热路径零额外开销、减少“靠堆 Hook 数量”的做法。

## 现状问题

1. 异步设备查询靠 `DeviceIoControl` + 8 个完成/等待 API（`GetOverlappedResult(Ex)`、`GetQueuedCompletionStatus(Ex)`、`WaitFor*`、`CloseHandle`）拼出“完成时机”，其中通用等待与 `CloseHandle` 是全进程最高频 API，已知影响编译器子进程，默认被关闭，导致事件等待式完成漏改写。
2. WMI 靠 COM 虚表动态 Detour，每种方法只跟踪首次遇到的实现地址，不同代理/回调实现会漏。
3. 仅覆盖 Win32 层，`NtDeviceIoControlFile`、SMBIOS 固件表等路径未覆盖。

## 阶段 0：验证当前修复（先做）

- CI 跑 `device-async` / 完整范围的运行探针；完整范围下追加“事件等待完成”和“OVERLAPPED 复用”用例。
- 完成 todo 中真实桌面验证项；记录各 Hook 的单次调用开销作为性能基线。
- 通过后评估是否恢复默认范围中的等待/`CloseHandle` Hook（现已有无挂起项时的无锁快速路径）。

## 阶段 1：设备查询收敛到 Nt 层

- 只 Hook `NtDeviceIoControlFile`（覆盖 `DeviceIoControl` 及直接调用 ntdll 的程序），识别 SMART/SCSI/StorageQuery 三类。
- 同步完成：直接改写。异步完成：对已识别的少数标识查询，用私有 `IO_STATUS_BLOCK` + 事件在 Hook 内等待，改写后再把结果写回调用方的 IOSB 并触发其事件/APC；IOCP 关联句柄需实测补发完成包的行为。
- 目标：删除 `WaitFor*`/`CloseHandle`/`GetQueuedCompletionStatus*` 全局 Hook 与待处理表。若 IOCP 语义无法保真，则退回“仅保留 GetOverlappedResult/GQCS，等待类 Hook 按需开启”。

## 阶段 2：补齐高频信息源

- SMBIOS/固件表：`GetSystemFirmwareTable`、`NtQuerySystemInformation(SystemFirmwareTableInformation)`。
- 卷序列号、MachineGuid、网卡信息等其余常见检测点按实际目标应用的命中频率排序，逐个核对。

## 阶段 3：WMI 覆盖面

- 以“实现地址 → trampoline”映射替代“首个地址”，每个不同实现各自挂接（预分配固定数量的模板槽位）。
- 补 `CoGetObject`/moniker（`winmgmts:`）入口。

## 阶段 4：决策门（按数据决定）

- 若目标应用使用直接 syscall、内核侧查询，或阶段 1–3 之后仍有高频泄漏：评估补充签名驱动，仅覆盖用户态 Hook 做不到的少数点；否则不引入。

## 阶段 5：配置与性能约束

- 将 `WORKSPACE_HOOK_SCOPE` 改为按目标应用的配置档。
- 新增 Hook 必须附带：单次调用开销数据、无挂起项时零锁/零分配的证明、子进程继承验证。
