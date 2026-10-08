# 设备隔离与启动流程待办

> 设备身份已重构为按能力启用的 DeviceIdentityProvider，默认不再安装设备类 Hook，`WORKSPACE_HOOK_SCOPE` 已删除（改用策略文件）。新的设计与状态见 `device-identity-architecture.md` 与 `device-identity-implementation.md`；下文的 Hook 范围描述为重构前的状态。

## 已接入

- [x] 修正 `GetWindow` 遍历、进程列表首项过滤，以及同步磁盘查询的长度与状态处理。
- [x] WMI 常见同步 COM 路径、异步对象回调和延迟结果在结果对象的 `Get`/`Next` 层改写序列号、UUID、设备实例 ID 和网卡地址；保持原始 HRESULT、VARIANT 类型、型号等非唯一字段。
- [x] 重叠 `DeviceIoControl` 在立即完成、事件等待、`GetOverlappedResult(Ex)` 与完成端口出队后改写输出；保持原始完成状态和错误码。
- [x] ATA/SCSI、存储描述符及 WMI 序列号使用同一环境派生函数；IP Helper、NetBIOS 及 WMI 网卡地址和网卡 GUID 分别共用对应转换函数。
- [x] 去掉运行时品牌字面量、可执行文件名和版本资源中的旧名称；Release x64 构建增加打包二进制中的 ASCII/UTF-16 字符串扫描。源码目录及项目文件路径仍保留仓库原有名称。
- [x] 数据目录只发现一份旧注册表 hive 且新文件不存在时自动迁移，保留现有环境配置；多份 hive 时不自动猜测。
- [x] 主启动器直接创建目标进程，省去命令解释器中转；将 RPC 和批量 Hook 初始化移至目标进程入口，先在 DLL 加载阶段校验并复制注入参数。
- [x] 批量 Hook 安装逐项检查 Detours 返回值，失败时中止事务，避免部分 Hook 静默缺失。
- [x] 增加可选 Hook 范围：`device` 保留设备查询和完整异步完成通知，`device-async` 保留设备查询及 `GetOverlappedResult`/完成端口结果处理但跳过通用等待和 `CloseHandle`，`device-minimal` 仅保留同步设备查询；三者都跳过 Ntdll 文件/注册表、User32 窗口、命名管道和额外启动入口 Hook。未设置时保持完整范围，但不启用已知会影响编译器子进程的通用等待和 `CloseHandle` Hook。
- [x] GitHub Actions 已配置 Debug/Release、x86/x64 构建；Release x64 增加原生与双环境运行探针，覆盖 WMI 同步/异步硬盘、BIOS/UUID/网卡、IP Helper、同步/重叠存储查询、短缓冲区和错误状态。

## 验证门槛

- [x] GitHub Actions 四种 Windows 构建全部通过；Release x64 打包二进制旧名称扫描通过（运行 36304622649）。
- [x] GitHub Actions 运行探针通过，并检查同一环境跨接口一致、不同环境标识不同、失败与短缓冲区状态不变。运行 36366466535 的四种 Windows 构建和 x64 Release 探针全部通过；两个托管探针均在 `device-async` 范围下执行。存储序列号由 runner 磁盘决定，缺失时保留 `NO_SERIAL`，结构、错误状态和短缓冲区路径仍被检查。
- [x] 排查托管 PowerShell 启动 `csc.exe` 时的子进程崩溃；`device-minimal` 和 `device-async` 均通过编译器子进程验证。对照运行显示崩溃集中在完整设备范围中的通用等待与 `CloseHandle` Hook，因此设备场景优先使用 `device-async`。
- [ ] 在真实 Windows 桌面上启动一个依赖 WMI 和异步设备查询的目标程序，检查启动、退出、子进程继承和长期运行。

## 仍需覆盖的路径

- [ ] WMI 脚本 `GetObject` 等其他入口，以及不同 COM 代理或回调对象实现；当前动态 Detour 只跟踪每种接口首次遇到的方法实现地址。
- [ ] `NtDeviceIoControlFile` 直接调用、线程池 I/O 回调和不经过受 Hook 完成 API 的路径；当前重叠输出改写只在已覆盖的完成通知后触发。
- [ ] 根据实际目标应用决定设备、文件、注册表、窗口和输入同步各组 Hook 的启用范围；当前提供全量默认、`device`、`device-async` 和 `device-minimal` 范围，仍需桌面环境评估配置粒度。
- [ ] 检查 SMBIOS/固件表、PnP、网络管理等其他设备信息入口；用户态 Hook 无法单独保证所有路径的设备隔离。
