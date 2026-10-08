# Device Identity Simulation：实现与验证状态

设计见 `device-identity-architecture.md`。本文记录已经实现了什么、怎么验证、哪些没有验证。

## 验证状态（先看这里）

| 内容 | 状态 |
|---|---|
| `common/device_identity/` 核心库（纯标准 C++） | 已在本机用 clang（`-Wall -Wextra -Wpedantic -Werror`，ASan + UBSan）编译并通过全部测试 |
| `tests/device_identity_tests.cpp`（156 项检查） | 通过；另做了 4 组变异验证（去掉域隔离、MAC 忽略盐、去掉别名表、UUID 取自来源值），测试都能抓到 |
| 宿主/DLL 的 Windows 接线（`Launcher`、`Env*`、`GlobalData`、`Hook-*`、`dllmain`、`biz_initializer`） | 4 种 Windows 构建通过（首次构建发现并修复了 `CoGetClassObject` Hook 的签名错误） |
| Windows 构建与运行探针（基线 vs 托管，SMBIOS 表 vs WMI 交叉检查，默认模式，按应用策略 + `MachineGuid`） | 已在 GitHub Actions 的 Windows runner 上通过（4 种构建 + Release x64 全部探针），三个探针步骤均为阻塞检查。两批探针（宿主重启前后）读到的画像值逐项相同，印证重启后身份稳定。runner 磁盘无可读序列号，存储序列号改写路径未被真实数据覆盖 |

在全局模块片段里 `#include` 标准库头文件（`GlobalData.ixx`、`Env-Envrironment.ixx`）已被 Windows 构建验证可用。

## 做了什么

**新的可移植核心** `common/device_identity/`（头文件，无 Windows 依赖，宿主、DLL、测试共用）

| 文件 | 内容 |
|---|---|
| `InstanceIdentity.hpp` | `InstanceId / InstanceIndex / SessionId / ObjectNamespaceId`；DLL 名、hive 名、注册表后缀、对象命名空间后缀各有独立访问器（数值沿用旧 `envFlag`，无需迁移） |
| `DeviceProfile.hpp` | `Storage/Network/Os/HardwareProfile`、生成、带校验和的文本序列化、`DeviceProfileStore`（原子写）、`obtain_profile`（已绑定则必须能读到，读不到抛异常，绝不静默重新生成） |
| `DeviceIdentityProvider.hpp` | 形状保留推导（磁盘/SMBIOS 序列号、PNP 后缀、网卡 GUID、MAC）、系统 UUID、SMBIOS 原始表原地改写（长度不变） |
| `DeviceLaunch.hpp` | 能力位、`HookPlan`、按应用策略解析、旧 `WORKSPACE_HOOK_SCOPE` 映射、`LaunchConfig` 编解码 |

**宿主（2Box.exe）**
- `Launcher`：每次启动前 `resolve_launch_config`（策略文件或旧环境变量 → 能力集；需要模拟时 `obtain_profile`），然后把 `LaunchConfig` 编进注入 payload。解析失败会让启动失败。
- `Env`：`getInstanceIdentity()`，以及与实例身份独立的 `deviceProfileId`（注册表 `DeviceProfile` QWORD，缺省 0）。
- `EnvManager`：`bindDeviceProfile`、`deviceProfileDirectory`；删除环境时删除它的画像文件。
- `DetourInjectParams` 增加 `launchConfigBytes`，配置文本紧跟在 `rootPath` 之后。

**目标进程（MemoryDll）**
- `Data` 改为持有 `InstanceIdentity + HookPlan + DeviceIdentityProvider`；删除 `envFlag` 哈希、缓存表、互斥锁；新增按数据域的 `virtual*` 访问器，无画像时是 no-op。
- `hook_all` 完全由 `HookPlan` 决定，不再读环境变量。
- 命名对象/管道后缀改用 `objectNamespaceName()`，注册表后缀用 `registrySuffixName()`。
- WMI：按数据域门控，使用同一组推导函数；**删除 `ProcessorId` 改写**。
- 新增 `GetSystemFirmwareTable` Hook（`smbios` 能力）。
- 子进程创建 Hook 原样转发 `LaunchConfig`。

## 行为变化（请确认）

1. **默认不再安装设备类 Hook**。以前未设置 `WORKSPACE_HOOK_SCOPE` 时，`DeviceIoControl`、完成端口类、IP Helper、NetBIOS、整个 WMI/COM 钩子对每个受管进程都生效；现在默认是"普通多开"（只有隔离类 Hook + 进程创建传播）。
2. `WORKSPACE_HOOK_SCOPE` 现在由宿主读取并映射成 `LaunchConfig`（CI 仍可使用）。映射保持原有 Hook 集合，另外 `device`/`device-async` 增加了 `smbios`，以保持 WMI 的 UUID/BIOS 序列号仍被改写。
3. 设备值的生成方式变了：序列号保持来源值的长度、字符类别、分隔符和厂商标签，不再是截断的 16 位十六进制；GUID 保持大小写和花括号；已有环境第一次启用设备模拟时会得到新的画像，数值与旧版本不同。

## 如何启用

默认什么都不用做。对单个应用启用：在 `<exeDir>/Env/data/device-policy.ini` 写入

```ini
[app]
match = target.exe
capabilities = storage, network, smbios, os, wmi
```

每次启动重新读取；第一次命中时为该环境创建画像并绑定，之后重启沿用同一个画像。运行测试：

```bash
tests/run-device-identity-tests.sh
```

## 测试覆盖对应关系

| 要求 | 测试 |
|---|---|
| 同一 Profile 重启后身份稳定 | `profile_is_stable_across_restart`、`same_profile_reproduces_identity_in_a_fresh_provider`、`golden_values_pin_the_derivation_algorithm`（防止升级后算法漂移） |
| 画像损坏/丢失不会变成新机器 | `damaged_or_missing_bound_profile_is_an_error_not_a_new_machine`、`failed_binding_removes_the_orphan_profile`、`newer_schema_version_is_rejected` |
| 不同 Profile 相互独立 | `different_profiles_produce_independent_identities`、`domains_are_isolated_from_each_other` |
| InstanceIdentity 与 DeviceIdentity 不耦合 | 两个 `static_assert`（不能由实例身份构造）、`instance_identity_does_not_influence_device_identity`、`device_profile_does_not_influence_instance_identity`、`two_instances_can_share_one_profile...` |
| 普通多开模式不受影响 | `default_launch_is_plain_isolation_without_device_simulation`、`no_policy_or_unmatched_policy_means_no_capabilities`、`simulation_is_enabled_per_application`、`legacy_scopes_map_to_the_same_hook_sets_as_before` |
| 不同 API 数据一致 | `same_disk_gives_same_serial_through_every_api_encoding`（描述符/WMI/ATA 字对调）、`smbios_table_and_wmi_style_queries_agree`、`guid_keeps_wrapping_and_case_and_agrees_across_spellings`、`mac_keeps_vendor_prefix_and_flags_and_agrees_across_apis`；Windows 探针里的 SMBIOS 表 vs WMI 检查 |
| 真实感 | `serials_keep_length_shape_and_vendor_tag`、`placeholder_serials_become_plausible_generated_serials`、`pnp_instance_suffix_keeps_its_structure` |
| 健壮性 | `smbios_rewrite_survives_malformed_input`（逐字节截断，ASan 下无越界） |

## 后续修复记录

- 新增 `os` 能力：注册表读取 `MachineGuid` 返回画像里的值（与宿主无关）。
- 序列号以"字母数字内容"为键，不同写法（如 NVMe 的 `0025_38B1_21A2_3C4D.` 与 `002538B121A23C4D`）得到相同的字符，仅排版跟随来源。
- 策略文件注释只在行首或空白之后开始，路径中可含 `#`、`;`。
- 别名表设上限（4096 项，满后清空）。
- 清理无用代码（这些文件在工程里本就是 `ExcludedFromBuild`，不影响构建结果）：反射式注入链（`Injector.ixx`、`LoadSelf.cpp`、`dllmain.cpp` 的 `REFLECTIVE_INJECT` 分支、`sys_defs.h` 中对应结构体、`pe_loader` 的 Loader/Exceptions/StaticTLS/Symbol/SystemInfo 分区、`Utility.Toolhelp`）和符号下载链（`SymbolLoader`、`WinHttp`、`UI.Page-Download`、`UI.FileStatusCtrl`、`UI.LoadingIndicator`），以及 `EssentialData.ixx` 里的注释掉的旧代码。
- `Hook-Kernel32.ixx` 中三个重复的同步 `Proc_*` 函数合并为 `classify_device_query` + `rewrite_device_query`。

## 已知限制与后续

- 重叠 I/O：`storage` 自带 `GetOverlappedResult(Ex)`/完成端口路径。仅靠事件等待、从不调用这些 API 的应用，其结果不会被改写（需要 `storage-wait`，实验性）；待处理表有 256 项上限，超出即清空，避免无限增长。

- **未覆盖的路径**（明确"未模拟"）：`NtQuerySystemInformation(SystemFirmwareTableInformation)`、直接 syscall、内核/驱动侧查询、CPUID、卷序列号、非 `os` 能力下的注册表 `MachineGuid`。`os` 能力只覆盖 `RegQueryValueExW`/`RegGetValueW`（W 版本），按值名 `MachineGuid` + GUID 形状识别，不校验键路径，A 版本与 `NtQueryValueKey` 直接调用未覆盖。
- 磁盘/网卡/SMBIOS 序列号依赖宿主来源值；宿主换硬件这些值会变。系统 UUID 与 `MachineGuid` 与宿主无关。
- UI 还没有"为某个应用启用设备模拟"的入口，目前通过策略文件。
- 启用后同一环境内同一应用的所有子进程都继承相同能力集。
- 画像与环境 1:1（存储结构支持共享，但删除环境会删除其画像）。
- `storage-wait` 仍是全局高频 Hook，仅作实验开关；计划被 `NtDeviceIoControlFile` 方案取代（见 `device-isolation-plan.md`）。
- 与本次任务无关、但值得处理的旧问题：RPC `login` 信任客户端传入的 `envFlag`/`pid`。
- 画像仍偏薄：存储/网络部分只是盐值，序列号对宿主真实值做形状保留的替换，型号/厂商/固件不模拟。要做成自包含画像，需要与宿主无关的设备键（如 PhysicalDrive 序号、适配器序号），并让 `DeviceIoControl`、WMI、IP Helper 都改用该键；存储 Hook 里取得序号要额外发 IOCTL 或解析句柄路径，无法脱离 Windows 验证，故未做。
