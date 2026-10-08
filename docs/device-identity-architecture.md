# Device Identity Simulation 架构分析与设计

适用范围：仅用于**自己控制的应用**做多设备、多实例兼容性测试。不针对任何第三方安全软件、反作弊、EDR 或完整性检测，不做模块隐藏、PEB unlink、手工映射等 stealth 技术，也不修改安全软件看到的系统状态。

本文对应前三个阶段（分析、设计、Hook 处置）；实现与测试状态见 `docs/device-identity-implementation.md`。

---

## 第一阶段：现状分析

### 1.1 模块依赖与数据流

```
┌────────────────────────────── 2Box.exe（宿主）──────────────────────────────┐
│  MainApp ─ UI ─▶ Launcher ─▶ EnvManager ─▶ Env ─▶ Env-Reg（app hive 注册表）│
│                     │            │                                          │
│                     │            └─ ensureCreateNewEnvFlag：随机 64 位 envFlag│
│                     │                                                       │
│                     ├─ Env::ensureDllInDeviceAndReturnPath()                │
│                     │      └─ 写出 bin/<envFlag>_{64,32}.bin（内嵌 MemoryDll）│
│                     ├─ DetourCreateProcessWithDllEx(CREATE_SUSPENDED)       │
│                     └─ DetourCopyPayloadToProcess(DetourInjectParams)       │
│                          { version, envFlag, envIndex, rootPath }           │
│  RpcServer（ncalrpc）◀───────────────────────────┐                          │
└──────────────────────────────────────────────────│──────────────────────────┘
                                                   │ login / window / process 查询
┌──────────────── 目标进程（含 MemoryDll）─────────────│──────────────────────────┐
│ DllMain(attach)                                    │                          │
│   └ 复制 payload，Detour 进程入口 → managed_process_entry                    │
│ managed_process_entry                              │                          │
│   └ biz_initialize(version, envFlag, envIndex, rootPath)                    │
│        1. Data::initialize：权限、RegLoadAppKey(Env/<index>/<envFlag>)、     │
│           DLL 路径、KnownFolder 重定向表                                     │
│        2. initialize_rpc：login(pid, envFlag) ──────┘ 宿主退出则终止自身      │
│        3. initialize_hook：读进程环境变量 WORKSPACE_HOOK_SCOPE → hook_all    │
│ 子进程：Kernel32/Advapi32/Shell32 的 CreateProcess* 钩子用 Data 里的         │
│         envFlag/envIndex/rootPath 重新注入同一个 DLL                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

`Hook-All.ixx` 的 Hook 模块：

| 模块 | 内容 |
|---|---|
| Ntdll | NT 命名对象后缀、文件重定向、`NtQuerySystemInformation`（进程列表过滤）、虚拟注册表 |
| Kernel32 | 进程创建传播、`WaitNamedPipe`、`CreateBoundaryDescriptor`、`OpenProcess`、`DeviceIoControl`、异步完成与等待类、`CloseHandle` |
| Advapi32 / Shell32 | `RegLoadAppKeyW`、`CreateProcessAsUser*`、`ShellExecute*`（传播与提权提示） |
| User32 | 窗口枚举与输入同步 |
| Ole32 | `CoCreateInstance(Ex)`/`CoGetClassObject` + WMI 虚表动态 Detour |
| Iphlpapi / Netapi32 | `GetAdaptersInfo/Addresses`、`Netbios` |

### 1.2 `envFlag` 实际承担的职责

`envFlag` 是宿主随机生成并写入注册表的 64 位值，目前同时是：

| # | 职责 | 位置 |
|---|---|---|
| 1 | 环境主键（EnvManager map、RPC 查找、exclude 列表） | `Env-EnvManager.cpp`、`RpcServer.cpp` |
| 2 | 注入 DLL 文件名 `bin/<flag>_64.bin` | `Env-Envrironment.cpp` `get_dll_full_path` |
| 3 | 注册表 hive 文件名 `Env/<index>/<flag>` | `GlobalData.cpp` `initializeRegistry` |
| 4 | NT 命名对象 / 命名管道 / Boundary Descriptor 的后缀（Mutex 等命名空间） | `Hook-Ntdll.ixx`、`Hook-Kernel32.ixx` |
| 5 | 虚拟注册表中 `RegLoadAppKeyW` 子键后缀 | `Hook-Advapi32.ixx` |
| 6 | RPC `login` 身份 | `biz_initializer.cpp` |
| 7 | **设备身份哈希种子**（磁盘序列号、GUID、MAC 都是 `envFlag ^ 常量` 的哈希） | `GlobalData.cpp` `virtual*` |

`envIndex` 单独负责文件系统重定向目录 `Env/<index>/...`。

### 1.3 问题清单

**A. 职责耦合**

1. `envFlag` 同时是 DLL 名、hive 名、对象命名空间、RPC 身份和设备种子（见 1.2）。想改其中一项（例如让同一个设备画像在两个环境间共享，或重建对象命名空间）都会牵动其它项。
2. 设备身份是 `hash(envFlag ^ 常量, 原值)`，不存在"设备画像"这个实体：无法单独导出、复用、审计或重置；换 `envFlag` 就等于换机器。

**B. 默认行为不是"普通多开"**

3. 未设置 `WORKSPACE_HOOK_SCOPE` 时 `hook_all` 走"完整范围"，`DeviceIoControl`、完成端口类、`Iphlpapi`、`Netapi32`、整个 WMI/COM 钩子对**每一个**受管进程都安装。设备模拟没有开关，也不能针对单个应用启用。
4. 钩子范围来自**进程环境变量**：会被子进程继承，目标程序自己也能改；它不在注入 payload 里，宿主与子进程是否一致没有保证。

**C. 设备模拟本身的正确性问题**

5. 序列号规则是"16 位十六进制哈希截断到原长度"。不保留原值的形状（字符类别、分隔符、`WD-` 之类厂商前缀、大小写），原本 `S4EVNX0M…` 的字段会变成纯十六进制串。
6. 不同域共用同一个映射函数和缓存：硬盘序列号、BIOS/主板序列号、`ProcessorId`、PNP 实例 ID 后缀都走 `virtualDiskSerial`。PNP 后缀的 `5&1A2B&0&000000` 结构被破坏；跨域同值会互相别名。
7. `Win32_Processor.ProcessorId` 被改写，但 CPUID 指令无法被用户态 Hook，同一进程里 WMI 与 CPUID 必然矛盾——这是**自相矛盾**，不是模拟。
8. 同一个"机器 UUID"有多个合法来源：WMI `Win32_ComputerSystemProduct.UUID`、SMBIOS 原始表（`GetSystemFirmwareTable`）、注册表 `MachineGuid`。目前只改 WMI，其余仍是真值，API 之间互相矛盾。
9. 映射依赖进程内 `unordered_map + mutex` 缓存才能幂等（`result→result`），热路径持锁；本质上推导函数应该是无状态的。
10. GUID 一律大写输出，不保留来源大小写；MAC 的重写没有保证首字节的单播/本地管理位不变（目前靠"只改后三字节"碰巧成立，没有显式约束）。

**D. 钩子数量与热路径**

11. 异步设备查询靠 `DeviceIoControl` + `GetOverlappedResult(Ex)` + `GetQueuedCompletionStatus(Ex)` + 4 个 `WaitFor*` + `CloseHandle` 拼出"完成时机"。后两类是全进程最高频 API，已知影响编译器子进程，已被默认关闭；关闭后事件等待式完成会漏改写。
12. WMI 每种方法只跟踪**首次**遇到的实现地址，且 `IWbemClassObject::Get` 的实现被所有 WMI 对象共享，改写函数还会多调一次 `Get(__CLASS)`——对同进程内与设备无关的 WMI 使用也有额外开销。
13. SMBIOS 固件表、`NtDeviceIoControlFile` 直接调用、直接 syscall 都不在覆盖范围，但没有任何地方声明这一点。

**E. RPC 与生命周期**

14. `login(pid, envFlag)` 完全信任客户端传来的 `envFlag`/`pid`，`ncalrpc` 端点无安全回调，任何本地进程都可以注册为某环境的进程或查询列表（`RpcRaiseException(0xE06D7363)` 还把所有错误压成同一个码）。**设备画像不应该经 RPC 传输。**
15. `m_currentIndex = max(index)+1`，删除最后一个环境后重启会复用 index；目前靠"先 rename 再异步 `rd`"规避，但这是隐含约定。
16. `REFLECTIVE_INJECT` 分支调用的 `biz_initialize` 参数与现有 5 参签名不一致，是不会编译的死代码。

**F. 可测试性**

17. 推导逻辑和 Windows 钩子、`import std` 模块混在一起，只能靠 Windows CI 的 PowerShell 探针做"基线 vs 托管"对比，无法脱离 Windows 做单元测试，也没有覆盖"重启稳定性""不同 Profile 独立"。

### 1.4 哪些能力当前无法安全支持（不用更多 Hook 硬补）

| 能力 | 原因 | 处理 |
|---|---|---|
| `ProcessorId` / CPUID | 指令级信息，用户态 Hook 无法覆盖，改 WMI 必然与 CPUID 矛盾 | 删除改写，Profile 不包含 CPU 标识 |
| 内核/驱动侧、直接 syscall 的查询 | 用户态 Hook 看不到 | 文档声明"不模拟"；真有目标应用需要再评估（见旧计划阶段 4） |
| 基于 `WaitFor*`/`CloseHandle` 的异步完成改写 | 需要全进程最高频 API 的 Hook | 不进入任何默认配置；仅保留实验性 `StorageWait` 能力，等 `NtDeviceIoControlFile` 方案替代后删除 |
| 与上述矛盾的"部分模拟" | 违反"不自相矛盾" | 每个 Capability 声明覆盖的 API 集合；没覆盖的路径明确标注"未模拟" |

---

## 第二阶段：DeviceIdentityProvider 设计

### 2.1 总体结构

```
InstanceIdentity（谁：隔离实例）            DeviceIdentity（像什么机器：设备画像）
├── InstanceId        = 旧 envFlag（兼容）   ├── StorageProfile   硬盘序列号推导
├── InstanceIndex     = 旧 envIndex          ├── NetworkProfile   MAC / 网卡 GUID 推导
├── SessionId         每次宿主运行随机       ├── OsProfile        MachineGuid
└── ObjectNamespaceId = 命名对象后缀         └── HardwareProfile  SMBIOS UUID / 序列号
        │                                              │
        └──────── 彼此不引用、不互相构造 ─────────────┘

DeviceProfile（持久化数据）──▶ DeviceIdentityProvider（只读、无状态的推导器）
DeviceCapabilities（本次启动启用哪些模拟）──▶ HookPlan（装哪些 Hook）
```

- `InstanceIdentity` 的数值直接沿用现有 `envFlag`/`envIndex`（`ObjectNamespaceId` 默认等于 `InstanceId`），**已有环境无需迁移**；但 DLL 名、hive 名、对象后缀、RPC 身份各自通过独立访问器取得，今后可以分别演进。
- `DeviceIdentityProvider` 的构造函数**只接受** `DeviceProfile`，编译期保证不依赖 `InstanceIdentity`。

### 2.2 推导策略：画像持久化 + 形状保留推导

不往字段里塞随机十六进制，也不要求画像覆盖宿主上所有设备：

- **显式存储的单例**（与宿主硬件无关，换机器也不变）：SMBIOS 系统 UUID、`MachineGuid`。
- **按来源值推导的多实例设备**（磁盘、网卡、SMBIOS 序列号）：`derive(domain, profile.salt, 规范化来源值)`，并且**保留来源值的形状**——长度、字符类别（数字/大写/小写/十六进制）、分隔符、大小写、`WD-` 这类 ≤4 位的厂商标签前缀；MAC 保留 OUI 与首字节标志位；GUID 保持 v4 版本位。型号等非唯一字段不改，所以"厂商/型号/序列号格式"天然一致。
- 域隔离：`DiskSerial`、`SmbiosSystemSerial`、`SmbiosBoardSerial`、`SmbiosChassisSerial`、`PnpStorageInstance`、`PnpNetworkInstance`、`AdapterGuid`、`Mac` 使用不同的盐，互不别名。
- 推导函数无状态、无锁；仅保留一个小的"输出别名表"，使已经改写过的值再次进入同一入口时保持不变（幂等），避免同一缓冲区被两个钩子路径各改一次后出现分叉。
- 已知占位值（`To Be Filled By O.E.M.` 等）不是标识，直接推导会得到乱码；统一替换为画像生成的通用序列号。
- 推导结果保证 ≠ 来源值（相同则确定性扰动最后一位），否则无法区分"已改写"。

限制（写入文档、不隐藏）：磁盘/网卡/SMBIOS 序列号依赖宿主来源值；宿主换硬件后这些值会变，与"换了块硬盘"同义。需要完全脱离宿主的画像需要显式存储 N 块设备，留作后续。

### 2.3 同一数据、不同 API 的一致性

| 数据 | 来源 API | 表示 | 共用的推导 |
|---|---|---|---|
| 磁盘序列号 | `DeviceIoControl` SMART/SCSI（ATA 字对调、20 字节空格填充）、`STORAGE_DEVICE_DESCRIPTOR`、WMI `Win32_DiskDrive/PhysicalMedia.SerialNumber` | 编码层不同 | 规范化后进入同一个 `DiskSerial` 推导，再各自编码 |
| 系统 UUID | WMI `Win32_ComputerSystemProduct.UUID`、SMBIOS 表 Type 1（前三段小端） | 文本 vs 字节 | 都映射到 `profile.hardware.systemUuid` |
| 系统序列号 | WMI `Win32_BIOS.SerialNumber`、`ComputerSystemProduct.IdentifyingNumber`、SMBIOS Type 1 字符串 | 文本 vs 表内字符串 | 同一 `SmbiosSystemSerial` 域；表内改写长度不变，不移动结构 |
| 主板序列号 | WMI `Win32_BaseBoard.SerialNumber`、SMBIOS Type 2 | 同上 | `SmbiosBoardSerial` |
| MAC | `GetAdaptersInfo/Addresses`、NetBIOS、WMI `MACAddress` | 字节 vs 文本 | 同一 `Mac` 推导 |
| 网卡 GUID | `AdapterName`、WMI `GUID/SettingID` | 带/不带花括号 | 同一 `AdapterGuid` 推导 |

### 2.4 数据结构（实际代码见 `common/device_identity/`）

```cpp
struct InstanceIdentity {         // 与设备无关
    uint64_t instanceId;          // 旧 envFlag
    uint32_t instanceIndex;       // 旧 envIndex
    uint64_t sessionId;           // 每次宿主运行
    uint64_t objectNamespaceId;   // 命名对象后缀
};

struct DeviceProfile {            // 持久化
    uint32_t schemaVersion;
    uint64_t profileId;
    StorageProfile  storage;      // { salt }
    NetworkProfile  network;      // { salt }
    OsProfile       os;           // { machineGuid }   消费者：阶段 2 的注册表读取
    HardwareProfile hardware;     // { salt, systemUuid }
};

// 数据域（模拟什么）：Storage / Network / Smbios
// 传输（经由哪些 API 到达）：Wmi / StorageAsync / StorageWait(实验)
enum Capability : uint32_t { kCapStorage, kCapNetwork, kCapSmbios,
                            kCapWmi, kCapStorageAsync, kCapStorageWait };

struct LaunchConfig {             // 宿主→目标进程，注入 payload 的一部分
    uint64_t sessionId, objectNamespaceId;
    uint32_t hooks;               // kHookIsolation / kHookProcessOnly
    uint32_t capabilities;        // 0 = 普通多开
    std::optional<DeviceProfile> profile;   // 仅当 capabilities 含数据域时存在
};
```

### 2.5 Profile 存储与生命周期

- **文件**：`<exeDir>/Env/data/device-profiles/<profileId>.profile`，带版本号和校验行的文本格式；原子写（临时文件 + rename）。
- **绑定**：环境注册表项新增 `DeviceProfile`（QWORD，缺省 0 = 未绑定）。画像与实例是"拥有"关系，不是同一个标识。
- **创建**：仅当某次启动**需要**设备模拟、且该环境未绑定画像时创建一次（CSPRNG 种子），立即落盘并写入绑定；之后永远读取。
- **加载失败**：文件缺失、损坏、版本过新 → **启动失败并提示**，绝不静默重新生成（否则每次都变成新机器）。
- **删除**：删除环境时同时删除其绑定的画像文件。
- **传输**：宿主读取画像后序列化进注入 payload（`LaunchConfig`），目标进程不读文件、不走 RPC；子进程原样转发 payload，因此整个进程树看到同一个画像。

### 2.6 启用方式（按应用）

- 默认：没有策略文件或不匹配 → `capabilities = 0`，只安装普通多开所需的隔离钩子，payload 不带画像。
- 策略文件 `<exeDir>/Env/data/device-policy.ini`，每次启动时读取：

```ini
[app]
match = target.exe            ; 只含文件名：按文件名匹配；含路径分隔符：按完整路径匹配（不区分大小写）
capabilities = storage, storage-async, network, smbios, wmi
```

- 子进程继承根进程的能力集（它们属于同一个被测应用）；解析出错（未知能力名等）会让启动失败并提示，而不是静默当作"未配置"。
- 兼容开关 `WORKSPACE_HOOK_SCOPE`（CI 用）由**宿主**映射为 `LaunchConfig`，DLL 不再读取环境变量。未设置时 = 普通多开。

### 2.7 Capability 与一致性规则、HookPlan

**数据域能力**决定"模拟什么"：同一数据域下的所有已知 API 要么**全部**改写，要么**都不**改写，不允许出现"WMI 说是虚拟值，`DeviceIoControl` 说是真值"的半成品。

| 能力 | 类型 | 覆盖的 API（同一数据域内一起生效） |
|---|---|---|
| `storage` | 数据域 | `DeviceIoControl`（SMART / SCSI miniport / `STORAGE_DEVICE_DESCRIPTOR`）、WMI `Win32_DiskDrive/PhysicalMedia` 序列号与 PNP 实例后缀 |
| `network` | 数据域 | IP Helper（`GetAdaptersInfo/Addresses`）、NetBIOS、WMI `Win32_NetworkAdapter(Configuration)` 的 MAC / GUID / PNP 后缀 |
| `smbios` | 数据域 | `GetSystemFirmwareTable('RSMB')` 的系统 UUID 与系统/主板/机箱序列号、WMI `Win32_ComputerSystemProduct/BIOS/BaseBoard/SystemEnclosure` |
| `os` | 数据域 | 注册表 `RegQueryValueExW`/`RegGetValueW` 读取 `MachineGuid`（按值名与 GUID 形状识别），返回画像里的 `os.machineGuid` |
| `wmi` | 传输 | 对已启用的数据域启用 WMI 结果改写；单独写 `wmi` 不改写任何东西（`normalize_capabilities` 会把它丢掉） |
| `storage-async` | 传输 | 重叠 I/O 完成路径：`GetOverlappedResult(Ex)`、`GetQueuedCompletionStatus(Ex)`；隐含 `storage` |
| `storage-wait` | 传输（实验） | 事件等待式完成：`WaitFor*`、`CloseHandle`；隐含 `storage`；不在任何默认组合内 |

Hook 只由 `HookPlan` 决定，`HookPlan` 是 `LaunchConfig` 的纯函数：

```
总是               → Kernel32 CreateProcessA/W、WinExec（把 LaunchConfig 原样传给子进程）
Isolation          → Ntdll / Advapi32 / Shell32 / User32 + Kernel32 的 Pipe/Boundary/OpenProcess
storage            → Kernel32 DeviceIoControl
storage-async      → GetOverlappedResult(Ex)、GetQueuedCompletionStatus(Ex)
storage-wait       → WaitFor*、CloseHandle
network            → Iphlpapi、Netapi32
smbios             → Kernel32 GetSystemFirmwareTable
wmi（且有数据域）   → Ole32/COM + WMI 虚表
```

默认的覆盖限制（明确"未模拟"，而不是悄悄漏掉）：`NtQuerySystemInformation(SystemFirmwareTableInformation)`、直接 syscall、内核/驱动侧查询、CPUID、卷序列号、注册表 `MachineGuid`、USBSTOR 这类把序列号嵌进 PNP ID 的设备。

---

## 第三阶段：现有 Hook 处置

| Hook | 处置 | 说明 |
|---|---|---|
| Ntdll 命名对象 / 管道后缀 | **保留**（Isolation） | 后缀改取 `ObjectNamespaceId`，数值不变 |
| Ntdll 文件重定向、虚拟注册表、`NtQuerySystemInformation` | **保留**（Isolation） | 普通多开本职 |
| Advapi32 / Shell32 / User32 | **保留**（Isolation） | 同上 |
| Kernel32 `CreateProcessA/W`、`WinExec` | **保留**（总是） | payload 增加 `LaunchConfig` |
| Kernel32 `WaitNamedPipe`、`CreateBoundaryDescriptor`、`OpenProcess` | **保留**（Isolation） | 同上 |
| Kernel32 `DeviceIoControl` | **改为 Capability** `storage` | 默认不再安装 |
| `GetOverlappedResult(Ex)`、`GetQueuedCompletionStatus(Ex)` | **改为 Capability** `storage-async` | 默认不再安装 |
| `WaitFor*`（4 个）、`CloseHandle` | **移出默认；仅实验 Capability** `storage-wait` | 计划被 `NtDeviceIoControlFile` 方案取代后删除 |
| Ole32 COM + WMI 虚表 | **改为 Capability** `wmi` | 默认不再安装；WMI 本身始终正常工作，不返回 `REGDB_E_CLASSNOTREG` |
| Iphlpapi / Netapi32 | **改为 Capability** `network` | 默认不再安装 |
| WMI `ProcessorId` 改写 | **删除** | 与 CPUID 矛盾 |
| `GlobalData` 里的 `envFlag` 哈希、缓存表、互斥锁 | **删除** | 由 `DeviceIdentityProvider` 取代（仅保留小型别名表保证幂等） |
| DLL 内读取 `WORKSPACE_HOOK_SCOPE` | **删除** | 宿主映射后经 payload 传入 |
| `GetSystemFirmwareTable` | **新增**（Capability `smbios`） | 低频 API，与 WMI UUID/序列号同源一致 |

