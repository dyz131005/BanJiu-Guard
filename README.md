# BanJiu-Guard —— 反银狐木马杀毒软件

一个完整可运行的 C++/Qt + WDK 杀毒软件工程，针对"银狐"木马的增强防护。

## 项目结构

```
BanJiu-Guard/
├── CMakeLists.txt               # 顶层构建（GUI + 服务 + 公共库）
├── src/
│   ├── common/                  # 公共库
│   │   ├── yx_protocol.h        #   内核↔用户态通信协议（YX_EVENT/YX_DECISION 结构体）
│   │   ├── yx_yinhu_db.h        #   银狐木马特征库/IOC/规则分类
│   │   ├── yx_rules.h/.cpp      #   行为规则引擎（注册表持久化/注入/任务计划/C2/BYOVD）
│   │   ├── yx_heuristic.h/.cpp  #   PE 启发式扫描引擎（节区熵/可疑导入/加壳/签名缺失）
│   │   ├── yx_ml_engine.h/.cpp  #   机器学习引擎（LightGBM 22维PE特征推理 + 分数融合）
│   │   └── CMakeLists.txt
│   ├── driver/                  # 内核驱动（WDK Minifilter）
│   │   ├── yx_driver.cpp        #   DriverEntry + Minifilter 注册 + 通信端口
│   │   ├── yx_callbacks.cpp     #   文件/进程/映像/注册表/线程回调 + IOCTL 处理
│   │   ├── BanJiu-Guard.inf     #   驱动安装 INF
│   │   └── build_driver.bat     #   驱动命令行编译脚本（含 /INTEGRITYCHECK）
│   ├── service/                 # 实时防护服务（用户态）
│   │   ├── yx_service.h/.cpp    #   驱动通信 + 事件处置 + 隔离 + 启发式扫描集成
│   │   ├── yx_first_run.h/.cpp  #   首次运行 + 测试模式引导
│   │   └── CMakeLists.txt
│   └── gui/                     # Qt GUI（静态 MSVC）
│       ├── main.cpp             #   入口
│       ├── mainwindow.h/.cpp    #   主窗口（导航 + 托盘）
│       ├── toast.h/.cpp         #   右下角拦截弹窗（圆角/动画/DPI）
│       ├── pages/               #   仪表盘/扫描/隔离/日志/设置
│       ├── theme/style.qss      #   QSS 深色主题
│       ├── resources.qrc        #   资源
│       └── CMakeLists.txt
├── tools/
│   └── sign_driver.bat          # 驱动测试签名脚本
├── third_party/
│   └── build_lightgbm.bat       # LightGBM 4.6.0 静态库一键构建（自动 clone + /MT 编译）
├── models/
│   └── lgbm_detector.txt        # LightGBM 预训练模型权重（22维PE特征，二分类）
└── signatures/                  # 特征库签名（预留）
```

## 防护能力

### 实时防护（内核驱动 + 用户态服务协同）

#### 进程启动拦截（同步决策）
- 内核 `PsSetCreateProcessNotifyRoutineEx` 回调，在进程创建前同步询问用户态
- 用户态对非微软签名进程执行双引擎检测：启发式 70% + LightGBM ML 30%（与静态扫描同一套引擎）
- 微软签名验证：`WinVerifyTrust` + `CryptCATAdmin` 目录签名（缓存加速）
- 判定为恶意时返回 `STATUS_ACCESS_DENIED`，进程根本无法创建
- 覆盖所有启动方式：Explorer 双击、Win+R 运行、浏览器下载直接运行、命令行、计划任务、服务、WMI 等

#### 文件系统监控
- Minifilter 文件创建/写入回调，实时拦截恶意文件落地
- 驱动级强制隔离（`ZwSetInformationFile` FileRenameInformation，绕过用户态权限）
- 用户态回退：`fs::rename` → `copy+remove`，多重保障

#### 行为规则引擎
- **注册表持久化**：Run/RunOnce/Winlogon/IFEO/AppInit_DLLs 等关键键值修改
- **进程注入**：远程线程创建（`PsSetCreateThreadNotifyRoutine`）+ 系统进程宿主检测
- **映像加载**：白加黑 DLL 侧加载（`PsSetLoadImageNotifyRoutine`）+ 黑 DLL 名特征
- **计划任务**：`schtasks` 输出解析，银狐伪装任务名特征匹配（如 `MicrosoftEdge UpdateTask`）
- **网络 C2**：公开银狐 C2 IP 拦截
- **BYOVD**：易滥用驱动黑名单（capcom.sys、RTCore64.sys 等）

#### 自我保护
- Ob 回调保护自身进程句柄，防止被终止/注入
- 隔离区目录、驱动 .sys、服务 .exe 文件受驱动保护
- 服务进程 PID 注册到驱动，受保护进程的文件操作直接放行
- `SeDebugPrivilege` 启用，确保可终止高完整性进程

### 威胁处置
- **隔离**：驱动 IOCTL 强制重命名到隔离区 → 用户态 fs 回退 → 自动重试（杀进程→等待→重试，最多 3 次）
- **删除**：驱动级 `ZwSetInformationFile` FileDispositionInformation 强制删除
- **计划任务清理**：对银狐持久化任务执行 `schtasks /delete /tn "任务名" /f`
- 文件不存在时自动跳过文件操作，仅清理持久化项

### 病毒扫描
- **双引擎融合打分**：PE 启发式 70% + LightGBM 机器学习 30%，静态扫描与运行前扫描使用同一套引擎
- **PE 启发式扫描**：节区熵值、可疑导入函数（VirtualAllocEx/WriteProcessMemory/CreateRemoteThread 等）、PE 结构异常、加壳检测、签名缺失
- **LightGBM ML 推理**：22 维 PE 特征（文件大小/导入导出/资源/签名/整体与节区熵/可写可执行节/RICH条目/overlay 等），输出恶意概率，模型缺失时自动回退为纯启发式
- 快速扫描 / 全盘扫描 / 自定义扫描

### GUI
- 仪表盘（防护状态 + 实时统计）
- 扫描页面（快速/全盘/自定义）
- 隔离区（隔离文件管理 + 恢复 + 删除）
- 安全日志（实时滚动日志 + 威胁记录）
- 设置页面（防护开关 + 驱动启动类型 + 自保护）
- 右下角 Toast 拦截弹窗（圆角/动画/DPI 自适应）
- 系统托盘图标

### 银狐木马专项特征
- **白加黑 DLL 侧加载**：映像加载回调 + 黑 DLL 名特征
- **伪装计划任务持久化**：`MicrosoftEdge UpdateTask` 等特征名匹配 + 自动删除任务
- **已知样本哈希**：公开 SHA1 IOC 匹配
- **C2 网络通信**：公开披露的银狐 C2 IP 拦截
- **BYOVD 攻击**：易滥用驱动黑名单

## 构建

### 前提
- MSVC（VS 2019+，实测 VS 2026 / MSVC 14.51）
- 静态 Qt 6.11.0（`D:\program\qt-static-msvc`，`-static-runtime`）
- WDK（`D:\program\Windows Kits\10`，含 km 头文件 + ntoskrnl.lib + fltMgr.lib）
- Ninja + CMake + Git（用于拉取 LightGBM 源码）

### 一键构建

```
build_all.bat
```

依次执行：驱动 → LightGBM 静态库 → 用户态 GUI/服务 → 驱动签名。
或按以下步骤手动构建：

### 1. 编译内核驱动

```
cd src\driver
build_driver.bat
```

输出 `build\src\gui\BanJiu-Guard.sys`（与 GUI 同目录，方便部署）。

链接选项含 `/INTEGRITYCHECK`，确保 `PsSetCreateProcessNotifyRoutineEx` 注册成功。

### 2. 编译 LightGBM 静态库

```
cd third_party
build_lightgbm.bat
```

自动 clone LightGBM v4.6.0 + 子模块，以 `/MT`（静态 CRT）编译输出 `third_party/LightGBM/lib_lightgbm.lib`。
首次构建需要联网；已构建时 `build_all.bat` 会自动跳过。

### 3. 编译用户态（服务 + GUI，静态 MSVC）

```
cmake -S . -B build -GNinja ^
  -DQT_STATIC_PREFIX="D:/program/qt-static-msvc" ^
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

输出 `build/src/gui/BanJiu-Guard.exe`（静态链接 LightGBM，含服务）。
模型权重 `models/lgbm_detector.txt` 会自动拷贝到 `build/src/gui/models/`。

### 4. 驱动签名（测试）

```
tools\sign_driver.bat
```

首次需生成测试证书，之后 `build_driver.bat` 会自动签名。

### 5. 运行

1. 开启测试签名模式（首次运行 GUI 里有引导，或手动）：`bcdedit /set testsigning on` 后重启
2. 以管理员权限运行 `BanJiu-Guard.exe`
3. 按首次运行引导开启完全防护

> 模型文件缺失时软件正常运行，检测自动回退为纯启发式打分（启动日志可见 `ML model loaded=false`）。

## 内核-用户态通信架构

```
内核驱动                              用户态服务
    │                                     │
    │  PsSetCreateProcessNotifyRoutineEx  │
    │  ──────────────────────────────►    │  FilterGetMessage（轮询）
    │         YX_EVENT (type=10)          │
    │                                     │  ├─ 微软签名验证 → 放行
    │                                     │  ├─ 启发式70%+LightGBM ML30% → 综合分≥30 阻止
    │                                     │  └─ 规则引擎 → 命中阻止
    │    FltSendMessage（同步等待）        │
    │  ◄──────────────────────────────    │  FilterReplyMessage
    │         YX_DECISION                  │
    │                                     │
    │  CreateInfo->CreationStatus =        │
    │    STATUS_ACCESS_DENIED              │
```

关键设计：
- **同步决策**：进程创建事件 8 秒超时（WinVerifyTrust 冷启动较慢），文件操作 500ms 超时
- **结构体对齐**：`#pragma pack(push,8)` 确保内核-用户态结构体内存布局一致
- **IOCTL 线程跟踪**：避免驱动自身 IOCTL 触发 minifilter 回调死锁

## 许可证

MIT License，详见 [LICENSE](LICENSE)。

## 重要说明

**用途与合规**：本工程为学习/研究/自用防护目的。生产部署需：
- 内核实名 EV 代码签名证书（非测试签名）
- 企业级威胁情报（本文特征基于公开报告，需自行补充）
- 充分的稳定性测试（内核驱动请务必先在虚拟机验证）

**风险**：内核驱动存在蓝屏风险，自我保护可能误伤。请勿在关键生产机上未经测试直接运行。

## 免责声明

本项目的银狐特征（哈希、C2 IP、文件名）来源于公开安全报告，仅用于安全研究。请勿用于任何非法用途。
