// BanJiu-Guard - 反银狐木马杀毒软件
// 公共通信协议定义（内核驱动 <-> 用户态服务 共享）
// 本文件在内核态和用户态各自编译，必须保持二进制兼容。
#pragma once

#include <stdint.h>

// CTL_CODE / METHOD_* / FILE_*_ACCESS 宏
// 内核态由 ntifs.h/ntddk.h 提供；用户态需包含 winioctl.h
#ifdef _KERNEL_MODE
    // 内核态，宏已由 NT 头提供
#else
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0A00
    #endif
    #ifndef WINVER
        #define WINVER 0x0A00
    #endif
    #include <windows.h>
    #include <winioctl.h>
    #include <fltUser.h>
#endif

// 驱动设备名与符号链接名
#define YX_DEVICE_NAME          L"\\Device\\BanJiu-Guard"
#define YX_DOS_DEVICE_NAME      L"\\DosDevices\\BanJiu-Guard"
#define YX_SYMLINK_NAME         L"\\??\\BanJiu-Guard"

// 服务名称
#define YX_SERVICE_NAME         L"BanJiu-GuardSvc"
#define YX_SERVICE_DISPLAY_NAME L"BanJiu-Guard Real-Time Protection Service"

// 通信端口（Minifilter 通信端口名）
#define YX_FILTER_PORT_NAME     L"\\BanJiu-GuardCommPort"
#define YX_FILTER_PORT_CONNECTION_NAME L"\\BanJiu-GuardCommPort"

// 控制码
#define YX_DEVICE_TYPE          0x9A21   // 0x8000+ 范围内自定义

// 内核->用户态 事件通知类型
typedef enum _YX_EVENT_TYPE {
    YX_EVENT_FILE_CREATE     = 1,   // 文件创建
    YX_EVENT_FILE_WRITE      = 2,   // 文件写入
    YX_EVENT_FILE_DELETE     = 3,   // 文件删除
    YX_EVENT_FILE_RENAME     = 4,   // 文件重命名
    YX_EVENT_PROCESS_CREATE  = 10,  // 进程创建
    YX_EVENT_PROCESS_TERM    = 11,  // 进程终止
    YX_EVENT_IMAGE_LOAD      = 12,  // 映像加载（DLL 加载，白加黑检测关键）
    YX_EVENT_REGISTRY_WRITE  = 20,  // 注册表写入（持久化检测）
    YX_EVENT_REGISTRY_CREATE = 21,  // 注册表建项
    YX_EVENT_TASK_SCHEDULE   = 30,  // 计划任务创建（持久化检测）
    YX_EVENT_NET_CONNECT     = 40,  // 网络连接（C2 检测）
    YX_EVENT_THREAD_CREATE   = 50,  // 远程线程创建（进程注入检测）
    YX_EVENT_DRIVER_LOAD     = 60,  // 驱动加载（BYOVD 检测）
    YX_EVENT_HANDLE_OPEN     = 70,  // 句柄打开（自我保护）
    YX_EVENT_MBR_PROTECT     = 80,  // MBR/GPT 扇区写入被拦截
    YX_EVENT_SELF_PROTECT    = 81   // 自我保护触发（隔离区/驱动文件被访问）
} YX_EVENT_TYPE;

// 拦截动作
typedef enum _YX_ACTION {
    YX_ACTION_ALLOW = 0,
    YX_ACTION_BLOCK = 1,
    YX_ACTION_QUARANTINE = 2,
} YX_ACTION;

// 威胁等级
typedef enum _YX_THREAT_LEVEL {
    YX_THREAT_NONE = 0,
    YX_THREAT_LOW = 1,
    YX_THREAT_MEDIUM = 2,
    YX_THREAT_HIGH = 3,
    YX_THREAT_CRITICAL = 4,
} YX_THREAT_LEVEL;

// 威胁 / 行为规则分类（银狐专项）
typedef enum _YX_RULE_CATEGORY {
    YX_RULE_UNKNOWN           = 0,
    YX_RULE_YINHU_DLL_SIDELOAD = 1,   // 银狐：白加黑 DLL 侧加载
    YX_RULE_YINHU_PROCESS_INJ  = 2,   // 银狐：进程注入
    YX_RULE_YINHU_TASK_PERSIST = 3,   // 银狐：伪装计划任务持久化
    YX_RULE_YINHU_BYOVD        = 4,   // 银狐：BYOVD 带漏洞驱动
    YX_RULE_YINHU_C2           = 5,   // 银狐：C2 网络通信
    YX_RULE_MALWARE_HASH       = 6,   // 特征库哈希命中
    YX_RULE_HEURISTIC          = 7,   // 启发式
    YX_RULE_SELF_PROTECT       = 8,   // 自我保护触发
    YX_RULE_MBR_PROTECT        = 9,   // MBR/GPT 引导区保护
} YX_RULE_CATEGORY;

// IOC 类型
typedef enum _YX_IOC_TYPE {
    YX_IOC_SHA1   = 1,
    YX_IOC_SHA256 = 2,
    YX_IOC_MD5    = 3,
    YX_IOC_PATH   = 4,   // 路径/文件名特征
    YX_IOC_C2_IP  = 5,   // C2 IP
    YX_IOC_C2_DOMAIN = 6,
    YX_IOC_PE_IMPORT = 7, // 可疑导入（如仅导入单一可疑 DLL）
} YX_IOC_TYPE;

// 事件上报包（内核 -> 用户态）
#pragma pack(push, 1)
typedef struct _YX_EVENT {
    YX_EVENT_TYPE   Type;           // 事件类型
    uint32_t        ProcessId;      // 发起进程 PID
    uint32_t        ThreadId;       // 线程 ID
    uint32_t        ParentProcessId;// 父进程 PID
    uint32_t        TargetProcessId;// 目标进程 PID（注入等情况）
    uint64_t        Timestamp;      // 时间戳（100ns 单位，FILETIME 通用）
    YX_RULE_CATEGORY Category;      // 规则分类
    YX_THREAT_LEVEL  Threat;        // 威胁等级
    // 可变长度字符串缓冲区，按需填充（name0~name2）
    wchar_t         Name0[260];     // 主体名（文件路径/进程路径/注册表键）
    wchar_t         Name1[260];     // 附加（目标路径/DLL 路径/值名）
    wchar_t         Name2[260];     // 附加（C2 地址/任务名等）
} YX_EVENT, *PYX_EVENT;

// 用户态 -> 内核 的决策响应
typedef struct _YX_DECISION {
    uint64_t        EventId;        // 关联事件 ID（用 Timestamp+PID 组合）
    YX_ACTION       Action;         // 允许/阻止/隔离
} YX_DECISION, *PYX_DECISION;

// 内核 -> 用户态 消息结构（含 reply header，便于 FilterReplyMessage）
typedef struct _YX_REQUEST {
    FILTER_MESSAGE_HEADER Header;   // 必须放在最前
    YX_EVENT              Event;
} YX_REQUEST, *PYX_REQUEST;

// 防护开关（用户态 -> 内核 同步设置）
#pragma pack(push, 1)
typedef struct _YX_PROTECT_FLAGS {
    uint32_t FileProtect         : 1; // 文件实时防护
    uint32_t ProcessProtect      : 1; // 进程行为防护
    uint32_t RegistryProtect     : 1; // 注册表防护
    uint32_t ScheduleProtect     : 1; // 计划任务防护
    uint32_t NetworkProtect      : 1; // 网络防护
    uint32_t InjectProtect       : 1; // 注入防护
    uint32_t YinHuProtect        : 1; // 银狐专项增强防护
    uint32_t SelfProtect         : 1; // 自我防护
    uint32_t MbrProtect          : 1; // MBR/GPT 引导区防护
    uint32_t Reserved            : 23;
} YX_PROTECT_FLAGS, *PYX_PROTECT_FLAGS;
#pragma pack(pop)

// MBR/GPT 保护范围：前 34 个扇区（MBR + GPT 头 + 分区表项）
// GPT 磁盘前 34 扇区包含：保护性 MBR(1) + GPT 头(1) + 分区表项(32)
#define YX_MBR_PROTECT_SECTORS  34
#define YX_MBR_PROTECT_BYTES    (YX_MBR_PROTECT_SECTORS * 512)

// IOCTL 定义
#define YX_IOCTL_BASE 0x800

#define IOCTL_YX_GET_VERSION      CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_SET_PROTECT_FLAGS CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_GET_PROTECT_FLAGS CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_QUERY_STATS      CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_REGISTER_PID     CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS) // 注册受保护进程 PID
#define IOCTL_YX_UNREGISTER_PID   CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_QUARANTINE_FILE    CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_SET_PROTECT_PATHS CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_KILL_PROCESS      CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_FORCE_DELETE_FILE CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YX_FORCE_QUARANTINE  CTL_CODE(YX_DEVICE_TYPE, YX_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 内核强制操作请求（终止进程 / 强制删除 / 强制隔离）
// 路径使用 \??\C:\... 格式（DOS 路径加 \??\ 前缀），内核 ZwCreateFile 可直接使用
#pragma pack(push, 1)
typedef struct _YX_FILE_OP_REQUEST {
    wchar_t  SourcePath[260];   // 源文件路径（\??\C:\...）
    wchar_t  DestPath[260];    // 目标路径（隔离时使用，\??\C:\...\Quarantine\...）
    uint32_t ProcessId;        // 进程 PID（终止进程时使用）
    uint32_t Success;          // 输出：0=失败, 1=成功
} YX_FILE_OP_REQUEST, *PYX_FILE_OP_REQUEST;
#pragma pack(pop)

// 版本
#define YX_DRIVER_VERSION_MAJOR 1
#define YX_DRIVER_VERSION_MINOR 0
#define YX_DRIVER_VERSION_BUILD 0

typedef struct _YX_VERSION_INFO {
    uint32_t Major;
    uint32_t Minor;
    uint32_t Build;
} YX_VERSION_INFO, *PYX_VERSION_INFO;

// 统计信息
typedef struct _YX_STATS {
    uint64_t FilesScanned;
    uint64_t FilesBlocked;
    uint64_t FilesQuarantined;
    uint64_t ProcessesBlocked;
    uint64_t ThreatsDetected;
    uint64_t YinHuDetected;
} YX_STATS, *PYX_STATS;

// 受保护路径设置（隔离区目录 + 驱动文件路径）
// 驱动会拦截除受保护 PID 外任何进程对这些路径的写入/删除/重命名
#pragma pack(push, 1)
typedef struct _YX_PROTECT_PATHS {
    wchar_t QuarantineDir[260];   // 隔离区目录（内核态路径，如 \??\C:\...\Quarantine）
    wchar_t DriverSysPath[260];   // 驱动 .sys 文件路径
    wchar_t ServiceExePath[260];  // 服务/主程序 .exe 路径
} YX_PROTECT_PATHS, *PYX_PROTECT_PATHS;
#pragma pack(pop)

// 平衡 YX_EVENT 处的 #pragma pack(push, 1)
#pragma pack(pop)
