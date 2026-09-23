// BanJiu-Guard - 实时防护服务（用户态系统服务）
// 职责：
//  1. 加载/连接内核驱动，接收事件
//  2. 用规则引擎判定，执行阻止/隔离
//  3. 文件系统/进程/注册表/计划任务/网络行为监控
//  4. 与 GUI 通过 pipe/IPC 通信
//  5. 自我保护（保护自身进程与安装目录）
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <filesystem>
#include <set>
#include <map>
#include "../common/yx_protocol.h"
#include "../common/yx_rules.h"
#include "../common/yx_heuristic.h"
#include "../common/yx_ml_engine.h"

namespace yx {

// Toast 类型
enum class ToastType {
    Info,
    Warning,
    Critical
};

// 统计信息（复用内核统计结构，用户态可见）
using Stats = YX_STATS;

// 威胁处置决策：由 GUI 弹窗返回给服务
// 0 = 放过, 1 = 拦截
struct ThreatDecision {
    static constexpr int Allow = 0;
    static constexpr int Block = 1;
};

// 服务回调接口（服务 -> GUI 的事件推送）
struct ServiceCallbacks {
    std::function<void(const yx::RuleHit&)> onThreat;
    std::function<void(const std::wstring&)> onLog;
    std::function<void(const yx::Stats&)>    onStats;
    std::function<void(yx::ToastType, const std::wstring&, const std::wstring&)> onToast;
    // 手动模式下弹出决策弹窗，decision 参数回传用户选择（Allow/Block）
    std::function<void(const yx::RuleHit&, std::function<void(int decision)>)> onThreatDecision;
};

// 防护开关（与内核 YX_PROTECT_FLAGS 对应）
struct ProtectSettings {
    bool fileProtect    = true;
    bool processProtect = true;
    bool registryProtect = true;
    bool scheduleProtect = true;
    bool networkProtect = true;
    bool injectProtect  = true;
    bool yinHuProtect   = true;
    bool selfProtect    = true;
    bool mbrProtect     = true;

    // 威胁处置设置
    bool autoHandle    = true;   // true=自动处理, false=手动确认（弹窗）
    int  autoAction    = 0;      // 自动处置方式: 0=隔离到隔离区, 1=直接强制删除

    // 进程启动前扫描：未通过微软签名验证的可执行文件启动时进行启发式扫描
    bool processStartScan = true;
};

// 实时防护服务
class ProtectionService {
public:
    ProtectionService();
    ~ProtectionService();

    bool Initialize();               // 初始化（连接驱动、注册回调）
    void Shutdown();

    bool Start();                    // 启动监控
    void Stop();

    void SetCallbacks(ServiceCallbacks cb);

    // 写一条日志到安全日志窗口
    void Log(const std::wstring& msg);

    // 设置防护开关（同步到内核）
    bool ApplySettings(const ProtectSettings& s);

    // 获取当前防护设置
    ProtectSettings GetProtectSettings() const;

    // 威胁处置：根据 action 执行杀进程 + 隔离/删除
    // action: 0=隔离, 1=删除, 2=放过
    bool ExecuteThreatAction(const yx::RuleHit& hit, int action);

    // 设置持久化（保存到安装目录 config.ini）
    bool SaveSettingsToFile();
    bool LoadSettingsFromFile();

    // 自我保护：注册保护自身进程 PID
    bool EnableSelfProtection();
    bool DisableSelfProtection();

    // 向驱动注册受保护路径（隔离区、驱动文件、服务程序）
    bool SendProtectPaths();

    // 统计
    yx::Stats GetStats() const;

    // 驱动是否加载
    bool IsDriverLoaded() const { return m_driverLoaded; }

    // 驱动启动类型（对应 Windows SERVICE_*_START）
    enum DriverStartType {
        DriverStart_Boot   = SERVICE_BOOT_START,    // 引导启动（最早，系统加载器阶段）
        DriverStart_System = SERVICE_SYSTEM_START,  // 系统启动（IoInitSystem 阶段，早于自动）
        DriverStart_Auto   = SERVICE_AUTO_START,    // 自动启动（SCM 阶段）
        DriverStart_Demand = SERVICE_DEMAND_START,  // 手动启动
        DriverStart_Disabled = SERVICE_DISABLED     // 禁用
    };

    // 设置驱动服务启动类型（修改注册表并 ChangeServiceConfig），重启后生效
    // 返回 false 表示修改失败，errMsg 包含详细错误
    bool SetDriverStartType(DriverStartType type, std::wstring& errMsg);
    // 获取当前驱动服务启动类型
    DriverStartType GetDriverStartType();

    // 隔离一个文件
    bool QuarantineFile(const std::wstring& path);
    // 恢复隔离文件
    bool RestoreFile(const std::wstring& path);
    // 获取隔离区目录
    std::wstring GetQuarantineDir() const { return m_quarantineDir; }

    // 内核强制操作：终止进程（通过驱动 IOCTL）
    bool KillProcessByPid(DWORD pid);
    // 内核强制操作：删除文件（通过驱动 IOCTL）
    bool ForceDeleteFile(const std::wstring& path);
    // 内核强制操作：隔离文件（通过驱动 IOCTL，移动到隔离区）
    bool ForceQuarantineFile(const std::wstring& path);
    // 查找文件对应的进程 PID（如果文件正在运行）
    DWORD FindProcessByPath(const std::wstring& path);

    // 带缓存的微软签名验证（WinVerifyTrust + CAT 目录签名库）
    bool IsMicrosoftSignedCached(const std::wstring& dosPath);

private:
    void MonitorThreadProc();
    void DriverMessageThreadProc();
    void HandleEvent(const yx::Event& ev);
    void HandleThreat(const yx::RuleHit& hit);
    void OnDriverEvent(const YX_EVENT& ev);

    void PollNetworkConnections();
    void PollScheduledTasks();

    // 驱动通信
    bool OpenDriver();
    void CloseDriver();
    bool ConnectFilterPort();
    bool SendProtectFlags();

    // 安装并启动内核驱动（通过 SCM）
    bool InstallAndStartDriver();
    // 查找驱动 .sys 文件路径
    std::wstring LocateDriverFile();

    // 隔离目录
    std::wstring m_quarantineDir;
    void EnsureQuarantineDir();

private:
    HANDLE m_driverHandle = INVALID_HANDLE_VALUE;
    HANDLE m_filterPort    = INVALID_HANDLE_VALUE;
    bool   m_driverLoaded  = false;
    bool   m_selfProtectOn = false;

    std::atomic<bool> m_running{false};
    std::thread m_monitorThread;
    std::thread m_driverThread;

    ProtectSettings m_settings;
    mutable std::mutex m_mutex;
    ServiceCallbacks m_callbacks;
    yx::Stats m_stats;
    RulesEngine m_rules;
    HeuristicEngine m_heuristic;
    MlEngine m_ml;  // LightGBM 机器学习检测引擎
    std::set<std::wstring> m_reportedTasks;

    // Toast 节流：防止驱动事件刷屏
    std::mutex m_toastMutex;
    std::map<uint32_t, ULONGLONG> m_lastToastByPid;  // pid -> 上次弹 toast 时间(ms)

    // 威胁处置去重：同一目标路径短时间内不重复处置
    std::mutex m_threatMutex;
    std::map<std::wstring, ULONGLONG> m_lastThreatByPath;  // 路径 -> 上次处置时间(ms)

    // 签名验证缓存：路径 -> 是否微软签名（避免对同一文件反复调用 WinVerifyTrust）
    std::mutex m_signCacheMutex;
    std::map<std::wstring, bool> m_signCache;  // 小写路径 -> 是否微软签名

    // 手动决策同步：驱动消息线程等待 GUI 弹窗返回用户选择
    std::mutex m_decisionMutex;
    std::condition_variable m_decisionCv;
    int m_pendingDecision = -1;  // -1=等待中, 0=放过, 1=拦截
};

// 进程（当前服务进程）自身 PID，用于自我保护
uint32_t GetSelfPid();

} // namespace yx
