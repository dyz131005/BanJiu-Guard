// BanJiu-Guard - 实时防护服务实现
#include "yx_service.h"
#include <windows.h>
#include <psapi.h>
#include <fltUser.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <vector>
#include <set>
#include <sstream>
#include <cstdio>
#include <cwchar>
#include <wincrypt.h>
#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <chrono>
#include <fstream>

// 崩溃日志写入函数（由 main.cpp 中的 GUI 模块定义，service 模块静态链接进同一 exe）
// 作用：在线程崩溃或异常路径上同步把消息写到 BanJiu-Guard-crash.log
// main.cpp 内部已加全局互斥锁，多线程调用安全
extern "C" void YxWriteCrashLog(const wchar_t* msg);

// 统一走 YxWriteCrashLog（main.cpp 中已加锁），避免双写穿插
static void SafeCrashLog(const std::wstring& msg)
{
    YxWriteCrashLog(msg.c_str());
}

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

namespace fs = std::filesystem;
namespace yx {

static std::wstring NormalizeFilename(const std::wstring& name)
{
    std::wstring s = name;
    while (!s.empty() && (s.back() == L'.' || s.back() == L' ')) {
        s.pop_back();
    }
    return s;
}

uint32_t GetSelfPid() { return (uint32_t)GetCurrentProcessId(); }

static std::wstring GetProcessImagePath(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return L"";
    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    std::wstring result;
    if (QueryFullProcessImageNameW(hProc, 0, buf, &size)) {
        result.assign(buf, size);
    }
    CloseHandle(hProc);
    return result;
}

// 将 DOS 路径（如 C:\xxx）转换为设备路径（如 \Device\HarddiskVolume2\xxx）
// 驱动内 FltGetFileNameInformation 返回的是设备路径格式，需统一才能比较
static std::wstring DosPathToDevicePath(const std::wstring& dosPath) {
    if (dosPath.size() < 3) return dosPath;
    if (dosPath[1] != L':' || dosPath[2] != L'\\') return dosPath;

    wchar_t drive[3] = { dosPath[0], L':', L'\0' };
    wchar_t devName[MAX_PATH];
    DWORD len = QueryDosDeviceW(drive, devName, MAX_PATH);
    if (len == 0) return dosPath;

    std::wstring devPath(devName);
    devPath += dosPath.substr(2);
    return devPath;
}

// 将 NT 设备路径（如 \Device\HarddiskVolume3\xxx）转换为 DOS 路径（如 C:\xxx）
// 驱动上报的文件路径是设备路径格式，用户态 fs 操作和驱动 ZwCreateFile(\??\...) 都需要 DOS 路径
static std::wstring DevicePathToDosPath(const std::wstring& devPath) {
    if (devPath.empty()) return devPath;
    // 已是 DOS 路径（盘符开头）则直接返回
    if (devPath.size() >= 3 && devPath[1] == L':' && devPath[2] == L'\\') return devPath;
    // 以 \??\ 开头则去掉前缀
    std::wstring p = devPath;
    if (p.size() >= 4 && p[0] == L'\\' && p[1] == L'?' && p[2] == L'?' && p[3] == L'\\') {
        p = p.substr(4);
        return p;
    }
    // 枚举所有盘符，查找匹配的设备路径前缀
    wchar_t drives[26 * 4] = { 0 };
    DWORD len = GetLogicalDriveStringsW(26 * 4, drives);
    if (len == 0) return devPath;

    for (wchar_t* d = drives; *d; d += wcslen(d) + 1) {
        wchar_t drive[3] = { d[0], L':', L'\0' };
        wchar_t devName[MAX_PATH];
        DWORD n = QueryDosDeviceW(drive, devName, MAX_PATH);
        if (n == 0) continue;
        std::wstring devStr(devName);
        if (devStr.empty()) continue;
        // 确保设备路径以反斜杠结尾以便前缀匹配
        if (devStr.back() != L'\\') devStr += L'\\';
        std::wstring pSlash = p;
        // 统一反斜杠
        for (auto& c : pSlash) if (c == L'/') c = L'\\';
        if (pSlash.size() >= devStr.size() &&
            _wcsnicmp(pSlash.c_str(), devStr.c_str(), devStr.size()) == 0) {
            std::wstring rest = pSlash.substr(devStr.size() - 1); // 含开头的反斜杠
            return std::wstring(1, d[0]) + L":" + rest;
        }
    }
    return devPath; // 无法转换则原样返回
}

static std::wstring GetInstallDir() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf);
    auto pos = p.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
}

ProtectionService::ProtectionService() {
    m_quarantineDir = GetInstallDir() + L"\\Quarantine";
}

ProtectionService::~ProtectionService() {
    Shutdown();
}

void ProtectionService::EnsureQuarantineDir() {
    std::error_code ec;
    fs::create_directories(m_quarantineDir, ec);
}

// 启用 SeDebugPrivilege，使服务能终止其他进程（包括高完整性进程）
static bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) != 0;
    }
    CloseHandle(token);
    return ok;
}

bool ProtectionService::Initialize() {
    EnableDebugPrivilege();
    SafeCrashLog(L"[Init] Start Initialize");
    EnsureQuarantineDir();
    SafeCrashLog(L"[Init] QuarantineDir=" + m_quarantineDir);
    // 加载持久化设置（在连接驱动前，确保开关状态正确）
    LoadSettingsFromFile();
    bool ok = OpenDriver();
    SafeCrashLog(L"[Init] OpenDriver ok=" + std::to_wstring(ok));
    if (!ok) {
        SafeCrashLog(L"[Init] Install and start driver");
        InstallAndStartDriver();
        ok = OpenDriver();
        SafeCrashLog(L"[Init] After install OpenDriver ok=" + std::to_wstring(ok));
    }
    if (ok) {
        bool fp = ConnectFilterPort();
        SafeCrashLog(L"[Init] ConnectFilterPort ok=" + std::to_wstring(fp));
        SendProtectFlags();
        SendProtectPaths();
        EnableSelfProtection();
        SafeCrashLog(L"[Init] SendProtectFlags/Paths/SelfProtect sent");
    }
    SafeCrashLog(L"[Init] Initialize done");
    return true;
}

void ProtectionService::Shutdown() {
    Stop();
    CloseDriver();
}

static void PushLog(ServiceCallbacks& cb, const std::wstring& msg) {
    if (cb.onLog) cb.onLog(msg);
}

std::wstring ProtectionService::LocateDriverFile() {
    std::wstring dir = GetInstallDir();
    std::wstring candidate = dir + L"\\BanJiu-Guard.sys";
    if (fs::exists(candidate)) {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[驱动] 找到驱动文件: " + candidate);
        return candidate;
    }
    std::lock_guard<std::mutex> lk(m_mutex);
    PushLog(m_callbacks, L"[驱动] 未找到驱动文件 (期望路径: " + dir + L"\\BanJiu-Guard.sys)");
    return L"";
}

static bool ConfigureMinifilterRegistry(const std::wstring& svcName) {
    std::wstring baseKey = L"SYSTEM\\CurrentControlSet\\Services\\" + svcName + L"\\Instances";
    const std::wstring instanceName = L"BanJiuGuardInstance";

    HKEY hKey = nullptr;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, baseKey.c_str(), 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (rc != ERROR_SUCCESS) return false;

    RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ,
                   (const BYTE*)instanceName.c_str(),
                   (DWORD)((instanceName.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    std::wstring instKey = baseKey + L"\\" + instanceName;
    rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, instKey.c_str(), 0, nullptr,
                         REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (rc != ERROR_SUCCESS) return false;

    const std::wstring altitude = L"369000";
    RegSetValueExW(hKey, L"Altitude", 0, REG_SZ,
                   (const BYTE*)altitude.c_str(),
                   (DWORD)((altitude.size() + 1) * sizeof(wchar_t)));
    DWORD flags = 0;
    RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (const BYTE*)&flags, sizeof(flags));
    RegCloseKey(hKey);
    return true;
}

bool ProtectionService::InstallAndStartDriver() {
    std::wstring sysPath = LocateDriverFile();
    if (sysPath.empty()) return false;

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[驱动] 正在通过 SCM 注册内核服务...");
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[驱动] 打开 SCM 失败，错误码: " + std::to_wstring(GetLastError()));
        return false;
    }

    const std::wstring svcName = L"BanJiu-Guard";
    // 默认使用 SYSTEM_START（系统启动阶段加载，早于 AUTO_START），
    // 确保驱动在软件启动前就已运行
    const DWORD defaultStartType = SERVICE_SYSTEM_START;

    SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(), SERVICE_ALL_ACCESS);
    if (!svc) {
        svc = CreateServiceW(scm, svcName.c_str(), svcName.c_str(),
                             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                             defaultStartType, SERVICE_ERROR_NORMAL,
                             sysPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (svc) {
                PushLog(m_callbacks, L"[驱动] 内核服务创建成功（启动类型=系统启动）");
            } else {
                PushLog(m_callbacks, L"[驱动] 内核服务创建失败，错误码: " + std::to_wstring(GetLastError()));
            }
        }
    } else {
        // 服务已存在，重新配置 binPath 防止指向旧路径导致 87 错误
        // 注意：不强制改启动类型，保留用户在设置中选择的值
        if (!ChangeServiceConfigW(svc, SERVICE_KERNEL_DRIVER, SERVICE_NO_CHANGE,
                                  SERVICE_ERROR_NORMAL, sysPath.c_str(),
                                  nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            std::lock_guard<std::mutex> lk(m_mutex);
            PushLog(m_callbacks, L"[驱动] 更新服务配置失败，错误码: " + std::to_wstring(GetLastError()));
        } else {
            std::lock_guard<std::mutex> lk(m_mutex);
            PushLog(m_callbacks, L"[驱动] 内核服务已存在，已更新 binPath");
        }
    }
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    // 配置 minifilter 注册表 Instances（Altitude/Flags），否则 FltRegisterFilter 失败
    if (!ConfigureMinifilterRegistry(svcName)) {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[驱动] 配置 minifilter 注册表失败");
    }

    // 查询当前服务配置并输出到日志，辅助诊断
    {
        DWORD bytesNeeded = 0;
        QueryServiceConfigW(svc, nullptr, 0, &bytesNeeded);
        if (bytesNeeded > 0) {
            std::vector<BYTE> buf(bytesNeeded);
            auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
            if (QueryServiceConfigW(svc, cfg, bytesNeeded, &bytesNeeded)) {
                std::wstring typeStr = (cfg->dwServiceType == SERVICE_KERNEL_DRIVER) ? L"内核驱动" :
                                       (cfg->dwServiceType == SERVICE_WIN32_OWN_PROCESS) ? L"用户态服务" :
                                       L"未知(" + std::to_wstring(cfg->dwServiceType) + L")";
                std::lock_guard<std::mutex> lk(m_mutex);
                PushLog(m_callbacks, L"[驱动] 服务配置: 类型=" + typeStr +
                    L", binPath=" + std::wstring(cfg->lpBinaryPathName) +
                    L", startType=" + std::to_wstring(cfg->dwStartType));
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[驱动] 正在启动内核驱动...");
    }
    BOOL started = StartServiceW(svc, 0, nullptr);
    if (!started) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            // already running, ok
        } else {
            // 查询服务状态获取驱动加载失败的具体退出码
            SERVICE_STATUS_PROCESS ssp{};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                     (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                std::lock_guard<std::mutex> lk(m_mutex);
                PushLog(m_callbacks, L"[驱动] 启动失败错误码=" + std::to_wstring(err) +
                    L", 服务退出码=" + std::to_wstring(ssp.dwWin32ExitCode) +
                    L", 服务特定退出码=" + std::to_wstring(ssp.dwServiceSpecificExitCode) +
                    L", 当前状态=" + std::to_wstring(ssp.dwCurrentState));
            }
            {
                std::lock_guard<std::mutex> lk(m_mutex);
                PushLog(m_callbacks, L"[驱动] 尝试删除旧服务重建...");
            }

            // 停止并删除旧服务，重新创建
            SERVICE_STATUS st{};
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            DeleteService(svc);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);

            // 重新打开 SCM 并创建服务
            scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (!scm) return false;
            svc = CreateServiceW(scm, svcName.c_str(), svcName.c_str(),
                                 SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                 defaultStartType, SERVICE_ERROR_NORMAL,
                                 sysPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
            if (!svc) {
                std::lock_guard<std::mutex> lk2(m_mutex);
                PushLog(m_callbacks, L"[驱动] 重建服务失败，错误码: " + std::to_wstring(GetLastError()));
                CloseServiceHandle(scm);
                return false;
            }
            ConfigureMinifilterRegistry(svcName);
            started = StartServiceW(svc, 0, nullptr);
            if (!started && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
                std::lock_guard<std::mutex> lk2(m_mutex);
                PushLog(m_callbacks, L"[驱动] 重建后启动仍失败，错误码: " + std::to_wstring(GetLastError()));
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                return false;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[驱动] 内核驱动已成功加载");
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool ProtectionService::OpenDriver() {
    if (m_driverHandle != INVALID_HANDLE_VALUE) return true;

    m_driverHandle = CreateFileW(L"\\\\.\\BanJiu-Guard",
                                 GENERIC_READ | GENERIC_WRITE,
                                 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (m_driverHandle != INVALID_HANDLE_VALUE) {
        m_driverLoaded = true;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            PushLog(m_callbacks, L"[驱动] 已连接设备 \\\\.\\BanJiu-Guard");
        }
        return true;
    }
    m_driverLoaded = false;
    return false;
}

void ProtectionService::CloseDriver() {
    if (m_filterPort != INVALID_HANDLE_VALUE) {
        FilterSendMessage(m_filterPort, nullptr, 0, nullptr, 0, nullptr);
        CloseHandle(m_filterPort);
        m_filterPort = INVALID_HANDLE_VALUE;
    }
    if (m_driverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_driverHandle);
        m_driverHandle = INVALID_HANDLE_VALUE;
    }
    m_driverLoaded = false;
}

bool ProtectionService::ConnectFilterPort() {
    if (m_filterPort != INVALID_HANDLE_VALUE) return true;

    HRESULT hr = FilterConnectCommunicationPort(L"\\BanJiu-GuardCommPort",
                                                0, nullptr, 0, nullptr,
                                                &m_filterPort);
    return SUCCEEDED(hr);
}

bool ProtectionService::SendProtectFlags() {
    if (m_filterPort == INVALID_HANDLE_VALUE && m_driverHandle == INVALID_HANDLE_VALUE) {
        SafeCrashLog(L"[Init] SendProtectFlags failed: no driver connection");
        return false;
    }

    YX_PROTECT_FLAGS flags{};
    flags.FileProtect     = m_settings.fileProtect ? 1 : 0;
    flags.ProcessProtect  = m_settings.processProtect ? 1 : 0;
    flags.RegistryProtect = m_settings.registryProtect ? 1 : 0;
    flags.ScheduleProtect = m_settings.scheduleProtect ? 1 : 0;
    flags.NetworkProtect  = m_settings.networkProtect ? 1 : 0;
    flags.InjectProtect   = m_settings.injectProtect ? 1 : 0;
    flags.YinHuProtect    = m_settings.yinHuProtect ? 1 : 0;
    flags.SelfProtect     = m_settings.selfProtect ? 1 : 0;
    flags.MbrProtect      = m_settings.mbrProtect ? 1 : 0;

    SafeCrashLog(L"[Init] ProtectFlags: file=" + std::to_wstring(flags.FileProtect) +
        L" proc=" + std::to_wstring(flags.ProcessProtect) +
        L" reg=" + std::to_wstring(flags.RegistryProtect) +
        L" sch=" + std::to_wstring(flags.ScheduleProtect) +
        L" net=" + std::to_wstring(flags.NetworkProtect) +
        L" inj=" + std::to_wstring(flags.InjectProtect) +
        L" yinhu=" + std::to_wstring(flags.YinHuProtect) +
        L" self=" + std::to_wstring(flags.SelfProtect) +
        L" mbr=" + std::to_wstring(flags.MbrProtect) +
        L" size=" + std::to_wstring(sizeof(flags)));

    if (m_filterPort != INVALID_HANDLE_VALUE) {
        DWORD ret = 0;
        HRESULT hr = FilterSendMessage(m_filterPort, &flags, sizeof(flags),
                                       nullptr, 0, &ret);
        if (SUCCEEDED(hr)) {
            SafeCrashLog(L"[Init] SendProtectFlags via FilterSendMessage ok");
            return true;
        }
        SafeCrashLog(L"[Init] SendProtectFlags via FilterSendMessage failed hr=0x" +
            std::to_wstring(static_cast<unsigned long>(hr)));
    }

    if (m_driverHandle != INVALID_HANDLE_VALUE) {
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(m_driverHandle, IOCTL_YX_SET_PROTECT_FLAGS,
                                  &flags, sizeof(flags), nullptr, 0, &ret, nullptr);
        if (ok) {
            SafeCrashLog(L"[Init] SendProtectFlags via IOCTL ok");
            return true;
        }
        SafeCrashLog(L"[Init] SendProtectFlags via IOCTL failed err=" +
            std::to_wstring(GetLastError()));
    }
    SafeCrashLog(L"[Init] SendProtectFlags ALL methods failed");
    return false;
}

void ProtectionService::SetCallbacks(ServiceCallbacks cb) {
    std::lock_guard<std::mutex> lk(m_mutex);
    m_callbacks = std::move(cb);
}

void ProtectionService::Log(const std::wstring& msg) {
    std::lock_guard<std::mutex> lk(m_mutex);
    if (m_callbacks.onLog) {
        m_callbacks.onLog(msg);
    }
}

ProtectionService::DriverStartType ProtectionService::GetDriverStartType() {
    const std::wstring svcName = L"BanJiu-Guard";
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return DriverStart_Demand;
    SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(), SERVICE_QUERY_CONFIG);
    CloseServiceHandle(scm);
    if (!svc) return DriverStart_Demand;

    DWORD bytesNeeded = 0;
    QueryServiceConfigW(svc, nullptr, 0, &bytesNeeded);
    DriverStartType result = DriverStart_Demand;
    if (bytesNeeded > 0) {
        std::vector<BYTE> buf(bytesNeeded);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (QueryServiceConfigW(svc, cfg, bytesNeeded, &bytesNeeded)) {
            result = static_cast<DriverStartType>(cfg->dwStartType);
        }
    }
    CloseServiceHandle(svc);
    return result;
}

bool ProtectionService::SetDriverStartType(DriverStartType type, std::wstring& errMsg) {
    errMsg.clear();
    const std::wstring svcName = L"BanJiu-Guard";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        DWORD le = GetLastError();
        errMsg = L"打开 SCM 失败，Win32 错误码 " + std::to_wstring(le);
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(), SERVICE_CHANGE_CONFIG);
    if (!svc) {
        DWORD le = GetLastError();
        errMsg = L"打开驱动服务失败，Win32 错误码 " + std::to_wstring(le);
        CloseServiceHandle(scm);
        return false;
    }

    if (!ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, static_cast<DWORD>(type),
                              SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                              nullptr, nullptr, nullptr, nullptr)) {
        DWORD le = GetLastError();
        errMsg = L"修改驱动启动类型失败，Win32 错误码 " + std::to_wstring(le);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    std::wstring typeStr;
    switch (type) {
        case DriverStart_Boot:    typeStr = L"引导启动"; break;
        case DriverStart_System:  typeStr = L"系统启动"; break;
        case DriverStart_Auto:    typeStr = L"自动启动"; break;
        case DriverStart_Demand:  typeStr = L"手动启动"; break;
        case DriverStart_Disabled: typeStr = L"已禁用"; break;
    }
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[驱动] 启动类型已设置为：" + typeStr + L"（重启后生效）");
    }
    return true;
}

bool ProtectionService::Start() {
    if (m_running) return true;
    m_running = true;
    m_driverThread = std::thread(&ProtectionService::DriverMessageThreadProc, this);
    m_monitorThread = std::thread(&ProtectionService::MonitorThreadProc, this);
    return true;
}

void ProtectionService::Stop() {
    m_running = false;
    // 先关闭驱动通信端口句柄，让阻塞在 FilterGetMessage 上的驱动消息线程立即返回，
    // 否则 join() 会永远等待线程退出
    if (m_filterPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_filterPort);
        m_filterPort = INVALID_HANDLE_VALUE;
    }
    if (m_driverThread.joinable()) m_driverThread.join();
    if (m_monitorThread.joinable()) m_monitorThread.join();
}

bool ProtectionService::ApplySettings(const ProtectSettings& s) {
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_settings = s;
    }
    SaveSettingsToFile();
    return SendProtectFlags();
}

bool ProtectionService::EnableSelfProtection() {
    m_selfProtectOn = true;
    if (m_driverHandle != INVALID_HANDLE_VALUE) {
        ULONG pid = GetCurrentProcessId();
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(m_driverHandle, IOCTL_YX_REGISTER_PID,
                                   &pid, sizeof(pid), nullptr, 0, &ret, nullptr);
        SafeCrashLog(L"[SelfProtect] REGISTER_PID pid=" + std::to_wstring(pid) +
                     L" ok=" + std::to_wstring(ok) +
                     L" err=" + std::to_wstring(GetLastError()));
    } else {
        SafeCrashLog(L"[SelfProtect] Invalid driver handle, skip PID register");
    }
    return SendProtectFlags();
}

bool ProtectionService::DisableSelfProtection() {
    m_selfProtectOn = false;
    return SendProtectFlags();
}

bool ProtectionService::SendProtectPaths() {
    if (m_driverHandle == INVALID_HANDLE_VALUE) return false;

    YX_PROTECT_PATHS paths{};
    // 隔离区目录（转为设备路径，与内核 FltGetFileNameInformation 返回格式一致）
    if (!m_quarantineDir.empty()) {
        std::wstring devQ = DosPathToDevicePath(m_quarantineDir);
        wcsncpy_s(paths.QuarantineDir, devQ.c_str(), _TRUNCATE);
    }
    // 驱动文件路径
    std::wstring drvPath = LocateDriverFile();
    if (!drvPath.empty()) {
        std::wstring devDrv = DosPathToDevicePath(drvPath);
        wcsncpy_s(paths.DriverSysPath, devDrv.c_str(), _TRUNCATE);
    }
    // 服务/主程序路径
    {
        wchar_t buf[MAX_PATH];
        GetModuleFileNameW(nullptr, buf, MAX_PATH);
        std::wstring devExe = DosPathToDevicePath(buf);
        wcsncpy_s(paths.ServiceExePath, devExe.c_str(), _TRUNCATE);
    }

    DWORD ret = 0;
    BOOL ok = DeviceIoControl(m_driverHandle, IOCTL_YX_SET_PROTECT_PATHS,
                              &paths, sizeof(paths), nullptr, 0, &ret, nullptr);
    if (ok) {
        std::lock_guard<std::mutex> lk(m_mutex);
        PushLog(m_callbacks, L"[自我保护] 已向驱动注册受保护路径：隔离区=" + m_quarantineDir);
    }
    return ok ? true : false;
}

yx::Stats ProtectionService::GetStats() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_stats;
}

// 前置声明：隔离元数据/路径辅助函数定义在本文件后文
static bool HasQuarSuffix(const std::wstring& s);
static std::wstring ToBackslashes(std::wstring s);
static std::wstring MetaPathOf(const std::wstring& quarantinedPath);
static void WriteQuarantineMeta(const std::wstring& quarantinedPath,
                                const std::wstring& originalPath);

bool ProtectionService::QuarantineFile(const std::wstring& path) {
    EnsureQuarantineDir();
    std::wstring origPath = ToBackslashes(path);
    std::wstring name = NormalizeFilename(fs::path(origPath).filename().wstring());
    // 添加 .quarantined 扩展名，防止文件被直接执行（已带后缀则不重复追加，杜绝双后缀）
    std::wstring dest = m_quarantineDir + L"\\" + name;
    if (!HasQuarSuffix(dest)) dest += L".quarantined";

    std::error_code ec;
    fs::rename(origPath, dest, ec);
    if (ec) {
        fs::copy_file(origPath, dest, fs::copy_options::overwrite_existing, ec);
        if (!ec) fs::remove(origPath, ec);
    }
    if (!ec) {
        // 记录原始完整路径，供恢复时回到原位置
        WriteQuarantineMeta(dest, origPath);
    }
    m_stats.FilesQuarantined++;
    return !ec;
}

// 将 DOS 路径转为 \??\C:\... 格式（驱动 ZwCreateFile 可直接使用）
static std::wstring DosToNtPath(const std::wstring& dos) {
    if (dos.empty()) return dos;
    // 已是 NT 路径则直接返回（但仍需规范化斜杠）
    std::wstring s = dos;
    // 正斜杠转反斜杠：内核 ZwCreateFile 不接受正斜杠
    for (auto& c : s) {
        if (c == L'/') c = L'\\';
    }
    if (s.size() >= 4 && s[0] == L'\\' && s[1] == L'?' && s[2] == L'?') return s;
    return L"\\??\\" + s;
}

// ---------------- 隔离文件元数据 / 驱动操作辅助 ----------------

static const wchar_t kQuarSuffix[] = L".quarantined";
static const size_t  kQuarSuffixLen = 11;

static bool HasQuarSuffix(const std::wstring& s) {
    return s.size() >= kQuarSuffixLen &&
           _wcsicmp(s.c_str() + s.size() - kQuarSuffixLen, kQuarSuffix) == 0;
}

// 去掉所有 .quarantined 后缀（处理历史双后缀残留）
static std::wstring StripQuarSuffixes(std::wstring s) {
    while (HasQuarSuffix(s)) s.resize(s.size() - kQuarSuffixLen);
    return s;
}

static std::wstring ToBackslashes(std::wstring s) {
    for (auto& c : s) if (c == L'/') c = L'\\';
    return s;
}

// 隔离文件的侧车元数据：<隔离文件>.meta，UTF-8 文本，内容为原始完整路径
static std::wstring MetaPathOf(const std::wstring& quarantinedPath) {
    return quarantinedPath + L".meta";
}

static void WriteQuarantineMeta(const std::wstring& quarantinedPath,
                                const std::wstring& originalPath) {
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, MetaPathOf(quarantinedPath).c_str(), L"w, ccs=UTF-8") != 0 || !fp) {
        SafeCrashLog(L"[Meta] write failed: " + MetaPathOf(quarantinedPath));
        return;
    }
    fwprintf(fp, L"%s", ToBackslashes(originalPath).c_str());
    fclose(fp);
}

static std::wstring ReadQuarantineMeta(const std::wstring& quarantinedPath) {
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, MetaPathOf(quarantinedPath).c_str(), L"r, ccs=UTF-8") != 0 || !fp)
        return L"";
    wchar_t buf[1024];
    std::wstring result;
    while (fgetws(buf, 1024, fp)) result += buf;
    fclose(fp);
    while (!result.empty() &&
           (result.back() == L'\r' || result.back() == L'\n' ||
            result.back() == L' '  || result.back() == L'\t')) {
        result.pop_back();
    }
    return ToBackslashes(result);
}

// 通过驱动 IOCTL 强制移动文件（ZwSetInformationFile，绕过本 minifilter）
struct DriverRenameResult {
    BOOL     ok = FALSE;
    uint32_t success = 0;
    uint32_t encStatus = 0;   // 驱动编码后的 NTSTATUS（高位=ZwCreateFile 失败）
    DWORD    lastError = 0;
};

static DriverRenameResult DriverForceRename(HANDLE hDriver,
                                            const std::wstring& srcDos,
                                            const std::wstring& dstDos) {
    DriverRenameResult r;
    if (hDriver == INVALID_HANDLE_VALUE) {
        r.lastError = ERROR_INVALID_HANDLE;
        return r;
    }
    YX_FILE_OP_REQUEST req{};
    std::wstring ntSrc = DosToNtPath(srcDos);
    std::wstring ntDst = DosToNtPath(dstDos);
    wcsncpy_s(req.SourcePath, ntSrc.c_str(), _TRUNCATE);
    wcsncpy_s(req.DestPath, ntDst.c_str(), _TRUNCATE);

    DWORD ret = 0;
    r.ok = DeviceIoControl(hDriver, IOCTL_YX_FORCE_QUARANTINE,
                           &req, sizeof(req), &req, sizeof(req), &ret, nullptr);
    r.lastError = r.ok ? 0 : GetLastError();
    r.success   = req.Success;
    r.encStatus = req.ProcessId;
    return r;
}

static std::wstring FormatEncStatus(uint32_t enc) {
    wchar_t buf[32];
    swprintf_s(buf, L"0x%08X(%s)", enc & 0x7FFFFFFF,
               (enc & 0x80000000) ? L"open" : L"rename");
    return buf;
}

bool ProtectionService::RestoreFile(const std::wstring& path) {
    EnsureQuarantineDir();

    // path：UI 传入隔离区内的实际文件名（含 .quarantined），也兼容完整路径
    std::wstring rawName = fs::path(path).filename().wstring();
    if (rawName.empty()) {
        SafeCrashLog(L"[Restore] empty input path");
        return false;
    }

    // ---------- 1. 构造候选源文件名 ----------
    // 不再依赖 fs::exists 预检：自我保护驱动可能以 ACCESS_DENIED 拒绝属性查询，
    // 旧逻辑把这种情况误判为“文件不存在”直接返回，导致永远恢复不了。
    std::vector<std::wstring> candidates;
    auto addCandidate = [&](const std::wstring& n) {
        if (n.empty()) return;
        for (const auto& c : candidates)
            if (_wcsicmp(c.c_str(), n.c_str()) == 0) return;
        candidates.push_back(n);
    };
    addCandidate(rawName);
    if (HasQuarSuffix(rawName))
        addCandidate(rawName.substr(0, rawName.size() - kQuarSuffixLen));
    else
        addCandidate(rawName + kQuarSuffix);

    // 枚举隔离区目录兜底：按“去后缀的基名”大小写不敏感匹配实际文件
    std::error_code ec;
    std::wstring baseRaw = StripQuarSuffixes(rawName);
    for (fs::directory_iterator it(m_quarantineDir, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
        std::wstring fn = it->path().filename().wstring();
        if (!HasQuarSuffix(fn)) continue;
        if (_wcsicmp(StripQuarSuffixes(fn).c_str(), baseRaw.c_str()) == 0)
            addCandidate(fn);
    }

    // exe 目录（最后兜底的恢复目标）
    wchar_t exePathBuf[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, exePathBuf, MAX_PATH);
    std::wstring exeDir = fs::path(exePathBuf).parent_path().wstring();

    std::wstring inputFull = ToBackslashes(path);
    bool inputHasDrive = (inputFull.size() >= 2 && inputFull[1] == L':');

    SafeCrashLog(L"[Restore] begin input=" + inputFull +
                 L" candidates=" + std::to_wstring(candidates.size()));

    // ---------- 2. 逐候选源 × 逐候选目标，优先走驱动 rename ----------
    for (const auto& qName : candidates) {
        std::wstring qPath = m_quarantineDir + L"\\" + qName;
        std::wstring baseName = NormalizeFilename(StripQuarSuffixes(qName));

        // 候选目标：① sidecar .meta 记录的原始目录 ② 入参完整路径的目录 ③ exe 目录
        std::vector<std::wstring> dests;
        auto addDest = [&](const std::wstring& d) {
            if (d.empty()) return;
            for (const auto& x : dests)
                if (_wcsicmp(x.c_str(), d.c_str()) == 0) return;
            dests.push_back(d);
        };
        std::wstring metaOrig = ReadQuarantineMeta(qPath);
        if (!metaOrig.empty()) {
            std::wstring metaParent = fs::path(metaOrig).parent_path().wstring();
            addDest(metaParent.empty() ? baseName : metaParent + L"\\" + baseName);
        }
        if (inputHasDrive) {
            std::wstring inParent = fs::path(inputFull).parent_path().wstring();
            addDest(inParent.empty() ? baseName : inParent + L"\\" + baseName);
        }
        addDest(exeDir + L"\\" + baseName);

        bool sourceMissing = false;
        for (const auto& dest : dests) {
            SafeCrashLog(L"[Restore] try driver src=" + qPath + L" dest=" + dest +
                         (metaOrig.empty() ? L"" : (L" meta=" + metaOrig)));
            if (m_driverHandle != INVALID_HANDLE_VALUE) {
                DriverRenameResult r = DriverForceRename(m_driverHandle, qPath, dest);
                SafeCrashLog(L"[Restore] driver ret ok=" + std::to_wstring(r.ok) +
                             L" success=" + std::to_wstring(r.success) +
                             L" status=" + FormatEncStatus(r.encStatus) +
                             L" err=" + std::to_wstring(r.lastError));
                if (r.ok && r.success) {
                    std::error_code rmEc;
                    fs::remove(MetaPathOf(qPath), rmEc);
                    SafeCrashLog(L"[Restore] Success src=" + qPath + L" dest=" + dest);
                    Log(L"[Restore] Success " + qPath + L" -> " + dest);
                    return true;
                }
                uint32_t low = r.encStatus & 0x7FFFFFFFu;
                if (low == 0x00000034u) { sourceMissing = true; break; } // NAME_NOT_FOUND：换下一个源
                if (low == 0x0000003Au) continue;                        // PATH_NOT_FOUND：换目标目录
                // 其它错误：继续尝试下一个目标/用户态回退
            }
        }
        if (sourceMissing) continue;

        // ---------- 3. 用户态回退（受保护 PID 会被 minifilter 放行） ----------
        bool srcExists = fs::exists(qPath, ec);
        SafeCrashLog(L"[Restore] user-mode fallback src=" + qPath +
                     L" exists=" + std::to_wstring(srcExists) +
                     L" ec=" + std::to_wstring(ec.value()));
        if (!srcExists) continue;
        for (const auto& dest : dests) {
            ec.clear();
            fs::rename(qPath, dest, ec);
            if (ec) {
                fs::copy_file(qPath, dest, fs::copy_options::overwrite_existing, ec);
                if (!ec) {
                    std::error_code rmEc;
                    fs::remove(qPath, rmEc);
                }
            }
            if (!ec) {
                std::error_code metaEc;
                fs::remove(MetaPathOf(qPath), metaEc);
                SafeCrashLog(L"[Restore] Success(user-mode) src=" + qPath + L" dest=" + dest);
                Log(L"[Restore] Success(user-mode) " + qPath + L" -> " + dest);
                return true;
            }
            SafeCrashLog(L"[Restore] user-mode dest failed dest=" + dest +
                         L" code=" + std::to_wstring(ec.value()));
        }
    }

    SafeCrashLog(L"[Restore] all attempts failed input=" + inputFull);
    return false;
}

bool ProtectionService::KillProcessByPid(DWORD pid) {
    if (pid == 0) {
        SafeCrashLog(L"[Kill] pid=0, skip");
        return false;
    }
    SafeCrashLog(L"[Kill] Start terminate pid=" + std::to_wstring(pid));

    // 优先尝试内核驱动强制终止
    if (m_driverHandle != INVALID_HANDLE_VALUE) {
        YX_FILE_OP_REQUEST req{};
        req.ProcessId = pid;

        DWORD ret = 0;
        SafeCrashLog(L"[Kill] Call IOCTL_YX_KILL_PROCESS pid=" + std::to_wstring(pid));
        BOOL ok = DeviceIoControl(m_driverHandle, IOCTL_YX_KILL_PROCESS,
                                   &req, sizeof(req), &req, sizeof(req), &ret, nullptr);
        DWORD le = ok ? 0 : GetLastError();
        SafeCrashLog(L"[Kill] IOCTL ret ok=" + std::to_wstring(ok) +
            L" success=" + std::to_wstring(req.Success) +
            L" err=" + std::to_wstring(le));
        if (ok && req.Success) {
            SafeCrashLog(L"[Kill] Success pid=" + std::to_wstring(pid));
            return true;
        }
        Log(L"[KillProcess] Driver IOCTL failed, fallback to user-mode TerminateProcess: pid=" +
            std::to_wstring(pid) + L", ret=" + std::to_wstring(ret));
    } else {
        SafeCrashLog(L"[Kill] Invalid driver handle, use user-mode");
    }

    // 用户态回退
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        DWORD le = GetLastError();
        Log(L"[KillProcess] OpenProcess failed, pid=" + std::to_wstring(pid) +
            L", err=" + std::to_wstring(le));
        SafeCrashLog(L"[Kill] OpenProcess failed pid=" + std::to_wstring(pid) +
            L" err=" + std::to_wstring(le));
        return false;
    }
    BOOL ok = TerminateProcess(hProc, 1);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(hProc);
    if (!ok) {
        Log(L"[KillProcess] TerminateProcess failed, pid=" + std::to_wstring(pid) +
            L", err=" + std::to_wstring(err));
        SafeCrashLog(L"[Kill] TerminateProcess failed pid=" + std::to_wstring(pid) +
            L" err=" + std::to_wstring(err));
    } else {
        SafeCrashLog(L"[Kill] TerminateProcess success pid=" + std::to_wstring(pid));
    }
    return ok != FALSE;
}

bool ProtectionService::ForceDeleteFile(const std::wstring& path) {
    // 先把 NT 设备路径（\Device\HarddiskVolume3\...）转为 DOS 路径（C:\...）
    std::wstring dosPath = DevicePathToDosPath(path);
    // 直接使用传入的路径（UI 传入的是实际文件名）
    std::wstring cleanPath = dosPath;
    // 规范化：去掉末尾点/空格
    std::wstring fn = fs::path(dosPath).filename().wstring();
    std::wstring parent = fs::path(dosPath).parent_path().wstring();
    // 去掉所有末尾点/空格（但保留 .quarantined 后缀）
    bool hasQ = fn.size() >= 11 && fn.substr(fn.size() - 11) == L".quarantined";
    std::wstring baseFn = hasQ ? fn.substr(0, fn.size() - 11) : fn;
    baseFn = NormalizeFilename(baseFn);
    if (hasQ) baseFn += L".quarantined";
    cleanPath = parent.empty() ? baseFn : parent + L"\\" + baseFn;

    // 文件存在性检查：如果精确路径找不到，尝试去掉一个 .quarantined 后缀
    std::error_code ec;
    if (!fs::exists(cleanPath, ec) && !ec) {
        if (baseFn.size() > 11 && baseFn.substr(baseFn.size() - 11) == L".quarantined") {
            std::wstring altFn = baseFn.substr(0, baseFn.size() - 11);
            std::wstring altPath = parent.empty() ? altFn : parent + L"\\" + altFn;
            if (fs::exists(altPath, ec) && !ec) {
                cleanPath = altPath;
                SafeCrashLog(L"[Del] Found file with stripped suffix: " + cleanPath);
            }
        }
    }

    SafeCrashLog(L"[Del] Start delete path=" + cleanPath);
    // 优先尝试内核驱动强制删除（绕过用户态权限）
    if (m_driverHandle != INVALID_HANDLE_VALUE) {
        YX_FILE_OP_REQUEST req{};
        std::wstring ntPath = DosToNtPath(cleanPath);
        wcsncpy_s(req.SourcePath, ntPath.c_str(), _TRUNCATE);
        SafeCrashLog(L"[Del] Call IOCTL_YX_FORCE_DELETE_FILE ntPath=" + ntPath);
        Log(L"[Delete] IOCTL path=" + cleanPath + L" ntPath=" + ntPath);

        DWORD ret = 0;
        BOOL ok = DeviceIoControl(m_driverHandle, IOCTL_YX_FORCE_DELETE_FILE,
                                   &req, sizeof(req), &req, sizeof(req), &ret, nullptr);
        DWORD le = ok ? 0 : GetLastError();
        // ProcessId 字段在删除操作中用于传回内核 NTSTATUS（调试用）
        // 高位 0x80000000 表示 ZwCreateFile 失败，否则为 ZwSetInformationFile 失败
        uint32_t drvSt = req.ProcessId;
        std::wstring stage = (drvSt & 0x80000000) ? L"ZwCreateFile" : L"ZwSetInformationFile";
        // 十六进制显示 NTSTATUS
        wchar_t hexBuf[16];
        swprintf_s(hexBuf, L"0x%08X", drvSt & 0x7FFFFFFF);
        SafeCrashLog(L"[Del] IOCTL ret ok=" + std::to_wstring(ok) +
            L" success=" + std::to_wstring(req.Success) +
            L" stage=" + stage +
            L" ntstatus=" + hexBuf +
            L" err=" + std::to_wstring(le));
        if (ok && req.Success) {
            std::error_code metaEc;
            fs::remove(MetaPathOf(cleanPath), metaEc);
            SafeCrashLog(L"[Del] Success path=" + cleanPath);
            Log(L"[Delete] Success path=" + cleanPath);
            return true;
        }
        Log(L"[Delete] Driver IOCTL failed, fallback to user-mode fs: ret=" + std::to_wstring(ret) +
            L", success=" + std::to_wstring(req.Success) +
            L", stage=" + stage +
            L", ntstatus=" + hexBuf);
    }

    // 用户态 fs 回退（ec 已在上面声明）
    bool removed = fs::remove(cleanPath, ec);
    if (ec) {
        std::string m = ec.message();
        Log(L"[Delete] User-mode fs::remove failed: " + std::wstring(m.begin(), m.end()));
        SafeCrashLog(L"[Del] fs::remove failed path=" + cleanPath +
            L" err=" + std::wstring(m.begin(), m.end()) +
            L" code=" + std::to_wstring(ec.value()));
        return false;
    }
    if (!removed) {
        SafeCrashLog(L"[Del] fs::remove not found path=" + cleanPath);
        return false;
    }
    SafeCrashLog(L"[Del] fs::remove success path=" + cleanPath);
    std::error_code metaEc2;
    fs::remove(MetaPathOf(cleanPath), metaEc2);
    return true;
}

bool ProtectionService::ForceQuarantineFile(const std::wstring& path) {
    // 先把 NT 设备路径（\Device\HarddiskVolume3\...）转为 DOS 路径（C:\...）
    std::wstring origPath = ToBackslashes(DevicePathToDosPath(path));
    SafeCrashLog(L"[Quar] Start quarantine path=" + origPath);
    EnsureQuarantineDir();
    std::wstring name = NormalizeFilename(fs::path(origPath).filename().wstring());
    // 添加 .quarantined 扩展名，防止文件被直接执行（已带后缀则不重复追加，杜绝双后缀）
    std::wstring dest = m_quarantineDir + L"\\" + name;
    if (!HasQuarSuffix(dest)) dest += L".quarantined";
    SafeCrashLog(L"[Quar] dest=" + dest);

    // 最多重试 3 次：文件被运行中的进程锁定时，先杀进程再重试
    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) {
            // 等待进程释放文件句柄
            Sleep(500);
        }

        // 优先尝试内核驱动强制隔离（IRP 路径，绕过用户态权限）
        if (m_driverHandle != INVALID_HANDLE_VALUE) {
            YX_FILE_OP_REQUEST req{};
            std::wstring ntSrc = DosToNtPath(origPath);
            std::wstring ntDst = DosToNtPath(dest);
            wcsncpy_s(req.SourcePath, ntSrc.c_str(), _TRUNCATE);
            wcsncpy_s(req.DestPath, ntDst.c_str(), _TRUNCATE);

            DWORD ret = 0;
            BOOL ok = DeviceIoControl(m_driverHandle, IOCTL_YX_FORCE_QUARANTINE,
                                       &req, sizeof(req), &req, sizeof(req), &ret, nullptr);
            DWORD le = ok ? 0 : GetLastError();
            uint32_t drvSt = req.ProcessId;
            std::wstring stage = (drvSt & 0x80000000) ? L"ZwCreateFile" : L"ZwSetInformationFile";
            wchar_t hexBuf[16];
            swprintf_s(hexBuf, L"0x%08X", drvSt & 0x7FFFFFFF);
            SafeCrashLog(L"[Quar] IOCTL ret ok=" + std::to_wstring(ok) +
                L" success=" + std::to_wstring(req.Success) +
                L" stage=" + stage +
                L" ntstatus=" + hexBuf +
                L" attempt=" + std::to_wstring(attempt) +
                L" err=" + std::to_wstring(le));
            if (ok && req.Success) {
                WriteQuarantineMeta(dest, origPath);
                m_stats.FilesQuarantined++;
                SafeCrashLog(L"[Quar] Success path=" + origPath);
                return true;
            }
            // SHARING_VIOLATION (0x40000043) 或 ERROR_SHARING_VIOLATION (32)：
            // 文件被进程锁定，杀掉进程后重试
            bool sharingViolation = ((drvSt & 0x7FFFFFFF) == 0x40000043);
            if (!sharingViolation) {
                // 其他错误：回退到用户态
                Log(L"[Quarantine] Driver IOCTL failed, fallback to user-mode fs");
            } else if (attempt < 2) {
                SafeCrashLog(L"[Quar] File locked, killing process and retrying attempt=" +
                             std::to_wstring(attempt));
                DWORD pid = FindProcessByPath(origPath);
                if (pid != 0) {
                    KillProcessByPid(pid);
                    for (int w = 0; w < 10; w++) {
                        HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
                        if (!h) break;
                        DWORD r = WaitForSingleObject(h, 200);
                        CloseHandle(h);
                        if (r == WAIT_OBJECT_0) break;
                    }
                }
                continue;  // 重试
            }
        }

        // 用户态 fs 回退：rename -> copy+remove
        std::error_code ec;
        fs::rename(origPath, dest, ec);
        if (!ec) {
            SafeCrashLog(L"[Quar] fs::rename success path=" + origPath);
            WriteQuarantineMeta(dest, origPath);
            m_stats.FilesQuarantined++;
            return true;
        }

        SafeCrashLog(L"[Quar] fs::rename failed code=" + std::to_wstring(ec.value()) +
            L" attempt=" + std::to_wstring(attempt) + L" try copy+remove");

        fs::copy_file(origPath, dest, fs::copy_options::overwrite_existing, ec);
        if (!ec) {
            fs::remove(origPath, ec);
            if (ec) {
                std::string m = ec.message();
                SafeCrashLog(L"[Quar] remove source failed path=" + origPath +
                    L" err=" + std::wstring(m.begin(), m.end()));
            }
            WriteQuarantineMeta(dest, origPath);
            m_stats.FilesQuarantined++;
            SafeCrashLog(L"[Quar] Success (copy+remove) path=" + origPath);
            return true;
        }

        // copy 也失败了：如果是共享冲突，杀进程重试
        if ((ec.value() == 32 || ec.value() == 5) && attempt < 2) {
            SafeCrashLog(L"[Quar] File locked, killing process and retrying attempt=" +
                         std::to_wstring(attempt));
            DWORD pid = FindProcessByPath(origPath);
            if (pid != 0) {
                KillProcessByPid(pid);
                for (int w = 0; w < 10; w++) {
                    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
                    if (!h) break;
                    DWORD r = WaitForSingleObject(h, 200);
                    CloseHandle(h);
                    if (r == WAIT_OBJECT_0) break;
                }
            }
            continue;  // 重试
        }

        // 非共享冲突错误，直接失败
        std::string m = ec.message();
        Log(L"[Quarantine] User-mode copy failed: " + std::wstring(m.begin(), m.end()) +
            L" (" + std::to_wstring(ec.value()) + L")");
        SafeCrashLog(L"[Quar] copy_file failed path=" + origPath +
            L" err=" + std::wstring(m.begin(), m.end()) +
            L" code=" + std::to_wstring(ec.value()));
        return false;
    }

    SafeCrashLog(L"[Quar] All retries exhausted path=" + origPath);
    return false;
}

DWORD ProtectionService::FindProcessByPath(const std::wstring& path) {
    DWORD pids[1024];
    DWORD needed = 0;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return 0;
    DWORD count = needed / sizeof(DWORD);

    // 规范化：统一反斜杠、转小写，确保匹配不受斜杠方向影响
    std::wstring lower = path;
    for (auto& c : lower) { if (c == L'/') c = L'\\'; }
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    for (DWORD i = 0; i < count; i++) {
        DWORD pid = pids[i];
        if (pid == 0 || pid == GetCurrentProcessId()) continue;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) continue;
        wchar_t buf[MAX_PATH];
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
            std::wstring img(buf);
            for (auto& c : img) { if (c == L'/') c = L'\\'; }
            std::transform(img.begin(), img.end(), img.begin(), ::towlower);
            if (img == lower) {
                CloseHandle(h);
                return pid;
            }
        }
        CloseHandle(h);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 事件处理：内核事件 -> 规则引擎 -> 处置
// ---------------------------------------------------------------------------
void ProtectionService::HandleEvent(const yx::Event& ev) {
    auto hit = m_rules.Evaluate(ev);
    if (hit) {
        HandleThreat(*hit);
    }
}

void ProtectionService::HandleThreat(const yx::RuleHit& hit) {
    m_stats.ThreatsDetected++;

    // 威胁处置去重：同一目标路径 10 秒内不重复处置
    std::wstring targetPath = hit.subject.empty() ? hit.object : hit.subject;
    if (!targetPath.empty()) {
        std::wstring key = DevicePathToDosPath(targetPath);
        std::transform(key.begin(), key.end(), key.begin(), ::towlower);
        ULONGLONG now = GetTickCount64();
        bool skip = false;
        {
            std::lock_guard<std::mutex> lk(m_threatMutex);
            auto it = m_lastThreatByPath.find(key);
            if (it != m_lastThreatByPath.end() && (now - it->second) < 10000) {
                skip = true;
            } else {
                m_lastThreatByPath[key] = now;
            }
        }
        if (skip) {
            return;
        }
    }

    // 先记录日志
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_callbacks.onLog) {
            m_callbacks.onLog(L"[Threat] " + hit.description + L"  subject=" + hit.subject);
        }
    }

    bool autoHandle = true;
    int autoAction = 0;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        autoHandle = m_settings.autoHandle;
        autoAction = m_settings.autoAction;
    }

    if (autoHandle) {
        // 自动处理：直接按设置的处置方式执行
        int action = autoAction;  // 0=隔离, 1=删除
        ExecuteThreatAction(hit, action);
        // 通知 GUI 显示拦截结果
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (m_callbacks.onToast) {
                std::wstring title = L"威胁已自动处置";
                std::wstring body = hit.description + L"\n处置: " +
                    std::wstring(action == 0 ? L"已隔离到隔离区" : L"已强制删除");
                m_callbacks.onToast(yx::ToastType::Critical, title, body);
            }
            if (m_callbacks.onThreat) {
                m_callbacks.onThreat(hit);
            }
        }
    } else {
        // 手动处理：弹窗让用户选择拦截或放过
        int decision = ThreatDecision::Allow;
        bool hasCallback = false;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            hasCallback = (bool)m_callbacks.onThreatDecision;
        }

        if (hasCallback) {
            // 重置决策状态
            {
                std::lock_guard<std::mutex> lk(m_decisionMutex);
                m_pendingDecision = -1;
            }

            // 在 GUI 线程弹窗，通过回调回传决策
            {
                std::lock_guard<std::mutex> lk(m_mutex);
                if (m_callbacks.onThreatDecision) {
                    m_callbacks.onThreatDecision(hit, [this](int d) {
                        std::lock_guard<std::mutex> lk(m_decisionMutex);
                        m_pendingDecision = d;
                        m_decisionCv.notify_all();
                    });
                }
            }

            // 等待用户决策（最多等 60 秒，超时默认放过）
            {
                std::unique_lock<std::mutex> lk(m_decisionMutex);
                if (m_pendingDecision == -1) {
                    m_decisionCv.wait_for(lk, std::chrono::seconds(60), [this] {
                        return m_pendingDecision != -1;
                    });
                }
                decision = (m_pendingDecision == -1) ? ThreatDecision::Allow : m_pendingDecision;
            }
        }

        if (decision == ThreatDecision::Block) {
            int action = autoAction;  // 拦截时按设置的处置方式
            ExecuteThreatAction(hit, action);
        }
    }
}

yx::ProtectSettings ProtectionService::GetProtectSettings() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_settings;
}

bool ProtectionService::ExecuteThreatAction(const yx::RuleHit& hit, int action) {
    // action: 0=隔离, 1=删除, 2=放过
    if (action == 2) {
        Log(L"[处置] 用户选择放过: " + hit.description);
        return true;
    }

    // protectedObject=true 表示客体是受保护的系统资源（hosts/system32/注册表等）
    // 此时只能处置修改者进程(subject)，绝不能删除客体(object)
    if (hit.protectedObject) {
        std::wstring procPath = hit.subject;
        if (procPath.empty()) {
            Log(L"[处置] 受保护资源被修改，但未获取到修改者进程，仅记录: " + hit.description);
            return true;
        }
        procPath = DevicePathToDosPath(procPath);
        DWORD pid = FindProcessByPath(procPath);
        if (pid != 0) {
            SafeCrashLog(L"[Action] Kill process (protected object) pid=" +
                         std::to_wstring(pid) + L" path=" + procPath);
            KillProcessByPid(pid);
            for (int w = 0; w < 15; w++) {
                HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
                if (!h) break;
                DWORD r = WaitForSingleObject(h, 100);
                CloseHandle(h);
                if (r == WAIT_OBJECT_0) break;
            }
            Log(L"[处置] 已终止修改受保护资源的进程: " + procPath);
        } else {
            Log(L"[处置] 修改者进程已退出，无需处置: " + procPath);
        }
        return true;
    }

    // 普通恶意文件：优先从 subject 取进程路径，没有则用 object
    std::wstring path = hit.subject;
    if (path.empty()) path = hit.object;

    // 银狐持久化任务：hit.object 是任务名，需要删除计划任务本身
    if (hit.category == yx::RuleCategory::YinHuTaskPersist && !hit.object.empty()) {
        std::wstring taskName = hit.object;
        std::wstring delCmd = L"schtasks.exe /delete /tn \"" + taskName + L"\" /f";
        std::vector<wchar_t> cmdBuf(delCmd.begin(), delCmd.end());
        cmdBuf.push_back(L'\0');

        STARTUPINFOW si{ sizeof(STARTUPINFOW) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        BOOL delOk = CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                                    CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (delOk) {
            WaitForSingleObject(pi.hProcess, 5000);
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            SafeCrashLog(L"[Action] Delete scheduled task: " + taskName +
                         L" exitCode=" + std::to_wstring(exitCode));
            Log(exitCode == 0 ? (L"[处置] 已删除计划任务: " + taskName)
                              : (L"[处置] 删除计划任务失败: " + taskName));
        }
    }

    if (path.empty()) {
        Log(L"[处置] 无目标路径，跳过: " + hit.description);
        return true;
    }

    // 统一转为 DOS 路径（驱动上报的是 NT 设备路径 \Device\...）
    path = DevicePathToDosPath(path);

    // 文件不存在：跳过隔离/删除（如 Edge 卸载后残留的任务，文件已不存在）
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        SafeCrashLog(L"[Action] Target file not exist, skip file op: " + path);
        Log(L"[处置] 目标文件不存在，跳过文件处置: " + path);
        return true;
    }

    // 查找并终止对应进程
    DWORD pid = FindProcessByPath(path);
    if (pid != 0) {
        SafeCrashLog(L"[Action] Kill process pid=" + std::to_wstring(pid) +
                     L" path=" + path);
        KillProcessByPid(pid);
        // 等待进程退出
        for (int w = 0; w < 15; w++) {
            HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
            if (!h) break;
            DWORD r = WaitForSingleObject(h, 100);
            CloseHandle(h);
            if (r == WAIT_OBJECT_0) break;
        }
    }

    bool ok = false;
    if (action == 0) {
        // 隔离到隔离区
        ok = ForceQuarantineFile(path);
        Log(ok ? (L"[处置] 已隔离文件: " + path)
               : (L"[处置] 隔离失败: " + path));
    } else if (action == 1) {
        // 直接强制删除
        ok = ForceDeleteFile(path);
        Log(ok ? (L"[处置] 已删除文件: " + path)
               : (L"[处置] 删除失败: " + path));
    }
    return ok;
}

bool ProtectionService::SaveSettingsToFile() {
    std::wstring cfgPath = GetInstallDir() + L"\\config.ini";
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, cfgPath.c_str(), L"w, ccs=UTF-8") != 0 || !fp) {
        Log(L"[设置] 保存配置失败: " + cfgPath);
        return false;
    }
    ProtectSettings s;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        s = m_settings;
    }
    fwprintf(fp, L"[ProtectSettings]\n");
    fwprintf(fp, L"fileProtect=%d\n", s.fileProtect ? 1 : 0);
    fwprintf(fp, L"processProtect=%d\n", s.processProtect ? 1 : 0);
    fwprintf(fp, L"registryProtect=%d\n", s.registryProtect ? 1 : 0);
    fwprintf(fp, L"scheduleProtect=%d\n", s.scheduleProtect ? 1 : 0);
    fwprintf(fp, L"networkProtect=%d\n", s.networkProtect ? 1 : 0);
    fwprintf(fp, L"injectProtect=%d\n", s.injectProtect ? 1 : 0);
    fwprintf(fp, L"yinHuProtect=%d\n", s.yinHuProtect ? 1 : 0);
    fwprintf(fp, L"selfProtect=%d\n", s.selfProtect ? 1 : 0);
    fwprintf(fp, L"mbrProtect=%d\n", s.mbrProtect ? 1 : 0);
    fwprintf(fp, L"autoHandle=%d\n", s.autoHandle ? 1 : 0);
    fwprintf(fp, L"autoAction=%d\n", s.autoAction);
    fwprintf(fp, L"processStartScan=%d\n", s.processStartScan ? 1 : 0);
    fclose(fp);
    return true;
}

bool ProtectionService::LoadSettingsFromFile() {
    std::wstring cfgPath = GetInstallDir() + L"\\config.ini";
    std::error_code ec;
    if (!fs::exists(cfgPath, ec)) return false;

    FILE* fp = nullptr;
    if (_wfopen_s(&fp, cfgPath.c_str(), L"r, ccs=UTF-8") != 0 || !fp) return false;

    ProtectSettings s;
    wchar_t line[512];
    while (fgetws(line, 512, fp)) {
        std::wstring ln(line);
        while (!ln.empty() && (ln.back() == L'\r' || ln.back() == L'\n')) ln.pop_back();
        auto eq = ln.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = ln.substr(0, eq);
        std::wstring val = ln.substr(eq + 1);
        int v = _wtoi(val.c_str());
        if (key == L"fileProtect") s.fileProtect = (v != 0);
        else if (key == L"processProtect") s.processProtect = (v != 0);
        else if (key == L"registryProtect") s.registryProtect = (v != 0);
        else if (key == L"scheduleProtect") s.scheduleProtect = (v != 0);
        else if (key == L"networkProtect") s.networkProtect = (v != 0);
        else if (key == L"injectProtect") s.injectProtect = (v != 0);
        else if (key == L"yinHuProtect") s.yinHuProtect = (v != 0);
        else if (key == L"selfProtect") s.selfProtect = (v != 0);
        else if (key == L"mbrProtect") s.mbrProtect = (v != 0);
        else if (key == L"autoHandle") s.autoHandle = (v != 0);
        else if (key == L"autoAction") s.autoAction = v;
        else if (key == L"processStartScan") s.processStartScan = (v != 0);
    }
    fclose(fp);

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_settings = s;
    }
    return true;
}

// 内核事件（YX_EVENT）转用户态 Event 并处理
void ProtectionService::OnDriverEvent(const YX_EVENT& ev) {
    yx::Event e;
    e.type = (int)ev.Type;
    e.pid = ev.ProcessId;
    e.parentPid = ev.ParentProcessId;
    e.targetPid = ev.TargetProcessId;
    e.timestamp = ev.Timestamp;
    e.name0 = ev.Name0;
    e.name1 = ev.Name1;
    e.name2 = ev.Name2;
    HandleEvent(e);
}

// 驱动消息线程：从 filter port 拉消息并回复决策
void ProtectionService::DriverMessageThreadProc() {
    SafeCrashLog(L"[DriverMsg] Thread start tid=" + std::to_wstring(GetCurrentThreadId()));
    SafeCrashLog(L"[DriverMsg] sizeof(FILTER_REPLY_HEADER)=" + std::to_wstring(sizeof(FILTER_REPLY_HEADER)) +
        L" sizeof(YX_DECISION)=" + std::to_wstring(sizeof(YX_DECISION)) +
        L" sizeof(YX_EVENT)=" + std::to_wstring(sizeof(YX_EVENT)) +
        L" sizeof(FILTER_MESSAGE_HEADER)=" + std::to_wstring(sizeof(FILTER_MESSAGE_HEADER)));
    ULONG64 recvCount = 0, errCount = 0;
    DWORD lastReconnectTick = 0;

    while (m_running) {
        // ---- 端口断开自动重连 ----
        if (m_filterPort == INVALID_HANDLE_VALUE) {
            DWORD now = GetTickCount();
            if (now - lastReconnectTick > 1000) {
                lastReconnectTick = now;
                SafeCrashLog(L"[DriverMsg] Invalid port, try reopen driver + connect filter port");
                OpenDriver();
                ConnectFilterPort();
                if (m_filterPort == INVALID_HANDLE_VALUE) {
                    errCount++;
                    if (errCount <= 5 || errCount % 30 == 0) {
                        SafeCrashLog(L"[DriverMsg] Reconnect failed count=" + std::to_wstring(errCount));
                    }
                    Sleep(1000);
                    continue;
                }
                SafeCrashLog(L"[DriverMsg] Reconnect success");
            } else {
                Sleep(200);
                continue;
            }
        }

        // ---- 接收驱动消息 ----
        constexpr DWORD bufSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(YX_EVENT) + 512;
        std::vector<BYTE> buf(bufSize);

        HRESULT hr = FilterGetMessage(m_filterPort,
                                      (PFILTER_MESSAGE_HEADER)buf.data(),
                                      bufSize, nullptr);

        if (!SUCCEEDED(hr)) {
            // 失败：端口可能已关闭
            DWORD le = GetLastError();
            std::wstring err = L"[DriverMsg] FilterGetMessage failed hr=0x" +
                std::to_wstring(static_cast<unsigned long>(hr)) +
                L" lastErr=" + std::to_wstring(le);
            SafeCrashLog(err);
            // 端口可能已失效，关闭等下次循环重连
            CloseHandle(m_filterPort);
            m_filterPort = INVALID_HANDLE_VALUE;
            Sleep(100);
            continue;
        }

        recvCount++;
        auto* hdr = (PFILTER_MESSAGE_HEADER)buf.data();
        auto* ev = (YX_EVENT*)(buf.data() + sizeof(FILTER_MESSAGE_HEADER));

        // 记录所有进程创建事件(type=10)，以及前200条事件中每10条记录一次
        // 进程创建事件必须记录，以便调试签名验证和启发式扫描逻辑
        bool isProcessCreate = (ev->Type == YX_EVENT_PROCESS_CREATE);
        if (isProcessCreate || recvCount <= 10 || (recvCount <= 200 && recvCount % 10 == 0)) {
            std::wstring name0 = ev->Name0[0] ? ev->Name0 : L"(empty)";
            std::wstring log = L"[DriverMsg] recv#" + std::to_wstring(recvCount) +
                L" type=" + std::to_wstring((int)ev->Type) +
                L" pid=" + std::to_wstring(ev->ProcessId) +
                L" name0=" + name0;
            SafeCrashLog(log);
        }

        // ---- 整个事件处理包在 try-catch 里：任何异常都不应让线程崩溃 ----
        try {
            // ---- MBR/GPT 保护事件：驱动已拦截，触发弹窗+隔离 ----
            if (ev->Type == YX_EVENT_MBR_PROTECT) {
                std::wstring procName = ev->Name0 ? ev->Name0 : L"(unknown)";
                std::wstring detail = L"Blocked write to MBR/GPT boot sector!\nProcess: " + procName;
                SafeCrashLog(L"[MBR] " + detail);

                // Toast 节流：同一进程 10 秒内只弹一次，防止刷屏
                bool showToast = false;
                {
                    std::lock_guard<std::mutex> lk(m_toastMutex);
                    ULONGLONG now = GetTickCount64();
                    auto it = m_lastToastByPid.find(ev->ProcessId);
                    if (it == m_lastToastByPid.end() || (now - it->second) > 10000) {
                        m_lastToastByPid[ev->ProcessId] = now;
                        showToast = true;
                    }
                }
                {
                    std::lock_guard<std::mutex> lk(m_mutex);
                    if (showToast && m_callbacks.onToast) {
                        m_callbacks.onToast(yx::ToastType::Critical, L"MBR Boot Sector Protection", detail);
                    }
                    if (m_callbacks.onLog) {
                        m_callbacks.onLog(L"[MBR] " + detail);
                    }
                }
                // 尝试隔离该进程的可执行文件（异步派发，避免在驱动消息线程中同步操作文件触发死锁）
                std::wstring imgPath;
                try {
                    imgPath = GetProcessImagePath((DWORD)ev->ProcessId);
                } catch (...) {
                    SafeCrashLog(L"[MBR] GetProcessImagePath exception pid=" + std::to_wstring(ev->ProcessId));
                }
                if (!imgPath.empty()) {
                    // 改为异步执行：在线程池中跑，避免阻塞驱动消息线程
                    std::thread([this, imgPath]() {
                        try {
                            SafeCrashLog(L"[MBR] Async quarantine pid path=" + imgPath);
                            QuarantineFile(imgPath);
                        } catch (const std::exception& e) {
                            std::string m = e.what();
                            SafeCrashLog(L"[MBR] Async quarantine exception: " + std::wstring(m.begin(), m.end()));
                        } catch (...) {
                            SafeCrashLog(L"[MBR] Async quarantine unknown exception");
                        }
                    }).detach();
                }
                // MBR 事件由驱动直接拦截，不回复
                continue;
            }

            // ---- 自我保护事件：驱动已拦截，仅记录日志（不弹 toast，避免刷屏） ----
            if (ev->Type == YX_EVENT_SELF_PROTECT) {
                std::wstring procName = ev->Name0 ? ev->Name0 : L"(unknown)";
                std::wstring detail = L"Blocked access to protected file! Process: " + procName +
                    L" Target: " + (ev->Name1 ? ev->Name1 : L"");
                SafeCrashLog(L"[SelfProtect] " + detail);
                {
                    std::lock_guard<std::mutex> lk(m_mutex);
                    if (m_callbacks.onLog) {
                        m_callbacks.onLog(L"[SelfProtect] " + detail);
                    }
                }
                continue;
            }

            // ---- 进程创建事件：启动前启发式扫描 + 签名验证 ----
            // 策略：微软官方签名的进程直接放行；其余进程走规则引擎启发式扫描
            if (ev->Type == YX_EVENT_PROCESS_CREATE) {
                bool startScanEnabled = true;
                {
                    std::lock_guard<std::mutex> lk(m_mutex);
                    startScanEnabled = m_settings.processStartScan;
                }

                YX_DECISION decision{ 0 };
                decision.EventId = ev->Timestamp;
                decision.Action = YX_ACTION_ALLOW;  // 默认放行

                std::wstring imgPath = ev->Name0 ? ev->Name0 : L"";
                if (!imgPath.empty()) {
                    // 驱动上报的是 NT 设备路径，转为 DOS 路径以便 WinVerifyTrust 使用
                    std::wstring dosPath = DevicePathToDosPath(imgPath);

                    if (startScanEnabled) {
                        // 1. 微软签名验证（含嵌入签名 + 系统 CAT 目录签名库）
                        bool msSigned = IsMicrosoftSignedCached(dosPath);

                        if (msSigned) {
                            // 微软官方签名：直接放行，不做启发式扫描
                            SafeCrashLog(L"[ProcessScan] Allow (Microsoft signed): " + dosPath);
                            decision.Action = YX_ACTION_ALLOW;
                        } else {
                            // 2. 非微软签名：先做 PE 启发式扫描（与静态扫描同一套引擎）
                            HeuristicResult heur = m_heuristic.ScanFile(dosPath);
                            if (heur.suspicious) {
                                SafeCrashLog(L"[ProcessScan] Block (PE heuristic): " + dosPath +
                                             L" score=" + std::to_wstring(heur.score));
                                decision.Action = YX_ACTION_BLOCK;

                                yx::RuleHit threatHit;
                                threatHit.category = RuleCategory::Heuristic;
                                threatHit.level = ThreatLevel::High;
                                threatHit.description = L"PE 启发式检测到可疑文件（score=" +
                                    std::to_wstring(heur.score) + L"）";
                                threatHit.subject = dosPath;
                                threatHit.object = dosPath;

                                std::thread([this, threatHit]() {
                                    try {
                                        HandleThreat(threatHit);
                                    } catch (...) {}
                                }).detach();
                            } else {
                                // 3. PE 扫描未命中：再走行为规则扫描
                                yx::Event e;
                                e.type = (int)ev->Type;
                                e.pid = ev->ProcessId;
                                e.parentPid = ev->ParentProcessId;
                                e.targetPid = ev->TargetProcessId;
                                e.timestamp = ev->Timestamp;
                                e.name0 = dosPath;
                                e.name1 = ev->Name1 ? ev->Name1 : L"";
                                e.name2 = ev->Name2 ? ev->Name2 : L"";

                                std::optional<yx::RuleHit> hit;
                                try {
                                    hit = m_rules.Evaluate(e);
                                } catch (...) {
                                    hit = std::nullopt;
                                }

                                if (hit) {
                                    SafeCrashLog(L"[ProcessScan] Block (heuristic rule): " + dosPath +
                                                 L" reason=" + hit->description);
                                    decision.Action = YX_ACTION_BLOCK;

                                    yx::RuleHit threatHit = *hit;
                                    std::thread([this, threatHit]() {
                                        try {
                                            HandleThreat(threatHit);
                                        } catch (...) {}
                                    }).detach();
                                } else {
                                    SafeCrashLog(L"[ProcessScan] Allow (no rule hit, PE score=" +
                                                 std::to_wstring(heur.score) + L"): " + dosPath);
                                    decision.Action = YX_ACTION_ALLOW;
                                }
                            }
                        }
                    } else {
                        // 进程启动扫描未开启：放行
                        decision.Action = YX_ACTION_ALLOW;
                    }
                }

                // 回复决策给内核（必须回复，否则内核等待超时）
                // 注意：不能用 sizeof(reply)，因为 ReplyBuf 含编译器填充，
                // 会导致 FilterReplyMessage 向驱动发送超过 sizeof(YX_DECISION) 的数据，
                // 驱动侧 FltSendMessage 因缓冲区不足返回 STATUS_BUFFER_OVERFLOW
                // （用户态表现为 HRESULT 0x800700EA = ERROR_MORE_DATA）。
                FILTER_REPLY_HEADER replyHdr;
                replyHdr.MessageId = hdr->MessageId;
                replyHdr.Status = (decision.Action == YX_ACTION_BLOCK) ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;

#pragma pack(push, 8)
                struct ReplyBuf {
                    FILTER_REPLY_HEADER hdr;
                    YX_DECISION decision;
                } reply;
#pragma pack(pop)
                reply.hdr = replyHdr;
                reply.decision = decision;

                DWORD replySize = sizeof(FILTER_REPLY_HEADER) + sizeof(YX_DECISION);
                HRESULT repHr = FilterReplyMessage(m_filterPort,
                    (PFILTER_REPLY_HEADER)&reply, replySize);
                if (!SUCCEEDED(repHr)) {
                    SafeCrashLog(L"[DriverMsg] ProcessCreate reply failed hr=0x" +
                        std::to_wstring(static_cast<unsigned long>(repHr)) +
                        L" replySize=" + std::to_wstring(replySize) +
                        L" sizeof(reply)=" + std::to_wstring(sizeof(reply)) +
                        L" sizeof(FILTER_REPLY_HEADER)=" + std::to_wstring(sizeof(FILTER_REPLY_HEADER)) +
                        L" sizeof(YX_DECISION)=" + std::to_wstring(sizeof(YX_DECISION)));
                }
                continue;
            }

            // ---- 普通事件：评估规则 ----
            yx::Event e;
            e.type = (int)ev->Type;
            e.pid = ev->ProcessId;
            e.parentPid = ev->ParentProcessId;
            e.targetPid = ev->TargetProcessId;
            e.timestamp = ev->Timestamp;
            e.name0 = ev->Name0 ? ev->Name0 : L"";
            e.name1 = ev->Name1 ? ev->Name1 : L"";
            e.name2 = ev->Name2 ? ev->Name2 : L"";

            YX_DECISION decision{ 0 };
            decision.EventId = ev->Timestamp;

            std::optional<yx::RuleHit> hit;
            try {
                hit = m_rules.Evaluate(e);
            } catch (const std::exception& ex) {
                std::string m = ex.what();
                SafeCrashLog(L"[DriverMsg] Rule evaluate exception type=" + std::to_wstring(e.type) +
                    L" what=" + std::wstring(m.begin(), m.end()));
            } catch (...) {
                SafeCrashLog(L"[DriverMsg] Rule evaluate unknown exception type=" + std::to_wstring(e.type));
            }

            if (hit) {
                try {
                    HandleThreat(*hit);
                } catch (const std::exception& ex) {
                    std::string m = ex.what();
                    SafeCrashLog(L"[DriverMsg] HandleThreat exception: " + std::wstring(m.begin(), m.end()));
                } catch (...) {
                    SafeCrashLog(L"[DriverMsg] HandleThreat unknown exception");
                }
                decision.Action = YX_ACTION_BLOCK;
            } else {
                decision.Action = YX_ACTION_ALLOW;
            }

            // 回复决策（即使是 ALLOW 也要回复，否则内核超时）
            FILTER_REPLY_HEADER replyHdr;
            replyHdr.MessageId = hdr->MessageId;
            replyHdr.Status = (decision.Action == YX_ACTION_BLOCK) ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;

#pragma pack(push, 8)
            struct ReplyBuf {
                FILTER_REPLY_HEADER hdr;
                YX_DECISION decision;
            } reply;
#pragma pack(pop)
            reply.hdr = replyHdr;
            reply.decision = decision;

            DWORD replySize = sizeof(FILTER_REPLY_HEADER) + sizeof(YX_DECISION);
            HRESULT repHr = FilterReplyMessage(m_filterPort,
                (PFILTER_REPLY_HEADER)&reply, replySize);
            if (!SUCCEEDED(repHr) && recvCount <= 20) {
                SafeCrashLog(L"[DriverMsg] FilterReplyMessage failed hr=0x" +
                    std::to_wstring(static_cast<unsigned long>(repHr)) +
                    L" replySize=" + std::to_wstring(replySize) +
                    L" sizeof(reply)=" + std::to_wstring(sizeof(reply)));
            }
        } catch (const std::exception& ex) {
            std::string m = ex.what();
            SafeCrashLog(L"[DriverMsg] Event process exception type=" +
                std::to_wstring((int)ev->Type) +
                L" what=" + std::wstring(m.begin(), m.end()));
        } catch (...) {
            SafeCrashLog(L"[DriverMsg] Event process unknown exception type=" +
                std::to_wstring((int)ev->Type));
        }
    }
    SafeCrashLog(L"[DriverMsg] Thread exit recv=" + std::to_wstring(recvCount));
}

// 监控线程：本地行为监控（计划任务/网络等用户态可观测部分）
void ProtectionService::MonitorThreadProc() {
    SafeCrashLog(L"[Monitor] Thread start tid=" + std::to_wstring(GetCurrentThreadId()));
    int tick = 0;
    ULONG64 netPolls = 0, schPolls = 0;
    while (m_running) {
        try {
            Sleep(1000);
            tick++;
            if (m_settings.networkProtect && tick % 3 == 0) {
                try {
                    netPolls++;
                    PollNetworkConnections();
                } catch (const std::exception& ex) {
                    std::string m = ex.what();
                    SafeCrashLog(L"[Monitor] PollNetworkConnections exception: " + std::wstring(m.begin(), m.end()));
                } catch (...) {
                    SafeCrashLog(L"[Monitor] PollNetworkConnections unknown exception");
                }
            }
            if (m_settings.scheduleProtect && tick % 10 == 0) {
                try {
                    schPolls++;
                    PollScheduledTasks();
                } catch (const std::exception& ex) {
                    std::string m = ex.what();
                    SafeCrashLog(L"[Monitor] PollScheduledTasks exception: " + std::wstring(m.begin(), m.end()));
                } catch (...) {
                    SafeCrashLog(L"[Monitor] PollScheduledTasks unknown exception");
                }
            }
        } catch (const std::exception& ex) {
            std::string m = ex.what();
            SafeCrashLog(L"[Monitor] Loop exception: " + std::wstring(m.begin(), m.end()));
            Sleep(1000);
        } catch (...) {
            SafeCrashLog(L"[Monitor] Loop unknown exception");
            Sleep(1000);
        }
    }
    SafeCrashLog(L"[Monitor] Thread exit net=" + std::to_wstring(netPolls) +
        L" sch=" + std::to_wstring(schPolls));
}

// 轮询网络连接：检测是否连接到已知 C2
void ProtectionService::PollNetworkConnections() {
    MIB_TCPTABLE_OWNER_MODULE* table = nullptr;
    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                   TCP_TABLE_OWNER_MODULE_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER) return;

    table = (MIB_TCPTABLE_OWNER_MODULE*)malloc(size);
    if (!table) return;

    rc = GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                             TCP_TABLE_OWNER_MODULE_ALL, 0);
    if (rc != NO_ERROR) {
        free(table);
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

        DWORD remoteIp = row.dwRemoteAddr;
        in_addr addr;
        addr.s_addr = remoteIp;
        char ipStr[INET_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));

        std::wstring ip = std::wstring(ipStr, ipStr + strlen(ipStr));
        if (m_rules.IsYinHuC2(ip)) {
            yx::Event e;
            e.type = 40; // YX_EVENT_NET_CONNECT
            e.pid = row.dwOwningPid;
            e.name2 = ip;
            HandleEvent(e);
        }
    }
    free(table);
}

// 检查签名者证书主体是否为微软
static bool CertIsMicrosoft(PCCERT_CONTEXT cert) {
    if (!cert) return false;
    wchar_t nameBuf[256] = { 0 };
    if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                           nullptr, nameBuf, 256) > 1) {
        std::wstring name(nameBuf);
        std::wstring lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                       [](wchar_t c) { return (wchar_t)towlower(c); });
        if (lowerName.find(L"microsoft") != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

// 检查文件是否带有有效的微软官方数字签名
// 同时验证嵌入签名 和 系统 CAT 目录签名（如 notepad.exe 等无嵌入签名但在系统目录里的文件）
static bool IsMicrosoftSigned(const std::wstring& filePath) {
    if (filePath.empty()) return false;

    // ---- 1. 嵌入签名验证（PKCS#7 embedded signature）----
    WINTRUST_FILE_INFO fileInfo{ sizeof(WINTRUST_FILE_INFO) };
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData{ sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &trustData);
    bool trustOk = (status == ERROR_SUCCESS);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trustData);

    if (trustOk) {
        // 签名链有效，取出签名者证书检查是否为微软
        HCERTSTORE hStore = nullptr;
        HCRYPTMSG hMsg = nullptr;
        BOOL ok = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, filePath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr,
            &hStore, &hMsg, nullptr);
        if (ok && hStore && hMsg) {
            bool isMicrosoft = false;
            DWORD signerInfoSize = 0;
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) {
                std::vector<BYTE> signerBuf(signerInfoSize);
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerBuf.data(), &signerInfoSize)) {
                    auto* si = (CMSG_SIGNER_INFO*)signerBuf.data();
                    CERT_INFO ci{};
                    ci.Issuer = si->Issuer;
                    ci.SerialNumber = si->SerialNumber;
                    PCCERT_CONTEXT cert = CertFindCertificateInStore(
                        hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                        CERT_FIND_SUBJECT_CERT, &ci, nullptr);
                    if (cert) {
                        isMicrosoft = CertIsMicrosoft(cert);
                        CertFreeCertificateContext(cert);
                    }
                }
            }
            CertCloseStore(hStore, 0);
            CryptMsgClose(hMsg);
            if (isMicrosoft) return true;
        }
    }

    // ---- 2. CAT 目录签名验证（系统目录签名库）----
    // 很多 Windows 系统文件没有嵌入签名，而是在系统 CAT 目录中签名
    // 使用 CryptCATAdmin* API 查找文件对应的目录签名
    HCATADMIN hCatAdmin = nullptr;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0)) {
        return false;
    }

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    DWORD hashLen = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, nullptr, 0);
    if (hashLen == 0) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    std::vector<BYTE> hash(hashLen, 0);
    BOOL hashOk = CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash.data(), 0);
    CloseHandle(hFile);
    if (!hashOk) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    // 枚举包含该哈希的目录
    bool isMicrosoft = false;
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
        hCatAdmin, hash.data(), hashLen, 0, nullptr);

    if (hCatInfo) {
        CATALOG_INFO catInfo{};
        catInfo.cbStruct = sizeof(CATALOG_INFO);
        if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            // 验证目录文件本身的签名
            WINTRUST_FILE_INFO catFileInfo{ sizeof(WINTRUST_FILE_INFO) };
            catFileInfo.pcwszFilePath = catInfo.wszCatalogFile;

            WINTRUST_DATA catTrustData{ sizeof(WINTRUST_DATA) };
            catTrustData.dwUIChoice = WTD_UI_NONE;
            catTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            catTrustData.dwUnionChoice = WTD_CHOICE_FILE;
            catTrustData.pFile = &catFileInfo;
            catTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
            catTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

            GUID catAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG catStatus = WinVerifyTrust(nullptr, &catAction, &catTrustData);
            bool catTrustOk = (catStatus == ERROR_SUCCESS);
            catTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &catAction, &catTrustData);

            if (catTrustOk) {
                // 取出目录签名者证书，检查是否为微软
                HCERTSTORE catStore = nullptr;
                HCRYPTMSG catMsg = nullptr;
                BOOL catOk = CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE, catInfo.wszCatalogFile,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr,
                    &catStore, &catMsg, nullptr);
                if (catOk && catStore && catMsg) {
                    DWORD signerInfoSize = 0;
                    if (CryptMsgGetParam(catMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) {
                        std::vector<BYTE> signerBuf(signerInfoSize);
                        if (CryptMsgGetParam(catMsg, CMSG_SIGNER_INFO_PARAM, 0, signerBuf.data(), &signerInfoSize)) {
                            auto* si = (CMSG_SIGNER_INFO*)signerBuf.data();
                            CERT_INFO ci{};
                            ci.Issuer = si->Issuer;
                            ci.SerialNumber = si->SerialNumber;
                            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                                catStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                CERT_FIND_SUBJECT_CERT, &ci, nullptr);
                            if (cert) {
                                isMicrosoft = CertIsMicrosoft(cert);
                                CertFreeCertificateContext(cert);
                            }
                        }
                    }
                    CertCloseStore(catStore, 0);
                    CryptMsgClose(catMsg);
                }
            }
        }
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    }

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return isMicrosoft;
}

// 带缓存的微软签名验证：同一文件只调用一次 WinVerifyTrust，结果缓存到 m_signCache
// 注意：缓存 key 使用小写 DOS 路径，路径需先通过 DevicePathToDosPath 转换
bool ProtectionService::IsMicrosoftSignedCached(const std::wstring& dosPath) {
    if (dosPath.empty()) return false;

    // 统一小写作为缓存 key
    std::wstring key = dosPath;
    std::transform(key.begin(), key.end(), key.begin(), ::towlower);

    {
        std::lock_guard<std::mutex> lk(m_signCacheMutex);
        auto it = m_signCache.find(key);
        if (it != m_signCache.end()) {
            return it->second;
        }
    }

    // 缓存未命中，执行实际验签
    bool result = IsMicrosoftSigned(dosPath);

    {
        std::lock_guard<std::mutex> lk(m_signCacheMutex);
        m_signCache[key] = result;
    }

    SafeCrashLog(L"[SignCheck] path=" + dosPath +
                 L" result=" + (result ? L"Microsoft signed" : L"not Microsoft signed"));
    return result;
}

// 从任务执行命令行中提取可执行文件路径
static std::wstring ExtractExePath(const std::wstring& taskToRun) {
    std::wstring s = taskToRun;
    while (!s.empty() && s.front() == L' ') s.erase(s.begin());
    if (s.empty()) return s;

    // 有引号：取引号内的路径
    if (s.front() == L'"') {
        size_t end = s.find(L'"', 1);
        if (end != std::wstring::npos) {
            return s.substr(1, end - 1);
        }
    }

    // 无引号但路径可能含空格（如 schtasks CSV 输出不加引号的情况）
    // 策略：找到第一个可执行扩展名，截取到该扩展名结束
    static const wchar_t* exts[] = {
        L".exe", L".bat", L".cmd", L".ps1", L".vbs",
        L".js", L".wsh", L".msi", L".scr", L".com", L".pif", nullptr
    };
    std::wstring lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    size_t bestEnd = std::wstring::npos;
    for (int i = 0; exts[i]; i++) {
        size_t pos = lower.find(exts[i]);
        if (pos != std::wstring::npos) {
            size_t end = pos + wcslen(exts[i]);
            if (bestEnd == std::wstring::npos || end < bestEnd) {
                bestEnd = end;
            }
        }
    }
    if (bestEnd != std::wstring::npos) {
        return s.substr(0, bestEnd);
    }

    // 找不到可执行扩展名，回退：取第一个空格前
    size_t sp = s.find(L' ');
    if (sp != std::wstring::npos) s = s.substr(0, sp);
    return s;
}

// 简单 CSV 行解析（支持引号转义）
static std::vector<std::wstring> ParseCsvLine(const std::wstring& line) {
    std::vector<std::wstring> fields;
    std::wstring cur;
    bool inQuote = false;
    for (size_t i = 0; i < line.size(); i++) {
        wchar_t c = line[i];
        if (c == L'"') {
            if (inQuote && i + 1 < line.size() && line[i + 1] == L'"') {
                cur += L'"';
                i++;
            } else {
                inQuote = !inQuote;
            }
        } else if (c == L',' && !inQuote) {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    fields.push_back(cur);
    return fields;
}

// 轮询计划任务：检测是否有银狐伪装任务
// 使用 CreateProcessW + 隐藏窗口 + 管道重定向，避免 CMD 黑窗弹出
// 维护已报任务集合，避免刷屏
// 对命中关键词的任务，验证其执行程序的数字签名；微软官方签名的正版任务放过
void ProtectionService::PollScheduledTasks() {
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;

    STARTUPINFOW si{ sizeof(STARTUPINFOW) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"schtasks.exe /query /v /fo csv /nh";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');

    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);

    if (!ok) {
        CloseHandle(hRead);
        return;
    }

    std::string output;
    char readBuf[4096];
    DWORD bytesRead = 0;
    while (ReadFile(hRead, readBuf, sizeof(readBuf), &bytesRead, nullptr) && bytesRead > 0) {
        output.append(readBuf, bytesRead);
    }

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // schtasks /v csv 的列：第 2 列是 TaskName，第 9 列（索引 8）是 Task To Run
    std::string line;
    for (char c : output) {
        if (c == '\r') continue;
        if (c == '\n') {
            if (!line.empty()) {
                // schtasks.exe 输出是系统代码页（中文系统为 GBK），
                // 必须用 MultiByteToWideChar(CP_ACP) 转 UTF-16，
                // 不能直接 string->wstring 逐字节拷贝（中文会乱码）
                int wlen = MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, nullptr, 0);
                std::wstring wline(wlen > 0 ? wlen - 1 : 0, L'\0');
                if (wlen > 0) {
                    MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, &wline[0], wlen);
                }
                auto fields = ParseCsvLine(wline);
                if (fields.size() >= 9) {
                    std::wstring taskName = fields[1];
                    std::wstring taskToRun = fields[8];

                    if (m_reportedTasks.count(taskName) == 0 &&
                        m_rules.IsYinHuTaskName(taskName)) {
                        m_reportedTasks.insert(taskName);

                        std::wstring exePath = ExtractExePath(taskToRun);

                        // 文件不存在：可能是 Edge 卸载后残留的任务，
                        // 也可能是恶意程序已被删除。不尝试隔离文件（必失败），
                        // 但仍上报事件，由处置逻辑删除计划任务本身。
                        std::error_code ec;
                        bool fileExists = fs::exists(exePath, ec);

                        if (fileExists) {
                            // 文件存在：微软签名的正版任务放过（如真正的 Edge 更新）
                            if (IsMicrosoftSigned(exePath)) {
                                continue;
                            }
                        } else {
                            SafeCrashLog(L"[Sched] Task target file not exist, task=" +
                                         taskName + L" path=" + exePath);
                        }

                        yx::Event e;
                        e.type = 30;
                        e.name0 = exePath;
                        e.name2 = taskName;
                        HandleEvent(e);
                    }
                }
            }
            line.clear();
        } else {
            line += c;
        }
    }
}

} // namespace yx
