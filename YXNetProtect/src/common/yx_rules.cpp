// BanJiu-Guard - 行为规则引擎实现
#include "yx_rules.h"
#include <cwctype>
#include <algorithm>

namespace yx {

static std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return std::towlower(c); });
    return s;
}

static bool Has(const std::wstring& hay, const std::wstring& needle) {
    return hay.find(needle) != std::wstring::npos;
}

static std::wstring BaseName(const std::wstring& p) {
    auto pos = p.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return p;
    return p.substr(pos + 1);
}

RulesEngine::RulesEngine() = default;

std::wstring RulesEngine::FileNameFromPath(const std::wstring& p) { return BaseName(p); }
std::wstring RulesEngine::ToLower(std::wstring s) { return Lower(std::move(s)); }
bool RulesEngine::Contains(const std::wstring& hay, const std::wstring& needle) { return Has(hay, needle); }

bool RulesEngine::IsYinHuC2(const std::wstring& ipOrDomain) const {
    for (auto* ip : kYinHuC2Ips) {
        if (ip && Has(ipOrDomain, ip)) return true;
    }
    return false;
}

bool RulesEngine::IsYinHuTaskName(const std::wstring& taskName) const {
    auto t = Lower(taskName);
    for (auto* p : kYinHuTaskNamePatterns) {
        if (p && Has(t, Lower(p))) return true;
    }
    return false;
}

bool RulesEngine::IsVulnerableDriver(const std::wstring& driverPath) const {
    auto d = Lower(driverPath);
    for (auto* p : kYinHuVulnerableDrivers) {
        if (p && Has(d, Lower(p))) return true;
    }
    return false;
}

bool RulesEngine::IsInjectionTarget(const std::wstring& processName) const {
    auto n = Lower(processName);
    for (auto* p : kYinHuInjectionTargets) {
        if (p && n == Lower(p)) return true;
    }
    return false;
}

bool RulesEngine::IsMemzName(const std::wstring& fileName) const {
    auto n = Lower(fileName);
    for (auto* p : kMemzNamePatterns) {
        if (p && Has(n, Lower(p))) return true;
    }
    return false;
}

std::optional<RuleHit> RulesEngine::CheckMd5(const std::wstring& md5Lower, const std::wstring& path) {
    auto h = Lower(md5Lower);
    for (auto* md5 : kMemzMd5Iocs) {
        if (md5 && h == Lower(md5)) {
            RuleHit hit;
            hit.category = RuleCategory::MalwareHash;
            hit.level = ThreatLevel::Critical;
            hit.description = L"命中 MEMZ 彩虹猫病毒已知样本特征 (MD5)";
            hit.subject = path;
            return hit;
        }
    }
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::CheckHash(const std::wstring& sha1Lower, const std::wstring& path) {
    auto h = Lower(sha1Lower);
    for (const auto& ioc : kYinHuSha1Iocs) {
        if (ioc.sha1 && h == Lower(ioc.sha1)) {
            RuleHit hit;
            hit.category = RuleCategory::MalwareHash;
            hit.level = ThreatLevel::Critical;
            hit.description = L"命中银狐木马已知样本特征 (SHA1)：" + std::wstring(ioc.name);
            hit.subject = path;
            return hit;
        }
    }
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::Evaluate(const Event& ev) {
    switch (ev.type) {
        case 12: return OnImageLoad(ev);      // YX_EVENT_IMAGE_LOAD
        case 10: return OnProcessCreate(ev);  // YX_EVENT_PROCESS_CREATE
        case 20:
        case 21: return OnRegistryWrite(ev);
        case 30: return OnTaskSchedule(ev);
        case 40: return OnNetConnect(ev);
        case 50: return OnThreadCreate(ev);
        case 60: return OnDriverLoad(ev);
        case 1:
        case 2:
        case 3:
        case 4: return OnFileEvent(ev);
        default: return std::nullopt;
    }
}

// 映像加载：白加黑 DLL 侧加载检测（银狐核心攻击手法）
// 简化判定：加载的 DLL 名称命中银狐黑 DLL 名；或命中已知黑名单。
std::optional<RuleHit> RulesEngine::OnImageLoad(const Event& ev) {
    std::wstring dllName = BaseName(ev.name1.empty() ? ev.name0 : ev.name1);
    auto dn = Lower(dllName);

    // 已知银狐侧加载黑 DLL
    for (auto* p : kYinHuNamePatterns) {
        if (p && dn == Lower(p)) {
            RuleHit hit;
            hit.category = RuleCategory::YinHuDllSideLoad;
            hit.level = ThreatLevel::Critical;
            hit.description = L"检测到银狐木马白加黑 DLL 侧加载：" + dllName;
            hit.subject = ev.name0;
            hit.object = dllName;
            return hit;
        }
    }
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::OnProcessCreate(const Event& ev) {
    std::wstring pname = BaseName(ev.name0);
    // 银狐注入宿主进程被可疑拉起可作为弱信号，此处不误报，仅记录等级低
    (void)pname;
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::OnRegistryWrite(const Event& ev) {
    std::wstring key = Lower(ev.name0);
    std::wstring val = Lower(ev.name1);
    std::wstring proc = Lower(ev.processPath);

    // 1. 自启动持久化：Run / RunOnce / RunServices 等
    bool isAutoStart =
        Has(key, L"\\run") || Has(key, L"runonce") || Has(key, L"runservices") ||
        Has(key, L"\\policies\\explorer\\run") ||
        Has(key, L"\\windows\\currentversion\\run");

    // 2. 系统核心持久化：Winlogon（Userinit、Shell、Notify）、IFEO、AppInit_DLLs
    bool isSystemCore =
        Has(key, L"\\winlogon") ||
        Has(key, L"image file execution options") ||
        Has(key, L"appinit_dlls") ||
        Has(key, L"\\session manager\\appcertdlls") ||
        Has(key, L"\\session manager\\subsystems") ||
        Has(key, L"\\windows nt\\currentversion\\windows");

    // 3. 服务 / 驱动注册：修改或创建系统服务
    bool isServiceKey = Has(key, L"\\system\\currentcontrolset\\services\\");

    // 4. 安全中心 / 防火墙 / Defender 关闭
    bool isSecurityDisable =
        Has(key, L"\\windows defender") ||
        Has(key, L"\\sharedaccess") ||
        Has(key, L"security center") ||
        Has(key, L"\\policies\\microsoft\\windows defender");

    // 对可疑进程写入这些关键位置直接判定为威胁
    // 可疑进程特征：位于临时目录、下载目录、桌面、压缩包解压路径等
    bool procSuspicious =
        !proc.empty() && (
            Has(proc, L"\\temp") ||
            Has(proc, L"appdata\\local\\temp") ||
            Has(proc, L"\\downloads") ||
            Has(proc, L"\\desktop") ||
            Has(proc, L"\\appdata\\local\\") ||
            Has(proc, L"\\programdata\\") ||
            Has(proc, L".zip") || Has(proc, L".rar") || Has(proc, L".7z") ||
            Has(proc, L"\\recycle.bin"));

    // 对系统核心注册表的写入始终告警（无论进程来源，避免合法安装也误伤，
    // 这里仅对非微软签名进程判定——规则引擎层无法验签，交由可疑进程特征+系统核心组合判定）
    if (isSystemCore) {
        RuleHit hit;
        hit.category = RuleCategory::Heuristic;
        hit.level = ThreatLevel::High;
        hit.description = L"检测到对系统核心注册表项的修改（持久化/劫持风险）";
        hit.subject = ev.processPath.empty() ? ev.name0 : ev.processPath;
        hit.object = ev.name0 + L" = " + ev.name1;
        hit.protectedObject = true;  // 注册表不是可删除文件，只处置修改者进程
        return hit;
    }

    if (isAutoStart) {
        RuleHit hit;
        hit.category = RuleCategory::YinHuTaskPersist;
        hit.level = ThreatLevel::High;
        hit.description = L"检测到注册表自启动项写入（持久化行为）";
        hit.subject = ev.processPath;
        hit.object = ev.name1;
        hit.protectedObject = true;  // 注册表项，不做文件删除
        return hit;
    }

    if (isServiceKey) {
        // 创建/修改服务：若进程可疑则告警
        if (procSuspicious) {
            RuleHit hit;
            hit.category = RuleCategory::Heuristic;
            hit.level = ThreatLevel::High;
            hit.description = L"可疑进程创建/修改系统服务（驱动级持久化风险）";
            hit.subject = ev.processPath;
            hit.object = ev.name0;
            hit.protectedObject = true;  // 服务注册表项，不做文件删除
            return hit;
        }
    }

    if (isSecurityDisable) {
        RuleHit hit;
        hit.category = RuleCategory::Heuristic;
        hit.level = ThreatLevel::Critical;
        hit.description = L"检测到修改安全软件/防火墙设置（可能为关闭防护）";
        hit.subject = ev.processPath;
        hit.object = ev.name0;
        hit.protectedObject = true;  // 安全设置注册表项，不做文件删除
        return hit;
    }

    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::OnTaskSchedule(const Event& ev) {
    // 计划任务持久化：命中银狐伪装任务名
    if (IsYinHuTaskName(ev.name2.empty() ? ev.name0 : ev.name2)) {
        RuleHit hit;
        hit.category = RuleCategory::YinHuTaskPersist;
        hit.level = ThreatLevel::Critical;
        hit.description = L"检测到伪装成 Edge 更新的计划任务（银狐持久化特征）";
        hit.subject = ev.name0;
        hit.object = ev.name2;
        return hit;
    }
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::OnNetConnect(const Event& ev) {
    if (IsYinHuC2(ev.name2.empty() ? ev.name0 : ev.name2)) {
        RuleHit hit;
        hit.category = RuleCategory::YinHuC2;
        hit.level = ThreatLevel::Critical;
        hit.description = L"检测到连接银狐木马 C2 服务器";
        hit.subject = ev.processPath;
        hit.object = ev.name2;
        return hit;
    }
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::OnThreadCreate(const Event& ev) {
    // 远程线程注入检测：目标是被注入的系统进程
    std::wstring target = BaseName(ev.name0);
    if (IsInjectionTarget(target)) {
        RuleHit hit;
        hit.category = RuleCategory::YinHuProcessInject;
        hit.level = ThreatLevel::Critical;
        hit.description = L"检测到向系统进程注入远程线程（银狐进程注入特征）";
        hit.subject = ev.processPath;
        hit.object = target;
        return hit;
    }
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::OnDriverLoad(const Event& ev) {
    if (IsVulnerableDriver(ev.name0)) {
        RuleHit hit;
        hit.category = RuleCategory::YinHuByovd;
        hit.level = ThreatLevel::Critical;
        hit.description = L"检测到加载易受攻击驱动（BYOVD 银狐特征）";
        hit.subject = ev.name0;
        return hit;
    }
    return std::nullopt;
}

std::optional<RuleHit> RulesEngine::OnFileEvent(const Event& ev) {
    std::wstring name = BaseName(ev.name0);
    std::wstring path = Lower(ev.name0);
    std::wstring proc = Lower(ev.processPath);

    // MEMZ 彩虹猫病毒文件名特征
    if (IsMemzName(name)) {
        RuleHit hit;
        hit.category = RuleCategory::Heuristic;
        hit.level = ThreatLevel::Critical;
        hit.description = L"命中 MEMZ 彩虹猫病毒文件名特征（Deltree Trojan）";
        hit.subject = ev.name0;
        return hit;
    }

    // 文件命中银狐文件名特征
    for (auto* p : kYinHuNamePatterns) {
        if (p && Has(Lower(name), Lower(p))) {
            RuleHit hit;
            hit.category = RuleCategory::MalwareHash; // 近似：文件名特征
            hit.level = ThreatLevel::High;
            hit.description = L"命中银狐木马文件名特征：" + name;
            hit.subject = ev.name0;
            return hit;
        }
    }

    // ---------- 系统文件保护 ----------
    // 关键系统目录：System32、SysWOW64、drivers\etc（hosts）、Boot 目录
    bool isSystemPath =
        Has(path, L"\\windows\\system32\\") ||
        Has(path, L"\\windows\\syswow64\\") ||
        Has(path, L"\\windows\\system32\\drivers\\") ||
        Has(path, L"\\windows\\boot\\") ||
        Has(path, L"\\efi\\") ||
        Has(path, L"\\boot\\");

    // hosts 文件单独标记
    bool isHostsFile =
        Has(path, L"\\drivers\\etc\\hosts") ||
        Lower(name) == L"hosts";

    // 系统可执行文件被覆盖/删除（.exe/.dll/.sys 在系统目录下）
    bool isSystemBinary = isSystemPath && (
        Has(Lower(name), L".exe") || Has(Lower(name), L".dll") ||
        Has(Lower(name), L".sys") || Has(Lower(name), L".drv"));

    // 可疑进程写入系统文件判定为威胁
    // 可疑进程特征：临时目录、下载目录、桌面、非系统盘等
    bool procSuspicious = !proc.empty() && (
        Has(proc, L"\\temp") ||
        Has(proc, L"\\downloads") ||
        Has(proc, L"\\desktop") ||
        Has(proc, L"\\appdata\\local\\temp") ||
        Has(proc, L"\\recycle.bin") ||
        Has(proc, L".zip") || Has(proc, L".rar") || Has(proc, L".7z"));

    // 排除系统进程（system、svchost、csrss 等系统进程名小写包含 system）
    bool isSystemProcess = !proc.empty() && (
        Has(proc, L"\\windows\\system32\\") ||
        Has(proc, L"\\windows\\syswow64\\") ||
        Lower(BaseName(proc)) == L"system" ||
        Lower(BaseName(proc)) == L"svchost.exe" ||
        Lower(BaseName(proc)) == L"csrss.exe" ||
        Lower(BaseName(proc)) == L"wininit.exe" ||
        Lower(BaseName(proc)) == L"winlogon.exe" ||
        Lower(BaseName(proc)) == L"services.exe" ||
        Lower(BaseName(proc)) == L"lsass.exe");

    if (isHostsFile && !isSystemProcess) {
        RuleHit hit;
        hit.category = RuleCategory::Heuristic;
        hit.level = ThreatLevel::Critical;
        hit.description = L"检测到修改 hosts 文件（可能用于域名劫持或屏蔽安全软件）";
        hit.subject = ev.processPath;
        hit.object = ev.name0;
        hit.protectedObject = true;  // hosts 是系统文件，只能处置修改者，不能删除 hosts
        return hit;
    }

    if (isSystemBinary && procSuspicious && !isSystemProcess) {
        RuleHit hit;
        hit.category = RuleCategory::Heuristic;
        hit.level = ThreatLevel::Critical;
        hit.description = L"可疑进程写入系统目录可执行文件（系统文件篡改风险）";
        hit.subject = ev.processPath;
        hit.object = ev.name0;
        hit.protectedObject = true;  // system32 下的 exe/dll/sys 是系统文件，不能删除
        return hit;
    }

    // 启动目录写入（Startup 文件夹持久化）
    bool isStartupDir =
        Has(path, L"\\microsoft\\windows\\start menu\\programs\\startup") ||
        Has(path, L"\\startup\\");

    if (isStartupDir && !isSystemProcess) {
        RuleHit hit;
        hit.category = RuleCategory::Heuristic;
        hit.level = ThreatLevel::High;
        hit.description = L"检测到向启动目录写入文件（开机自启持久化）";
        hit.subject = ev.processPath;
        hit.object = ev.name0;
        return hit;
    }

    return std::nullopt;
}

} // namespace yx
