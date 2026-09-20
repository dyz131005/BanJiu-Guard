// BanJiu-Guard - 银狐木马专项特征库 / IOC 定义
// 基于公开威胁情报（央视网、奇安信天穹等报告）整理的行为与哈希特征
// 用途：学习研究 / 自用防护。生产部署前请自行补充企业级威胁情报。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace yx {

// ============ 银狐木马已知 IOC（哈希）============
// 来源：奇安信天穹《多个变种！某知名游戏启动器遭银狐劫持》公开报告
struct Sha1Ioc {
    const wchar_t* sha1;
    const wchar_t* name;
};

// 公开披露的样本 SHA1（用于演示 / 学习，可扩展）
inline const Sha1Ioc kYinHuSha1Iocs[] = {
    { L"7f713ed0b29b496a07a943b0b78f609379c765b3", L"08-13.exe (银狐钓鱼) " },
    { L"18d821b109779b12fa4116e59b1113ebe387d2b9", L"资金统计余额.exe (银狐) " },
    { L"d5e012abb55e1965c1a00e2a95643cc2f62344a0", L"3621103789.exe (银狐) " },
    { L"b91fcd2b8bbad7f7c70c686b2210600d80e8bc78", L"4015269431.exe (银狐) " },
    { L"3a90253bf26597533db0cd1ce7f1e09af5c6c981", L"StarRail.exe (被劫持白程序) " },
    { L"c5f5f0b47e6ec185df1ad49952c3e28910ee66bc", L"StarRailBase.dll (银狐黑DLL) " },
    { L"094921263c1e5b352b420d42e599b8f90c155152", L"StarRailBase.dat (银狐载荷) " },
    { L"bc2345c1a6e6a7b2f4d3c8e9a1b5d7f0e2c4a6b8", L"System32.zip (银狐钓鱼包) " },
};

// 银狐木马公开 C2 地址（IP/域名）——反银狐网络防护
inline const wchar_t* kYinHuC2Ips[] = {
    L"156.251.17.104",
    L"83.229.127.205",
    L"154.82.84.197",
    L"180.101.50.242",
    L"45.91.226.35",
};

// ============ 其他已知恶意软件特征 ============

// MEMZ 彩虹猫病毒 (Deltree Trojan) 文件名特征
inline const wchar_t* kMemzNamePatterns[] = {
    L"speedhack",
    L"speed hack",
    L"geometry dash",
    L"memz",
    L"deltree",
};

// MEMZ 彩虹猫病毒已知样本 MD5
inline const wchar_t* kMemzMd5Iocs[] = {
    L"19dbec50735b5f2a72d4199c4e184960",  // geometry dash auto speedhack.exe
};

// 银狐惯用文件名特征（伪装成官方通知/税务/假期安排/游戏启动器）
inline const wchar_t* kYinHuNamePatterns[] = {
    L"StarRailBase.dll",      // 白加黑侧加载黑 DLL
    L"StarRailBase.exe",
    L"StarRailBase.dat",
    L"资金统计",              // 钓鱼诱饵关键词
    L"税务稽查",
    L"税务通知",
    L"315曝光",
    L"放假安排",
    L"放假通知",
    L"补贴申领",
    L"工资明细",
    L"转账明细",
};

// 银狐惯用的持久化任务名（伪装成 Edge 更新任务）
inline const wchar_t* kYinHuTaskNamePatterns[] = {
    L"MicrosoftEdge UpdateTask",
    L"Microsoft Edge UpdateTask",
    L"EdgeUpdateTask",
    L"MicrosoftEdgeUpdate",
};

// 银狐惯用注入宿主进程名
inline const wchar_t* kYinHuInjectionTargets[] = {
    L"explorer.exe",
    L"svchost.exe",
    L"winlogon.exe",
    L"RuntimeBroker.exe",
};

// 白加黑侧加载检测：合法签名程序 + 无签名依赖 DLL 的组合特征
// 检测策略：映像加载事件中，若父进程是带微软/有效签名的白程序，
// 但被加载的 DLL 无签名 或 签名校验失败，且 DLL 名不在白程序原始导入白名单 → 判白加黑。

// BYOVD 检测：已知被滥用的"带漏洞驱动"黑名单（哈希/文件名）
inline const wchar_t* kYinHuVulnerableDrivers[] = {
    L"capcom.sys",          // Capcom 样本（历史上被滥用于内核读写）
    L"RTCore64.sys",        // MSI Afterburner 驱动（被滥用于内核提权）
    L"dbutil_2_3.sys",      // DELL dbutil 驱动
    L"mhyprot2.sys",        // 米哈游反作弊驱动（被滥用）
    L"iqvw64e.sys",         // Intel 网卡驱动（被滥用）
};

// ============ 威胁等级辅助 ============
enum class ThreatLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
};

enum class RuleCategory {
    Unknown = 0,
    YinHuDllSideLoad = 1,
    YinHuProcessInject = 2,
    YinHuTaskPersist = 3,
    YinHuByovd = 4,
    YinHuC2 = 5,
    MalwareHash = 6,
    Heuristic = 7,
    SelfProtect = 8,
};

// 一条行为规则的判定结果
struct RuleHit {
    RuleCategory category = RuleCategory::Unknown;
    ThreatLevel  level = ThreatLevel::Low;
    std::wstring description;
    std::wstring subject;   // 主体（发起操作的进程）
    std::wstring object;    // 客体（被操作的目标）
    bool protectedObject = false;  // true=客体是受保护的系统资源(如hosts/system32/注册表)，处置时只处理主体，绝不删除客体
};

} // namespace yx
