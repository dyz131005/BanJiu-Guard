// BanJiu-Guard - 行为规则引擎（用户态）
// 声明：负责将内核上报的事件与银狐特征库比对，产出 RuleHit。
#pragma once

#include <string>
#include <vector>
#include <optional>
#include "yx_yinhu_db.h"

namespace yx {

// 事件（从内核 YX_EVENT 转化而来的用户态结构，便于处理）
struct Event {
    int          type = 0;          // YX_EVENT_TYPE
    uint32_t     pid = 0;
    uint32_t     parentPid = 0;
    uint32_t     targetPid = 0;
    uint64_t     timestamp = 0;
    std::wstring name0;             // 主体路径
    std::wstring name1;             // 客体/目标路径
    std::wstring name2;             // 附加（C2/IP/任务名）
    std::wstring processPath;       // 进程完整路径（解析出）
    std::wstring parentPath;
};

// 已认证白名单进程（带签名的系统进程等）
class RulesEngine {
public:
    RulesEngine();

    // 判定一个事件是否命中银狐/恶意特征
    // 返回 optional：命中 -> 有值；未命中 -> nullopt
    std::optional<RuleHit> Evaluate(const Event& ev);

    // 仅做哈希查库（用于扫描器）
    std::optional<RuleHit> CheckHash(const std::wstring& sha1Lower, const std::wstring& path);

    // 仅做 MD5 查库（用于扫描器）
    std::optional<RuleHit> CheckMd5(const std::wstring& md5Lower, const std::wstring& path);

    // 检查 C2 IP
    bool IsYinHuC2(const std::wstring& ipOrDomain) const;

    // 检查银狐伪装任务名
    bool IsYinHuTaskName(const std::wstring& taskName) const;

    // 检查易漏洞驱动名（BYOVD）
    bool IsVulnerableDriver(const std::wstring& driverPath) const;

    // 检查注入目标进程
    bool IsInjectionTarget(const std::wstring& processName) const;

    // 检查 MEMZ 彩虹猫病毒文件名特征
    bool IsMemzName(const std::wstring& fileName) const;

private:
    std::optional<RuleHit> OnImageLoad(const Event& ev);
    std::optional<RuleHit> OnProcessCreate(const Event& ev);
    std::optional<RuleHit> OnRegistryWrite(const Event& ev);
    std::optional<RuleHit> OnTaskSchedule(const Event& ev);
    std::optional<RuleHit> OnNetConnect(const Event& ev);
    std::optional<RuleHit> OnThreadCreate(const Event& ev);
    std::optional<RuleHit> OnDriverLoad(const Event& ev);
    std::optional<RuleHit> OnFileEvent(const Event& ev);

    static std::wstring FileNameFromPath(const std::wstring& p);
    static std::wstring ToLower(std::wstring s);
    static bool Contains(const std::wstring& hay, const std::wstring& needle);
};

} // namespace yx
