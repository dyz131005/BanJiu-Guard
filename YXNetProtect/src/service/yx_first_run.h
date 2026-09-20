// BanJiu-Guard - 首次运行引导 & 测试模式管理
// 实现需求：
//  1. 检测注册表"是否运行过"标记
//  2. 首次运行：检测测试签名模式，未开启则弹提示询问
//  3. 用户同意 -> 写标记 + bcdedit /set testsigning on + 提示重启
//  4. 用户拒绝 -> 仅写"已运行"标记，进入用户态-only 模式
//  5. 之后可在设置里点击"启用完全防护"重新触发
#pragma once

#include <windows.h>
#include <string>

namespace yx {

// 首次运行 / 测试模式管理
class FirstRunManager {
public:
    // 注册表键路径
    static constexpr const wchar_t* kRegKey = L"Software\\BanJiu-Guard";
    static constexpr const wchar_t* kRegValueRan = L"HasRunBefore";
    static constexpr const wchar_t* kRegValueTestSigning = L"TestSigningEnabled";

    // 是否曾经运行过
    static bool HasRunBefore();

    // 标记已运行过
    static bool MarkHasRun();

    // 检测测试签名模式是否开启（读 BCD 配置）
    static bool IsTestSigningEnabled();

    // 启用测试签名模式（bcdedit /set testsigning on），成功返回 true
    static bool EnableTestSigning();

    // 禁用测试签名模式
    static bool DisableTestSigning();

    // 检查是否以管理员权限运行
    static bool IsElevated();

    // 开机自启管理（通过任务计划程序，ONSTART 触发，SYSTEM 身份，所有用户级别）
    static constexpr const wchar_t* kTaskName = L"BanJiu-Guard";
    static bool IsAutoStartEnabled();
    // errMsg 接收失败时的详细错误信息（含 Win32 错误码和描述）
    static bool EnableAutoStart(const std::wstring& exePath, std::wstring& errMsg);
    static bool DisableAutoStart(std::wstring& errMsg);
};

} // namespace yx
