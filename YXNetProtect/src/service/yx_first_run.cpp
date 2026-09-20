// BanJiu-Guard - 首次运行引导实现
#include "yx_first_run.h"
#include <windows.h>
#include <memory>
#include <vector>
#include <string>

namespace yx {

bool FirstRunManager::HasRunBefore() {
    HKEY hkey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegKey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        return false;
    }
    DWORD v = 0, sz = sizeof(v);
    LONG r = RegQueryValueExW(hkey, kRegValueRan, nullptr, nullptr,
                              (LPBYTE)&v, &sz);
    RegCloseKey(hkey);
    return (r == ERROR_SUCCESS && v == 1);
}

bool FirstRunManager::MarkHasRun() {
    HKEY hkey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hkey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    DWORD v = 1;
    LONG r = RegSetValueExW(hkey, kRegValueRan, 0, REG_DWORD, (LPBYTE)&v, sizeof(v));
    RegCloseKey(hkey);
    return r == ERROR_SUCCESS;
}

bool FirstRunManager::IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev{};
        DWORD sz = 0;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz)) {
            elevated = elev.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated != FALSE;
}

// 检测测试签名模式：运行 bcdedit 查询
bool FirstRunManager::IsTestSigningEnabled() {
    // 通过 bcdedit 输出判断
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return false;

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    std::wstring cmd = L"bcdedit /enum {current}";
    std::vector<wchar_t> c(cmd.begin(), cmd.end());
    c.push_back(0);

    BOOL ok = CreateProcessW(nullptr, c.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) {
        CloseHandle(hRead); CloseHandle(hWrite);
        return false;
    }
    CloseHandle(hWrite);

    // 读全部输出
    std::string output;
    char buf[256];
    DWORD rd = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &rd, nullptr) && rd > 0) {
        output.append(buf, rd);
    }
    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // 查找 testsigning Yes
    return output.find("testsigning") != std::string::npos &&
           output.find("Yes") != std::string::npos;
}

bool FirstRunManager::EnableTestSigning() {
    // bcdedit /set testsigning on
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"bcdedit /set testsigning on";
    std::vector<wchar_t> c(cmd.begin(), cmd.end());
    c.push_back(0);

    BOOL ok = CreateProcessW(nullptr, c.data(), nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return false;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

bool FirstRunManager::DisableTestSigning() {
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"bcdedit /set testsigning off";
    std::vector<wchar_t> c(cmd.begin(), cmd.end());
    c.push_back(0);

    BOOL ok = CreateProcessW(nullptr, c.data(), nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return false;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

// 把 Win32 错误码转为文本
static std::wstring FormatWin32Error(DWORD code) {
    LPWSTR buf = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buf, 0, nullptr);
    std::wstring msg;
    if (len > 0 && buf) {
        msg.assign(buf, len);
        while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n' || msg.back() == L' '))
            msg.pop_back();
        LocalFree(buf);
    }
    return msg;
}

// 执行命令行并返回退出码，可选捕获输出
static DWORD RunCmd(const std::wstring& cmd, std::string* output = nullptr) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (output && !CreatePipe(&hRead, &hWrite, &sa, 0)) return (DWORD)-1;

    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (output) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;
    }
    std::vector<wchar_t> c(cmd.begin(), cmd.end());
    c.push_back(0);

    BOOL ok = CreateProcessW(nullptr, c.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (output) CloseHandle(hWrite);
    if (!ok) {
        if (output) CloseHandle(hRead);
        return (DWORD)-1;
    }

    if (output) {
        char buf[512];
        DWORD rd = 0;
        while (ReadFile(hRead, buf, sizeof(buf), &rd, nullptr) && rd > 0)
            output->append(buf, rd);
        CloseHandle(hRead);
    }

    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
}

bool FirstRunManager::IsAutoStartEnabled() {
    std::wstring cmd = L"schtasks /Query /TN \"" + std::wstring(kTaskName) + L"\"";
    std::string out;
    DWORD code = RunCmd(cmd, &out);
    return code == 0;
}

bool FirstRunManager::EnableAutoStart(const std::wstring& exePath, std::wstring& errMsg) {
    errMsg.clear();
    // 任务在用户登录时触发（ONLOGON），以当前用户身份运行。
    // 必须在用户会话中运行，否则 Session 0 没有桌面，托盘图标无法显示。
    // /IT = 仅当用户登录时运行（交互令牌），确保托盘/窗口能正常显示。
    // /TR 的值需要：外层引号 + 内部 exe 路径用转义引号 \"，这样 schtasks 才能正确解析带空格路径和参数

    // 获取当前用户名（DOMAIN\USERNAME 格式）
    wchar_t domain[256] = {0};
    wchar_t username[256] = {0};
    GetEnvironmentVariableW(L"USERDOMAIN", domain, 256);
    GetEnvironmentVariableW(L"USERNAME", username, 256);
    std::wstring ru;
    if (domain[0] && username[0]) {
        ru = std::wstring(domain) + L"\\" + username;
    } else {
        DWORD ulen = 256;
        GetUserNameW(username, &ulen);
        ru = username;
    }

    std::wstring cmd = L"schtasks /Create /TN \"" + std::wstring(kTaskName) +
                       L"\" /TR \"\\\"" + exePath + L"\\\" --autostart\""
                       L" /SC ONLOGON /RU \"" + ru + L"\" /IT /RL HIGHEST /F";
    std::string out;
    DWORD code = RunCmd(cmd, &out);
    if (code == 0) return true;

    // 格式化错误信息
    errMsg = L"创建开机自启任务失败。";
    if (code == (DWORD)-1) {
        DWORD le = GetLastError();
        errMsg += L" CreateProcess 失败，Win32 错误码 " + std::to_wstring(le) +
                  L"：" + FormatWin32Error(le);
    } else {
        errMsg += L" schtasks 退出码 " + std::to_wstring(code) + L"。";
        if (!out.empty()) {
            // schtasks 输出使用系统 OEM 代码页（中文系统为 GBK/936），按当前代码页解码
            UINT cp = GetOEMCP();
            int wlen = MultiByteToWideChar(cp, 0, out.c_str(), (int)out.size(), nullptr, 0);
            if (wlen > 0) {
                std::wstring wout(wlen, 0);
                MultiByteToWideChar(cp, 0, out.c_str(), (int)out.size(), &wout[0], wlen);
                // 去掉末尾换行
                while (!wout.empty() && (wout.back() == L'\r' || wout.back() == L'\n'))
                    wout.pop_back();
                errMsg += L" 输出：" + wout;
            }
        }
    }
    return false;
}

bool FirstRunManager::DisableAutoStart(std::wstring& errMsg) {
    errMsg.clear();
    std::wstring cmd = L"schtasks /Delete /TN \"" + std::wstring(kTaskName) + L"\" /F";
    std::string out;
    DWORD code = RunCmd(cmd, &out);
    if (code == 0) return true;

    errMsg = L"删除开机自启任务失败。";
    if (code == (DWORD)-1) {
        DWORD le = GetLastError();
        errMsg += L" CreateProcess 失败，Win32 错误码 " + std::to_wstring(le) +
                  L"：" + FormatWin32Error(le);
    } else {
        errMsg += L" schtasks 退出码 " + std::to_wstring(code) + L"。";
        if (!out.empty()) {
            UINT cp = GetOEMCP();
            int wlen = MultiByteToWideChar(cp, 0, out.c_str(), (int)out.size(), nullptr, 0);
            if (wlen > 0) {
                std::wstring wout(wlen, 0);
                MultiByteToWideChar(cp, 0, out.c_str(), (int)out.size(), &wout[0], wlen);
                while (!wout.empty() && (wout.back() == L'\r' || wout.back() == L'\n'))
                    wout.pop_back();
                errMsg += L" 输出：" + wout;
            }
        }
    }
    return false;
}

} // namespace yx
