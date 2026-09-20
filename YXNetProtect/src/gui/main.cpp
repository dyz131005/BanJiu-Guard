// BanJiu-Guard - Qt GUI entry
#include <QApplication>
#include <QCoreApplication>
#include <QStyleFactory>
#include <QFont>
#include <QFile>
#include <QDateTime>
#include <QWinEventNotifier>
#include <windows.h>
#include <dbghelp.h>
#include <chrono>
#include <fstream>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <mutex>
#include <string>
#include "mainwindow.h"
#include "../common/yx_protocol.h"

// ============================================================
// 崩溃日志系统：未捕获异常时写 minidump + 调用栈到文件
// 不依赖 Qt 事件循环，崩溃时立即同步写入磁盘
// ============================================================
static std::wstring g_crashLogPath;
static std::mutex   g_crashLogMutex;

// 以 UTF-8 编码向日志文件追加一段文本（调用方需持有 g_crashLogMutex）
// 必须用 ccs=UTF-8：std::wofstream 默认 C locale 无法编码中文，
// 遇到中文字符会置 failbit，导致该行后续内容（含换行）全部丢失
static void AppendLogUtf8(const std::wstring& text)
{
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, g_crashLogPath.c_str(), L"a, ccs=UTF-8") != 0 || !fp) return;
    fwprintf(fp, L"%s", text.c_str());
    fclose(fp);
}

static void WriteCrashLog(const wchar_t* type, EXCEPTION_POINTERS* ep)
{
    std::lock_guard<std::mutex> lk(g_crashLogMutex);
    auto now = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz").toStdWString();
    std::wstring body;
    body += L"\n========================================\n";
    body += L"[" + now + L"] CRASH: " + type + L"\n";

    if (ep && ep->ExceptionRecord) {
        wchar_t line[256];
        swprintf_s(line, 256, L"  ExceptionCode: 0x%08X\n",
                   (unsigned)ep->ExceptionRecord->ExceptionCode);
        body += line;
        swprintf_s(line, 256, L"  ExceptionAddress: 0x%p\n",
                   ep->ExceptionRecord->ExceptionAddress);
        body += line;
        swprintf_s(line, 256, L"  ExceptionFlags: %u\n",
                   (unsigned)ep->ExceptionRecord->ExceptionFlags);
        body += line;
        swprintf_s(line, 256, L"  NumParameters: %u\n",
                   (unsigned)ep->ExceptionRecord->NumberParameters);
        body += line;
    }

    AppendLogUtf8(body);

    // 写 minidump
    std::wstring dumpPath = g_crashLogPath + L".dmp";
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mei;
        mei.ThreadId = GetCurrentThreadId();
        mei.ExceptionPointers = ep;
        mei.ClientPointers = FALSE;
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                          MiniDumpNormal, &mei, nullptr, nullptr);
        CloseHandle(hFile);
        AppendLogUtf8(L"  MiniDump: " + dumpPath + L"\n");
    }
}

static LONG WINAPI UnhandledExceptionFilterCb(EXCEPTION_POINTERS* ep)
{
    WriteCrashLog(L"UnhandledException", ep);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void TerminateHandlerCb()
{
    WriteCrashLog(L"std::terminate", nullptr);
    std::abort();
}

static void PureCallHandlerCb()
{
    WriteCrashLog(L"PureVirtualCall", nullptr);
    std::abort();
}

static void InstallCrashHandlers(const std::wstring& logPath)
{
    g_crashLogPath = logPath;
    SetUnhandledExceptionFilter(UnhandledExceptionFilterCb);
    std::set_terminate(TerminateHandlerCb);
    _set_purecall_handler(PureCallHandlerCb);
    // SIGABRT / SIGSEGV
    signal(SIGABRT, [](int) { WriteCrashLog(L"SIGABRT", nullptr); std::abort(); });
    signal(SIGSEGV, [](int) { WriteCrashLog(L"SIGSEGV", nullptr); std::abort(); });
}

// 同步把消息写到崩溃日志文件（供 service 模块通过 extern 调用）
extern "C" void YxWriteCrashLog(const wchar_t* msg)
{
    if (g_crashLogPath.empty() || !msg) return;
    std::lock_guard<std::mutex> lk(g_crashLogMutex);
    auto now = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz").toStdWString();
    AppendLogUtf8(L"[" + now + L"] " + msg + L"\n");
}

// 静态链接 Qt 必须显式导入 platform plugins（否则找不到 qwindows）
#include <QtPlugin>
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)
Q_IMPORT_PLUGIN(QICOPlugin)

// 强制链接器保留静态插件符号（防止被 /OPT:REF 优化丢弃）
// 符号 mangled 名来自 qwindows.lib/qico.lib 内的定义
#if defined(_MSC_VER) && defined(QT_STATIC)
#pragma comment(linker, "/include:?qt_static_plugin_QWindowsIntegrationPlugin@@YA?BUQStaticPlugin@@XZ")
#pragma comment(linker, "/include:?qt_static_plugin_QICOPlugin@@YA?BUQStaticPlugin@@XZ")
#endif

// 防多开：命名互斥量 + 命名事件
static constexpr const wchar_t* kInstanceMutex  = L"Global\\BanJiuGuard_InstanceMutex";
static constexpr const wchar_t* kShowWindowEvent = L"Global\\BanJiuGuard_ShowWindowEvent";

// 创建开放安全描述符（允许 Everyone 访问），确保跨会话/跨用户实例能互相发现
static PSECURITY_DESCRIPTOR CreateOpenSD()
{
    static BYTE sdBuf[SECURITY_DESCRIPTOR_MIN_LENGTH];
    PSECURITY_DESCRIPTOR sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(sdBuf);
    if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)) return nullptr;
    // DACL 为空表示允许所有访问
    if (!SetSecurityDescriptorDacl(sd, TRUE, nullptr, FALSE)) return nullptr;
    return sd;
}

static bool IsElevated()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION elev{};
    DWORD sz = 0;
    bool ok = GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz)
              && elev.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

int main(int argc, char *argv[])
{
    // ---- 崩溃日志：尽早安装，确保后续任何崩溃都能捕获 ----
    {
        wchar_t exeDir[MAX_PATH];
        GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
        std::wstring p(exeDir);
        auto pos = p.find_last_of(L"\\/");
        std::wstring dir = (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
        std::wstring crashLog = dir + L"\\BanJiu-Guard-crash.log";
        InstallCrashHandlers(crashLog);
        YxWriteCrashLog(L"==== BanJiu-Guard start ====");
    }

    // ---- 管理员权限检查（双保险，manifest 已要求提权，这里再兜底）----
    if (!IsElevated()) {
        MessageBoxW(nullptr,
            L"BanJiu-Guard 需要管理员权限运行。\n请右键选择「以管理员身份运行」。",
            L"BanJiu-Guard", MB_OK | MB_ICONERROR);
        return 1;
    }

    // ---- 防多开检测 ----
    // 使用开放安全描述符，确保不同用户/会话创建的实例能互相发现
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = CreateOpenSD();

    HANDLE hMutex = CreateMutexW(&sa, FALSE, kInstanceMutex);
    bool alreadyRunning = (GetLastError() == ERROR_ALREADY_EXISTS);

    if (alreadyRunning) {
        // 已有实例在运行 → 通知它显示窗口，然后自己退出
        HANDLE hEvt = OpenEventW(EVENT_MODIFY_STATE, FALSE, kShowWindowEvent);
        if (hEvt) {
            SetEvent(hEvt);
            CloseHandle(hEvt);
        }
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    // 创建显示窗口事件（供其他实例触发）
    HANDLE hShowEvt = CreateEventW(&sa, FALSE, FALSE, kShowWindowEvent);

#if defined(QT_STATIC)
    // 静态链接时禁用 Qt 所有外部插件/库搜索路径。
    QCoreApplication::setLibraryPaths(QStringList{});
    qputenv("QT_PLUGIN_PATH", QByteArray());
    qputenv("QT_QPA_PLATFORM_PLUGIN_PATH", QByteArray());
#endif

    // 高 DPI 适配
    QApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

    QApplication app(argc, argv);
    app.setApplicationName("BanJiu-Guard");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("BanJiu-Guard");

    // 关闭最后一个窗口时不自动退出（窗口会最小化到托盘，应用继续运行）
    app.setQuitOnLastWindowClosed(false);

    // 加载 QSS 主题
    QFile qss(":/theme/style.qss");
    if (qss.open(QFile::ReadOnly | QFile::Text)) {
        QString style = QString::fromUtf8(qss.readAll());
        app.setStyleSheet(style);
        qss.close();
    }

    MainWindow w;

    // 监听显示窗口事件（其他实例发来的请求）
    if (hShowEvt) {
        auto* notifier = new QWinEventNotifier(hShowEvt, &app);
        QObject::connect(notifier, &QWinEventNotifier::activated, &w, [&w, hShowEvt] {
            w.onShowWindowRequested();
            ResetEvent(hShowEvt);
        });
    }

    // 判断是否带自启参数
    bool autoStart = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--autostart") == 0) {
            autoStart = true;
            break;
        }
    }

    if (autoStart) {
        // 自启模式：启动防护但隐藏 GUI，仅显示托盘
        w.startHidden();
    } else {
        w.show();
    }

    int ret = app.exec();

    if (hShowEvt) CloseHandle(hShowEvt);
    if (hMutex)   CloseHandle(hMutex);
    return ret;
}
