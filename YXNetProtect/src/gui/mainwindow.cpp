// BanJiu-Guard - 主窗口实现
#include "mainwindow.h"
#include "pages/dashboardpage.h"
#include "pages/scanpage.h"
#include "pages/quarantinepage.h"
#include "pages/logpage.h"
#include "pages/settingspage.h"
#include "toast.h"
#include "../service/yx_service.h"

#include <QApplication>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QCloseEvent>
#include <QTimer>
#include <QScreen>
#include <QPropertyAnimation>
#include <QPixmap>
#include <QPainter>
#include <QPainterPath>
#include <windows.h>
#include <shellapi.h>

// ============================================================
// NativeTrayIcon：用 Win32 Shell_NotifyIconW 原生 API 实现的托盘图标
// 比 QSystemTrayIcon 更可靠——析构时同步调用 NIM_DELETE，不会残留
// ============================================================
class NativeTrayIcon
{
public:
    NativeTrayIcon();
    ~NativeTrayIcon();

    void setIcon(HICON hIcon) { m_hIcon = hIcon; }
    void setToolTip(const QString& tip) { m_toolTip = tip; }
    void show();
    void hide();
    void showMessage(const QString& title, const QString& body);
    void setContextMenu(QMenu* menu) { m_menu = menu; }

    HWND hwnd() const { return m_hwnd; }
    static constexpr UINT WM_TRAY = WM_APP + 0x1000;
    static constexpr UINT TRAY_ID = 1;

    // 由窗口过程调用
    void onTrayCallback(HWND hwnd, UINT msg);

private:
    bool doAdd();  // 执行 NIM_ADD，成功返回 true

    HWND m_hwnd = nullptr;
    HICON m_hIcon = nullptr;
    QString m_toolTip;
    QMenu* m_menu = nullptr;
    bool m_added = false;
    int m_retryCount = 0;
    QTimer* m_retryTimer = nullptr;
};

static LRESULT CALLBACK NativeTrayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == NativeTrayIcon::WM_TRAY && lParam != 0) {
        // 找到对应的 NativeTrayIcon 实例并处理
        // 简化处理：全局只有一个，直接遍历不行，用 SetWindowLongPtr 存指针
        NativeTrayIcon* tray = reinterpret_cast<NativeTrayIcon*>(
            GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (tray) {
            tray->onTrayCallback(hwnd, (UINT)lParam);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static const wchar_t* kTrayWndClass = L"BanJiuGuardTrayMsgWnd";

static HWND CreateTrayMessageWindow(NativeTrayIcon* owner)
{
    static bool s_registered = false;
    if (!s_registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = NativeTrayWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = kTrayWndClass;
        RegisterClassExW(&wc);
        s_registered = true;
    }
    HWND hwnd = CreateWindowExW(0, kTrayWndClass, L"", 0, 0, 0, 0, 0,
                                HWND_MESSAGE, nullptr,
                                GetModuleHandleW(nullptr), nullptr);
    if (hwnd) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)owner);
    }
    return hwnd;
}

NativeTrayIcon::NativeTrayIcon()
{
    m_hwnd = CreateTrayMessageWindow(this);
}

NativeTrayIcon::~NativeTrayIcon()
{
    if (m_retryTimer) {
        m_retryTimer->stop();
        delete m_retryTimer;
        m_retryTimer = nullptr;
    }
    // 同步删除托盘图标——这是关键，立即通知 Explorer 移除
    if (m_added && m_hwnd) {
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = m_hwnd;
        nid.uID = TRAY_ID;
        Shell_NotifyIconW(NIM_DELETE, &nid);
        m_added = false;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

bool NativeTrayIcon::doAdd()
{
    if (!m_hwnd || m_added) return true;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = m_hwnd;
    nid.uID = TRAY_ID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = m_hIcon;
    wcsncpy_s(nid.szTip, m_toolTip.toStdWString().c_str(), _TRUNCATE);
    if (Shell_NotifyIconW(NIM_ADD, &nid)) {
        m_added = true;
        return true;
    }
    return false;
}

void NativeTrayIcon::show()
{
    if (m_added) return;
    if (doAdd()) return;

    // NIM_ADD 失败（通常是登录瞬间 Explorer 还没就绪），启动定时重试
    m_retryCount = 0;
    if (!m_retryTimer) {
        m_retryTimer = new QTimer();
        m_retryTimer->setInterval(1000);
        QObject::connect(m_retryTimer, &QTimer::timeout, [this] {
            if (doAdd()) {
                m_retryTimer->stop();
                delete m_retryTimer;
                m_retryTimer = nullptr;
                return;
            }
            m_retryCount++;
            if (m_retryCount >= 30) {  // 最多重试 30 秒
                m_retryTimer->stop();
                delete m_retryTimer;
                m_retryTimer = nullptr;
            }
        });
    }
    m_retryTimer->start();
}

void NativeTrayIcon::hide()
{
    if (!m_added || !m_hwnd) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = m_hwnd;
    nid.uID = TRAY_ID;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    m_added = false;
}

void NativeTrayIcon::showMessage(const QString& title, const QString& body)
{
    if (!m_hwnd || !m_added) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = m_hwnd;
    nid.uID = TRAY_ID;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    wcsncpy_s(nid.szInfoTitle, title.toStdWString().c_str(), _TRUNCATE);
    wcsncpy_s(nid.szInfo, body.toStdWString().c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void NativeTrayIcon::onTrayCallback(HWND /*hwnd*/, UINT msg)
{
    switch (msg) {
    case WM_LBUTTONUP: {
        // 左键：显示主窗口
        if (auto* w = qobject_cast<MainWindow*>(qApp->activeWindow())) {
            w->show();
            w->raise();
        } else {
            // 遍历找主窗口
            QWidgetList list = QApplication::topLevelWidgets();
            for (QWidget* w : list) {
                if (qobject_cast<MainWindow*>(w)) {
                    w->show();
                    w->raise();
                    break;
                }
            }
        }
        break;
    }
    case WM_RBUTTONUP: {
        // 右键：弹出菜单
        if (m_menu) {
            POINT pt;
            GetCursorPos(&pt);
            // 必须 SetForegroundWindow 否则菜单不会消失
            SetForegroundWindow(m_hwnd);
            m_menu->exec(QPoint(pt.x, pt.y));
            PostMessageW(m_hwnd, WM_NULL, 0, 0);
        }
        break;
    }
    default:
        break;
    }
}

// ============================================================

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle("BanJiu-Guard 银狐防护");
    setMinimumSize(1080, 680);

    buildUi();
    buildNav();
    buildTray();
    setupService();

    // 居中显示
    QScreen* scr = QGuiApplication::primaryScreen();
    if (scr) {
        QRect g = scr->availableGeometry();
        move(g.center() - rect().center());
    }
}

MainWindow::~MainWindow()
{
    if (m_tray) {
        delete m_tray;
        m_tray = nullptr;
    }
}

void MainWindow::startHidden()
{
    // 服务已在构造函数中启动，这里只发一条托盘通知告知用户防护已驻留
    if (m_tray) {
        m_tray->showMessage("BanJiu-Guard", "防护已启动并驻留系统托盘");
    }
}

void MainWindow::onShowWindowRequested()
{
    show();
    raise();
}

void MainWindow::buildUi()
{
    m_central = new QWidget(this);
    m_central->setObjectName("centralRoot");
    setCentralWidget(m_central);

    auto* root = new QHBoxLayout(m_central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    m_navBar = new QWidget(m_central);
    m_navBar->setObjectName("navBar");
    m_navBar->setFixedWidth(220);

    m_stack = new QStackedWidget(m_central);
    m_stack->setObjectName("stack");

    root->addWidget(m_navBar);
    root->addWidget(m_stack, 1);
}

void MainWindow::buildNav()
{
    auto* lay = new QVBoxLayout(m_navBar);
    lay->setContentsMargins(16, 24, 16, 16);
    lay->setSpacing(8);

    auto* logo = new QLabel(m_navBar);
    logo->setObjectName("logoLabel");
    logo->setText("BanJiu-Guard");
    logo->setAlignment(Qt::AlignCenter);
    lay->addWidget(logo);
    lay->addSpacing(16);

    auto mk = [&](const QString& txt, QPushButton*& btn) {
        btn = new QPushButton(txt, m_navBar);
        btn->setObjectName("navBtn");
        btn->setCheckable(true);
        btn->setCursor(Qt::PointingHandCursor);
        lay->addWidget(btn);
    };
    mk("仪表盘", m_btnDashboard);
    mk("病毒扫描", m_btnScan);
    mk("隔离区", m_btnQuarantine);
    mk("安全日志", m_btnLog);
    mk("设置", m_btnSettings);

    // 互斥按钮组：确保始终只有一个导航按钮高亮，再点当前按钮也不会取消高亮
    m_navGroup = new QButtonGroup(this);
    m_navGroup->setExclusive(true);
    m_navGroup->addButton(m_btnDashboard, 0);
    m_navGroup->addButton(m_btnScan, 1);
    m_navGroup->addButton(m_btnQuarantine, 2);
    m_navGroup->addButton(m_btnLog, 3);
    m_navGroup->addButton(m_btnSettings, 4);

    m_btnDashboard->setChecked(true);
    lay->addStretch(1);
}

void MainWindow::buildTray()
{
    m_tray = new NativeTrayIcon();

    // 从 exe 嵌入的资源图标加载（app.rc 中 IDI_APP_ICON），与文件管理器显示的图标一致
    HICON hIconBig = reinterpret_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), L"IDI_APP_ICON", IMAGE_ICON, 256, 256, LR_SHARED));
    HICON hIconSmall = reinterpret_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), L"IDI_APP_ICON", IMAGE_ICON, 16, 16, LR_SHARED));
    if (hIconBig) {
        HWND hwnd = reinterpret_cast<HWND>(winId());
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hIconBig));
        if (hIconSmall) SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIconSmall));
        m_tray->setIcon(hIconBig);
    }
    if (!hIconBig) {
        // 兜底：代码绘制盾牌图标
        QPixmap pix(64, 64);
        pix.fill(Qt::transparent);
        QPainter p(&pix);
        p.setRenderHint(QPainter::Antialiasing, true);

        QPainterPath shield;
        shield.moveTo(32, 4);
        shield.lineTo(56, 14);
        shield.lineTo(56, 34);
        shield.cubicTo(56, 50, 44, 58, 32, 62);
        shield.cubicTo(20, 58, 8, 50, 8, 34);
        shield.lineTo(8, 14);
        shield.closeSubpath();

        QLinearGradient grad(0, 0, 0, 64);
        grad.setColorAt(0.0, QColor("#6366f1"));
        grad.setColorAt(1.0, QColor("#4338ca"));
        p.fillPath(shield, grad);
        p.setPen(QPen(QColor("#818cf8"), 2));
        p.drawPath(shield);

        p.setPen(QPen(Qt::white, 2));
        QFont f;
        f.setPixelSize(36);
        f.setBold(true);
        p.setFont(f);
        p.drawText(pix.rect(), Qt::AlignCenter, "B");
        p.end();

        setWindowIcon(QIcon(pix));
        m_tray->setIcon(QIcon(pix).pixmap(64).toImage().toHICON());
    }
    m_tray->setToolTip("BanJiu-Guard 银狐防护");

    auto* menu = new QMenu(this);
    menu->addAction("打开主界面", this, [this] {
        show();
        raise();
    });
    menu->addSeparator();
    menu->addAction("退出程序", this, [this] {
        m_quitting = true;
        if (m_service) {
            m_service->Stop();
            m_service->Shutdown();
        }
        // 同步析构 NativeTrayIcon，析构函数里立即调用 Shell_NotifyIconW(NIM_DELETE)
        // 同步通知 Explorer 移除托盘图标，不会残留
        delete m_tray;
        m_tray = nullptr;
        hide();
        // 延迟 200ms 退出，给 Explorer 时间处理移除消息
        QTimer::singleShot(200, qApp, &QCoreApplication::quit);
    });
    m_tray->setContextMenu(menu);
    m_tray->show();
}

void MainWindow::setupService()
{
    m_service.reset(new yx::ProtectionService());

    // 先创建日志页面，以便在 Initialize（加载驱动）前就能接收日志
    m_log = new LogPage(m_service.get(), this);

    // 设置服务回调（必须在 Initialize 之前，否则驱动加载日志丢失）
    yx::ServiceCallbacks cb;
    cb.onLog = [this](const std::wstring& msg) {
        QMetaObject::invokeMethod(m_log, "appendLog", Qt::QueuedConnection,
                                  Q_ARG(QString, QString::fromStdWString(msg)));
    };
    // 重要：服务回调可能由驱动消息线程（DriverMessageThreadProc）调用，
    // 绝不能在非 UI 线程直接创建 QWidget / 操作 UI，否则 Qt 跨线程访问 UI
    // 会导致死锁或 UI 未响应（处理威胁时尤为明显）。必须用 QueuedConnection
    // 异步派发回 UI 线程执行。
    cb.onThreat = [this](const yx::RuleHit& hit) {
        QString desc = QString::fromStdWString(hit.description);
        QMetaObject::invokeMethod(this, [this, desc] {
            showThreatNotification("检测到威胁", desc);
        }, Qt::QueuedConnection);
    };
    cb.onToast = [this](yx::ToastType type, const std::wstring& title, const std::wstring& body) {
        Q_UNUSED(type);
        QString qtitle = QString::fromStdWString(title);
        QString qbody  = QString::fromStdWString(body);
        QMetaObject::invokeMethod(this, [this, qtitle, qbody] {
            Toast::show(qtitle, qbody);
        }, Qt::QueuedConnection);
    };
    // 手动模式下的威胁决策弹窗：在 UI 线程弹出"拦截/放过"双按钮弹窗，
    // 用户点击后通过 decisionCallback 回传选择给服务（服务在驱动线程等待）
    cb.onThreatDecision = [this](const yx::RuleHit& hit,
                                  std::function<void(int decision)> decisionCallback) {
        std::wstring bodyW = hit.description + L"\n进程: " + hit.subject;
        if (!hit.object.empty()) bodyW += L"\n目标: " + hit.object;
        QString title = QString::fromStdWString(L"检测到威胁，请选择处理方式");
        QString body = QString::fromStdWString(bodyW);
        // 将回调移动到 UI 线程执行
        auto cb = std::make_shared<std::function<void(int)>>(std::move(decisionCallback));
        QMetaObject::invokeMethod(this, [this, title, body, cb] {
            Toast::showDecision(title, body, [cb](int decision) {
                if (*cb) (*cb)(decision);
            });
        }, Qt::QueuedConnection);
    };
    m_service->SetCallbacks(std::move(cb));

    m_service->Initialize();
    m_service->Start();

    // 创建其余页面
    m_dashboard = new DashboardPage(m_service.get(), this);
    m_scan = new ScanPage(m_service.get(), this);
    m_quarantine = new QuarantinePage(m_service.get(), this);
    m_settings = new SettingsPage(m_service.get(), this);

    m_stack->addWidget(m_dashboard);
    m_stack->addWidget(m_scan);
    m_stack->addWidget(m_quarantine);
    m_stack->addWidget(m_log);
    m_stack->addWidget(m_settings);

    // 导航：点击按钮切换到对应页面
    connect(m_navGroup, &QButtonGroup::idClicked, m_stack, [this](int id) {
        m_stack->setCurrentIndex(id);
    });
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason /*reason*/)
{
    // 由 NativeTrayIcon 原生处理托盘点击，此函数保留为空
}

void MainWindow::showThreatNotification(const QString& title, const QString& body)
{
    // 右下角弹窗（各分辨率适配，自动定位到工作区右下角）
    Toast::show(title, body);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    // 退出菜单已设 m_quitting，正常接受关闭
    if (m_quitting) {
        event->accept();
        return;
    }
    // 否则最小化到托盘而非退出
    if (m_tray) {
        hide();
        m_tray->showMessage("BanJiu-Guard", "防护仍在后台运行");
        event->ignore();
    } else {
        event->accept();
    }
}
