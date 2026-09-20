// BanJiu-Guard - 主窗口
#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QButtonGroup>
#include <memory>

class QPushButton;
class QLabel;
class QMenu;
class DashboardPage;
class ScanPage;
class QuarantinePage;
class LogPage;
class SettingsPage;
class NativeTrayIcon;

namespace yx {
class ProtectionService;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void showThreatNotification(const QString& title, const QString& body);

    // 由自启参数（--autostart）调用：启动服务但隐藏 GUI，仅显示托盘
    void startHidden();

    // 收到其他实例发来的显示窗口请求
    void onShowWindowRequested();

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);

private:
    void buildUi();
    void buildNav();
    void buildTray();
    void setupService();

private:
    QWidget* m_central = nullptr;
    QWidget* m_navBar = nullptr;
    QStackedWidget* m_stack = nullptr;

    QPushButton* m_btnDashboard = nullptr;
    QPushButton* m_btnScan = nullptr;
    QPushButton* m_btnQuarantine = nullptr;
    QPushButton* m_btnLog = nullptr;
    QPushButton* m_btnSettings = nullptr;
    QButtonGroup* m_navGroup = nullptr;

    DashboardPage*   m_dashboard = nullptr;
    ScanPage*        m_scan = nullptr;
    QuarantinePage*  m_quarantine = nullptr;
    LogPage*         m_log = nullptr;
    SettingsPage*    m_settings = nullptr;

    NativeTrayIcon* m_tray = nullptr;
    bool m_quitting = false;  // 退出标志，避免 closeEvent 拦截正常退出

    std::unique_ptr<yx::ProtectionService> m_service;
};
