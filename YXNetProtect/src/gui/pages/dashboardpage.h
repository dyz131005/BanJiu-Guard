// BanJiu-Guard - 仪表盘页面
#pragma once

#include <QWidget>
#include <QTimer>

class QLabel;
class QPushButton;
class QProgressBar;

namespace yx { class ProtectionService; }

class DashboardPage : public QWidget
{
    Q_OBJECT
public:
    explicit DashboardPage(yx::ProtectionService* svc, QWidget* parent = nullptr);

private slots:
    void refresh();
    void onQuickScan();

private:
    void buildUi();

    yx::ProtectionService* m_svc = nullptr;
    QTimer m_timer;

    QLabel* m_statusIcon = nullptr;
    QLabel* m_statusText = nullptr;
    QLabel* m_engineState = nullptr;
    QLabel* m_driverState = nullptr;

    QLabel* m_filesScanned = nullptr;
    QLabel* m_filesBlocked = nullptr;
    QLabel* m_quarantined = nullptr;
    QLabel* m_threatsDetected = nullptr;
    QLabel* m_yinHuDetected = nullptr;
};
