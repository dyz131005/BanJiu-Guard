// BanJiu-Guard - 设置页面
#pragma once

#include <QWidget>
#include "../../service/yx_service.h"

class QCheckBox;
class QPushButton;
class QLabel;
class QComboBox;

class SettingsPage : public QWidget
{
    Q_OBJECT
public:
    explicit SettingsPage(yx::ProtectionService* svc, QWidget* parent = nullptr);

signals:
    void settingsChanged(const yx::ProtectSettings& s);

private slots:
    void onAnyToggled();
    void onEnableFullProtect();
    void onDisableTestSigning();
    void onAutoStartToggled(bool checked);
    void onDriverStartTypeChanged(int index);

private:
    void buildUi();
    void apply();
    void updateTestSigningState();

    yx::ProtectionService* m_svc = nullptr;

    QCheckBox* m_fileProtect = nullptr;
    QCheckBox* m_processProtect = nullptr;
    QCheckBox* m_registryProtect = nullptr;
    QCheckBox* m_scheduleProtect = nullptr;
    QCheckBox* m_networkProtect = nullptr;
    QCheckBox* m_injectProtect = nullptr;
    QCheckBox* m_yinHuProtect = nullptr;
    QCheckBox* m_selfProtect = nullptr;
    QCheckBox* m_mbrProtect = nullptr;
    QCheckBox* m_autoStart = nullptr;
    QComboBox* m_driverStartType = nullptr;

    // 威胁处置设置
    QComboBox* m_handleMode = nullptr;   // 自动处理 / 手动确认
    QComboBox* m_actionType = nullptr;   // 隔离到隔离区 / 直接强制删除
    QCheckBox* m_processStartScan = nullptr;  // 进程启动前扫描（微软签名放行）

    QPushButton* m_btnEnableFull = nullptr;
    QLabel* m_testSigningState = nullptr;
};
