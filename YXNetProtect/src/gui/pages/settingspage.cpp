// BanJiu-Guard - 设置页面实现
#include "settingspage.h"
#include "../../service/yx_first_run.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QCheckBox>
#include <QPushButton>
#include <QGroupBox>
#include <QMessageBox>
#include <QCoreApplication>
#include <QComboBox>
#include <QScrollArea>
#include <thread>

SettingsPage::SettingsPage(yx::ProtectionService* svc, QWidget* parent)
    : QWidget(parent), m_svc(svc)
{
    buildUi();

    // 测试签名状态 / 开机自启状态：用后台线程异步加载
    // 原因：两者分别调用 bcdedit 和 schtasks，CreateProcessW 会同步触发
    // 内核 YxProcessNotify → YxQueryDecision(8000ms) → DriverMsg 线程验签 2 秒，
    // 同步执行会把主线程阻塞 7~20 秒，导致 MainWindow 构造期间主界面无法显示。
    // 占位文字先显示"加载中..."，加载完成后用 invokeMethod 回 UI 线程更新。
    m_testSigningState->setText("测试签名模式：加载中...");
    m_autoStart->setEnabled(false);
    m_autoStart->setText("开机自启（加载中...）");

    std::thread([this]() {
        bool tsOn = yx::FirstRunManager::IsTestSigningEnabled();
        bool asOn = yx::FirstRunManager::IsAutoStartEnabled();
        // 捕获 this 安全：SettingsPage 在 MainWindow 生命周期内一直存在
        QMetaObject::invokeMethod(this, [this, tsOn, asOn]() {
            m_testSigningState->setText(tsOn
                ? "测试签名模式：已开启 ✓"
                : "测试签名模式：未开启（内核防护未激活）");
            m_autoStart->setText("开机自启");
            m_autoStart->setEnabled(true);
            // blockSignals 防止 setChecked 触发 onAutoStartToggled 误创建任务
            m_autoStart->blockSignals(true);
            m_autoStart->setChecked(asOn);
            m_autoStart->blockSignals(false);
        }, Qt::QueuedConnection);
    }).detach();

    // 初始化驱动启动类型选择
    if (m_svc) {
        auto curType = m_svc->GetDriverStartType();
        int idx = 0;
        switch (curType) {
            case yx::ProtectionService::DriverStart_Boot:    idx = 0; break;
            case yx::ProtectionService::DriverStart_System:  idx = 1; break;
            case yx::ProtectionService::DriverStart_Auto:    idx = 2; break;
            case yx::ProtectionService::DriverStart_Demand:  idx = 3; break;
            case yx::ProtectionService::DriverStart_Disabled: idx = 4; break;
        }
        m_driverStartType->blockSignals(true);
        m_driverStartType->setCurrentIndex(idx);
        m_driverStartType->blockSignals(false);

        // 初始化威胁处置设置
        auto curSettings = m_svc->GetProtectSettings();
        m_handleMode->blockSignals(true);
        m_handleMode->setCurrentIndex(curSettings.autoHandle ? 0 : 1);
        m_handleMode->blockSignals(false);
        m_actionType->blockSignals(true);
        m_actionType->setCurrentIndex(curSettings.autoAction);
        m_actionType->blockSignals(false);

        // 同步防护开关到当前设置
        m_fileProtect->setChecked(curSettings.fileProtect);
        m_processProtect->setChecked(curSettings.processProtect);
        m_registryProtect->setChecked(curSettings.registryProtect);
        m_scheduleProtect->setChecked(curSettings.scheduleProtect);
        m_networkProtect->setChecked(curSettings.networkProtect);
        m_injectProtect->setChecked(curSettings.injectProtect);
        m_yinHuProtect->setChecked(curSettings.yinHuProtect);
        m_selfProtect->setChecked(curSettings.selfProtect);
        m_mbrProtect->setChecked(curSettings.mbrProtect);
    }

    // 处置下拉框变化时立即保存
    connect(m_handleMode, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SettingsPage::apply);
    connect(m_actionType, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SettingsPage::apply);
}

void SettingsPage::buildUi()
{
    // 外层滚动区域，内容溢出时出现滚动条，不会挤在一起
    auto* outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    outerLayout->addWidget(scroll);

    auto* container = new QWidget(scroll);
    scroll->setWidget(container);

    auto* lay = new QVBoxLayout(container);
    lay->setContentsMargins(32, 28, 32, 28);
    lay->setSpacing(16);

    auto* header = new QLabel("设置", container);
    header->setObjectName("pageTitle");
    lay->addWidget(header);

    // 实时防护开关组
    auto* group = new QGroupBox("实时防护", container);
    group->setObjectName("settingsGroup");
    auto* g = new QVBoxLayout(group);
    g->setSpacing(10);

    auto mk = [&](const QString& txt, QCheckBox*& cb, const QString& desc) {
        auto* row = new QWidget(group);
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0);
        cb = new QCheckBox(txt, row);
        cb->setObjectName("settingCheck");
        cb->setChecked(true);
        auto* d = new QLabel(desc, row);
        d->setObjectName("hintText");
        d->setWordWrap(true);
        h->addWidget(cb, 0);
        h->addWidget(d, 1);
        g->addWidget(row);
        connect(cb, &QCheckBox::toggled, this, &SettingsPage::onAnyToggled);
    };

    mk("文件实时防护", m_fileProtect, "监控文件创建/写入/删除，拦截恶意文件落地");
    mk("进程行为防护", m_processProtect, "监控进程创建与行为，拦截可疑进程");
    mk("注册表防护", m_registryProtect, "监控自启动项等注册表持久化写入");
    mk("计划任务防护", m_scheduleProtect, "拦截伪装成 Edge 更新等计划任务持久化");
    mk("网络防护", m_networkProtect, "拦截连接银狐木马 C2 服务器的通信");
    mk("注入防护", m_injectProtect, "检测向系统进程注入远程线程的银狐行为");
    mk("银狐专项增强防护", m_yinHuProtect, "针对白加黑 DLL 侧加载、BYOVD、无文件攻击等银狐手法");
    mk("自我防护", m_selfProtect, "保护本软件进程/文件，防止被恶意终止或篡改");
    mk("MBR/GPT 引导区防护", m_mbrProtect, "监控并拦截对磁盘 MBR/GPT 分区表的写入，防止引导区被篡改");

    lay->addWidget(group);

    // 威胁处置设置组
    auto* thGroup = new QGroupBox("威胁处置", container);
    thGroup->setObjectName("settingsGroup");
    auto* thl = new QVBoxLayout(thGroup);
    thl->setSpacing(10);

    // 处理模式选择
    {
        auto* row = new QWidget(thGroup);
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0);
        auto* lbl = new QLabel("处理模式：", row);
        lbl->setObjectName("hintText");
        lbl->setFixedWidth(120);
        m_handleMode = new QComboBox(row);
        m_handleMode->addItem("自动处理", 1);
        m_handleMode->addItem("手动确认（弹窗）", 0);
        m_handleMode->setFixedWidth(180);
        auto* d = new QLabel("自动处理：检测到威胁立即按处置方式执行；手动确认：弹出对话框由用户选择放过或拦截", row);
        d->setObjectName("hintText");
        d->setWordWrap(true);
        h->addWidget(lbl, 0);
        h->addWidget(m_handleMode, 0);
        h->addWidget(d, 1);
        thl->addWidget(row);
    }

    // 处置方式选择
    {
        auto* row = new QWidget(thGroup);
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0);
        auto* lbl = new QLabel("处置方式：", row);
        lbl->setObjectName("hintText");
        lbl->setFixedWidth(120);
        m_actionType = new QComboBox(row);
        m_actionType->addItem("隔离到隔离区", 0);
        m_actionType->addItem("直接强制删除", 1);
        m_actionType->setFixedWidth(180);
        auto* d = new QLabel("隔离到隔离区：将威胁文件移入隔离区并加 .quarantined 后缀禁止执行；直接强制删除：通过驱动强制删除文件", row);
        d->setObjectName("hintText");
        d->setWordWrap(true);
        h->addWidget(lbl, 0);
        h->addWidget(m_actionType, 0);
        h->addWidget(d, 1);
        thl->addWidget(row);
    }

    // 进程启动前扫描
    {
        auto* row = new QWidget(thGroup);
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0);
        m_processStartScan = new QCheckBox("进程启动前启发式扫描", row);
        m_processStartScan->setObjectName("settingCheck");
        m_processStartScan->setChecked(true);
        auto* d = new QLabel("可执行文件启动时先验证微软官方签名（含系统CAT目录签名库），未通过签名的进程进行启发式扫描", row);
        d->setObjectName("hintText");
        d->setWordWrap(true);
        h->addWidget(m_processStartScan, 0);
        h->addWidget(d, 1);
        thl->addWidget(row);
        connect(m_processStartScan, &QCheckBox::toggled, this, &SettingsPage::onAnyToggled);
    }

    lay->addWidget(thGroup);

    // 启动设置组（开机自启 + 驱动启动类型）
    auto* asGroup = new QGroupBox("启动设置", container);
    asGroup->setObjectName("settingsGroup");
    auto* asl = new QVBoxLayout(asGroup);
    asl->setSpacing(10);

    {
        auto* row = new QWidget(asGroup);
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0);
        m_autoStart = new QCheckBox("开机自启", row);
        m_autoStart->setObjectName("settingCheck");
        auto* d = new QLabel("用户登录时自动启动防护程序并驻留系统托盘", row);
        d->setObjectName("hintText");
        d->setWordWrap(true);
        h->addWidget(m_autoStart, 0);
        h->addWidget(d, 1);
        asl->addWidget(row);
        connect(m_autoStart, &QCheckBox::toggled, this, &SettingsPage::onAutoStartToggled);
    }

    // 驱动启动类型选择
    {
        auto* row = new QWidget(asGroup);
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0);
        auto* lbl = new QLabel("内核驱动启动类型：", row);
        lbl->setObjectName("hintText");
        lbl->setFixedWidth(120);
        m_driverStartType = new QComboBox(row);
        m_driverStartType->addItem("引导启动（最早）", yx::ProtectionService::DriverStart_Boot);
        m_driverStartType->addItem("系统启动（推荐）", yx::ProtectionService::DriverStart_System);
        m_driverStartType->addItem("自动启动", yx::ProtectionService::DriverStart_Auto);
        m_driverStartType->addItem("手动启动", yx::ProtectionService::DriverStart_Demand);
        m_driverStartType->addItem("禁用", yx::ProtectionService::DriverStart_Disabled);
        m_driverStartType->setFixedWidth(180);
        auto* d = new QLabel("决定驱动何时加载。引导/系统启动在软件启动前加载，确保开机即受保护", row);
        d->setObjectName("hintText");
        d->setWordWrap(true);
        h->addWidget(lbl, 0);
        h->addWidget(m_driverStartType, 0);
        h->addWidget(d, 1);
        asl->addWidget(row);
        connect(m_driverStartType, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &SettingsPage::onDriverStartTypeChanged);
    }

    lay->addWidget(asGroup);

    // 测试签名 / 完全防护组
    auto* tsGroup = new QGroupBox("完全防护（内核模式）", container);
    tsGroup->setObjectName("settingsGroup");
    auto* tsl = new QVBoxLayout(tsGroup);
    tsl->setSpacing(10);

    m_testSigningState = new QLabel("测试签名模式：检测中...", tsGroup);
    m_testSigningState->setObjectName("hintText");
    tsl->addWidget(m_testSigningState);

    auto* desc = new QLabel("内核驱动需要测试签名模式才能加载。开启后系统会显示\"测试模式\"水印，"
                            "需重启生效。可在正式签名（EV 证书）后关闭。", tsGroup);
    desc->setObjectName("hintText");
    desc->setWordWrap(true);
    tsl->addWidget(desc);

    m_btnEnableFull = new QPushButton("启用完全防护（开启测试签名并重启）", tsGroup);
    m_btnEnableFull->setObjectName("primaryBtn");
    m_btnEnableFull->setCursor(Qt::PointingHandCursor);
    connect(m_btnEnableFull, &QPushButton::clicked, this, &SettingsPage::onEnableFullProtect);
    tsl->addWidget(m_btnEnableFull);

    lay->addWidget(tsGroup);

    // 保存按钮
    auto* save = new QPushButton("应用防护设置", container);
    save->setObjectName("primaryBtn");
    save->setCursor(Qt::PointingHandCursor);
    connect(save, &QPushButton::clicked, this, &SettingsPage::apply);
    lay->addWidget(save);

    lay->addStretch(1);
}

void SettingsPage::onAnyToggled()
{
    apply();
}

void SettingsPage::apply()
{
    yx::ProtectSettings s;
    s.fileProtect    = m_fileProtect->isChecked();
    s.processProtect = m_processProtect->isChecked();
    s.registryProtect = m_registryProtect->isChecked();
    s.scheduleProtect = m_scheduleProtect->isChecked();
    s.networkProtect = m_networkProtect->isChecked();
    s.injectProtect  = m_injectProtect->isChecked();
    s.yinHuProtect   = m_yinHuProtect->isChecked();
    s.selfProtect    = m_selfProtect->isChecked();
    s.mbrProtect     = m_mbrProtect->isChecked();

    // 威胁处置设置
    s.autoHandle = (m_handleMode->currentData().toInt() != 0);
    s.autoAction = m_actionType->currentData().toInt();
    s.processStartScan = m_processStartScan->isChecked();

    if (m_svc) m_svc->ApplySettings(s);
    emit settingsChanged(s);
}

void SettingsPage::updateTestSigningState()
{
    bool on = yx::FirstRunManager::IsTestSigningEnabled();
    m_testSigningState->setText(on
        ? "测试签名模式：已开启 ✓"
        : "测试签名模式：未开启（内核防护未激活）");
}

void SettingsPage::onEnableFullProtect()
{
    if (!yx::FirstRunManager::IsElevated()) {
        QMessageBox::warning(this, "需要管理员权限",
            "开启测试签名模式需要以管理员身份运行本软件，请用管理员权限重新启动。");
        return;
    }

    auto ret = QMessageBox::question(this, "启用完全防护",
        "将开启 Windows 测试签名模式以加载内核驱动，之后需要重启系统。是否继续？",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (ret != QMessageBox::Yes) return;

    if (yx::FirstRunManager::EnableTestSigning()) {
        yx::FirstRunManager::MarkHasRun();
        auto r2 = QMessageBox::question(this, "即将重启",
            "测试签名模式已开启，需要重启系统才能生效。现在重启吗？",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (r2 == QMessageBox::Yes) {
            // 重启系统（需 SeShutdownPrivilege）
            system("shutdown /r /t 5");
        }
    } else {
        QMessageBox::warning(this, "开启失败",
            "无法开启测试签名模式，请检查是否以管理员权限运行，或手动执行 bcdedit /set testsigning on");
    }
    updateTestSigningState();
}

void SettingsPage::onDisableTestSigning()
{
    yx::FirstRunManager::DisableTestSigning();
    updateTestSigningState();
}

void SettingsPage::onAutoStartToggled(bool checked)
{
    // 开机自启需要管理员权限（创建 SYSTEM 级计划任务）
    if (checked && !yx::FirstRunManager::IsElevated()) {
        if (m_svc) m_svc->Log(L"[设置] 开启开机自启失败：当前未以管理员权限运行，无法创建 SYSTEM 级计划任务。");
        QMessageBox::warning(this, "需要管理员权限",
            "开启开机自启需要管理员权限。请以管理员身份运行本软件后再开启。");
        m_autoStart->blockSignals(true);
        m_autoStart->setChecked(false);
        m_autoStart->blockSignals(false);
        return;
    }

    QString exePath = QCoreApplication::applicationFilePath();

    if (checked) {
        std::wstring errMsg;
        bool ok = yx::FirstRunManager::EnableAutoStart(exePath.toStdWString(), errMsg);
        if (!ok) {
            if (m_svc) m_svc->Log(L"[设置] " + errMsg);
            QMessageBox::warning(this, "开启失败",
                "无法创建开机自启任务，详细信息已写入安全日志。");
            m_autoStart->blockSignals(true);
            m_autoStart->setChecked(false);
            m_autoStart->blockSignals(false);
        } else {
            if (m_svc) m_svc->Log(L"[设置] 开机自启已开启，计划任务将在系统启动时以 SYSTEM 身份运行。");
        }
    } else {
        std::wstring errMsg;
        bool ok = yx::FirstRunManager::DisableAutoStart(errMsg);
        if (!ok) {
            if (m_svc) m_svc->Log(L"[设置] " + errMsg);
            QMessageBox::warning(this, "关闭失败",
                "无法删除开机自启任务，详细信息已写入安全日志。");
            m_autoStart->blockSignals(true);
            m_autoStart->setChecked(true);
            m_autoStart->blockSignals(false);
        } else {
            if (m_svc) m_svc->Log(L"[设置] 开机自启已关闭。");
        }
    }
}

void SettingsPage::onDriverStartTypeChanged(int index)
{
    if (!m_svc || index < 0) return;

    auto type = static_cast<yx::ProtectionService::DriverStartType>(
        m_driverStartType->itemData(index).toInt());

    std::wstring errMsg;
    if (!m_svc->SetDriverStartType(type, errMsg)) {
        if (m_svc) m_svc->Log(L"[设置] 设置驱动启动类型失败：" + errMsg);
        QMessageBox::warning(this, "设置失败",
            "无法修改驱动启动类型，详细信息已写入安全日志。");
        // 回滚到当前实际值
        auto cur = m_svc->GetDriverStartType();
        int idx = 0;
        switch (cur) {
            case yx::ProtectionService::DriverStart_Boot:    idx = 0; break;
            case yx::ProtectionService::DriverStart_System:  idx = 1; break;
            case yx::ProtectionService::DriverStart_Auto:    idx = 2; break;
            case yx::ProtectionService::DriverStart_Demand:  idx = 3; break;
            case yx::ProtectionService::DriverStart_Disabled: idx = 4; break;
        }
        m_driverStartType->blockSignals(true);
        m_driverStartType->setCurrentIndex(idx);
        m_driverStartType->blockSignals(false);
    } else {
        QMessageBox::information(this, "设置成功",
            "驱动启动类型已修改，重启系统后生效。");
    }
}
