// BanJiu-Guard - 仪表盘页面实现
#include "dashboardpage.h"
#include "../../service/yx_service.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QFrame>

static QFrame* makeStatLabel(const QString& title, QLabel*& valueLabel, QWidget* parent)
{
    auto* card = new QFrame(parent);
    card->setObjectName("statCard");

    auto* v = new QVBoxLayout(card);
    v->setContentsMargins(20, 16, 20, 16);
    v->setSpacing(6);

    auto* t = new QLabel(title, card);
    t->setObjectName("statTitle");
    valueLabel = new QLabel("0", card);
    valueLabel->setObjectName("statValue");

    v->addWidget(t);
    v->addWidget(valueLabel);
    return card;
}

DashboardPage::DashboardPage(yx::ProtectionService* svc, QWidget* parent)
    : QWidget(parent), m_svc(svc)
{
    buildUi();
    connect(&m_timer, &QTimer::timeout, this, &DashboardPage::refresh);
    m_timer.start(1000);
}

void DashboardPage::buildUi()
{
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(32, 28, 32, 28);
    lay->setSpacing(20);

    // 标题
    auto* header = new QLabel("安全防护状态", this);
    header->setObjectName("pageTitle");
    lay->addWidget(header);

    // 状态大卡片
    auto* statusCard = new QFrame(this);
    statusCard->setObjectName("heroCard");
    auto* statusLay = new QHBoxLayout(statusCard);
    statusLay->setContentsMargins(28, 24, 28, 24);
    statusLay->setSpacing(20);

    m_statusIcon = new QLabel(statusCard);
    m_statusIcon->setObjectName("statusIcon");
    m_statusIcon->setText("🛡");
    m_statusIcon->setStyleSheet("font-size:64px;");

    auto* statusTxtLay = new QVBoxLayout();
    m_statusText = new QLabel("正在保护您的系统", statusCard);
    m_statusText->setObjectName("statusTitle");
    m_engineState = new QLabel("引擎运行中", statusCard);
    m_engineState->setObjectName("statusSub");
    m_driverState = new QLabel("内核驱动：未加载", statusCard);
    m_driverState->setObjectName("statusSub");
    statusTxtLay->addWidget(m_statusText);
    statusTxtLay->addWidget(m_engineState);
    statusTxtLay->addWidget(m_driverState);
    statusTxtLay->addStretch(1);

    statusLay->addWidget(m_statusIcon);
    statusLay->addLayout(statusTxtLay, 1);
    lay->addWidget(statusCard);

    // 统计网格
    auto* grid = new QGridLayout();
    grid->setSpacing(16);

    QLabel* v1, *v2, *v3, *v4, *v5;
    grid->addWidget(makeStatLabel("已扫描文件", v1, this), 0, 0);
    grid->addWidget(makeStatLabel("已阻止文件", v2, this), 0, 1);
    grid->addWidget(makeStatLabel("已隔离", v3, this), 0, 2);
    grid->addWidget(makeStatLabel("检测到威胁", v4, this), 1, 0);
    grid->addWidget(makeStatLabel("银狐威胁", v5, this), 1, 1);

    m_filesScanned = v1;
    m_filesBlocked = v2;
    m_quarantined = v3;
    m_threatsDetected = v4;
    m_yinHuDetected = v5;

    lay->addLayout(grid);
    lay->addStretch(1);
}

void DashboardPage::refresh()
{
    if (!m_svc) return;

    auto stats = m_svc->GetStats();
    m_filesScanned->setText(QString::number(stats.FilesScanned));
    m_filesBlocked->setText(QString::number(stats.FilesBlocked));
    m_quarantined->setText(QString::number(stats.FilesQuarantined));
    m_threatsDetected->setText(QString::number(stats.ThreatsDetected));
    m_yinHuDetected->setText(QString::number(stats.YinHuDetected));

    m_driverState->setText(m_svc->IsDriverLoaded()
        ? "内核驱动：已加载 ✓"
        : "内核驱动：未加载（仅限用户态防护，可在设置中启用测试模式）");
}

void DashboardPage::onQuickScan()
{
    // 触发扫描（切换到扫描页由主窗口处理，这里仅刷新）
    refresh();
}
