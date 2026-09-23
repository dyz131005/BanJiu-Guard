// BanJiu-Guard - 关于页面实现
// 与扫描完成界面一致：在当前窗口内展示（不弹独立弹窗），左上角返回按钮回到主页
#include "aboutpage.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>

// 软件版本与开发者信息（与 app.rc 中的文件版本 1.0.0.0 保持一致）
static const char* kAppName    = "BanJiu-Guard 银狐防护";
static const char* kAppVersion = "1.0";
static const char* kAppDev     = "dyz131005";

// 代码绘制盾牌 Logo（与 MainWindow 托盘兜底图标风格一致）
static QPixmap MakeShieldPixmap(int size)
{
    QPixmap pix(size, size);
    pix.fill(Qt::transparent);

    QPainter p(&pix);
    p.setRenderHint(QPainter::Antialiasing, true);

    QPainterPath shield;
    const qreal w = size, h = size;
    shield.moveTo(w * 0.5,  h * 0.06);
    shield.lineTo(w * 0.875, h * 0.22);
    shield.lineTo(w * 0.875, h * 0.53);
    shield.cubicTo(w * 0.875, h * 0.78, w * 0.69, h * 0.90, w * 0.5, h * 0.97);
    shield.cubicTo(w * 0.31,  h * 0.90, w * 0.125, h * 0.78, w * 0.125, h * 0.53);
    shield.lineTo(w * 0.125, h * 0.22);
    shield.closeSubpath();

    QLinearGradient grad(0, 0, 0, h);
    grad.setColorAt(0.0, QColor("#6366f1"));
    grad.setColorAt(1.0, QColor("#4338ca"));
    p.fillPath(shield, grad);
    p.setPen(QPen(QColor("#818cf8"), size * 0.02));
    p.drawPath(shield);

    p.setPen(QPen(Qt::white, size * 0.03));
    QFont f;
    f.setPixelSize(size * 0.55);
    f.setBold(true);
    p.setFont(f);
    p.drawText(pix.rect(), Qt::AlignCenter, "B");
    p.end();
    return pix;
}

AboutPage::AboutPage(QWidget* parent) : QWidget(parent)
{
    buildUi();
}

void AboutPage::buildUi()
{
    auto* mainLay = new QVBoxLayout(this);
    mainLay->setContentsMargins(32, 28, 32, 28);
    mainLay->setSpacing(16);

    // 顶部行：左上角返回按钮 + 标题
    auto* topRow = new QHBoxLayout();
    topRow->setSpacing(16);
    m_btnBack = new QPushButton("← 返回", this);
    m_btnBack->setObjectName("backBtn");
    m_btnBack->setCursor(Qt::PointingHandCursor);
    m_btnBack->setToolTip("返回主页");
    topRow->addWidget(m_btnBack);

    auto* titleLbl = new QLabel("关于", this);
    titleLbl->setObjectName("pageTitle");
    topRow->addWidget(titleLbl);
    topRow->addStretch(1);
    mainLay->addLayout(topRow);

    mainLay->addStretch(1);

    // 中部卡片：Logo + 软件名 + 版本 / 开发者
    auto* card = new QWidget(this);
    card->setObjectName("heroCard");
    card->setFixedWidth(460);
    auto* cardLay = new QVBoxLayout(card);
    cardLay->setContentsMargins(48, 40, 48, 40);
    cardLay->setSpacing(10);

    auto* logoLbl = new QLabel(card);
    logoLbl->setPixmap(MakeShieldPixmap(96));
    logoLbl->setAlignment(Qt::AlignCenter);
    cardLay->addWidget(logoLbl);
    cardLay->addSpacing(6);

    auto* nameLbl = new QLabel(QString::fromUtf8(kAppName), card);
    nameLbl->setObjectName("aboutName");
    nameLbl->setAlignment(Qt::AlignCenter);
    cardLay->addWidget(nameLbl);

    auto* versionLbl = new QLabel(QString("版本号：%1").arg(QString::fromUtf8(kAppVersion)), card);
    versionLbl->setObjectName("aboutText");
    versionLbl->setAlignment(Qt::AlignCenter);
    cardLay->addWidget(versionLbl);

    auto* devLbl = new QLabel(QString("开发者：%1").arg(QString::fromUtf8(kAppDev)), card);
    devLbl->setObjectName("aboutText");
    devLbl->setAlignment(Qt::AlignCenter);
    cardLay->addWidget(devLbl);

    auto* centerRow = new QHBoxLayout();
    centerRow->addStretch(1);
    centerRow->addWidget(card);
    centerRow->addStretch(1);
    mainLay->addLayout(centerRow);

    mainLay->addStretch(1);

    connect(m_btnBack, &QPushButton::clicked, this, &AboutPage::backToHome);
}
