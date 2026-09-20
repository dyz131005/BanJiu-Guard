// BanJiu-Guard - 右下角弹窗实现
#include "toast.h"
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QScreen>
#include <QGuiApplication>
#include <QTimer>
#include <QApplication>
#include <QPainter>
#include <QPainterPath>
#include <QLinearGradient>

QList<Toast*> Toast::s_instances;

Toast::Toast(const QString& title, const QString& body, const QString& actionText,
             bool decisionMode, std::function<void(int decision)> onDecision)
    : QWidget(nullptr)
    , m_decisionMode(decisionMode)
    , m_onDecision(std::move(onDecision))
{
    setObjectName("toastCard");
    // 决策弹窗加大宽度以容纳双按钮和详细信息
    const int cardWidth = decisionMode ? 480 : 360;
    setFixedWidth(cardWidth);
    setAttribute(Qt::WA_TranslucentBackground);
    setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);

    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(20, 16, 20, 16);
    lay->setSpacing(8);

    // 顶部：标题 + 关闭
    auto* top = new QHBoxLayout();
    m_title = new QLabel(title, this);
    m_title->setObjectName("toastTitle");
    m_title->setWordWrap(true);

    m_close = new QPushButton("×", this);
    m_close->setObjectName("toastClose");
    m_close->setFixedSize(24, 24);
    m_close->setCursor(Qt::PointingHandCursor);
    connect(m_close, &QPushButton::clicked, this, &Toast::onDismiss);

    top->addWidget(m_title, 1);
    top->addWidget(m_close, 0, Qt::AlignTop);
    lay->addLayout(top);

    // 正文
    m_body = new QLabel(body, this);
    m_body->setObjectName("toastBody");
    m_body->setWordWrap(true);
    lay->addWidget(m_body);

    if (decisionMode) {
        // 决策模式：拦截 + 放过 双按钮
        auto* btnRow = new QHBoxLayout();
        btnRow->setSpacing(12);

        m_allowBtn = new QPushButton("放过", this);
        m_allowBtn->setObjectName("toastAllowBtn");
        m_allowBtn->setFixedHeight(34);
        m_allowBtn->setCursor(Qt::PointingHandCursor);
        connect(m_allowBtn, &QPushButton::clicked, this, &Toast::onAllow);

        m_blockBtn = new QPushButton("拦截", this);
        m_blockBtn->setObjectName("toastBlockBtn");
        m_blockBtn->setFixedHeight(34);
        m_blockBtn->setCursor(Qt::PointingHandCursor);
        connect(m_blockBtn, &QPushButton::clicked, this, &Toast::onBlock);

        btnRow->addStretch(1);
        btnRow->addWidget(m_allowBtn);
        btnRow->addWidget(m_blockBtn);
        lay->addLayout(btnRow);
    } else {
        // 普通模式：单个操作按钮
        if (!actionText.isEmpty()) {
            auto* btnRow = new QHBoxLayout();
            btnRow->addStretch(1);
            m_action = new QPushButton(actionText, this);
            m_action->setObjectName("toastAction");
            m_action->setCursor(Qt::PointingHandCursor);
            connect(m_action, &QPushButton::clicked, this, &Toast::onAction);
            btnRow->addWidget(m_action);
            lay->addLayout(btnRow);
        }
    }

    adjustSize();
    setFixedWidth(cardWidth);

    // 透明效果
    auto* effect = new QGraphicsOpacityEffect(this);
    effect->setOpacity(0.0);
    setGraphicsEffect(effect);

    s_instances.append(this);
    reposition();
    QWidget::show();

    // 延迟启动进来动画
    QTimer::singleShot(30, this, [this] { startShowAnimation(); });

    // 决策弹窗不自动消失，等待用户操作
    if (!decisionMode) {
        QTimer::singleShot(6000, this, [this] {
            if (!m_hovered) startHideAnimation();
        });
    }

    relayoutAll();
}

void Toast::show(const QString& title, const QString& body, const QString& actionText)
{
    new Toast(title, body, actionText, false, nullptr);
}

void Toast::showDecision(const QString& title, const QString& body,
                         std::function<void(int decision)> onDecision)
{
    new Toast(title, body, QString(), true, std::move(onDecision));
}

void Toast::dismissAll()
{
    auto list = s_instances;
    for (auto* t : list) {
        if (t) t->startHideAnimation();
    }
}

void Toast::startShowAnimation()
{
    if (m_anim) { m_anim->stop(); m_anim->deleteLater(); }

    // 从右下角滑入
    auto* effect = qobject_cast<QGraphicsOpacityEffect*>(graphicsEffect());
    m_anim = new QPropertyAnimation(effect, "opacity", this);
    m_anim->setDuration(220);
    m_anim->setStartValue(0.0);
    m_anim->setEndValue(1.0);
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    m_anim->start(QAbstractAnimation::DeleteWhenStopped);
    m_anim = nullptr;
}

void Toast::startHideAnimation()
{
    auto* effect = qobject_cast<QGraphicsOpacityEffect*>(graphicsEffect());
    auto* anim = new QPropertyAnimation(effect, "opacity", this);
    anim->setDuration(180);
    anim->setStartValue(effect ? effect->opacity() : 1.0);
    anim->setEndValue(0.0);
    anim->setEasingCurve(QEasingCurve::InCubic);
    connect(anim, &QPropertyAnimation::finished, this, [this] {
        s_instances.removeAll(this);
        deleteLater();
        relayoutAll();
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void Toast::reposition()
{
    QScreen* scr = QGuiApplication::primaryScreen();
    if (!scr) return;
    QRect avail = scr->availableGeometry();
    move(avail.right() - width() - 16, avail.bottom() - height() - 16);
}

void Toast::relayoutAll()
{
    QScreen* scr = QGuiApplication::primaryScreen();
    if (!scr) return;
    QRect avail = scr->availableGeometry();

    int y = avail.bottom() - 16;
    for (auto* t : s_instances) {
        if (!t) continue;
        y -= t->height() + 10;
        t->move(avail.right() - t->width() - 16, y);
    }
}

void Toast::paintEvent(QPaintEvent*)
{
    // 顶层窗口开启了 WA_TranslucentBackground，QSS 的 background 不会自动绘制，
    // 这里手动画出圆角卡片背景（与 style.qss 中 #toastCard 保持一致）
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    QRectF rect = this->rect();
    qreal radius = 14.0;

    QLinearGradient grad(rect.topLeft(), rect.topRight());
    grad.setColorAt(0.0, QColor(0x23, 0x28, 0x3c));
    grad.setColorAt(1.0, QColor(0x1c, 0x20, 0x30));

    QPainterPath path;
    path.addRoundedRect(rect, radius, radius);
    p.fillPath(path, grad);

    // 边框：红色微光
    QPen pen(QColor(255, 82, 82, 102));  // rgba(255,82,82,0.4)
    pen.setWidth(1);
    p.setPen(pen);
    p.drawPath(path);
}

void Toast::enterEvent(QEnterEvent* e)
{
    m_hovered = true;
    QWidget::enterEvent(e);
}

void Toast::leaveEvent(QEvent* e)
{
    m_hovered = false;
    QWidget::leaveEvent(e);
    // 决策弹窗不自动消失，等待用户点击按钮
    if (m_decisionMode) return;
    QTimer::singleShot(3000, this, [this] {
        if (!m_hovered) startHideAnimation();
    });
}

void Toast::onDismiss() { startHideAnimation(); }
void Toast::onAction()  { startHideAnimation(); }

void Toast::onBlock()
{
    if (m_onDecision) m_onDecision(1);  // 拦截
    startHideAnimation();
}

void Toast::onAllow()
{
    if (m_onDecision) m_onDecision(0);  // 放过
    startHideAnimation();
}
