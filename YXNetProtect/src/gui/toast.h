// BanJiu-Guard - 右下角拦截弹窗（Toast 通知）
// 特性：圆角、滑入动画、透明度渐变、自动消失、多分辨率/多DPI 自适应、堆叠
#pragma once

#include <QWidget>
#include <QString>
#include <QList>
#include <functional>

class QLabel;
class QPushButton;
class QPropertyAnimation;
class QVBoxLayout;

class Toast : public QWidget
{
    Q_OBJECT
public:
    // 主入口：弹出一个通知（自动定位到屏幕右下角）
    static void show(const QString& title, const QString& body,
                     const QString& actionText = QString());

    // 决策弹窗：手动模式下弹出"拦截/放过"双按钮，不自动消失
    // decision 回调参数：0=放过, 1=拦截
    static void showDecision(const QString& title, const QString& body,
                             std::function<void(int decision)> onDecision);

    // 移除全部
    static void dismissAll();

protected:
    void paintEvent(QPaintEvent* e) override;
    void enterEvent(QEnterEvent* e) override;
    void leaveEvent(QEvent* e) override;

private:
    Toast(const QString& title, const QString& body, const QString& actionText,
          bool decisionMode = false,
          std::function<void(int decision)> onDecision = nullptr);

    void startShowAnimation();
    void startHideAnimation();
    void reposition();          // 多分辨率自适应定位
    static void relayoutAll();

private slots:
    void onDismiss();
    void onAction();
    void onBlock();
    void onAllow();

private:
    QLabel* m_title = nullptr;
    QLabel* m_body = nullptr;
    QPushButton* m_action = nullptr;
    QPushButton* m_close = nullptr;
    QPushButton* m_blockBtn = nullptr;
    QPushButton* m_allowBtn = nullptr;
    QPropertyAnimation* m_anim = nullptr;
    bool m_hovered = false;
    bool m_decisionMode = false;
    std::function<void(int decision)> m_onDecision;

    static QList<Toast*> s_instances;
};
