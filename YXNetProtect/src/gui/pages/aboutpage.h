// BanJiu-Guard - 关于页面
#pragma once

#include <QWidget>

class QPushButton;

class AboutPage : public QWidget
{
    Q_OBJECT
public:
    explicit AboutPage(QWidget* parent = nullptr);

signals:
    // 点击左上角"返回"按钮时发出，主窗口据此切回主页（仪表盘）
    void backToHome();

private:
    void buildUi();

    QPushButton* m_btnBack = nullptr;
};
