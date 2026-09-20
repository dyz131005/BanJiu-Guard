// BanJiu-Guard - 安全日志页面
#pragma once

#include <QWidget>

class QListWidget;
class QPushButton;

namespace yx { class ProtectionService; }

class LogPage : public QWidget
{
    Q_OBJECT
public:
    explicit LogPage(yx::ProtectionService* svc, QWidget* parent = nullptr);

public slots:
    void appendLog(const QString& line);

private slots:
    void onClear();

private:
    void buildUi();

    yx::ProtectionService* m_svc = nullptr;
    QListWidget* m_list = nullptr;
    QPushButton* m_btnClear = nullptr;
};
