// BanJiu-Guard - 隔离区页面
#pragma once

#include <QWidget>

class QListWidget;
class QPushButton;

namespace yx { class ProtectionService; }

class QuarantinePage : public QWidget
{
    Q_OBJECT
public:
    explicit QuarantinePage(yx::ProtectionService* svc, QWidget* parent = nullptr);

private slots:
    void refresh();
    void onRestore();
    void onDelete();

private:
    void buildUi();

    yx::ProtectionService* m_svc = nullptr;
    QListWidget* m_list = nullptr;
    QPushButton* m_btnRefresh = nullptr;
    QPushButton* m_btnRestore = nullptr;
    QPushButton* m_btnDelete = nullptr;
};
