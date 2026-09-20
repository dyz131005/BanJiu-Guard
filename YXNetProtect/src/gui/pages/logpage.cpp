// BanJiu-Guard - 安全日志页面实现
#include "logpage.h"
#include "../../service/yx_service.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>

LogPage::LogPage(yx::ProtectionService* svc, QWidget* parent)
    : QWidget(parent), m_svc(svc)
{
    buildUi();
}

void LogPage::buildUi()
{
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(32, 28, 32, 28);
    lay->setSpacing(16);

    auto* header = new QLabel("安全日志", this);
    header->setObjectName("pageTitle");
    lay->addWidget(header);

    m_list = new QListWidget(this);
    m_list->setObjectName("resultList");
    lay->addWidget(m_list, 1);

    auto* bRow = new QHBoxLayout();
    m_btnClear = new QPushButton("清空日志", this);
    m_btnClear->setObjectName("secondaryBtn");
    bRow->addWidget(m_btnClear);
    bRow->addStretch(1);
    lay->addLayout(bRow);

    connect(m_btnClear, &QPushButton::clicked, this, &LogPage::onClear);
}

void LogPage::appendLog(const QString& line)
{
    m_list->addItem(line);
    m_list->scrollToBottom();
}

void LogPage::onClear()
{
    m_list->clear();
}
