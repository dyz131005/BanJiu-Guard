// BanJiu-Guard - 隔离区页面实现
#include "quarantinepage.h"
#include "../../service/yx_service.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>
#include <QDir>
#include <QFileInfo>

QuarantinePage::QuarantinePage(yx::ProtectionService* svc, QWidget* parent)
    : QWidget(parent), m_svc(svc)
{
    buildUi();
    refresh();
}

void QuarantinePage::buildUi()
{
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(32, 28, 32, 28);
    lay->setSpacing(16);

    auto* header = new QLabel("隔离区", this);
    header->setObjectName("pageTitle");
    lay->addWidget(header);

    auto* tip = new QLabel("被隔离的威胁文件会保存在安全位置，无法运行。", this);
    tip->setObjectName("hintText");
    lay->addWidget(tip);

    m_list = new QListWidget(this);
    m_list->setObjectName("resultList");
    lay->addWidget(m_list, 1);

    auto* bRow = new QHBoxLayout();
    m_btnRefresh = new QPushButton("刷新", this);
    m_btnRestore = new QPushButton("恢复", this);
    m_btnDelete = new QPushButton("彻底删除", this);
    m_btnRefresh->setObjectName("secondaryBtn");
    m_btnRestore->setObjectName("secondaryBtn");
    m_btnDelete->setObjectName("dangerBtn");
    m_btnRefresh->setCursor(Qt::PointingHandCursor);
    m_btnRestore->setCursor(Qt::PointingHandCursor);
    m_btnDelete->setCursor(Qt::PointingHandCursor);
    bRow->addWidget(m_btnRefresh);
    bRow->addWidget(m_btnRestore);
    bRow->addWidget(m_btnDelete);
    bRow->addStretch(1);
    lay->addLayout(bRow);

    connect(m_btnRefresh, &QPushButton::clicked, this, &QuarantinePage::refresh);
    connect(m_btnRestore, &QPushButton::clicked, this, &QuarantinePage::onRestore);
    connect(m_btnDelete, &QPushButton::clicked, this, &QuarantinePage::onDelete);
}

void QuarantinePage::refresh()
{
    m_list->clear();
    // 使用服务层管理的隔离目录（exe 所在目录下的 Quarantine）
    QString dir;
    if (m_svc) {
        dir = QString::fromStdWString(m_svc->GetQuarantineDir());
    } else {
        dir = QDir::currentPath() + "/Quarantine";
    }
    QDir qd(dir);
    if (!qd.exists()) {
        m_list->addItem("（隔离区为空）");
        return;
    }
    for (const auto& f : qd.entryList(QDir::Files)) {
        // 只显示 .quarantined 后缀的隔离文件，过滤掉 folder.jpg 等杂项
        if (!f.endsWith(".quarantined", Qt::CaseInsensitive)) continue;
        // 去掉 .quarantined 后缀，显示原始文件名
        QString displayName = f;
        displayName.chop(11);
        // 去掉末尾的点和空格（Windows 规范化可能产生的残留）
        while (displayName.endsWith('.') || displayName.endsWith(' ')) {
            displayName.chop(1);
        }
        auto* item = new QListWidgetItem(displayName);
        // 保存实际文件名（可能含双点等），用于恢复/删除时准确定位
        item->setData(Qt::UserRole, f);
        m_list->addItem(item);
    }
    if (m_list->count() == 0) {
        m_list->addItem("（隔离区为空）");
    }
}

void QuarantinePage::onRestore()
{
    auto* item = m_list->currentItem();
    if (!item) return;
    QString text = item->text();
    if (text == "（隔离区为空）") return;
    // 使用保存的实际文件名（含 .quarantined 后缀）
    QString actualName = item->data(Qt::UserRole).toString();
    if (actualName.isEmpty()) actualName = text + ".quarantined";
    // RestoreFile 接收实际隔离文件名，内部会自动处理后缀和规范化
    if (m_svc) m_svc->RestoreFile(actualName.toStdWString());
    refresh();
}

void QuarantinePage::onDelete()
{
    auto* item = m_list->currentItem();
    if (!item) return;
    QString text = item->text();
    if (text == "（隔离区为空）") return;
    // 使用保存的实际文件名（含 .quarantined 后缀）
    QString actualName = item->data(Qt::UserRole).toString();
    if (actualName.isEmpty()) actualName = text + ".quarantined";
    // 通过驱动 IOCTL 执行强制删除（绕过自身 minifilter 拦截）
    if (m_svc) {
        QString dir = QString::fromStdWString(m_svc->GetQuarantineDir());
        std::wstring qPath = dir.toStdWString() + L"\\" + actualName.toStdWString();
        m_svc->ForceDeleteFile(qPath);
    } else {
        QString dir = QDir::currentPath() + "/Quarantine";
        QFile::remove(dir + "/" + actualName);
    }
    refresh();
}
