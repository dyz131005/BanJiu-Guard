// BanJiu-Guard - 病毒扫描页面
#pragma once

#include <QWidget>
#include <QThread>
#include <QButtonGroup>
#include <QListWidget>
#include <QCheckBox>
#include <QProgressBar>
#include <QLabel>
#include <QPushButton>
#include <atomic>
#include <vector>
#include <algorithm>

class QLabel;
class QPushButton;
class QProgressBar;
class QListWidget;
class QCheckBox;
class QTreeWidgetItem;
class QTreeWidget;

namespace yx { class ProtectionService; }

// 威胁项数据
struct ThreatItem {
    QString filePath;
    QString reason;
    bool quarantined = false;
    bool deleted = false;
    bool allowed = false;
};

// 扫描工作线程
class ScanWorker : public QObject
{
    Q_OBJECT
public:
    explicit ScanWorker(QObject* parent = nullptr);
    void run(const QString& rootPath, const QString& quarantineDir = QString());
    void cancel();

signals:
    void progress(int percent, const QString& currentFile);
    void found(const QString& file, const QString& reason);
    void finished(int scanned, int found);

private:
    void scanDir(const QString& dir, const QString& qDir, int& scanned, int& found);
    bool isMalicious(const QString& path, QString& reason);

    std::atomic<bool> m_cancel{false};
};

// 威胁处理工作线程
class ThreatWorker : public QObject
{
    Q_OBJECT
public:
    explicit ThreatWorker(QObject* parent = nullptr) : QObject(parent) {}

    void run(yx::ProtectionService* svc,
             const std::vector<ThreatItem>& items,
             const std::vector<int>& indices,
             int action);  // 0=quarantine, 1=delete, 2=allow

    void cancel() { m_cancel = true; }

signals:
    void progress(int current, int total, const QString& currentFile);
    void itemDone(int index, bool success, const QString& msg);
    void finished(int processed, int success, int failed);

private:
    std::atomic<bool> m_cancel{false};
};

class ScanPage : public QWidget
{
    Q_OBJECT
public:
    explicit ScanPage(yx::ProtectionService* svc, QWidget* parent = nullptr);

private slots:
    void onStartScan();
    void onProgress(int p, const QString& f);
    void onFound(const QString& f, const QString& r);
    void onFinished(int scanned, int found);

    // 威胁处理
    void onQuarantineSelected();
    void onDeleteSelected();
    void onAllowSelected();
    void onThreatProgress(int cur, int total, const QString& file);
    void onThreatItemDone(int idx, bool ok, const QString& msg);
    void onThreatFinished(int processed, int success, int failed);

    // 返回/完成
    void onBackClicked();
    void onCompleteClicked();

    // 全选
    void onSelectAllChanged(int state);

private:
    void buildUi();
    void resetToIdle();
    void showResultsView();
    void showProcessingView();
    void showDoneView();
    void updateSelectAllState();

    // 获取选中的威胁索引
    std::vector<int> getSelectedIndices();

    yx::ProtectionService* m_svc = nullptr;
    QThread* m_thread = nullptr;
    ScanWorker* m_worker = nullptr;
    QThread* m_threatThread = nullptr;
    ThreatWorker* m_threatWorker = nullptr;

    // 扫描状态
    int m_scannedCount = 0;
    int m_foundCount = 0;
    std::vector<ThreatItem> m_threats;
    std::vector<QTreeWidgetItem*> m_threatItems;

    // 统计
    int m_quarantinedCount = 0;
    int m_deletedCount = 0;
    int m_allowedCount = 0;

    // UI - 扫描视图
    QWidget* m_scanView = nullptr;
    QPushButton* m_btnQuick = nullptr;
    QPushButton* m_btnFull = nullptr;
    QPushButton* m_btnCustom = nullptr;
    QButtonGroup* m_typeGroup = nullptr;
    QPushButton* m_btnStart = nullptr;
    QProgressBar* m_scanProgress = nullptr;
    QLabel* m_scanStatus = nullptr;

    // UI - 结果视图
    QWidget* m_resultsView = nullptr;
    QPushButton* m_btnBack = nullptr;
    QCheckBox* m_selectAll = nullptr;
    QTreeWidget* m_threatList = nullptr;
    QPushButton* m_btnQuarantine = nullptr;
    QPushButton* m_btnDelete = nullptr;
    QPushButton* m_btnAllow = nullptr;

    // UI - 处理视图
    QProgressBar* m_processProgress = nullptr;
    QLabel* m_processStatus = nullptr;

    // UI - 完成视图
    QWidget* m_doneView = nullptr;
    QLabel* m_doneLabel = nullptr;
    QPushButton* m_btnComplete = nullptr;
};
