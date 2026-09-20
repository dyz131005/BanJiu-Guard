// BanJiu-Guard - 病毒扫描页面实现
#include "scanpage.h"
#include "../../service/yx_service.h"
#include "../../common/yx_rules.h"
#include "../../common/yx_heuristic.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QCheckBox>
#include <QFileDialog>
#include <QDirIterator>
#include <QFileInfo>
#include <QFile>
#include <QStackedLayout>
#include <QMessageBox>
#include <QHeaderView>
#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <mutex>

extern "C" void YxWriteCrashLog(const wchar_t* msg);

static QString ComputeSha1(const QString& filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) return QString();

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    QString result;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        f.close();
        return result;
    }
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        f.close();
        return result;
    }

    QByteArray buf;
    while (!f.atEnd()) {
        buf = f.read(1024 * 1024);
        if (!CryptHashData(hHash, (BYTE*)buf.constData(), (DWORD)buf.size(), 0)) {
            break;
        }
    }

    DWORD hashSize = 0;
    DWORD len = sizeof(DWORD);
    if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &len, 0) && hashSize > 0) {
        QByteArray hashBuf(hashSize, 0);
        DWORD hashLen = hashSize;
        if (CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hashBuf.data(), &hashLen, 0)) {
            result = QString::fromLatin1(hashBuf.toHex());
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    f.close();
    return result;
}

static QString ComputeMd5(const QString& filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) return QString();

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    QString result;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        f.close();
        return result;
    }
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        f.close();
        return result;
    }

    QByteArray buf;
    while (!f.atEnd()) {
        buf = f.read(1024 * 1024);
        if (!CryptHashData(hHash, (BYTE*)buf.constData(), (DWORD)buf.size(), 0)) {
            break;
        }
    }

    DWORD hashSize = 0;
    DWORD len = sizeof(DWORD);
    if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &len, 0) && hashSize > 0) {
        QByteArray hashBuf(hashSize, 0);
        DWORD hashLen = hashSize;
        if (CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hashBuf.data(), &hashLen, 0)) {
            result = QString::fromLatin1(hashBuf.toHex());
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    f.close();
    return result;
}

// 威胁处理过程日志写入文件（独立于 UI 日志窗口），便于在 UI 卡死时排查
// 路径：C:\BanJiu\threat_process.log
static std::wstring ThreatLogFile()
{
    wchar_t exeBuf[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
    std::wstring dir(exeBuf);
    auto pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) dir = dir.substr(0, pos);
    else dir = L"C:\\BanJiu";
    return dir + L"\\threat_process.log";
}

static void ThreatLog(const std::wstring& msg)
{
    static std::mutex s_logMutex;
    std::lock_guard<std::mutex> lk(s_logMutex);
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, ThreatLogFile().c_str(), L"a, ccs=UTF-8") == 0 && fp) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fwprintf(fp, L"[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        fputws(msg.c_str(), fp);
        fputws(L"\n", fp);
        fclose(fp);
    }
}

// ---------------- ScanWorker ----------------
ScanWorker::ScanWorker(QObject* parent) : QObject(parent) {}

void ScanWorker::cancel() { m_cancel = true; }
void ScanWorker::run(const QString& rootPath, const QString& quarantineDir)
{
    m_cancel = false;
    int scanned = 0, found = 0;
    QString qDir = quarantineDir;
    if (!qDir.isEmpty()) {
        qDir = QDir(qDir).absolutePath();
        qDir = QDir::toNativeSeparators(qDir).toLower();
    }
    scanDir(rootPath, qDir, scanned, found);
    emit finished(scanned, found);
}

void ScanWorker::scanDir(const QString& dir, const QString& qDir, int& scanned, int& found)
{
    if (m_cancel) return;
    QDirIterator it(dir, QDir::Files | QDir::NoSymLinks,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        if (m_cancel) return;
        QString f = it.next();
        // 跳过隔离区目录下的文件（防止二次隔离）
        if (!qDir.isEmpty()) {
            QString nativeF = QDir::toNativeSeparators(f).toLower();
            if (nativeF.startsWith(qDir)) continue;
        }
        // 跳过 .quarantined 后缀的文件
        if (f.endsWith(".quarantined", Qt::CaseInsensitive)) continue;
        QString reason;
        if (isMalicious(f, reason)) {
            ++found;
            emit ScanWorker::found(f, reason);
        }
        ++scanned;
        if (scanned % 20 == 0) {
            emit progress((scanned % 100), f);
        }
    }
}

bool ScanWorker::isMalicious(const QString& path, QString& reason)
{
    QFileInfo fi(path);
    QString n = fi.fileName().toLower();
    yx::RulesEngine rules;

    // 1. MEMZ 彩虹猫病毒文件名特征
    if (rules.IsMemzName(n.toStdWString())) {
        reason = "命中 MEMZ 彩虹猫病毒文件名特征（Deltree Trojan）";
        return true;
    }

    // 2. 文件名特征匹配（银狐诱饵关键词）
    static const char* kws[] = {
        "资金统计", "税务稽查", "税务通知", "315曝光", "放假安排",
        "补贴申领", "工资明细", "starrailbase.dll", "starrailbase.exe"
    };
    for (auto* k : kws) {
        if (n.contains(QString::fromUtf8(k).toLower())) {
            reason = "命中银狐木马文件名特征";
            return true;
        }
    }

    // 3. MD5 哈希特征库匹配
    QString md5 = ComputeMd5(path);
    if (!md5.isEmpty()) {
        auto hit = rules.CheckMd5(md5.toStdWString(), path.toStdWString());
        if (hit) {
            reason = QString::fromStdWString(hit->description);
            return true;
        }
    }

    // 4. SHA1 哈希特征库匹配
    QString sha1 = ComputeSha1(path);
    if (!sha1.isEmpty()) {
        auto hit = rules.CheckHash(sha1.toStdWString(), path.toStdWString());
        if (hit) {
            reason = QString::fromStdWString(hit->description);
            return true;
        }
    }

    // 5. 启发式扫描（PE 结构分析）
    yx::HeuristicEngine heuristic;
    auto hr = heuristic.ScanFile(path.toStdWString());
    if (hr.suspicious) {
        reason = QString("启发式检测可疑文件（威胁分数 %1/100）：%2")
                     .arg(hr.score)
                     .arg(QString::fromStdString(hr.reason));
        return true;
    }

    return false;
}

// ---------------- ThreatWorker ----------------
void ThreatWorker::run(yx::ProtectionService* svc,
                       const std::vector<ThreatItem>& items,
                       const std::vector<int>& indices,
                       int action)
{
    YxWriteCrashLog(L"[ThreatWorker] run entry");
    m_cancel = false;
    int total = (int)items.size();
    int success = 0, failed = 0;

    const wchar_t* actionName = L"unknown";
    if (action == 0) actionName = L"quarantine";
    else if (action == 1) actionName = L"delete";
    else if (action == 2) actionName = L"allow";

    YxWriteCrashLog((L"[ThreatWorker] action=" + std::wstring(actionName) +
                     L", total=" + std::to_wstring(total) +
                     L", svc=" + std::to_wstring((uintptr_t)svc)).c_str());

    ThreatLog(L"========== Threat process start: action=" + std::wstring(actionName) +
              L", total=" + std::to_wstring(total) + L" ==========");

    for (int i = 0; i < total; i++) {
        if (m_cancel) {
            ThreatLog(L"User cancelled, processed " + std::to_wstring(i) + L"/" + std::to_wstring(total));
            break;
        }

        const ThreatItem& item = items[i];
        // 使用原始索引，避免 UI 层改错行
        int origIdx = (i < (int)indices.size()) ? indices[i] : i;

        // progress 每 20 项上报一次，避免 UI 事件风暴
        if (i % 20 == 0 || i == total - 1) {
            emit progress(i + 1, total, item.filePath);
        }

        std::wstring wpath = item.filePath.toStdWString();
        ThreatLog(L"[" + std::to_wstring(i + 1) + L"/" + std::to_wstring(total) + L"] " +
                  L"action=" + actionName + L", path=" + wpath);

        bool ok = false;
        QString msg;

        if (action == 2) {
            // 放过
            ok = true;
            msg = "Allowed";
            ThreatLog(L"  -> Allowed");
        } else {
            // 先检查是否有对应进程，有的话先终止
            DWORD t0 = GetTickCount();
            DWORD pid = svc->FindProcessByPath(wpath);
            DWORD t1 = GetTickCount();
            ThreatLog(L"  FindProcessByPath elapsed " + std::to_wstring(t1 - t0) +
                      L"ms, pid=" + std::to_wstring(pid));

            if (pid != 0) {
                t0 = GetTickCount();
                bool killed = svc->KillProcessByPid(pid);
                t1 = GetTickCount();
                ThreatLog(L"  KillProcessByPid elapsed " + std::to_wstring(t1 - t0) +
                          L"ms, ok=" + std::to_wstring(killed));

                // 等待进程退出（缩短为最多 1.5 秒）
                DWORD waitStart = GetTickCount();
                for (int w = 0; w < 15; w++) {
                    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
                    if (!h) break;
                    DWORD r = WaitForSingleObject(h, 100);
                    CloseHandle(h);
                    if (r == WAIT_OBJECT_0) break;
                }
                ThreatLog(L"  Wait process exit elapsed " +
                          std::to_wstring(GetTickCount() - waitStart) + L"ms");
            }

            if (action == 0) {
                // 隔离
                t0 = GetTickCount();
                ok = svc->ForceQuarantineFile(wpath);
                t1 = GetTickCount();
                ThreatLog(L"  ForceQuarantineFile elapsed " + std::to_wstring(t1 - t0) +
                          L"ms, ok=" + std::to_wstring(ok));
                msg = ok ? "Quarantined" : "Quarantine failed";
            } else if (action == 1) {
                // 强制删除
                t0 = GetTickCount();
                ok = svc->ForceDeleteFile(wpath);
                t1 = GetTickCount();
                ThreatLog(L"  ForceDeleteFile elapsed " + std::to_wstring(t1 - t0) +
                          L"ms, ok=" + std::to_wstring(ok));
                msg = ok ? "Deleted" : "Delete failed";
            }
        }

        if (ok) success++; else failed++;
        emit itemDone(origIdx, ok, msg);
    }

    YxWriteCrashLog((L"[ThreatWorker] Loop finished, emit finished. success=" +
                     std::to_wstring(success) + L", failed=" + std::to_wstring(failed)).c_str());
    ThreatLog(L"========== Threat process end: success=" + std::to_wstring(success) +
              L", failed=" + std::to_wstring(failed) + L" ==========\n");
    emit finished(total, success, failed);
    YxWriteCrashLog(L"[ThreatWorker] run return normally");
}

// ---------------- ScanPage ----------------
ScanPage::ScanPage(yx::ProtectionService* svc, QWidget* parent)
    : QWidget(parent), m_svc(svc)
{
    buildUi();
}

void ScanPage::buildUi()
{
    auto* mainLay = new QVBoxLayout(this);
    mainLay->setContentsMargins(0, 0, 0, 0);
    mainLay->setSpacing(0);

    // 使用 QStackedLayout 切换不同视图
    auto* stack = new QStackedLayout();
    mainLay->addLayout(stack);

    // === 扫描视图 ===
    m_scanView = new QWidget(this);
    auto* scanLay = new QVBoxLayout(m_scanView);
    scanLay->setContentsMargins(32, 28, 32, 28);
    scanLay->setSpacing(16);

    auto* header = new QLabel("病毒扫描", m_scanView);
    header->setObjectName("pageTitle");
    scanLay->addWidget(header);

    auto* typeRow = new QHBoxLayout();
    m_btnQuick = new QPushButton("快速扫描", m_scanView);
    m_btnFull = new QPushButton("全盘扫描", m_scanView);
    m_btnCustom = new QPushButton("自定义扫描", m_scanView);
    m_btnQuick->setObjectName("segBtn");
    m_btnFull->setObjectName("segBtn");
    m_btnCustom->setObjectName("segBtn");
    m_btnQuick->setCheckable(true);
    m_btnFull->setCheckable(true);
    m_btnCustom->setCheckable(true);

    m_typeGroup = new QButtonGroup(this);
    m_typeGroup->setExclusive(true);
    m_typeGroup->addButton(m_btnQuick, 0);
    m_typeGroup->addButton(m_btnFull, 1);
    m_typeGroup->addButton(m_btnCustom, 2);
    m_btnQuick->setChecked(true);
    typeRow->addWidget(m_btnQuick);
    typeRow->addWidget(m_btnFull);
    typeRow->addWidget(m_btnCustom);
    typeRow->addStretch(1);
    scanLay->addLayout(typeRow);

    m_scanProgress = new QProgressBar(m_scanView);
    m_scanProgress->setObjectName("scanProgress");
    m_scanProgress->setRange(0, 100);
    m_scanProgress->setValue(0);
    scanLay->addWidget(m_scanProgress);

    m_scanStatus = new QLabel("就绪", m_scanView);
    m_scanStatus->setObjectName("scanStatus");
    scanLay->addWidget(m_scanStatus);

    auto* bRow = new QHBoxLayout();
    m_btnStart = new QPushButton("开始扫描", m_scanView);
    m_btnStart->setObjectName("primaryBtn");
    m_btnStart->setCursor(Qt::PointingHandCursor);
    bRow->addWidget(m_btnStart);
    bRow->addStretch(1);
    scanLay->addLayout(bRow);
    scanLay->addStretch(1);

    stack->addWidget(m_scanView);

    // === 结果视图 ===
    m_resultsView = new QWidget(this);
    auto* resLay = new QVBoxLayout(m_resultsView);
    resLay->setContentsMargins(32, 28, 32, 28);
    resLay->setSpacing(16);

    // 顶部行：返回箭头 + 标题
    auto* topRow = new QHBoxLayout();
    m_btnBack = new QPushButton(m_resultsView);
    m_btnBack->setText("←");
    m_btnBack->setObjectName("backBtn");
    m_btnBack->setFixedSize(40, 40);
    m_btnBack->setCursor(Qt::PointingHandCursor);
    auto* titleLbl = new QLabel("发现威胁", m_resultsView);
    titleLbl->setObjectName("pageTitle");
    topRow->addWidget(m_btnBack);
    topRow->addWidget(titleLbl);
    topRow->addStretch(1);
    resLay->addLayout(topRow);

    // 全选复选框
    m_selectAll = new QCheckBox("全选", m_resultsView);
    resLay->addWidget(m_selectAll);

    // 威胁列表（带复选框的 TreeWidget）
    m_threatList = new QTreeWidget(m_resultsView);
    m_threatList->setObjectName("resultList");
    m_threatList->setColumnCount(3);
    m_threatList->setHeaderLabels({"威胁", "路径", "状态"});
    m_threatList->header()->setStretchLastSection(false);
    m_threatList->header()->setSectionResizeMode(0, QHeaderView::Interactive);
    m_threatList->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_threatList->header()->setSectionResizeMode(2, QHeaderView::Interactive);
    m_threatList->header()->resizeSection(0, 200);
    m_threatList->header()->resizeSection(2, 80);
    resLay->addWidget(m_threatList, 1);

    // 处理进度（初始隐藏，在处理阶段显示）
    m_processProgress = new QProgressBar(m_resultsView);
    m_processProgress->setObjectName("scanProgress");
    m_processProgress->setRange(0, 100);
    m_processProgress->setValue(0);
    m_processProgress->setVisible(false);
    resLay->addWidget(m_processProgress);

    m_processStatus = new QLabel(m_resultsView);
    m_processStatus->setObjectName("scanStatus");
    m_processStatus->setVisible(false);
    resLay->addWidget(m_processStatus);

    // 底部操作按钮
    auto* actRow = new QHBoxLayout();
    m_btnQuarantine = new QPushButton("隔离已选威胁", m_resultsView);
    m_btnQuarantine->setObjectName("primaryBtn");
    m_btnQuarantine->setCursor(Qt::PointingHandCursor);
    m_btnDelete = new QPushButton("强制删除已选威胁", m_resultsView);
    m_btnDelete->setObjectName("dangerBtn");
    m_btnDelete->setCursor(Qt::PointingHandCursor);
    m_btnAllow = new QPushButton("放过已选威胁", m_resultsView);
    m_btnAllow->setObjectName("secondaryBtn");
    m_btnAllow->setCursor(Qt::PointingHandCursor);
    actRow->addWidget(m_btnQuarantine);
    actRow->addWidget(m_btnDelete);
    actRow->addWidget(m_btnAllow);
    actRow->addStretch(1);
    resLay->addLayout(actRow);

    stack->addWidget(m_resultsView);

    // === 完成视图 ===
    m_doneView = new QWidget(this);
    auto* doneLay = new QVBoxLayout(m_doneView);
    doneLay->setContentsMargins(32, 28, 32, 28);
    doneLay->setSpacing(16);
    doneLay->addStretch(1);

    auto* doneTitle = new QLabel("处理完成", m_doneView);
    doneTitle->setObjectName("pageTitle");
    doneTitle->setAlignment(Qt::AlignCenter);
    doneLay->addWidget(doneTitle);

    m_doneLabel = new QLabel(m_doneView);
    m_doneLabel->setObjectName("scanStatus");
    m_doneLabel->setAlignment(Qt::AlignCenter);
    doneLay->addWidget(m_doneLabel);

    doneLay->addStretch(1);
    auto* doneBtnRow = new QHBoxLayout();
    doneBtnRow->addStretch(1);
    m_btnComplete = new QPushButton("完成", m_doneView);
    m_btnComplete->setObjectName("primaryBtn");
    m_btnComplete->setCursor(Qt::PointingHandCursor);
    doneBtnRow->addWidget(m_btnComplete);
    doneBtnRow->addStretch(1);
    doneLay->addLayout(doneBtnRow);
    doneLay->addStretch(1);

    stack->addWidget(m_doneView);

    // 信号连接
    connect(m_btnStart, &QPushButton::clicked, this, &ScanPage::onStartScan);
    connect(m_btnBack, &QPushButton::clicked, this, &ScanPage::onBackClicked);
    connect(m_btnComplete, &QPushButton::clicked, this, &ScanPage::onCompleteClicked);
    connect(m_selectAll, &QCheckBox::stateChanged, this, &ScanPage::onSelectAllChanged);
    connect(m_btnQuarantine, &QPushButton::clicked, this, &ScanPage::onQuarantineSelected);
    connect(m_btnDelete, &QPushButton::clicked, this, &ScanPage::onDeleteSelected);
    connect(m_btnAllow, &QPushButton::clicked, this, &ScanPage::onAllowSelected);

    resetToIdle();
}

void ScanPage::resetToIdle()
{
    m_threats.clear();
    m_threatItems.clear();
    m_scannedCount = 0;
    m_foundCount = 0;
    m_quarantinedCount = 0;
    m_deletedCount = 0;
    m_allowedCount = 0;
    m_threatList->clear();
    m_scanProgress->setValue(0);
    m_scanStatus->setText("就绪");
    m_btnStart->setEnabled(true);
    m_btnStart->setText("开始扫描");

    // 切换到扫描视图
    auto* stack = qobject_cast<QStackedLayout*>(layout()->itemAt(0)->layout());
    if (stack) stack->setCurrentWidget(m_scanView);
}

void ScanPage::showResultsView()
{
    auto* stack = qobject_cast<QStackedLayout*>(layout()->itemAt(0)->layout());
    if (stack) stack->setCurrentWidget(m_resultsView);

    // 隐藏处理进度
    m_processProgress->setVisible(false);
    m_processStatus->setVisible(false);
    // 显示操作按钮
    m_btnQuarantine->setVisible(true);
    m_btnDelete->setVisible(true);
    m_btnAllow->setVisible(true);
    m_selectAll->setEnabled(true);
    m_threatList->setEnabled(true);
}

void ScanPage::showProcessingView()
{
    // 在结果视图上叠加处理进度
    m_processProgress->setVisible(true);
    m_processStatus->setVisible(true);
    m_btnQuarantine->setEnabled(false);
    m_btnDelete->setEnabled(false);
    m_btnAllow->setEnabled(false);
    m_selectAll->setEnabled(false);
    m_threatList->setEnabled(false);
}

void ScanPage::showDoneView()
{
    auto* stack = qobject_cast<QStackedLayout*>(layout()->itemAt(0)->layout());
    if (stack) stack->setCurrentWidget(m_doneView);

    m_doneLabel->setText(
        QString("扫描完成：共 %1 个文件，发现 %2 个威胁\n"
                "隔离 %3 个 | 删除 %4 个 | 放过 %5 个")
            .arg(m_scannedCount)
            .arg(m_foundCount)
            .arg(m_quarantinedCount)
            .arg(m_deletedCount)
            .arg(m_allowedCount));
}

void ScanPage::updateSelectAllState()
{
    bool allChecked = true;
    for (int i = 0; i < m_threatList->topLevelItemCount(); i++) {
        auto* item = m_threatList->topLevelItem(i);
        if (item->checkState(0) != Qt::Checked) {
            allChecked = false;
            break;
        }
    }
    // 阻止信号递归
    m_selectAll->blockSignals(true);
    m_selectAll->setCheckState(allChecked ? Qt::Checked : Qt::Unchecked);
    m_selectAll->blockSignals(false);
}

std::vector<int> ScanPage::getSelectedIndices()
{
    std::vector<int> indices;
    for (int i = 0; i < m_threatList->topLevelItemCount(); i++) {
        auto* item = m_threatList->topLevelItem(i);
        if (item->checkState(0) == Qt::Checked) {
            indices.push_back(i);
        }
    }
    return indices;
}

// ---- 扫描 ----
void ScanPage::onStartScan()
{
    if (m_thread) return;

    QString root = "C:\\Users\\" + QString(qgetenv("USERNAME"));
    if (m_btnFull->isChecked()) root = "C:\\";
    else if (m_btnCustom->isChecked()) {
        root = QFileDialog::getExistingDirectory(this, "选择扫描目录", "C:\\");
        if (root.isEmpty()) return;
    }

    m_threats.clear();
    m_threatList->clear();
    m_selectAll->setCheckState(Qt::Unchecked);
    m_scannedCount = 0;
    m_foundCount = 0;

    m_thread = new QThread(this);
    m_worker = new ScanWorker();
    m_worker->moveToThread(m_thread);

    connect(m_thread, &QThread::started, m_worker, [this, root] {
        QString qDir;
        if (m_svc) qDir = QString::fromStdWString(m_svc->GetQuarantineDir());
        m_worker->run(root, qDir);
    });
    connect(m_worker, &ScanWorker::progress, this, &ScanPage::onProgress);
    connect(m_worker, &ScanWorker::found, this, &ScanPage::onFound);
    connect(m_worker, &ScanWorker::finished, this, &ScanPage::onFinished);
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);

    m_thread->start();
    m_scanStatus->setText("正在扫描 " + root + " ...");
    m_btnStart->setEnabled(false);
}

void ScanPage::onProgress(int p, const QString& f)
{
    m_scanProgress->setValue(p);
    m_scanStatus->setText("正在扫描：" + f);
}

void ScanPage::onFound(const QString& f, const QString& r)
{
    ThreatItem item;
    item.filePath = f;
    item.reason = r;
    m_threats.push_back(item);
    m_foundCount++;

    auto* treeItem = new QTreeWidgetItem(m_threatList);
    treeItem->setFlags(treeItem->flags() | Qt::ItemIsUserCheckable);
    treeItem->setCheckState(0, Qt::Unchecked);
    treeItem->setText(0, r);
    treeItem->setText(1, f);
    treeItem->setText(2, "待处理");
    m_threatItems.push_back(treeItem);
}

void ScanPage::onFinished(int scanned, int found)
{
    m_scannedCount = scanned;
    m_foundCount = found;
    m_scanProgress->setValue(100);

    if (m_thread) {
        m_thread->quit();
        m_thread->wait();
        m_thread->deleteLater();
        m_thread = nullptr;
    }

    if (found == 0) {
        // 无威胁，回到扫描视图显示结果
        m_scanStatus->setText(QString("扫描完成：共 %1 个文件，未发现威胁").arg(scanned));
        m_btnStart->setEnabled(true);
        m_btnStart->setText("重新扫描");
    } else {
        // 切换到结果视图
        showResultsView();
    }
}

// ---- 威胁处理 ----
void ScanPage::onQuarantineSelected()
{
    YxWriteCrashLog(L"[ScanPage] onQuarantineSelected entry");
    auto indices = getSelectedIndices();
    if (indices.empty()) { YxWriteCrashLog(L"[ScanPage] onQuarantineSelected no selection, return"); return; }
    YxWriteCrashLog((L"[ScanPage] onQuarantineSelected selected count=" + std::to_wstring(indices.size())).c_str());

    std::vector<ThreatItem> selected;
    for (int idx : indices) selected.push_back(m_threats[idx]);

    showProcessingView();
    m_processProgress->setRange(0, (int)selected.size());
    m_processProgress->setValue(0);
    m_processStatus->setText("Processing threats...");

    YxWriteCrashLog(L"[ScanPage] onQuarantineSelected create thread");
    m_threatThread = new QThread(this);
    m_threatWorker = new ThreatWorker();
    m_threatWorker->moveToThread(m_threatThread);

    connect(m_threatThread, &QThread::started, m_threatWorker,
            [this, selected, indices] { m_threatWorker->run(m_svc, selected, indices, 0); });
    connect(m_threatWorker, &ThreatWorker::progress, this, &ScanPage::onThreatProgress);
    connect(m_threatWorker, &ThreatWorker::itemDone, this, &ScanPage::onThreatItemDone);
    connect(m_threatWorker, &ThreatWorker::finished, this, &ScanPage::onThreatFinished);
    connect(m_threatThread, &QThread::finished, m_threatWorker, &QObject::deleteLater);

    YxWriteCrashLog(L"[ScanPage] onQuarantineSelected start thread");
    m_threatThread->start();
    YxWriteCrashLog(L"[ScanPage] onQuarantineSelected thread started");
}

void ScanPage::onDeleteSelected()
{
    auto indices = getSelectedIndices();
    if (indices.empty()) return;

    // 确认弹窗
    auto* msgBox = new QMessageBox(this);
    msgBox->setIcon(QMessageBox::Warning);
    msgBox->setWindowTitle("确认强制删除");
    msgBox->setText(QString("确认强制删除 %1 个威胁文件？\n此操作不可撤销！").arg(indices.size()));
    msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox->setDefaultButton(QMessageBox::No);
    if (msgBox->exec() != QMessageBox::Yes) return;

    std::vector<ThreatItem> selected;
    for (int idx : indices) selected.push_back(m_threats[idx]);

    showProcessingView();
    m_processProgress->setRange(0, (int)selected.size());
    m_processProgress->setValue(0);
    m_processStatus->setText("正在强制删除威胁...");

    m_threatThread = new QThread(this);
    m_threatWorker = new ThreatWorker();
    m_threatWorker->moveToThread(m_threatThread);

    connect(m_threatThread, &QThread::started, m_threatWorker,
            [this, selected, indices] { m_threatWorker->run(m_svc, selected, indices, 1); });
    connect(m_threatWorker, &ThreatWorker::progress, this, &ScanPage::onThreatProgress);
    connect(m_threatWorker, &ThreatWorker::itemDone, this, &ScanPage::onThreatItemDone);
    connect(m_threatWorker, &ThreatWorker::finished, this, &ScanPage::onThreatFinished);
    connect(m_threatThread, &QThread::finished, m_threatWorker, &QObject::deleteLater);

    m_threatThread->start();
}

void ScanPage::onAllowSelected()
{
    auto indices = getSelectedIndices();
    if (indices.empty()) return;

    std::vector<ThreatItem> selected;
    for (int idx : indices) selected.push_back(m_threats[idx]);

    showProcessingView();
    m_processProgress->setRange(0, (int)selected.size());
    m_processProgress->setValue(0);
    m_processStatus->setText("正在标记放过...");

    m_threatThread = new QThread(this);
    m_threatWorker = new ThreatWorker();
    m_threatWorker->moveToThread(m_threatThread);

    connect(m_threatThread, &QThread::started, m_threatWorker,
            [this, selected, indices] { m_threatWorker->run(m_svc, selected, indices, 2); });
    connect(m_threatWorker, &ThreatWorker::progress, this, &ScanPage::onThreatProgress);
    connect(m_threatWorker, &ThreatWorker::itemDone, this, &ScanPage::onThreatItemDone);
    connect(m_threatWorker, &ThreatWorker::finished, this, &ScanPage::onThreatFinished);
    connect(m_threatThread, &QThread::finished, m_threatWorker, &QObject::deleteLater);

    m_threatThread->start();
}

void ScanPage::onThreatProgress(int cur, int total, const QString& file)
{
    m_processProgress->setValue(cur);
    m_processStatus->setText(QString("正在处理 (%1/%2)：%3").arg(cur).arg(total).arg(file));
}

void ScanPage::onThreatItemDone(int idx, bool ok, const QString& msg)
{
    YxWriteCrashLog((L"[ScanPage] onThreatItemDone idx=" + std::to_wstring(idx) +
                     L" ok=" + std::to_wstring(ok) +
                     L" msg=" + msg.toStdWString()).c_str());
    if (idx < 0 || idx >= (int)m_threatItems.size()) return;
    QTreeWidgetItem* item = m_threatItems[idx];
    if (!item) return;

    if (msg == "Quarantined")      m_threats[idx].quarantined = true;
    else if (msg == "Deleted")     m_threats[idx].deleted = true;
    else if (msg == "Allowed")     m_threats[idx].allowed = true;

    delete item;
    m_threatItems[idx] = nullptr;
}

void ScanPage::onThreatFinished(int processed, int success, int failed)
{
    YxWriteCrashLog((L"[ScanPage] onThreatFinished processed=" + std::to_wstring(processed) +
                     L", success=" + std::to_wstring(success) +
                     L", failed=" + std::to_wstring(failed)).c_str());

    // 统计
    for (size_t i = 0; i < m_threats.size(); i++) {
        if (m_threats[i].quarantined) m_quarantinedCount++;
        else if (m_threats[i].deleted) m_deletedCount++;
        else if (m_threats[i].allowed) m_allowedCount++;
    }

    // 异步清理线程，避免 wait() 阻塞 UI 线程
    if (m_threatThread) {
        QThread* t = m_threatThread;
        m_threatThread = nullptr;
        m_threatWorker = nullptr;
        t->quit();
        connect(t, &QThread::finished, t, &QObject::deleteLater);
    }

    // 检查是否还有未处理的威胁（m_threatItems 中仍非空的项）
    int remaining = 0;
    for (auto* p : m_threatItems) {
        if (p) remaining++;
    }

    if (remaining == 0) {
        showDoneView();
    } else {
        m_processProgress->setVisible(false);
        m_processStatus->setVisible(false);
        m_btnQuarantine->setEnabled(true);
        m_btnDelete->setEnabled(true);
        m_btnAllow->setEnabled(true);
        m_selectAll->setEnabled(true);
        m_threatList->setEnabled(true);
        m_processStatus->setText(QString("处理完成：成功 %1，失败 %2，剩余 %3 个待处理")
                                     .arg(success).arg(failed).arg(remaining));
    }
}

// ---- 返回/完成 ----
void ScanPage::onBackClicked()
{
    auto* msgBox = new QMessageBox(this);
    msgBox->setIcon(QMessageBox::Question);
    msgBox->setWindowTitle("放弃处理");
    msgBox->setText("是否放弃处理剩余威胁？\n未处理的威胁将保留在原位置。");
    msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox->setDefaultButton(QMessageBox::No);
    if (msgBox->exec() == QMessageBox::Yes) {
        resetToIdle();
    }
}

void ScanPage::onCompleteClicked()
{
    resetToIdle();
}

// ---- 全选 ----
void ScanPage::onSelectAllChanged(int state)
{
    bool checked = (state == Qt::Checked);
    for (int i = 0; i < m_threatList->topLevelItemCount(); i++) {
        auto* item = m_threatList->topLevelItem(i);
        // 只对可勾选的项操作
        if (item->flags() & Qt::ItemIsUserCheckable) {
            item->setCheckState(0, checked ? Qt::Checked : Qt::Unchecked);
        }
    }
}
