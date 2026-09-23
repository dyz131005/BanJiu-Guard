// BanJiu-Guard - driver callbacks implementation
#include <fltKernel.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include "yx_protocol.h"

// PsGetProcessImageFileName 声明在 ntifs.h 中，minifilter 默认不包含
extern "C" PCSTR PsGetProcessImageFileName(PEPROCESS Process);

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

// WDK 可能未直接暴露 FILE_DISPOSITION_INFO，手动定义
#ifndef _FILE_DISPOSITION_INFO_DEFINED
typedef struct _FILE_DISPOSITION_INFO {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFO, *PFILE_DISPOSITION_INFO;
#define _FILE_DISPOSITION_INFO_DEFINED
#endif

// Globals (defined in yx_driver.cpp)
extern PDRIVER_OBJECT    g_DriverObject;
extern PFLT_FILTER        g_Filter;
extern PFLT_PORT          g_ServerPort;
extern PFLT_PORT          g_ClientPort;
extern YX_PROTECT_FLAGS   g_ProtectFlags;
extern YX_STATS           g_Stats;
extern ULONG              g_ProtectedPids[64];
extern ULONG              g_ProtectedPidCount;
extern PVOID              g_ObHandle;
extern LARGE_INTEGER      g_Cookie;
extern WCHAR              g_QuarantineDir[260];
extern WCHAR              g_DriverSysPath[260];
extern WCHAR              g_ServiceExePath[260];
extern WCHAR              g_ConfigPath[260];
extern WCHAR              g_ModelDir[260];
extern volatile PVOID     g_IoctlActiveThread;  // 当前处理 IOCTL 的线程对象指针

// ---------------------------------------------------------------------------
// 防死锁绕过：当前线程正在处理 IOCTL 时直接放行 minifilter 回调
// 比 PID 检查更直接：不依赖 PID 是否已注册
// ---------------------------------------------------------------------------
static inline BOOLEAN YxIsIoctlActiveThread()
{
    return (g_IoctlActiveThread != nullptr &&
            g_IoctlActiveThread == (PVOID)KeGetCurrentThread());
}

// ---------------------------------------------------------------------------
// 自我保护：是否保护某 PID
// ---------------------------------------------------------------------------
BOOLEAN YxIsPidProtected(ULONG pid)
{
    for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
        if (g_ProtectedPids[i] == pid) return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// 路径归一化：转小写、去掉 \??\ 前缀、统一反斜杠
// ---------------------------------------------------------------------------
VOID YxNormalizePath(PCWSTR in, WCHAR* out, ULONG outChars)
{
    if (!out || !outChars) return;
    out[0] = L'\0';
    if (!in) return;

    PCWSTR p = in;
    // 跳过 \??\ 或 \?? 前缀
    if (p[0] == L'\\' && p[1] == L'?' && p[2] == L'?') {
        if (p[3] == L'\\') p += 4;
        else p += 3;
    }

    ULONG i = 0;
    while (*p && i < outChars - 1) {
        WCHAR c = *p++;
        if (c == L'/') c = L'\\';
        if (c >= L'A' && c <= L'Z') c = c + (L'a' - L'A');
        out[i++] = c;
    }
    out[i] = L'\0';

    // 去掉末尾反斜杠（目录比较用）
    while (i > 1 && out[i - 1] == L'\\') {
        out[--i] = L'\0';
    }
}

// ---------------------------------------------------------------------------
// 判断路径是否在受保护范围内（隔离区目录、驱动文件、服务程序）
// ---------------------------------------------------------------------------
BOOLEAN YxIsProtectedPath(PCWSTR path)
{
    if (!path || !path[0]) return FALSE;

    WCHAR normPath[520];
    YxNormalizePath(path, normPath, 520);

    // 检查是否在隔离区目录下
    if (g_QuarantineDir[0]) {
        WCHAR normQ[260];
        YxNormalizePath(g_QuarantineDir, normQ, 260);
        ULONG qLen = (ULONG)wcslen(normQ);
        if (qLen > 0 && wcsncmp(normPath, normQ, qLen) == 0) {
            // 确保是子路径（后面跟着 \ 或完全相等）
            if (normPath[qLen] == L'\\' || normPath[qLen] == L'\0') {
                return TRUE;
            }
        }
    }

    // 检查是否是驱动 .sys 文件
    if (g_DriverSysPath[0]) {
        WCHAR normDrv[260];
        YxNormalizePath(g_DriverSysPath, normDrv, 260);
        if (wcscmp(normPath, normDrv) == 0) return TRUE;
    }

    // 检查是否是服务 .exe 文件
    if (g_ServiceExePath[0]) {
        WCHAR normSvc[260];
        YxNormalizePath(g_ServiceExePath, normSvc, 260);
        if (wcscmp(normPath, normSvc) == 0) return TRUE;
    }

    // 检查是否是 config.ini 配置文件
    if (g_ConfigPath[0]) {
        WCHAR normCfg[260];
        YxNormalizePath(g_ConfigPath, normCfg, 260);
        if (wcscmp(normPath, normCfg) == 0) return TRUE;
    }

    // 检查是否在模型目录下（models\，含其子路径）
    if (g_ModelDir[0]) {
        WCHAR normModel[260];
        YxNormalizePath(g_ModelDir, normModel, 260);
        ULONG mLen = (ULONG)wcslen(normModel);
        if (mLen > 0 && wcsncmp(normPath, normModel, mLen) == 0) {
            if (normPath[mLen] == L'\\' || normPath[mLen] == L'\0') return TRUE;
        }
    }

    return FALSE;
}

// ---------------------------------------------------------------------------
// 判断是否是 MBR/GPT 区域写入（前 34 扇区 = 17408 字节）
// 仅对真正的原始卷/磁盘设备写入有效
// ---------------------------------------------------------------------------
BOOLEAN YxIsMbrWrite(PFLT_CALLBACK_DATA Data)
{
    if (!Data) return FALSE;
    if (Data->Iopb->MajorFunction != IRP_MJ_WRITE) return FALSE;

    PFILE_OBJECT fo = Data->Iopb->TargetFileObject;
    if (!fo) return FALSE;

    // 排除 paging I/O（缓存回写 / lazy writer）
    // 缓存管理器回写普通文件时使用特殊 FileObject，FileName 可能为空、
    // RelatedFileObject 可能为 NULL，若不排除会把小文件写入误判为 MBR 写入
    if (Data->Iopb->IrpFlags & IRP_PAGING_IO) return FALSE;

    // 判断是否为原始卷/磁盘设备打开（如 \\.\C: 或 \\.\PhysicalDrive0）
    // 可靠判据：FileName 为空 且 RelatedFileObject 为 NULL
    //   - 普通文件：FileName 非空，或 RelatedFileObject 指向父目录
    //   - 原始卷：FileName 为空，RelatedFileObject 为 NULL
    // 注意：不能用 SectionObjectPointer 判断，原始卷打开时它也不为 NULL
    if (fo->FileName.Length != 0) return FALSE;
    if (fo->RelatedFileObject != nullptr) return FALSE;

    LARGE_INTEGER offset = Data->Iopb->Parameters.Write.ByteOffset;

    // 保护区域 [0, YX_MBR_PROTECT_BYTES)
    if (offset.QuadPart >= 0 && offset.QuadPart < YX_MBR_PROTECT_BYTES) {
        return TRUE;
    }

    return FALSE;
}

// ---------------------------------------------------------------------------
// 判断是否为关键系统进程（放行其对受保护路径的访问，避免系统功能异常）
// ---------------------------------------------------------------------------
static BOOLEAN YxIsCriticalSystemProcess(ULONG pid)
{
    // System 进程（pid=4）必须放行，否则系统更新/卷元数据写入会被拦
    if (pid == 4) return TRUE;
    return FALSE;
}

// ---------------------------------------------------------------------------
// 大小写不敏感的 ANSI 字符串比较（内核中不依赖 _stricmp）
// ---------------------------------------------------------------------------
static BOOLEAN YxStrEqualIA(PCSTR a, PCSTR b)
{
    if (!a || !b) return FALSE;
    while (*a && *b) {
        CHAR ca = *a++;
        CHAR cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
        if (cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
        if (ca != cb) return FALSE;
    }
    return (*a == *b);
}

// ---------------------------------------------------------------------------
// 判断当前进程是否为对隔离区目录应放行的系统进程
// 隔离区在桌面目录，explorer/搜索索引/Defender 会频繁扫描，不应拦截
// ---------------------------------------------------------------------------
static BOOLEAN YxShouldAllowQuarantineAccess()
{
    PEPROCESS proc = PsGetCurrentProcess();
    if (!proc) return FALSE;

    PCSTR imgName = PsGetProcessImageFileName(proc);
    if (!imgName) return FALSE;

    // explorer.exe、搜索索引器、Defender、系统服务宿主
    if (YxStrEqualIA(imgName, "explorer.exe")) return TRUE;
    if (YxStrEqualIA(imgName, "SearchIndexer.exe")) return TRUE;
    if (YxStrEqualIA(imgName, "SearchProtocolHost.exe")) return TRUE;
    if (YxStrEqualIA(imgName, "MsMpEng.exe")) return TRUE;
    if (YxStrEqualIA(imgName, "MsSense.exe")) return TRUE;
    if (YxStrEqualIA(imgName, "svchost.exe")) return TRUE;
    if (YxStrEqualIA(imgName, "dwm.exe")) return TRUE;

    return FALSE;
}

// ---------------------------------------------------------------------------
// 判断路径是否为隔离区目录内的路径（区分隔离区和驱动/服务文件）
// 驱动/服务文件需要严格保护，隔离区则允许系统进程访问
// ---------------------------------------------------------------------------
static BOOLEAN YxIsQuarantinePath(PCWSTR path)
{
    if (!path || !path[0] || !g_QuarantineDir[0]) return FALSE;

    WCHAR normPath[520];
    YxNormalizePath(path, normPath, 520);

    WCHAR normQ[260];
    YxNormalizePath(g_QuarantineDir, normQ, 260);
    ULONG qLen = (ULONG)wcslen(normQ);
    if (qLen > 0 && wcsncmp(normPath, normQ, qLen) == 0) {
        if (normPath[qLen] == L'\\' || normPath[qLen] == L'\0') {
            return TRUE;
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// 同步决策：发送事件并等待用户态回复
// timeoutMs: 等待用户态回复的超时时间（毫秒）
//   - 文件操作事件：500ms（快速判定，避免阻塞 IO）
//   - 进程创建事件：8000ms（WinVerifyTrust 签名验证首次调用较慢）
// 返回 TRUE=允许, FALSE=阻止
// ---------------------------------------------------------------------------
static BOOLEAN YxQueryDecision(
    YX_EVENT_TYPE type,
    YX_RULE_CATEGORY category,
    YX_THREAT_LEVEL threat,
    ULONG pid, ULONG parentPid, ULONG targetPid,
    PCWSTR name0, PCWSTR name1, PCWSTR name2,
    ULONG timeoutMs)
{
    if (!g_ClientPort) return TRUE;

    // 重要：FltSendMessage 的 SenderBuffer 只含消息体（YX_EVENT），
    // 框架会在用户态 FilterGetMessage 收到的消息前自动加 FILTER_MESSAGE_HEADER。
    // 如果 SenderBuffer 也塞一个 header，用户态 ev 偏移会错位读到全 0。
    ULONG total = sizeof(YX_EVENT);
    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, total, 'xPYX');
    if (!buf) return TRUE;

    RtlZeroMemory(buf, total);
    PYX_EVENT ev = (PYX_EVENT)buf;

    ev->Type = type;
    ev->Category = category;
    ev->Threat = threat;
    ev->ProcessId = pid;
    ev->ParentProcessId = parentPid;
    ev->TargetProcessId = targetPid;
    ev->Timestamp = (ULONG64)KeQueryInterruptTime();
    if (name0) RtlStringCbCopyW(ev->Name0, sizeof(ev->Name0), name0);
    if (name1) RtlStringCbCopyW(ev->Name1, sizeof(ev->Name1), name1);
    if (name2) RtlStringCbCopyW(ev->Name2, sizeof(ev->Name2), name2);

    // 回复缓冲区：FILTER_REPLY_HEADER(16) + YX_DECISION(12) = 28 字节
    // 用原始字节数组避免编译器对齐填充问题
    // （#pragma pack(1) 在某些 WDK 版本中对嵌套结构体不生效）
    UCHAR replyBuf[28] = { 0 };
    PFILTER_REPLY_HEADER replyHdr = (PFILTER_REPLY_HEADER)replyBuf;
    YX_DECISION* replyDecision = (YX_DECISION*)(replyBuf + sizeof(FILTER_REPLY_HEADER));
    const ULONG EXPECTED_REPLY_SIZE = sizeof(FILTER_REPLY_HEADER) + sizeof(YX_DECISION);
    ULONG replySize = EXPECTED_REPLY_SIZE;

    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)timeoutMs * 10000 * 10LL);

    PFLT_PORT port = g_ClientPort;
    NTSTATUS st = FltSendMessage(g_Filter, &port, buf, total,
                                 replyBuf, &replySize, &timeout);

    ExFreePoolWithTag(buf, 'xPYX');

    DbgPrint("[BanJiu-Guard][QueryDecision] type=%d st=0x%X replySize=%lu (need %lu) action=%d\n",
             (int)type, st, replySize, EXPECTED_REPLY_SIZE, (int)replyDecision->Action);

    if (NT_SUCCESS(st) && replySize >= EXPECTED_REPLY_SIZE) {
        g_Stats.FilesScanned++;
        if (replyDecision->Action == YX_ACTION_BLOCK) {
            g_Stats.FilesBlocked++;
            g_Stats.QDBlockCount++;
            return FALSE;
        }
        g_Stats.QDAllowCount++;
    } else if (!NT_SUCCESS(st)) {
        g_Stats.QDTimeoutCount++;
    } else {
        g_Stats.QDBadReplyCount++;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// 事件上报：向用户态服务发送事件（异步，不等待回复）
// ---------------------------------------------------------------------------
VOID YxReportEvent(
    YX_EVENT_TYPE type,
    YX_RULE_CATEGORY category,
    YX_THREAT_LEVEL threat,
    ULONG pid, ULONG parentPid, ULONG targetPid,
    PCWSTR name0, PCWSTR name1, PCWSTR name2)
{
    if (!g_ClientPort) return;

    // 同 YxQueryDecision：SenderBuffer 不含 FILTER_MESSAGE_HEADER
    ULONG total = sizeof(YX_EVENT);
    PFLT_PORT port = g_ClientPort;
    if (!port) return;

    PVOID buf = ExAllocatePoolWithTag(NonPagedPoolNx, total, 'xPYX');
    if (!buf) return;

    RtlZeroMemory(buf, total);
    PYX_EVENT ev = (PYX_EVENT)buf;

    ev->Type = type;
    ev->Category = category;
    ev->Threat = threat;
    ev->ProcessId = pid;
    ev->ParentProcessId = parentPid;
    ev->TargetProcessId = targetPid;
    ev->Timestamp = (ULONG64)KeQueryInterruptTime();
    if (name0) RtlStringCbCopyW(ev->Name0, sizeof(ev->Name0), name0);
    if (name1) RtlStringCbCopyW(ev->Name1, sizeof(ev->Name1), name1);
    if (name2) RtlStringCbCopyW(ev->Name2, sizeof(ev->Name2), name2);

    g_Stats.FilesScanned++;

    LARGE_INTEGER timeout;
    timeout.QuadPart = -50 * 10000 * 10LL; // 50ms fire-and-forget

    FltSendMessage(g_Filter, &port, buf, total, nullptr, nullptr, &timeout);
    ExFreePoolWithTag(buf, 'xPYX');
}

// ---------------------------------------------------------------------------
// 从 Data 提取文件路径
// ---------------------------------------------------------------------------
static VOID YxGetFilename(PFLT_CALLBACK_DATA Data, WCHAR* out, ULONG outChars)
{
    NTSTATUS st;
    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;

    st = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (NT_SUCCESS(st)) {
        FltParseFileNameInformation(nameInfo);
        // UNICODE_STRING.Buffer 不保证 null 结尾，必须用 Length 限制复制长度
        RtlStringCbCopyNW(out, outChars * sizeof(WCHAR), nameInfo->Name.Buffer, nameInfo->Name.Length);
        FltReleaseFileNameInformation(nameInfo);
    } else {
        if (outChars) out[0] = L'\0';
    }
}

// ---------------------------------------------------------------------------
// 判断路径是否命中 hosts 文件（与 yx_rules.cpp 的 hosts 规则保持一致）
// hosts 文件：任何进程修改都拦截，不豁免系统进程。
// 注意：这里做的是"本地硬拦截"，不依赖用户态 FilterReplyMessage 回复——
// 服务端回复失败/超时被放行的漏洞不能再出现在 hosts 上。
// ---------------------------------------------------------------------------
static BOOLEAN YxIsHostsPath(PCWSTR path)
{
    if (!path || !path[0]) return FALSE;

    // 复制到本地小写缓冲区（UNICODE 路径，逐字符转小写）
    WCHAR lower[520];
    size_t klen = wcslen(path);
    if (klen >= 512) return FALSE;
    for (size_t i = 0; i < klen; i++) lower[i] = (WCHAR)towlower(path[i]);
    lower[klen] = L'\0';

    // 1. 完整路径命中 \drivers\etc\hosts
    if (wcsstr(lower, L"\\drivers\\etc\\hosts")) return TRUE;

    // 2. 文件名命中 hosts（覆盖 hosts.tmp 改名 hosts、直接以 hosts 命名的文件）
    const WCHAR* slash = wcsrchr(lower, L'\\');
    PCWSTR name = slash ? slash + 1 : lower;
    if (wcscmp(name, L"hosts") == 0) return TRUE;

    return FALSE;
}

// ---------------------------------------------------------------------------
// PreCreate：文件创建/打开拦截入口
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS YxPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // ---- 最优先：当前线程正在处理 IOCTL → 绕过所有规则评估 + 通知 ----
    // 避免 ZwCreateFile/ZwSetInformationFile 触发自身 minifilter 回调死锁
    if (YxIsIoctlActiveThread()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // ---- 受保护 PID（服务进程自身）发起的文件操作直接放行 ----
    if (YxIsPidProtected(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    WCHAR path[512];
    YxGetFilename(Data, path, 512);

    // ---- 自我保护：隔离区/驱动文件/服务程序 ----
    // 仅受保护 PID（服务进程自身）可访问，其余所有进程（含 System）一律拦截
    if (g_ProtectFlags.SelfProtect && !YxIsPidProtected(pid)) {
        if (YxIsProtectedPath(path)) {
            // 隔离区/驱动文件/服务程序：拦截所有非授权进程的任何访问
            ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            ACCESS_MASK anyAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA |
                                    FILE_EXECUTE | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                                    FILE_READ_EA | FILE_READ_ATTRIBUTES |
                                    DELETE | WRITE_DAC | WRITE_OWNER;
            if (desired & anyAccess) {
                YxReportEvent(YX_EVENT_SELF_PROTECT, YX_RULE_SELF_PROTECT, YX_THREAT_HIGH,
                              pid, 0, 0, path, L"受保护路径被访问", nullptr);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
    }

    // ---- MBR 保护：原始卷打开阶段不上报事件 ----
    // 真正的写入拦截在 YxPreWrite -> YxIsMbrWrite 中完成。
    // 若在 Create 阶段就上报事件，每次带写权限打开卷都会触发用户态弹窗/隔离，造成刷屏。
    // 这里仅做统计，不发送事件。

    if (!g_ProtectFlags.FileProtect && !g_ProtectFlags.YinHuProtect) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // ---- hosts 文件本地硬拦截（不依赖用户态回复，防止通信超时被放行）----
    // 只拦"带写权限"的打开/创建，避免误拦只读查看 hosts
    // 与 yx_rules.cpp 的 hosts 规则一致：任何进程修改都拦截，不豁免系统进程
    if (YxIsHostsPath(path)) {
        ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        ACCESS_MASK writeAccess = FILE_WRITE_DATA | FILE_APPEND_DATA |
                                  FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                                  DELETE | WRITE_DAC | WRITE_OWNER;
        if (desired & writeAccess) {
            YxReportEvent(YX_EVENT_FILE_WRITE, YX_RULE_HEURISTIC, YX_THREAT_CRITICAL,
                          pid, 0, 0, path, L"检测到修改 hosts 文件（驱动本地硬拦截）", nullptr);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    BOOLEAN allow = YxQueryDecision(YX_EVENT_FILE_CREATE, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                                    pid, 0, 0, path, nullptr, nullptr, 500);

    if (!allow) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS YxPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ---------------------------------------------------------------------------
// PreWrite：文件写入
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS YxPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // ---- IOCTL 处理线程绕过 ----
    if (YxIsIoctlActiveThread()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // ---- 受保护 PID 绕过 ----
    if (YxIsPidProtected(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    WCHAR path[512];
    YxGetFilename(Data, path, 512);

    // ---- MBR/GPT 保护：拦截对引导区的写入 ----
    if (g_ProtectFlags.MbrProtect) {
        if (YxIsMbrWrite(Data)) {
            YxReportEvent(YX_EVENT_MBR_PROTECT, YX_RULE_MBR_PROTECT, YX_THREAT_CRITICAL,
                          pid, 0, 0, path ? path : L"(raw disk)", L"MBR/GPT 写入被拦截", nullptr);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    // ---- 自我保护：禁止写入隔离区/驱动文件/服务程序 ----
    // 仅受保护 PID 可写入，其余全部拦截（含 System）
    if (g_ProtectFlags.SelfProtect && !YxIsPidProtected(pid)) {
        if (YxIsProtectedPath(path)) {
            YxReportEvent(YX_EVENT_SELF_PROTECT, YX_RULE_SELF_PROTECT, YX_THREAT_HIGH,
                          pid, 0, 0, path, L"写入受保护文件", nullptr);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    if (!g_ProtectFlags.FileProtect && !g_ProtectFlags.YinHuProtect) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // ---- hosts 文件本地硬拦截（不依赖用户态回复，防止通信超时被放行）----
    // 与 yx_rules.cpp 的 hosts 规则一致：任何进程修改都拦截，不豁免系统进程
    if (YxIsHostsPath(path)) {
        YxReportEvent(YX_EVENT_FILE_WRITE, YX_RULE_HEURISTIC, YX_THREAT_CRITICAL,
                      pid, 0, 0, path, L"检测到修改 hosts 文件（驱动本地硬拦截）", nullptr);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    BOOLEAN allow = YxQueryDecision(YX_EVENT_FILE_WRITE, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                                    pid, 0, 0, path, nullptr, nullptr, 500);

    if (!allow) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// PreSetInformation：文件删除/重命名
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS YxPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // ---- IOCTL 处理线程绕过 ----
    if (YxIsIoctlActiveThread()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // ---- 受保护 PID 绕过 ----
    if (YxIsPidProtected(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass != FileDispositionInformation &&
        infoClass != FileDispositionInformationEx &&
        infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    WCHAR path[512];
    YxGetFilename(Data, path, 512);

    // 重命名：提取目标完整路径（相对路径基于源文件目录拼接）。
    // 不查目标路径会漏掉"写 hosts.tmp 再改名 hosts"这类另存为绕过。
    WCHAR targetPath[512] = { 0 };
    PCWSTR targetArg = nullptr;
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        auto* ri = (PFILE_RENAME_INFORMATION)
            Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (ri && ri->FileNameLength >= sizeof(WCHAR) &&
            ri->FileNameLength <= 500 * sizeof(WCHAR)) {
            ULONG chars = ri->FileNameLength / sizeof(WCHAR);
            PCWSTR src = ri->FileName;
            // 跳过 \??\ 前缀（对象管理器 DOS 路径）
            if (chars >= 4 && src[0] == L'\\' && src[1] == L'?' &&
                src[2] == L'?' && src[3] == L'\\') {
                src += 4;
                chars -= 4;
            }
            if (src[0] == L'\\') {
                // 绝对对象路径（\Device\HarddiskVolumeN\...）
                RtlStringCbCopyNW(targetPath, sizeof(targetPath), src, chars * sizeof(WCHAR));
                targetArg = targetPath;
            } else {
                // 相对路径：相对源文件所在目录，拼接 源目录\目标名
                ULONG srcLen = (ULONG)wcslen(path);
                LONG cut = -1;
                for (LONG i = (LONG)srcLen - 1; i >= 0; i--) {
                    if (path[i] == L'\\') { cut = i; break; }
                }
                if (cut > 0) {
                    WCHAR dirPart[512];
                    RtlStringCbCopyNW(dirPart, sizeof(dirPart), path, (ULONG)cut * sizeof(WCHAR));
                    RtlStringCbCopyW(targetPath, sizeof(targetPath), dirPart);
                    RtlStringCbCatW(targetPath, sizeof(targetPath), L"\\");
                    RtlStringCbCatNW(targetPath, sizeof(targetPath), src, chars * sizeof(WCHAR));
                    targetArg = targetPath;
                }
            }
        }
    }

    // ---- 自我保护：禁止删除/重命名隔离区文件/驱动文件/服务程序 ----
    // 仅受保护 PID 可操作，其余全部拦截（含 System）
    if (g_ProtectFlags.SelfProtect && !YxIsPidProtected(pid)) {
        if (YxIsProtectedPath(path)) {
            YxReportEvent(YX_EVENT_SELF_PROTECT, YX_RULE_SELF_PROTECT, YX_THREAT_HIGH,
                          pid, 0, 0, path, L"删除/重命名受保护文件", nullptr);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    if (!g_ProtectFlags.FileProtect && !g_ProtectFlags.YinHuProtect) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    YX_EVENT_TYPE evType = (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx)
                               ? YX_EVENT_FILE_RENAME
                               : YX_EVENT_FILE_DELETE;

    // ---- hosts 文件本地硬拦截（不依赖用户态回复，防止通信超时被放行）----
    // 源或目标任一命中即拦，覆盖"删 hosts"和"hosts.tmp 改名 hosts"绕过
    if (YxIsHostsPath(path) || (targetArg && YxIsHostsPath(targetArg))) {
        YxReportEvent(evType, YX_RULE_HEURISTIC, YX_THREAT_CRITICAL,
                      pid, 0, 0, path, L"检测到删除/重命名 hosts 文件（驱动本地硬拦截）", nullptr);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    BOOLEAN allow = YxQueryDecision(evType, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                                    pid, 0, 0, path, targetArg, nullptr, 500);

    if (!allow) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ---------------------------------------------------------------------------
// 进程通知（同步决策）
// 进程创建前会触发此回调，通过 CreateInfo->CreationStatus 可阻止进程启动。
// 策略：通过 FilterGetMessage 同步询问用户态服务，由用户态完成签名校验
// （WinVerifyTrust + CAT 目录签名库）和启发式扫描后再回复决策。
// ---------------------------------------------------------------------------
VOID YxProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (!CreateInfo || !CreateInfo->ImageFileName) {
        return;
    }

    // 进程防护或银狐专项未开启时直接放行
    if (!g_ProtectFlags.ProcessProtect && !g_ProtectFlags.YinHuProtect) {
        return;
    }

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG ppid = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;

    // UNICODE_STRING.Buffer 不保证 null 结尾，先复制到本地 null 结尾缓冲区
    WCHAR imgPath[520];
    RtlStringCbCopyNW(imgPath, sizeof(imgPath),
                      CreateInfo->ImageFileName->Buffer,
                      CreateInfo->ImageFileName->Length);
    PCWSTR path = imgPath;

    // 跳过本服务自身进程：避免递归检查和死锁
    if (g_ServiceExePath[0] && path) {
        WCHAR normSvc[260];
        WCHAR normImg[520];
        YxNormalizePath(g_ServiceExePath, normSvc, 260);
        YxNormalizePath(path, normImg, 520);
        if (wcscmp(normSvc, normImg) == 0) {
            return;
        }
    }

    // 同步查询用户态决策：用户态会先验签（微软签名放行），再做启发式扫描
    // 进程创建需要 8 秒超时：WinVerifyTrust 首次调用（冷缓存）可能较慢
    BOOLEAN allow = YxQueryDecision(YX_EVENT_PROCESS_CREATE, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                                    pid, ppid, 0, path, nullptr, nullptr, 8000);

    if (!allow) {
        // 阻止进程创建：返回拒绝访问，进程将无法启动
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

// ---------------------------------------------------------------------------
// 线程通知：远程线程注入检测
// ---------------------------------------------------------------------------
VOID YxThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create) return;
    if (!g_ProtectFlags.InjectProtect && !g_ProtectFlags.YinHuProtect) return;

    ULONG targetPid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG creatorPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    if (creatorPid != targetPid) {
        YxReportEvent(YX_EVENT_THREAD_CREATE, YX_RULE_HEURISTIC, YX_THREAT_MEDIUM,
                      creatorPid, 0, targetPid, L"(thread)", nullptr, nullptr);
    }
}

// ---------------------------------------------------------------------------
// 映像加载通知：白加黑 DLL 侧加载、驱动加载检测
// ---------------------------------------------------------------------------
VOID YxLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!FullImageName || !FullImageName->Buffer) return;

    // UNICODE_STRING.Buffer 不保证 null 结尾，先复制到本地 null 结尾缓冲区
    WCHAR imgPath[520];
    RtlStringCbCopyNW(imgPath, sizeof(imgPath), FullImageName->Buffer, FullImageName->Length);

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    if (ImageInfo && ImageInfo->SystemModeImage) {
        // 驱动加载（BYOVD 检测）
        if (g_ProtectFlags.YinHuProtect) {
            YxReportEvent(YX_EVENT_DRIVER_LOAD, YX_RULE_HEURISTIC, YX_THREAT_HIGH,
                          pid, 0, 0, imgPath, nullptr, nullptr);
        }
    } else {
        // 用户态 DLL 加载（白加黑检测）
        if (g_ProtectFlags.YinHuProtect || g_ProtectFlags.ProcessProtect) {
            // 节流：每秒最多上报 YX_IMAGE_LOAD_MAX_PER_SEC 条。
            // 海量 DLL 加载事件会拖垮用户态服务消息队列，导致同步文件决策
            // （如 hosts 写入）超时被默认放行——必须先保证同步决策链路畅通。
            const ULONG MAX_PER_SEC = 50;
            static ULONG s_lastSec = 0;
            static ULONG s_count = 0;
            static ULONG s_dropped = 0;
            ULONG nowSec = (ULONG)(KeQueryInterruptTime() / 10000000ULL);
            if (nowSec != s_lastSec) {
                s_lastSec = nowSec;
                s_count = 0;
            }
            if (s_count < MAX_PER_SEC) {
                s_count++;
                YxReportEvent(YX_EVENT_IMAGE_LOAD, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                              pid, 0, 0, imgPath, nullptr, nullptr);
            } else {
                s_dropped++;
                if (s_dropped % 1000 == 1) {
                    DbgPrint("[BanJiu-Guard][LoadImage] throttled, dropped=%lu\n", s_dropped);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 注册表回调：解析键名和值名
// ---------------------------------------------------------------------------
static VOID YxRegGetFullPath(REG_NOTIFY_CLASS cls, PVOID argument2, WCHAR* outBuf, ULONG outChars)
{
    if (!outBuf || !outChars) {
        if (outBuf) outBuf[0] = L'\0';
        return;
    }
    if (!argument2) {
        outBuf[0] = L'\0';
        return;
    }

    WCHAR path[512] = { 0 };

    switch (cls) {
        case RegNtPreSetValueKey:
        case RegNtPostSetValueKey: {
            PREG_SET_VALUE_KEY_INFORMATION p = (PREG_SET_VALUE_KEY_INFORMATION)argument2;
            if (p && p->Object) {
                PCUNICODE_STRING name = p->ValueName;
                PCUNICODE_STRING objName = nullptr;
                // WDK 10.0.28000.0 中 CmCallbackGetKeyObjectID 第一个参数为 PLARGE_INTEGER
                if (NT_SUCCESS(CmCallbackGetKeyObjectID(&g_Cookie, p->Object, nullptr, &objName)) && objName && objName->Buffer) {
                    RtlStringCbCopyNW(path, sizeof(path), objName->Buffer, objName->Length);
                    if (name && name->Buffer) {
                        RtlStringCbCatW(path, sizeof(path), L"\\");
                        RtlStringCbCatNW(path, sizeof(path), name->Buffer, name->Length);
                    }
                }
            }
            break;
        }
        case RegNtPreCreateKeyEx:
        case RegNtPostCreateKeyEx: {
            PREG_CREATE_KEY_INFORMATION p = (PREG_CREATE_KEY_INFORMATION)argument2;
            if (p && p->RootObject) {
                PCUNICODE_STRING rootName = nullptr;
                if (NT_SUCCESS(CmCallbackGetKeyObjectID(&g_Cookie, p->RootObject, nullptr, &rootName)) && rootName && rootName->Buffer) {
                    RtlStringCbCopyNW(path, sizeof(path), rootName->Buffer, rootName->Length);
                    if (p->CompleteName && p->CompleteName->Buffer) {
                        RtlStringCbCatW(path, sizeof(path), L"\\");
                        RtlStringCbCatNW(path, sizeof(path), p->CompleteName->Buffer, p->CompleteName->Length);
                    }
                }
            }
            break;
        }
        case RegNtPreDeleteKey:
        case RegNtPostDeleteKey: {
            PREG_DELETE_KEY_INFORMATION p = (PREG_DELETE_KEY_INFORMATION)argument2;
            if (p && p->Object) {
                PCUNICODE_STRING objName = nullptr;
                if (NT_SUCCESS(CmCallbackGetKeyObjectID(&g_Cookie, p->Object, nullptr, &objName)) && objName && objName->Buffer) {
                    RtlStringCbCopyNW(path, sizeof(path), objName->Buffer, objName->Length);
                }
            }
            break;
        }
        case RegNtPreDeleteValueKey:
        case RegNtPostDeleteValueKey: {
            PREG_DELETE_VALUE_KEY_INFORMATION p = (PREG_DELETE_VALUE_KEY_INFORMATION)argument2;
            if (p && p->Object) {
                PCUNICODE_STRING objName = nullptr;
                if (NT_SUCCESS(CmCallbackGetKeyObjectID(&g_Cookie, p->Object, nullptr, &objName)) && objName && objName->Buffer) {
                    RtlStringCbCopyNW(path, sizeof(path), objName->Buffer, objName->Length);
                    if (p->ValueName && p->ValueName->Buffer) {
                        RtlStringCbCatW(path, sizeof(path), L"\\");
                        RtlStringCbCatNW(path, sizeof(path), p->ValueName->Buffer, p->ValueName->Length);
                    }
                }
            }
            break;
        }
        default:
            break;
    }

    RtlStringCbCopyW(outBuf, outChars * sizeof(WCHAR), path);
}

NTSTATUS YxRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    // 回调调用计数（用户态通过 IOCTL_YX_QUERY_STATS 读取，诊断回调是否在工作）
    g_Stats.RegCallbackCount++;

    REG_NOTIFY_CLASS cls = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    // 按回调类统计次数，用于定位 regedit 走了哪个回调类
    if ((ULONG)cls < 32) {
        g_Stats.RegClassCounts[(ULONG)cls]++;
    }

    if (!g_ProtectFlags.RegistryProtect && !g_ProtectFlags.YinHuProtect) {
        return STATUS_SUCCESS;
    }

    // Argument1 是 REG_NOTIFY_CLASS 值本身（不是指针），Argument2 是操作信息结构指针
    if (!Argument2) return STATUS_SUCCESS;

    // 只在 Pre 阶段做同步拦截决策；Post 阶段操作已完成，无需也无法阻止
    BOOLEAN isPreSetValue = (cls == RegNtPreSetValueKey);
    BOOLEAN isPreCreateKey = (cls == RegNtPreCreateKeyEx);
    BOOLEAN isPreDeleteKey = (cls == RegNtPreDeleteKey);
    BOOLEAN isPreDeleteValue = (cls == RegNtPreDeleteValueKey);

    if (!isPreSetValue && !isPreCreateKey && !isPreDeleteKey && !isPreDeleteValue) {
        return STATUS_SUCCESS;
    }

    WCHAR keyPath[512];
    YxRegGetFullPath(cls, Argument2, keyPath, 512);

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // 诊断：路径提取失败时上报（用于定位 regedit/reg.exe 为何路径为空）
    if (keyPath[0] == L'\0') {
        g_Stats.RegPathFailCount++;
        WCHAR clsStr[16] = L"cls=";
        int c = (int)cls;
        WCHAR num[8];
        int nlen = 0;
        if (c == 0) { num[nlen++] = L'0'; }
        else { while (c > 0) { num[nlen++] = L'0' + (c % 10); c /= 10; } }
        int pos = 4;
        for (int i = nlen - 1; i >= 0; i--) clsStr[pos++] = num[i];
        clsStr[pos] = L'\0';
        // 只对 regedit/reg.exe 进程上报路径提取失败，避免日志洪水
        // 用 PID + 类作为指纹做简单节流：每秒最多 1 条
        YxReportEvent(YX_EVENT_REG_DIAG, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                      pid, 0, 0,
                      L"<path-empty>", clsStr, nullptr);
        return STATUS_SUCCESS;
    }

    // 诊断：对四个处理的回调类，若路径包含 run（不区分大小写）则上报到用户态日志，
    // 用于定位 regedit 写 Run 键为何未触发拦截
    {
        WCHAR lower2[512];
        size_t klen2 = wcslen(keyPath);
        if (klen2 < 512) {
            for (size_t i = 0; i < klen2; i++) lower2[i] = (WCHAR)towlower(keyPath[i]);
            lower2[klen2] = L'\0';
            if (wcsstr(lower2, L"run")) {
                WCHAR clsStr[16] = L"cls=";
                int c = (int)cls;
                WCHAR num[8];
                int nlen = 0;
                if (c == 0) { num[nlen++] = L'0'; }
                else { while (c > 0) { num[nlen++] = L'0' + (c % 10); c /= 10; } }
                int pos = 4;
                for (int i = nlen - 1; i >= 0; i--) clsStr[pos++] = num[i];
                clsStr[pos] = L'\0';
                YxReportEvent(YX_EVENT_REG_DIAG, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                              pid, 0, 0,
                              keyPath, clsStr, nullptr);
            }
        }
    }

    // 本地路径预过滤：与 yx_rules.cpp 的规则关键字保持一致
    // 不命中规则关键字直接放行，避免每个系统正常注册表事件都走同步决策导致系统卡死
    WCHAR lower[512];
    size_t klen = wcslen(keyPath);
    if (klen >= 512) return STATUS_SUCCESS;
    for (size_t i = 0; i < klen; i++) lower[i] = (WCHAR)towlower(keyPath[i]);
    lower[klen] = L'\0';

    BOOLEAN hitPath = FALSE;
    if (wcsstr(lower, L"\\run") || wcsstr(lower, L"runonce") ||
        wcsstr(lower, L"runservices") || wcsstr(lower, L"\\policies\\explorer\\run") ||
        wcsstr(lower, L"\\windows\\currentversion\\run") ||
        wcsstr(lower, L"\\winlogon") || wcsstr(lower, L"image file execution options") ||
        wcsstr(lower, L"appinit_dlls") || wcsstr(lower, L"\\session manager\\appcertdlls") ||
        wcsstr(lower, L"\\session manager\\subsystems") ||
        wcsstr(lower, L"\\windows nt\\currentversion\\windows") ||
        wcsstr(lower, L"\\system\\currentcontrolset\\services\\") ||
        wcsstr(lower, L"\\windows defender") || wcsstr(lower, L"\\sharedaccess") ||
        wcsstr(lower, L"security center") ||
        wcsstr(lower, L"\\policies\\microsoft\\windows defender")) {
        hitPath = TRUE;
    }

    if (!hitPath) {
        g_Stats.RegPathMissCount++;
        return STATUS_SUCCESS;  // 本地判断不命中规则，直接放行，不走同步决策
    }

    g_Stats.RegPathHitCount++;
    DbgPrint("[BanJiu-Guard][RegCb] hit cls=%d path=%ws\n", (int)cls, keyPath);

    YX_EVENT_TYPE evType = isPreCreateKey ? YX_EVENT_REGISTRY_CREATE
                                          : YX_EVENT_REGISTRY_WRITE;

    // 直接拦截：不依赖 FltSendMessage 回复机制（filter manager 回复大小不匹配）
    // 驱动直接返回 STATUS_ACCESS_DENIED 阻止注册表写入
    // 异步通知用户态记录日志
    YxReportEvent(evType, YX_RULE_HEURISTIC, YX_THREAT_LOW,
                  pid, 0, 0, keyPath, L"REG_BLOCKED", nullptr);

    return STATUS_ACCESS_DENIED;
}

// ---------------------------------------------------------------------------
// Self-protection: Ob callback
// ---------------------------------------------------------------------------
static OB_OPERATION_REGISTRATION g_ObOps[1];
static OB_CALLBACK_REGISTRATION  g_ObReg;

OB_PREOP_CALLBACK_STATUS YxObPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_ProtectFlags.SelfProtect) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    ULONG targetPid = (ULONG)(ULONG_PTR)PsGetProcessId((PEPROCESS)OperationInformation->Object);
    if (YxIsPidProtected(targetPid)) {
        constexpr ACCESS_MASK kDangerousAccess =
            0x0001 /* PROCESS_TERMINATE */ |
            0x0020 /* PROCESS_VM_WRITE */ |
            0x0008 /* PROCESS_VM_OPERATION */ |
            0x0800 /* PROCESS_SUSPEND_RESUME */ |
            0x0002 /* PROCESS_CREATE_THREAD */ |
            0x0200 /* PROCESS_SET_INFORMATION */;
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~kDangerousAccess;
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS YxEnableSelfProtection()
{
    if (g_ObHandle) return STATUS_SUCCESS;

    RtlZeroMemory(g_ObOps, sizeof(g_ObOps));
    g_ObOps[0].ObjectType = PsProcessType;
    g_ObOps[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOps[0].PreOperation = YxObPreCallback;

    RtlZeroMemory(&g_ObReg, sizeof(g_ObReg));
    g_ObReg.Version = OB_FLT_REGISTRATION_VERSION;
    g_ObReg.OperationRegistrationCount = 1;
    g_ObReg.Altitude = RTL_CONSTANT_STRING(L"369000");
    g_ObReg.RegistrationContext = nullptr;
    g_ObReg.OperationRegistration = g_ObOps;

    return ObRegisterCallbacks(&g_ObReg, &g_ObHandle);
}

VOID YxDisableSelfProtection()
{
    if (g_ObHandle) {
        ObUnRegisterCallbacks(g_ObHandle);
        g_ObHandle = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Communication: connect/disconnect notify
// ---------------------------------------------------------------------------
NTSTATUS YxConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    g_ClientPort = ClientPort;
    *ConnectionPortCookie = nullptr;
    return STATUS_SUCCESS;
}

VOID YxDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_Filter, &g_ClientPort);
    g_ClientPort = nullptr;
}

// ---------------------------------------------------------------------------
// Communication: message notify (user -> kernel settings)
// ---------------------------------------------------------------------------
NTSTATUS YxMessageNotify(
    _In_ PVOID ConnectionCookie,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

    if (!InputBuffer || InputBufferLength < sizeof(YX_PROTECT_FLAGS)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&g_ProtectFlags, InputBuffer, sizeof(YX_PROTECT_FLAGS));

    if (g_ProtectFlags.SelfProtect) {
        YxEnableSelfProtection();
    } else {
        YxDisableSelfProtection();
    }
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IRP Dispatch: Create / Close
// ---------------------------------------------------------------------------
NTSTATUS YxDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS YxDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IRP Dispatch: DeviceControl (IOCTL)
// ---------------------------------------------------------------------------
// RAII 包装：进入 IOCTL 处理时设置 g_IoctlActiveThread，离开时清除
// 用于让 minifilter Pre 回调识别"当前线程正在处理 IOCTL"从而绕过规则
// 防止 ZwCreateFile/ZwSetInformationFile 触发自身回调死锁
class IoctlThreadScope {
public:
    IoctlThreadScope() {
        m_PrevThread = g_IoctlActiveThread;
        g_IoctlActiveThread = (PVOID)KeGetCurrentThread();
    }
    ~IoctlThreadScope() {
        g_IoctlActiveThread = m_PrevThread;
    }
private:
    PVOID m_PrevThread;
};

// ---------------------------------------------------------------------------
// IRP Dispatch: DeviceControl (IOCTL)
// ---------------------------------------------------------------------------
NTSTATUS YxDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytesReturned = 0;

    // 标记当前线程正在处理 IOCTL，minifilter Pre 回调检查到后会直接放行
    // 这样 IOCTL 中调 ZwCreateFile/ZwSetInformationFile 不会触发规则评估死锁
    IoctlThreadScope ioctlScope;

    switch (ioctlCode) {
        case IOCTL_YX_GET_VERSION: {
            if (outLen >= sizeof(YX_VERSION_INFO)) {
                YX_VERSION_INFO ver = { YX_DRIVER_VERSION_MAJOR, YX_DRIVER_VERSION_MINOR, YX_DRIVER_VERSION_BUILD };
                RtlCopyMemory(outBuf, &ver, sizeof(ver));
                bytesReturned = sizeof(ver);
                status = STATUS_SUCCESS;
            }
            break;
        }
        case IOCTL_YX_SET_PROTECT_FLAGS: {
            if (inBuf && inLen >= sizeof(YX_PROTECT_FLAGS)) {
                RtlCopyMemory(&g_ProtectFlags, inBuf, sizeof(YX_PROTECT_FLAGS));
                if (g_ProtectFlags.SelfProtect) {
                    YxEnableSelfProtection();
                } else {
                    YxDisableSelfProtection();
                }
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        case IOCTL_YX_GET_PROTECT_FLAGS: {
            if (outLen >= sizeof(YX_PROTECT_FLAGS)) {
                RtlCopyMemory(outBuf, &g_ProtectFlags, sizeof(g_ProtectFlags));
                bytesReturned = sizeof(g_ProtectFlags);
                status = STATUS_SUCCESS;
            }
            break;
        }
        case IOCTL_YX_QUERY_STATS: {
            if (outLen >= sizeof(YX_STATS)) {
                RtlCopyMemory(outBuf, &g_Stats, sizeof(g_Stats));
                bytesReturned = sizeof(g_Stats);
                status = STATUS_SUCCESS;
            }
            break;
        }
        case IOCTL_YX_REGISTER_PID: {
            if (inBuf && inLen >= sizeof(ULONG)) {
                ULONG pid = *(PULONG)inBuf;
                if (g_ProtectedPidCount < 64) {
                    g_ProtectedPids[g_ProtectedPidCount++] = pid;
                }
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        case IOCTL_YX_UNREGISTER_PID: {
            if (inBuf && inLen >= sizeof(ULONG)) {
                ULONG pid = *(PULONG)inBuf;
                for (ULONG i = 0; i < g_ProtectedPidCount; i++) {
                    if (g_ProtectedPids[i] == pid) {
                        for (ULONG j = i; j < g_ProtectedPidCount - 1; j++) {
                            g_ProtectedPids[j] = g_ProtectedPids[j + 1];
                        }
                        g_ProtectedPidCount--;
                        break;
                    }
                }
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        case IOCTL_YX_QUARANTINE_FILE: {
            // 旧接口保留（兼容），实际逻辑由 FORCE_QUARANTINE 处理
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_YX_KILL_PROCESS: {
            if (inBuf && inLen >= sizeof(YX_FILE_OP_REQUEST)) {
                PYX_FILE_OP_REQUEST req = (PYX_FILE_OP_REQUEST)inBuf;
                req->Success = 0;

                // 内核强制终止进程
                HANDLE hProc = nullptr;
                OBJECT_ATTRIBUTES oa;
                CLIENT_ID cid;
                cid.UniqueProcess = (HANDLE)(ULONG_PTR)req->ProcessId;
                cid.UniqueThread = nullptr;
                InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

                NTSTATUS killSt = ZwOpenProcess(&hProc, PROCESS_TERMINATE, &oa, &cid);
                if (NT_SUCCESS(killSt)) {
                    killSt = ZwTerminateProcess(hProc, STATUS_SUCCESS);
                    if (NT_SUCCESS(killSt)) {
                        req->Success = 1;
                    }
                    ZwClose(hProc);
                }

                // 允许输出缓冲区回传 Success 字段
                if (outLen >= sizeof(YX_FILE_OP_REQUEST)) {
                    RtlCopyMemory(outBuf, inBuf, sizeof(YX_FILE_OP_REQUEST));
                    bytesReturned = sizeof(YX_FILE_OP_REQUEST);
                }
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        case IOCTL_YX_FORCE_DELETE_FILE: {
            if (inBuf && inLen >= sizeof(YX_FILE_OP_REQUEST)) {
                PYX_FILE_OP_REQUEST req = (PYX_FILE_OP_REQUEST)inBuf;
                req->Success = 0;

                UNICODE_STRING uniPath;
                RtlInitUnicodeString(&uniPath, req->SourcePath);
                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, &uniPath,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

                IO_STATUS_BLOCK iosb{};
                HANDLE hFile = nullptr;
                NTSTATUS delSt = ZwCreateFile(&hFile,
                    DELETE | SYNCHRONIZE, &oa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

                if (!NT_SUCCESS(delSt)) {
                    // ZwCreateFile 失败，把 NTSTATUS 传回用户态便于诊断
                    req->ProcessId = (uint32_t)(0x80000000 | (delSt & 0x7FFFFFFF));
                } else {
                    FILE_DISPOSITION_INFO info;
                    info.DeleteFile = TRUE;
                    delSt = ZwSetInformationFile(hFile, &iosb, &info,
                        sizeof(info), FileDispositionInformation);
                    if (NT_SUCCESS(delSt)) {
                        req->Success = 1;
                    } else {
                        // ZwSetInformationFile 失败，NTSTATUS 高位不带 0x80 标记
                        req->ProcessId = (uint32_t)(delSt & 0x7FFFFFFF);
                    }
                    ZwClose(hFile);
                }

                if (outLen >= sizeof(YX_FILE_OP_REQUEST)) {
                    RtlCopyMemory(outBuf, inBuf, sizeof(YX_FILE_OP_REQUEST));
                    bytesReturned = sizeof(YX_FILE_OP_REQUEST);
                }
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        case IOCTL_YX_FORCE_QUARANTINE: {
            if (inBuf && inLen >= sizeof(YX_FILE_OP_REQUEST)) {
                PYX_FILE_OP_REQUEST req = (PYX_FILE_OP_REQUEST)inBuf;
                req->Success = 0;

                // 先尝试重命名（同卷秒移）
                UNICODE_STRING srcUni;
                RtlInitUnicodeString(&srcUni, req->SourcePath);
                OBJECT_ATTRIBUTES srcOa;
                InitializeObjectAttributes(&srcOa, &srcUni,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

                IO_STATUS_BLOCK iosb{};
                HANDLE hSrc = nullptr;
                NTSTATUS qSt = ZwCreateFile(&hSrc,
                    DELETE | SYNCHRONIZE, &srcOa, &iosb, nullptr,
                    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

                if (!NT_SUCCESS(qSt)) {
                    // ZwCreateFile 失败：高位带 0x80 标记
                    req->ProcessId = (uint32_t)(0x80000000 | (qSt & 0x7FFFFFFF));
                }

                if (NT_SUCCESS(qSt)) {
                    // 用 FileRenameInformation 重命名到目标路径
                    UNICODE_STRING dstUni;
                    RtlInitUnicodeString(&dstUni, req->DestPath);

                    // 计算 rename info 大小
                    ULONG renameLen = sizeof(FILE_RENAME_INFORMATION) + dstUni.Length;
                    PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)
                        ExAllocatePoolWithTag(NonPagedPool, renameLen, 'xQyY');
                    if (renameInfo) {
                        renameInfo->ReplaceIfExists = TRUE;
                        renameInfo->RootDirectory = nullptr;
                        renameInfo->FileNameLength = dstUni.Length;
                        RtlCopyMemory(renameInfo->FileName, dstUni.Buffer, dstUni.Length);

                        NTSTATUS rnSt = ZwSetInformationFile(hSrc, &iosb, renameInfo,
                            renameLen, FileRenameInformation);
                        ExFreePoolWithTag(renameInfo, 'xQyY');

                        if (NT_SUCCESS(rnSt)) {
                            req->Success = 1;
                        } else {
                            // 重命名失败（可能跨卷），回退到复制+删除
                            // 用 ZwCreateFile 打开目标写
                            UNICODE_STRING dstUni2;
                            RtlInitUnicodeString(&dstUni2, req->DestPath);
                            OBJECT_ATTRIBUTES dstOa;
                            InitializeObjectAttributes(&dstOa, &dstUni2,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
                            IO_STATUS_BLOCK iosb2{};
                            HANDLE hDst = nullptr;
                            NTSTATUS dstSt = ZwCreateFile(&hDst,
                                FILE_WRITE_DATA | SYNCHRONIZE, &dstOa, &iosb2, nullptr,
                                FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
                            if (NT_SUCCESS(dstSt)) {
                                // 分块拷贝
                                ULONG bufSz = 64 * 1024;
                                PUCHAR copyBuf = (PUCHAR)ExAllocatePoolWithTag(
                                    NonPagedPool, bufSz, 'cCyY');
                                if (copyBuf) {
                                    LARGE_INTEGER offset = { 0 };
                                    BOOLEAN copyOk = TRUE;
                                    while (TRUE) {
                                        IO_STATUS_BLOCK rwIosb{};
                                        NTSTATUS rdSt = ZwReadFile(hSrc, nullptr, nullptr, nullptr,
                                            &rwIosb, copyBuf, bufSz, &offset, nullptr);
                                        ULONG bytes = (ULONG)rwIosb.Information;
                                        if (bytes > 0) {
                                            NTSTATUS wrSt = ZwWriteFile(hDst, nullptr, nullptr, nullptr,
                                                &rwIosb, copyBuf, bytes, &offset, nullptr);
                                            if (!NT_SUCCESS(wrSt)) { copyOk = FALSE; break; }
                                        }
                                        offset.QuadPart += bytes;
                                        if (rdSt == STATUS_END_OF_FILE || bytes < bufSz) break;
                                        if (!NT_SUCCESS(rdSt)) { copyOk = FALSE; break; }
                                    }
                                    ExFreePoolWithTag(copyBuf, 'cCyY');
                                    if (copyOk) {
                                        // 删除源文件
                                        FILE_DISPOSITION_INFO disp{};
                                        disp.DeleteFile = TRUE;
                                        NTSTATUS delSt2 = ZwSetInformationFile(hSrc,
                                            &iosb, &disp, sizeof(disp),
                                            FileDispositionInformation);
                                        if (NT_SUCCESS(delSt2)) req->Success = 1;
                                    }
                                }
                                ZwClose(hDst);
                            }
                        }
                    }
                    ZwClose(hSrc);
                }

                if (outLen >= sizeof(YX_FILE_OP_REQUEST)) {
                    RtlCopyMemory(outBuf, inBuf, sizeof(YX_FILE_OP_REQUEST));
                    bytesReturned = sizeof(YX_FILE_OP_REQUEST);
                }
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        case IOCTL_YX_SET_PROTECT_PATHS: {
            if (inBuf && inLen >= sizeof(YX_PROTECT_PATHS)) {
                PYX_PROTECT_PATHS paths = (PYX_PROTECT_PATHS)inBuf;
                RtlZeroMemory(g_QuarantineDir, sizeof(g_QuarantineDir));
                RtlZeroMemory(g_DriverSysPath, sizeof(g_DriverSysPath));
                RtlZeroMemory(g_ServiceExePath, sizeof(g_ServiceExePath));
                RtlStringCbCopyW(g_QuarantineDir, sizeof(g_QuarantineDir), paths->QuarantineDir);
                RtlStringCbCopyW(g_DriverSysPath, sizeof(g_DriverSysPath), paths->DriverSysPath);
                RtlStringCbCopyW(g_ServiceExePath, sizeof(g_ServiceExePath), paths->ServiceExePath);
                RtlStringCbCopyW(g_ConfigPath, sizeof(g_ConfigPath), paths->ConfigPath);
                RtlStringCbCopyW(g_ModelDir, sizeof(g_ModelDir), paths->ModelDir);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
