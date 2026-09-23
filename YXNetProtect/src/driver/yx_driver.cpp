// BanJiu-Guard - kernel driver (anti-YinHu trojan)
// Minifilter + process/image/registry/Ob callbacks + self-protection
//
// NOTE: For study/personal protection use. Production needs EV signing + WHQL.
//
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "yx_protocol.h"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
PDRIVER_OBJECT    g_DriverObject = nullptr;
PFLT_FILTER       g_Filter = nullptr;

// Communication port
PFLT_PORT         g_ServerPort = nullptr;
PFLT_PORT         g_ClientPort = nullptr;

// Protect flags
YX_PROTECT_FLAGS  g_ProtectFlags = { 0 };

// Stats
YX_STATS          g_Stats = { 0 };

// Protected PIDs (self-protection)
ULONG             g_ProtectedPids[64] = { 0 };
ULONG             g_ProtectedPidCount = 0;

// 关键防死锁：当前正在处理 IOCTL_YX_FORCE_* / IOCTL_YX_KILL_PROCESS 的线程对象指针
// Pre 回调开头检查：若当前线程 == 此指针，直接放行（绕过规则评估+FltSendMessage）
// 比 PID 绕过更可靠：PID 绕过依赖 PID 注册成功，而线程对象指针在 IOCTL 进入时即设置
volatile PVOID   g_IoctlActiveThread = nullptr;

// Protected paths (quarantine dir, driver sys, service exe) - set via IOCTL
WCHAR             g_QuarantineDir[260] = { 0 };
WCHAR             g_DriverSysPath[260] = { 0 };
WCHAR             g_ServiceExePath[260] = { 0 };
WCHAR             g_ConfigPath[260] = { 0 };
WCHAR             g_ModelDir[260] = { 0 };

// Ob callback handle
PVOID              g_ObHandle = nullptr;

// Registry callback cookie (unused with CmRegisterCallbackEx signature)
LARGE_INTEGER      g_Cookie = { 0 };

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
extern "C" VOID     DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

FLT_PREOP_CALLBACK_STATUS YxPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS YxPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS YxPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS YxPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

NTSTATUS YxDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS YxDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS YxDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

VOID YxThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);

NTSTATUS YxMessageNotify(
    _In_ PVOID ConnectionCookie,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

NTSTATUS YxConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie);

VOID YxDisconnectNotify(_In_opt_ PVOID ConnectionCookie);

VOID YxProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID YxLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);

NTSTATUS YxRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2);

OB_PREOP_CALLBACK_STATUS YxObPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

VOID YxReportEvent(YX_EVENT_TYPE type, YX_RULE_CATEGORY category,
                   YX_THREAT_LEVEL threat,
                   ULONG pid, ULONG parentPid, ULONG targetPid,
                   PCWSTR name0, PCWSTR name1, PCWSTR name2);

BOOLEAN YxIsPidProtected(ULONG pid);
NTSTATUS YxEnableSelfProtection();
VOID YxDisableSelfProtection();

// MBR/GPT protection helpers
BOOLEAN YxIsMbrWrite(PFLT_CALLBACK_DATA Data);
// Self-protection path check: returns TRUE if path is in quarantine dir or is driver/service file
BOOLEAN YxIsProtectedPath(PCWSTR path);
// Convert Win32 path (\??\C:\...) to normalized form for comparison
VOID YxNormalizePath(PCWSTR in, WCHAR* out, ULONG outChars);

#define YX_POOL_TAG 'xPYX'

// ===========================================================================
// DriverEntry
// ===========================================================================
extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    g_DriverObject = DriverObject;

    // ---- 1. Register Minifilter ----
    const FLT_OPERATION_REGISTRATION callbacks[] = {
        { IRP_MJ_CREATE, 0, YxPreCreate, YxPostCreate },
        { IRP_MJ_WRITE,  0, YxPreWrite,  nullptr },
        { IRP_MJ_SET_INFORMATION, 0, YxPreSetInformation, nullptr },
        { IRP_MJ_OPERATION_END }
    };

    const FLT_REGISTRATION filterRegistration = {
        sizeof(FLT_REGISTRATION),   // Size
        FLT_REGISTRATION_VERSION,   // Version
        0,                          // Flags
        nullptr,                    // ContextRegistration
        callbacks,                  // OperationRegistration
        nullptr,                    // FilterUnloadCallback
        nullptr,                    // InstanceSetupCallback
        nullptr,                    // InstanceQueryTeardownCallback
        nullptr,                    // InstanceTeardownStartCallback
        nullptr,                    // InstanceTeardownCompleteCallback
        nullptr,                    // GenerateFileNameCallback
        nullptr,                    // NormalizeNameComponentCallback
        nullptr,                    // NormalizeContextCleanupCallback
        nullptr,                    // TransactionNotificationCallback
        nullptr,                    // NormalizeNameComponentExCallback
        nullptr                     // SectionNotificationCallback
    };

    status = FltRegisterFilter(DriverObject, &filterRegistration, &g_Filter);
    if (!NT_SUCCESS(status)) return status;

    // ---- 2. Start filtering ----
    status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_Filter);
        g_Filter = nullptr;
        return status;
    }

    // ---- 3. Process notify callback ----
    status = PsSetCreateProcessNotifyRoutineEx(YxProcessNotify, FALSE);
    DbgPrint("[BanJiu-Guard] PsSetCreateProcessNotifyRoutineEx: 0x%X\n", status);

    // ---- 4. Load image notify callback (white-black DLL side-load detection) ----
    status = PsSetLoadImageNotifyRoutine(YxLoadImageNotify);
    DbgPrint("[BanJiu-Guard] PsSetLoadImageNotifyRoutine: 0x%X\n", status);

    // ---- 4b. Thread notify callback (remote thread injection detection) ----
    status = PsSetCreateThreadNotifyRoutine(YxThreadNotify);
    DbgPrint("[BanJiu-Guard] PsSetCreateThreadNotifyRoutine: 0x%X\n", status);

    // ---- 5. Registry callback (persistence detection) ----
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"369000");
    NTSTATUS regStatus = CmRegisterCallbackEx(YxRegistryCallback, &altitude,
                         DriverObject, nullptr, &g_Cookie, nullptr);
    g_Stats.RegCallbackStatus = (int32_t)regStatus;
    DbgPrint("[BanJiu-Guard] CmRegisterCallbackEx: 0x%X (cookie=%p)\n", regStatus, g_Cookie);

    // ---- 6. Communication port (user-mode service connects) ----
    PSECURITY_DESCRIPTOR sd = nullptr;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING portName = RTL_CONSTANT_STRING(YX_FILTER_PORT_NAME);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &portName,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   nullptr, sd);
        FltCreateCommunicationPort(g_Filter, &g_ServerPort, &oa, nullptr,
                                   YxConnectNotify, YxDisconnectNotify,
                                   YxMessageNotify, 1);
        FltFreeSecurityDescriptor(sd);
    }

    // ---- 7. Control device object (IOCTL) ----
    UNICODE_STRING devName = RTL_CONSTANT_STRING(YX_DEVICE_NAME);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(YX_SYMLINK_NAME);
    PDEVICE_OBJECT ctrlDev = nullptr;
    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &ctrlDev);
    if (NT_SUCCESS(status)) {
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = YxDispatchCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = YxDispatchClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = YxDispatchDeviceControl;
        ctrlDev->Flags |= DO_BUFFERED_IO;
        ctrlDev->Flags &= ~DO_DEVICE_INITIALIZING;
        IoCreateSymbolicLink(&symName, &devName);
    }

    DriverObject->DriverUnload = DriverUnload;
    DbgPrint("[BanJiu-Guard] Driver loaded.\n");
    return STATUS_SUCCESS;
}

// ===========================================================================
// Unload
// ===========================================================================
extern "C" VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = nullptr;
    }

    PsSetCreateProcessNotifyRoutineEx(YxProcessNotify, TRUE);
    PsRemoveLoadImageNotifyRoutine(YxLoadImageNotify);
    PsRemoveCreateThreadNotifyRoutine(YxThreadNotify);
    if (g_Cookie.QuadPart) CmUnRegisterCallback(g_Cookie);

    YxDisableSelfProtection();

    if (g_Filter) {
        FltUnregisterFilter(g_Filter);
        g_Filter = nullptr;
    }

    UNICODE_STRING symName = RTL_CONSTANT_STRING(YX_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);
    if (g_DriverObject && g_DriverObject->DeviceObject) {
        IoDeleteDevice(g_DriverObject->DeviceObject);
    }

    DbgPrint("[BanJiu-Guard] Driver unloaded.\n");
}
