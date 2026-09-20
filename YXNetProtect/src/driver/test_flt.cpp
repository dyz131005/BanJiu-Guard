#include <fltKernel.h>

extern "C" VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

PFLT_FILTER g_Filter = nullptr;

FLT_PREOP_CALLBACK_STATUS YxPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    const FLT_OPERATION_REGISTRATION callbacks[] = {
        { IRP_MJ_CREATE, 0, YxPreCreate, nullptr },
        { IRP_MJ_OPERATION_END }
    };

    const FLT_REGISTRATION filterRegistration = {
        sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, nullptr, callbacks,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
    };

    NTSTATUS status = FltRegisterFilter(DriverObject, &filterRegistration, &g_Filter);
    if (!NT_SUCCESS(status)) return status;

    status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_Filter);
        g_Filter = nullptr;
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DbgPrint("[TestFlt] Driver loaded with minifilter.\n");
    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_Filter) {
        FltUnregisterFilter(g_Filter);
        g_Filter = nullptr;
    }
    DbgPrint("[TestFlt] Driver unloaded.\n");
}
