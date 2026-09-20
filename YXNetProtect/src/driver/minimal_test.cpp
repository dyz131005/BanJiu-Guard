#include <ntddk.h>

extern "C" VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    DbgPrint("[MinimalTest] Driver loaded.\n");
    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[MinimalTest] Driver unloaded.\n");
}
