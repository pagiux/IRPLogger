#include <initguid.h>
#include <stdio.h>

#include "IRPLoggerKernel.h"
#include "IRPLoggerUtils.h"
#include "IRPLoggerLog.h"

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, read_driver_parameters)
#if IRPLOGGER_VISTA
    #pragma alloc_text(PAGE, build_ecp_data_str)
    #pragma alloc_text(PAGE, parse_ecps)
#endif
#endif

VOID read_driver_parameters(_In_ PUNICODE_STRING registry_path)
/*++
Routine Description:
	This routine tries to read the IRPLogger-specific parameters from
	the registry.  These values will be found in the registry location
	indicated by the RegistryPath passed in.
	This processes the following registry keys:
	hklm\system\CurrentControlSet\Services\IRPLogger\MaxRecords
	hklm\system\CurrentControlSet\Services\IRPLogger\NameQueryMethod
Arguments:
	registry_path - the path key which contains the values that are the IRPLogger parameters
Return Value:
	None.
--*/
{
	OBJECT_ATTRIBUTES attributes;
	HANDLE driver_reg_key;
	NTSTATUS status;
	ULONG result_len;
	UNICODE_STRING value_name;
	PKEY_VALUE_PARTIAL_INFORMATION pvalue_partial_info;
	UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(LONG)];

	//  Open the registry
	InitializeObjectAttributes(&attributes,
		registry_path,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenKey(&driver_reg_key, KEY_READ, &attributes);

	if (!NT_SUCCESS(status))
		return;

	// Read the MaxRecordsToAllocate entry from the registry
	RtlInitUnicodeString(&value_name, MAX_RECORDS_TO_ALLOCATE);

	status = ZwQueryValueKey(driver_reg_key,
		&value_name,
		KeyValuePartialInformation,
		buffer,
		sizeof(buffer),
		&result_len);

	if (NT_SUCCESS(status)) {
		pvalue_partial_info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
		FLT_ASSERT(pvalue_partial_info->Type == REG_DWORD);
		irp_logger_data.max_records_to_allocate = *((PLONG) &(pvalue_partial_info->Data));
	}

	// Read the NameQueryMethod entry from the registry
	RtlInitUnicodeString(&value_name, NAME_QUERY_METHOD);

	status = ZwQueryValueKey(driver_reg_key,
		&value_name,
		KeyValuePartialInformation,
		buffer,
		sizeof(buffer),
		&result_len);

	if (NT_SUCCESS(status)) {
		pvalue_partial_info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
		FLT_ASSERT(pvalue_partial_info->Type == REG_DWORD);
		irp_logger_data.name_query_method = *((PLONG) &(pvalue_partial_info->Data));
	}

	ZwClose(driver_reg_key);
}

UCHAR tx_notification_to_minor_code(_In_ ULONG tx_notification)
{
    UCHAR count = 0;

    if (tx_notification == 0)
        return 0;

    FLT_ASSERT(!((tx_notification) & (tx_notification - 1)));

    while (tx_notification) {
        count++;
		tx_notification >>= 1;

        FLT_ASSERT(count != 0);
    }
    return count;
}

VOID delete_txf_context(_Inout_ PIRPLOGGER_TRANSACTION_CONTEXT context, _In_ FLT_CONTEXT_TYPE context_type)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(context_type);

	FLT_ASSERT(FLT_TRANSACTION_CONTEXT == context_type);
	FLT_ASSERT(context->count != 0);
}


LONG exception_filter(_In_ PEXCEPTION_POINTERS exception_pointer, _In_ BOOLEAN accessing_user_buffer)
{
	NTSTATUS status;

	status = exception_pointer->ExceptionRecord->ExceptionCode;
	if (!FsRtlIsNtstatusExpected(status) && !accessing_user_buffer)
		return EXCEPTION_CONTINUE_SEARCH;

	return EXCEPTION_EXECUTE_HANDLER;
}

static void punicode_to_wchar(
	_Inout_ WCHAR *result,
	_In_ PUNICODE_STRING s
)
{
	USHORT len = (s->Length < (MY_MAX_PATH * sizeof * result))
		? s->Length
		: MY_MAX_PATH * sizeof * result;

	RtlCopyMemory(result, s->Buffer, len);
	result[len] = 0;
}

NTSTATUS GetProcessImageName(WCHAR *process_image_name)
{
	NTSTATUS status;
	ULONG returned_length;
	PVOID buffer;
	PUNICODE_STRING image_name;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (NULL == ZwQueryInformationProcess) {

		UNICODE_STRING routineName;

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess) {
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
		}
	}

	// Step one - get the size we need
	status = ZwQueryInformationProcess(NtCurrentProcess(),
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&returned_length);

	if (STATUS_INFO_LENGTH_MISMATCH != status) 
		return status;

	// If we get here, the buffer IS going to be big enough for us, so 
	// let's allocate some storage.
	buffer = ExAllocatePoolWithTag(PagedPool, returned_length, 'ipgD');
	if (NULL == buffer) 		
		return STATUS_INSUFFICIENT_RESOURCES;

	// Now lets go get the data
	status = ZwQueryInformationProcess(NtCurrentProcess(),
		ProcessImageFileName,
		buffer,
		returned_length,
		&returned_length);

	if (NT_SUCCESS(status)) {
		// Ah, we got what we needed
		image_name = (PUNICODE_STRING)buffer;
		punicode_to_wchar(process_image_name, image_name);
	}

	// free our buffer
	ExFreePool(buffer);

	// And tell the caller what happened.
	return status;
}
