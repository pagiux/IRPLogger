#include <stdio.h>
#include <math.h>
#include "IRPLoggerKernel.h"
#include "IRPLoggerLog.h"
#include "IRPLoggerUtils.h"

#if IRPLOGGER_VISTA
#include <ntifs.h>
#include <wsk.h>
#endif

PRECORD_LIST allocate_buffer(_Out_ PULONG record_type)
{
	PVOID new_buffer;
	ULONG new_record_type = RECORD_TYPE_NORMAL;

	//  See if we have room to allocate more buffers
	if (irp_logger_data.records_allocated < irp_logger_data.max_records_to_allocate) {
		InterlockedIncrement(&irp_logger_data.records_allocated);

		new_buffer = ExAllocateFromNPagedLookasideList(&irp_logger_data.free_buf_list);
		if (new_buffer == NULL) {
			InterlockedDecrement(&irp_logger_data.records_allocated);
			new_record_type = RECORD_TYPE_FLAG_OUT_OF_MEMORY;
		}
	}
	else {
		new_record_type = RECORD_TYPE_FLAG_EXCEED_MEMORY_ALLOWANCE;
		new_buffer = NULL;
	}

	*record_type = new_record_type;
	return new_buffer;
}


VOID free_buffer(_In_ PVOID buffer)
{
	//  Free the memory, update the counter
	InterlockedDecrement(&irp_logger_data.records_allocated);
	ExFreeToNPagedLookasideList(&irp_logger_data.free_buf_list, buffer);
}

PRECORD_LIST new_record(VOID)
{
	PRECORD_LIST new_record;
	ULONG initial_record_type;

	//  Allocate the buffer
	new_record = allocate_buffer(&initial_record_type);
	if (new_record == NULL) {
		if (!InterlockedExchange(&irp_logger_data.static_buffer_in_use, TRUE)) {
			new_record = (PRECORD_LIST)irp_logger_data.out_of_memory_buf;
			initial_record_type |= RECORD_TYPE_FLAG_STATIC;
		}
	}

	//  If we got a record (doesn't matter if it is static or not), init it
	if (new_record != NULL) {
		// Init the new record
		new_record->log_record.record_type = initial_record_type;
		new_record->log_record.length = sizeof(LOG_RECORD);

		new_record->log_record.sequence_number = InterlockedIncrement(&irp_logger_data.log_sequence_number);
		RtlZeroMemory(&new_record->log_record.data, sizeof(RECORD_DATA));
	}

	return new_record;
}

VOID free_record(_In_ PRECORD_LIST record)
{
	if (FlagOn(record->log_record.record_type, RECORD_TYPE_FLAG_STATIC)) {
		// This was our static buffer, mark it available.
		FLT_ASSERT(irp_logger_data.static_buffer_in_use);
		irp_logger_data.static_buffer_in_use = FALSE;
	}
	else
		free_buffer(record);
}

#if IRPLOGGER_VISTA

VOID build_ecp_data_str(
	_In_ PRECORD_LIST record_list,
	_Inout_ PUNICODE_STRING ecp_data,
	_In_reads_(ecps_known_number) PVOID *context_pointers
)
/*++
Routine Description:
	Given the ECP presence data and context pointers located in SpyParseEcps,
	uses _snwprintf to write a human-readable log output to a string provided.
Arguments:
	record_list - Pointer to the record, so we can see ECP count and masking
	ecp_data - Pointer to string to receive formatted ECP log
	context_pointers - Pointer to array of pointers, each of which is either NULL
					  or a context structure specific to a given type of ECP
Return Value:
	None.
--*/
{
	ULONG known_count = 0;
	SHORT wchars_copied = 0;
	PRECORD_DATA record_data = &record_list->log_record.data;
	PWCHAR print_pointer = ecp_data->Buffer;

#if IRPLOGGER_WIN7
	TCHAR address_buffer[ADDRESS_STRING_BUFFER_SIZE];
	ULONG address_buffer_len;
	LONG address_conv_status;
#endif
	PAGED_CODE();
	FLT_ASSERT(NULL != context_pointers);

	//  Print initial ECP text
#pragma prefast(push)
#pragma prefast(disable: __WARNING_POTENTIAL_BUFFER_OVERFLOW_HIGH_PRIORITY __WARNING_BANNED_API_USAGE, "reviewed and safe usage")
//  Prefast complains here because _snwprintf has some oddities.
//  We've (Microsoft) code reviewed to ensure safe usage.

	wchars_copied = (SHORT)_snwprintf(print_pointer,
		MAX_NAME_WCHARS_LESS_NULL,
		L"[%d ECPs:",
		record_data->ecp_count);

	//  Next, check all the known ECPs against the mask that was set in SpyParseEcps.
	//  If we recognize any of the ECPs, add their data to the log string.
#if IRPLOGGER_WIN7
	//  Oplock key ECP
	if (FlagOn(record_data->known_ecp_mask, ECP_TYPE_FLAG_OPLOCK_KEY)) {
		POPLOCK_KEY_ECP_CONTEXT oplock_ecp_context = NULL;
		LPGUID oplock_key_guid;
		UNICODE_STRING oplock_key_guid_str;

		known_count++;
		oplock_ecp_context = (POPLOCK_KEY_ECP_CONTEXT)context_pointers[ECP_OPLOCK_KEY];

		FLT_ASSERT(NULL != oplock_ecp_context);
		oplock_key_guid = &oplock_ecp_context->OplockKey;

		if (NT_SUCCESS(RtlStringFromGUID(oplock_key_guid, &oplock_key_guid_str))) {
			//  Format an output string to display the key in GUID form
			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s OPLOCK KEY: %wZ;",
				print_pointer,
				&oplock_key_guid_str);

			RtlFreeUnicodeString(&oplock_key_guid_str);

		}
		else {
			// Error processing the GUID
			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s INVALID OPLOCK KEY;",
				print_pointer);
		}
	}
	//  NFS ECP
	if (FlagOn(record_data->known_ecp_mask, ECP_TYPE_FLAG_NFS)) {
		PNFS_OPEN_ECP_CONTEXT nfs_ecp_context = NULL;
		PUNICODE_STRING nfs_share_name_string;
		PSOCKADDR_STORAGE_NFS nfs_client_socket_addr;

		known_count++;
		nfs_ecp_context = (PNFS_OPEN_ECP_CONTEXT)context_pointers[ECP_NFS_OPEN];

		FLT_ASSERT(NULL != nfs_ecp_context);

		nfs_share_name_string = nfs_ecp_context->ExportAlias;
		nfs_client_socket_addr = nfs_ecp_context->ClientSocketAddress;

		//  Print the share name, if the string (optional) is present
		if (nfs_share_name_string) {

			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s NFS SHARE NAME: %wZ,",
				print_pointer,
				nfs_share_name_string);
		}

		FLT_ASSERT(nfs_client_socket_addr != NULL);

		address_conv_status = STATUS_INVALID_PARAMETER;
		address_buffer_len = ADDRESS_STRING_BUFFER_SIZE;

		if (nfs_client_socket_addr->ss_family == AF_INET) {
			PSOCKADDR_IN ipv4_socket_addr = (PSOCKADDR_IN) nfs_client_socket_addr;
			//  Format IPv4 address and port
			address_conv_status = RtlIpv4AddressToStringEx(
				&ipv4_socket_addr->sin_addr,
				ipv4_socket_addr->sin_port,
				address_buffer,
				&address_buffer_len);

		}
		else if (nfs_client_socket_addr->ss_family == AF_INET6) {
			PSOCKADDR_IN6 ipv6_socket_addr = (PSOCKADDR_IN6) nfs_client_socket_addr;
			//  Format IPv6 address and port
			address_conv_status = RtlIpv6AddressToStringEx(
				&ipv6_socket_addr->sin6_addr,
				0,
				ipv6_socket_addr->sin6_port,
				address_buffer,
				&address_buffer_len);
		}
		//  Print the address (and port)
		if ((STATUS_INVALID_PARAMETER != address_conv_status) && (0 < address_buffer_len)) {

			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s NFS SOCKET ADDR: %S;",
				print_pointer,
				address_buffer);

		}
		else {
			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s NFS INVALID SOCKET ADDR;",
				print_pointer);
		}
	}
	//  SRV ECP
	if (FlagOn(record_data->known_ecp_mask, ECP_TYPE_FLAG_SRV)) {
		PSRV_OPEN_ECP_CONTEXT srv_ecp_context = NULL;
		PUNICODE_STRING srv_share_name_string;
		PSOCKADDR_STORAGE_NFS srv_client_socket_addr;

		known_count++;

		//  We now know this context pointer points to a SRV_OPEN_ECP_CONTEXT structure
		srv_ecp_context = (PSRV_OPEN_ECP_CONTEXT)context_pointers[ECP_SVR_OPEN];
		FLT_ASSERT(NULL != srv_ecp_context);

		srv_share_name_string = srv_ecp_context->ShareName;
		srv_client_socket_addr = srv_ecp_context->SocketAddress;

		//  Print the share name, if the string is present
		if (srv_share_name_string) {
			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s SRV SHARE NAME: %wZ,",
				print_pointer,
				srv_share_name_string);
		}

		FLT_ASSERT(srv_client_socket_addr != NULL);

		address_conv_status = STATUS_INVALID_PARAMETER;
		address_buffer_len = ADDRESS_STRING_BUFFER_SIZE;

		//  Print the address, whether it's IPv4 or IPv6
		if (srv_client_socket_addr->ss_family == AF_INET) {
			PSOCKADDR_IN ipv4_socket_addr = (PSOCKADDR_IN)srv_client_socket_addr;

			//  Format IPv4 address and port
			address_conv_status = RtlIpv4AddressToStringEx(
				&ipv4_socket_addr->sin_addr,
				ipv4_socket_addr->sin_port,
				address_buffer,
				&address_buffer_len);

		}
		else if (srv_client_socket_addr->ss_family == AF_INET6) {
			PSOCKADDR_IN6 ipv6_socket_addr = (PSOCKADDR_IN6)srv_client_socket_addr;

			//  Format IPv6 address and port
			address_conv_status = RtlIpv6AddressToStringEx(
				&ipv6_socket_addr->sin6_addr,
				0,
				ipv6_socket_addr->sin6_port,
				address_buffer,
				&address_buffer_len);
		}

		if ((STATUS_INVALID_PARAMETER != address_conv_status) && (0 < address_buffer_len)) {
			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s SRV SOCKET ADDR: %S;",
				print_pointer,
				address_buffer);
		}
		else {
			wchars_copied = (SHORT)_snwprintf(print_pointer,
				MAX_NAME_WCHARS_LESS_NULL,
				L"%s SRV INVALID SOCKET ADDR;",
				print_pointer);
		}
		//  Print SRV flags
		wchars_copied = (SHORT)_snwprintf(print_pointer,
			MAX_NAME_WCHARS_LESS_NULL,
			L"%s SRV FLAGS: %s%s%s;",
			print_pointer,
			(srv_ecp_context->OplockBlockState) ? L"B" : L"-",
			(srv_ecp_context->OplockAppState) ? L"A" : L"-",
			(srv_ecp_context->OplockFinalState) ? L"F" : L"-");
	}

#else
	UNREFERENCED_PARAMETER(context_pointers);
#endif
	//  Prefetch ECP
	if (FlagOn(record_data->known_ecp_mask, ECP_TYPE_FLAG_PREFETCH)) {
		known_count++;

		wchars_copied = (SHORT)_snwprintf(print_pointer,
			MAX_NAME_WCHARS_LESS_NULL,
			L"%s PREFETCH;",
			print_pointer);
	}

	//  Print closing ECP text
	if (known_count < record_data->ecp_count) {
		wchars_copied = (SHORT)_snwprintf(print_pointer,
			MAX_NAME_WCHARS_LESS_NULL,
			L"%s %d unknown ECPs]",
			print_pointer,
			record_data->ecp_count - known_count);

	}
	else {
		wchars_copied = (SHORT)_snwprintf(print_pointer,
			MAX_NAME_WCHARS_LESS_NULL,
			L"%s]",
			print_pointer);
	}

	if (wchars_copied >= 0)
		ecp_data->Length = wchars_copied * sizeof(WCHAR);
	else {
		//  There wasn't enough buffer space, so manually truncate in a NULL
		ecp_data->Length = MAX_NAME_SPACE_LESS_NULL;
		ecp_data->Buffer[MAX_NAME_WCHARS_LESS_NULL] = UNICODE_NULL;
	}
#pragma prefast(pop)
}

VOID parse_ecps(
	_In_ PFLT_CALLBACK_DATA data,
	_Inout_ PRECORD_LIST record_list,
	_Inout_ PUNICODE_STRING ecp_data
)
/*++
Routine Description:
	Extracts ECPs from the given callback data and logs them,
	then calls SpyBuildEcpDataString to write a MiniSpy-specific
	ECP log string.
Arguments:
	data - The Data structure that contains the information we want to record.
	record_list - Pointer to the record, so we can set ECP count and masking
	ecp_data - Pointer to string to receive formatted ECP log
Return Value:
	None.
--*/
{
	NTSTATUS status;
	PECP_LIST ecp_list;
	PRECORD_DATA record_data = &record_list->log_record.data;
	PVOID ecp_context = NULL;
	GUID ecp_guid = { 0 };
	ULONG ecp_context_size = 0;
	ULONG ecp_flag;
	PVOID context_pointers[ECP_KNOWN_NUMBER];
	UCHAR offset = 0;

	PAGED_CODE();

	RtlZeroMemory(context_pointers, sizeof(PVOID) * ECP_KNOWN_NUMBER);

	//  Try to get an ECP list pointer from filter manager
	status = FltGetEcpListFromCallbackData(irp_logger_data.filter,
		data,
		&ecp_list);

	if (NT_SUCCESS(status) && (NULL != ecp_list)) {
		//  Now ask filter manager for each ECP
		while (NT_SUCCESS(
			FltGetNextExtraCreateParameter(irp_logger_data.filter,
				ecp_list,
				ecp_context,
				(LPGUID)&ecp_guid,
				&ecp_context,
				&ecp_context_size))) {

			ecp_flag = 0;
			if (IsEqualGUID(&GUID_ECP_PREFETCH_OPEN, &ecp_guid)) {
				//  Prefetch ECP
				ecp_flag = ECP_TYPE_FLAG_PREFETCH;
				offset = ECP_PREFETCH_OPEN;
			}
#if IRPLOGGER_WIN7
			//  There are three system-defined ECPs that are only available as of Windows 7
			else if (IsEqualGUID(&GUID_ECP_OPLOCK_KEY, &ecp_guid)) {
				//  Oplock key ECP
				ecp_flag = ECP_TYPE_FLAG_OPLOCK_KEY;
				offset = ECP_OPLOCK_KEY;
			}
			else if (IsEqualGUID(&GUID_ECP_NFS_OPEN, &ecp_guid)) {
				//  NFS open ECP
				ecp_flag = ECP_TYPE_FLAG_NFS;
				offset = ECP_NFS_OPEN;
			}
			else if (IsEqualGUID(&GUID_ECP_SRV_OPEN, &ecp_guid)) {
				//  SRV ECP
				ecp_flag = ECP_TYPE_FLAG_SRV;
				offset = ECP_SVR_OPEN;
			}
#endif

			//  We don't accept user mode ECPs because of the potential for bad buffers
			if ((0 != ecp_flag) && !FltIsEcpFromUserMode(irp_logger_data.filter, ecp_context)) {

				FLT_ASSERT(!FlagOn(record_data->known_ecp_mask, ecp_flag));
				//  Set the flag to indicate a given type of ECP was found
				record_data->known_ecp_mask |= ecp_flag;

				//  Save the context pointer so we can get detailed data later
				context_pointers[offset] = ecp_context;
			}
			//  Increment the number of total ECPs (counting both known and unknown)
			record_data->ecp_count++;
		}

		//  Call the IRPLogger-specific function to format the ECP data string for output
		if (0 < record_data->ecp_count)
			build_ecp_data_str(record_list, ecp_data, context_pointers);
	}
}

VOID set_record_name_and_ecp_data(
	_Inout_ PLOG_RECORD log_record,
	_In_ PUNICODE_STRING name,
	_In_opt_ PUNICODE_STRING ecp_data
)
/*++
Routine Description:
	Sets the given file name in the LogRecord.
	NOTE:  This code must be NON-PAGED because it can be called on the
		   paging path.
Arguments:
	log_record - The record in which to set the name.
	name - The name to insert
	ecp_data - A string of variable-length ECP data to insert
Return Value:
	None.
--*/
{

	PWCHAR print_pointer = (PWCHAR)log_record->name;
	SHORT wchars_copied;
	USHORT string_length;

	FLT_ASSERT(NULL != name);

	if (NULL != ecp_data) {
#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
		wchars_copied = (SHORT)_snwprintf(print_pointer,
			MAX_NAME_WCHARS_LESS_NULL,
			L"%wZ %wZ",
			name,
			ecp_data);

	}
	else {
#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
		wchars_copied = (SHORT)_snwprintf(print_pointer,
			MAX_NAME_WCHARS_LESS_NULL,
			L"%wZ",
			name);
	}

	if (wchars_copied >= 0)
		string_length = wchars_copied * sizeof(WCHAR);
	else {
		string_length = MAX_NAME_SPACE_LESS_NULL;
		print_pointer[MAX_NAME_WCHARS_LESS_NULL] = UNICODE_NULL;
	}

	log_record->length = ROUND_TO_SIZE((log_record->length +
		string_length +
		sizeof(UNICODE_NULL)),
		sizeof(PVOID));

	FLT_ASSERT(log_record->length <= MAX_LOG_RECORD_LENGTH);
}

#else
VOID set_record_name(
	_Inout_ PLOG_RECORD log_record,
	_In_ PUNICODE_STRING name
)
/*++
Routine Description:
	Sets the given file name in the LogRecord.
	NOTE:  This code must be NON-PAGED because it can be called on the
		   paging path.
Arguments:
	LogRecord - The record in which to set the name.
	Name - The name to insert
Return Value:
	None.
--*/
{

	PWCHAR print_pointer = (PWCHAR)log_record->Name;
	SHORT wchars_copied;
	USHORT string_length;

	FLT_ASSERT(NULL != name);

#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
	wchars_copied = (SHORT)_snwprintf(print_pointer,
		MAX_NAME_WCHARS_LESS_NULL,
		L"%wZ",
		name);

	if (wchars_copied >= 0)
		string_length = wchars_copied * sizeof(WCHAR);
	else {
		string_length = MAX_NAME_SPACE_LESS_NULL;
		print_pointer[MAX_NAME_WCHARS_LESS_NULL] = UNICODE_NULL;
	}

	log_record->Length = ROUND_TO_SIZE((log_record->Length +
		string_length +
		sizeof(UNICODE_NULL)),
		sizeof(PVOID));

	FLT_ASSERT(log_record->Length <= MAX_LOG_RECORD_LENGTH);
}

#endif

double shannon_entropy(PUCHAR buffer, ULONG size)
{
	double M_LOG2E = 1.4426950408889634;

	double entropy = 0.0;
	ULONG bucket_byte[256] = { 0 };
	for (ULONG i = 0; i < size; i++)
	{
		bucket_byte[buffer[i]]++;
	}

	XSTATE_SAVE SaveState;
	__try {
		KeSaveExtendedProcessorState(XSTATE_MASK_LEGACY, &SaveState);
		for (ULONG i = 0; i < 256; i++)
		{
			if (bucket_byte[i] != 0)
			{
				double val = (double)bucket_byte[i] / (double)size;
				entropy += (-1) * val * log(val) * M_LOG2E;
			}
		}
	}
	__finally {
		KeRestoreExtendedProcessorState(&SaveState);
	}
	return entropy;
}

VOID log_pre_operation_data(
	_In_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_Inout_ PRECORD_LIST record_list
)
/*++
Routine Description:
	This is called from the pre-operation callback routine to copy the
	necessary information into the log record.
	NOTE:  This code must be NON-PAGED because it can be called on the
		   paging path.
Arguments:
	Data - The Data structure that contains the information we want to record.
	FltObjects - Pointer to the io objects involved in this operation.
	RecordList - Where we want to save the data
Return Value:
	None.
--*/
{
	PRECORD_DATA record_data = &record_list->log_record.data;
	PDEVICE_OBJECT dev_obj;
	NTSTATUS status;

	status = FltGetDeviceObject(flt_objects->Volume, &dev_obj);
	if (NT_SUCCESS(status))
		ObDereferenceObject(dev_obj);
	else
		dev_obj = NULL;

	//  Save the information we want
	record_data->callback_major_id = data->Iopb->MajorFunction;
	record_data->callback_minor_id = data->Iopb->MinorFunction;
	record_data->irp_flags = data->Iopb->IrpFlags;
	record_data->flags = data->Flags;

	record_data->device_object = (FILE_ID)dev_obj;
	record_data->file_object = (FILE_ID)flt_objects->FileObject;
	record_data->transaction = (FILE_ID)flt_objects->Transaction;
	record_data->process_id = (FILE_ID)PsGetCurrentProcessId();
	record_data->thread_id = (FILE_ID)PsGetCurrentThreadId();

	GetProcessImageName(record_data->process_name);

	record_data->Arg1 = data->Iopb->Parameters.Others.Argument1;
	record_data->Arg2 = data->Iopb->Parameters.Others.Argument2;
	record_data->Arg3 = data->Iopb->Parameters.Others.Argument3;
	record_data->Arg4 = data->Iopb->Parameters.Others.Argument4;
	record_data->Arg5 = data->Iopb->Parameters.Others.Argument5;
	record_data->Arg6.QuadPart = data->Iopb->Parameters.Others.Argument6.QuadPart;

	KeQuerySystemTime(&record_data->originating_time);
}

VOID log_post_operation_data(
	_In_ PFLT_CALLBACK_DATA data,
	_Inout_ PRECORD_LIST record_list
)
/*++
Routine Description:
	This is called from the post-operation callback routine to copy the
	necessary information into the log record.
	NOTE:  This code must be NON-PAGED because it can be called on the
		   paging path or at DPC level.
Arguments:
	Data - The Data structure that contains the information we want to record.
	RecordList - Where we want to save the data
Return Value:
	None.
--*/
{
	PRECORD_DATA record_data = &record_list->log_record.data;
	PVOID data_buffer = NULL;
	ULONG data_len = 0;

	record_data->status = data->IoStatus.Status;
	record_data->information = data->IoStatus.Information;

	if (record_data->callback_major_id == IRP_MJ_WRITE) {
		data_len = data->Iopb->Parameters.Write.Length;

		if (data_len > 0) {
			if (data->Iopb->Parameters.Write.MdlAddress == NULL) { //there's mdl buffer, we use it
				data_buffer = data->Iopb->Parameters.Write.WriteBuffer;
			}
			else {
				data_buffer = MmGetSystemAddressForMdlSafe(data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
			}

			//  Copy the memory, we must do this inside the try/except because we may be using a users buffer address
			try {
				record_data->data_len = data_len;
				record_data->entropy = shannon_entropy(data_buffer, data_len);

			}
			except(EXCEPTION_EXECUTE_HANDLER) {
				record_data->data_len = 0;
				record_data->entropy = 0.0;
			}
		}
	}

	else if (record_data->callback_major_id == IRP_MJ_READ) {
		data_len = data->Iopb->Parameters.Read.Length;

		if (data_len > 0) {
			if (data->Iopb->Parameters.Read.MdlAddress == NULL) { //there's mdl buffer, we use it
				data_buffer = data->Iopb->Parameters.Read.ReadBuffer;
			}
			else {
				data_buffer = MmGetSystemAddressForMdlSafe(data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
			}

			//  Copy the memory, we must do this inside the try/except because we may be using a users buffer address
			try {
				record_data->data_len = data_len;
				record_data->entropy = shannon_entropy(data_buffer, data_len);

			}
			except(EXCEPTION_EXECUTE_HANDLER) {
				record_data->data_len = 0;
				record_data->entropy = 0.0;
			}
		}
	}

	KeQuerySystemTime(&record_data->completion_time);
}

VOID log_transaction_notify(
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_Inout_ PRECORD_LIST record_list,
	_In_ ULONG transaction_notification
)
/*++
Routine Description:
	This routine logs the transaction notification.
Arguments:
	FltObjects - Pointer to the io objects involved in this operation.
	RecordList - Where we want to save the data
	TransactionNotification - Notification for this transaction.
Return Value:
	None.
--*/
{
	PRECORD_DATA record_data = &record_list->log_record.data;
	PDEVICE_OBJECT dev_obj;
	NTSTATUS status;

	status = FltGetDeviceObject(flt_objects->Volume, &dev_obj);
	if (NT_SUCCESS(status))
		ObDereferenceObject(dev_obj);
	else
		dev_obj = NULL;


	record_data->callback_major_id = IRP_MJ_TRANSACTION_NOTIFY;
	record_data->callback_minor_id = tx_notification_to_minor_code(transaction_notification);

	record_data->device_object = (FILE_ID)dev_obj;
	record_data->file_object = (FILE_ID)flt_objects->FileObject;
	record_data->transaction = (FILE_ID)flt_objects->Transaction;
	record_data->process_id = (FILE_ID)PsGetCurrentProcessId();
	record_data->thread_id = (FILE_ID)PsGetCurrentThreadId();

	KeQuerySystemTime(&record_data->originating_time);
}

VOID logging(_In_ PRECORD_LIST record_list)
/*++
Routine Description:
	This routine inserts the given log record into the list to be sent
	to the user mode application.
	NOTE:  This code must be NON-PAGED because it can be called on the
		   paging path or at DPC level and uses a spin-lock
Arguments:
	RecordList - The record to append to the MiniSpyData.OutputBufferList
Return Value:
	None.
--*/
{
	KIRQL old_irql;

	KeAcquireSpinLock(&irp_logger_data.out_buffer_lock, &old_irql);
	InsertTailList(&irp_logger_data.out_buffer_list, &record_list->list);
	KeReleaseSpinLock(&irp_logger_data.out_buffer_lock, old_irql);
}

NTSTATUS get_log(
	_Out_writes_bytes_to_(out_buffer_length, *return_out_buffer_length) PUCHAR out_buffer,
	_In_ ULONG out_buffer_length,
	_Out_ PULONG return_out_buffer_length
)
/*++
Routine Description:
	This function fills OutputBuffer with as many LOG_RECORDs as possible.
	The LOG_RECORDs are variable sizes and are tightly packed in the
	OutputBuffer.
	NOTE:  This code must be NON-PAGED because it uses a spin-lock.
Arguments:
	out_buffer - The user's buffer to fill with the log data we have collected
	out_buffer_length - The size in bytes of OutputBuffer
	return_out_buffer_length - The amount of data actually written into the OutputBuffer.
Return Value:
	STATUS_SUCCESS if some records were able to be written to the OutputBuffer.
	STATUS_NO_MORE_ENTRIES if we have no data to return.
	STATUS_BUFFER_TOO_SMALL if the OutputBuffer is too small to hold even one record and we have data to return.
--*/
{
	PLIST_ENTRY plist;
	ULONG bytes_written = 0;
	PLOG_RECORD plog_record;
	NTSTATUS status = STATUS_NO_MORE_ENTRIES;
	PRECORD_LIST precord_list;
	KIRQL old_irql;
	BOOLEAN records_available = FALSE;

	KeAcquireSpinLock(&irp_logger_data.out_buffer_lock, &old_irql);

	while (!IsListEmpty(&irp_logger_data.out_buffer_list) && (out_buffer_length > 0)) {
		//  Mark we have records
		records_available = TRUE;
		//  Get the next available record
		plist = RemoveHeadList(&irp_logger_data.out_buffer_list);
		precord_list = CONTAINING_RECORD(plist, RECORD_LIST, list);
		plog_record = &precord_list->log_record;

		//  If no filename was set then make it into a NULL file name.
		if (REMAINING_NAME_SPACE(plog_record) == MAX_NAME_SPACE) {
			plog_record->length += ROUND_TO_SIZE(sizeof(UNICODE_NULL), sizeof(PVOID));
			plog_record->name[0] = UNICODE_NULL;
		}

		//  Put it back if we've run out of room.
		if (out_buffer_length < plog_record->length) {
			InsertHeadList(&irp_logger_data.out_buffer_list, plist);
			break;
		}

		KeReleaseSpinLock(&irp_logger_data.out_buffer_lock, old_irql);

		try {
			RtlCopyMemory(out_buffer, plog_record, plog_record->length);
		}
		except(exception_filter(GetExceptionInformation(), TRUE)) {
			//  Put the record back in
			KeAcquireSpinLock(&irp_logger_data.out_buffer_lock, &old_irql);
			InsertHeadList(&irp_logger_data.out_buffer_list, plist);
			KeReleaseSpinLock(&irp_logger_data.out_buffer_lock, old_irql);

			return GetExceptionCode();
		}

		bytes_written += plog_record->length;
		out_buffer_length -= plog_record->length;
		out_buffer += plog_record->length;
		free_record(precord_list);

		//  Relock the list
		KeAcquireSpinLock(&irp_logger_data.out_buffer_lock, &old_irql);
	}

	KeReleaseSpinLock(&irp_logger_data.out_buffer_lock, old_irql);

	//  Set proper status
	if ((bytes_written == 0) && records_available)
		status = STATUS_BUFFER_TOO_SMALL;
	else if (bytes_written > 0)
		status = STATUS_SUCCESS;

	*return_out_buffer_length = bytes_written;

	return status;
}

VOID empty_output_buffer_list(VOID)
/*++
Routine Description:
	This routine frees all the remaining log records in the out_buffer_list
	that are not going to get sent up to the user mode application since
	IRPLogger is shutting down.
	NOTE:  This code must be NON-PAGED because it uses a spin-lock
Arguments:
	None.
Return Value:
	None.
--*/
{
	PLIST_ENTRY plist;
	PRECORD_LIST precord_list;
	KIRQL old_irql;

	KeAcquireSpinLock(&irp_logger_data.out_buffer_lock, &old_irql);

	while (!IsListEmpty(&irp_logger_data.out_buffer_list)) {
		plist = RemoveHeadList(&irp_logger_data.out_buffer_list);

		KeReleaseSpinLock(&irp_logger_data.out_buffer_lock, old_irql);
		precord_list = CONTAINING_RECORD(plist, RECORD_LIST, list);
		free_record(precord_list);
		KeAcquireSpinLock(&irp_logger_data.out_buffer_lock, &old_irql);
	}
	KeReleaseSpinLock(&irp_logger_data.out_buffer_lock, old_irql);
}