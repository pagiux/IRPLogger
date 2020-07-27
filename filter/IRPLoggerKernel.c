#include "IRPLoggerKernel.h"
#include "IRPLoggerConnection.h"
#include "IRPLoggerLog.h"
#include "IRPLoggerUtils.h"
#include <stdio.h>

IRPLOGGER_DATA irp_logger_data;
NTSTATUS break_on = 0;
DRIVER_INITIALIZE driver_entry;

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT driver_object,
	_In_ PUNICODE_STRING registry_path
);

NTSTATUS enlist_in_transaction(_In_ PCFLT_RELATED_OBJECTS flt_objects);

//---------------------------------------------------------------------------
//  Assign text sections for each routine.
//---------------------------------------------------------------------------

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, filter_unload)
#pragma alloc_text(PAGE, query_teardown)
#pragma alloc_text(PAGE, connect)
#pragma alloc_text(PAGE, disconnect)
#pragma alloc_text(PAGE, messages)
#endif

#define SetFlagInterlocked(_ptrFlags,_flagToSet) \
    ((VOID)InterlockedOr(((volatile LONG *)(_ptrFlags)),_flagToSet))

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT driver_object,
	_In_ PUNICODE_STRING registry_path
)
{
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uni_string;
	NTSTATUS status = STATUS_SUCCESS;

	try {
		irp_logger_data.log_sequence_number = 0;
		irp_logger_data.max_records_to_allocate = DEFAULT_MAX_RECORDS_TO_ALLOCATE;
		irp_logger_data.records_allocated = 0;
		irp_logger_data.name_query_method = DEFAULT_NAME_QUERY_METHOD;

		irp_logger_data.driver_object = driver_object;

		InitializeListHead(&irp_logger_data.out_buffer_list);
		KeInitializeSpinLock(&irp_logger_data.out_buffer_lock);

		ExInitializeNPagedLookasideList(&irp_logger_data.free_buf_list,
			NULL,
			NULL,
			POOL_NX_ALLOCATION,
			RECORD_SIZE,
			IRPLOGGER_TAG,
			0);

#if IRPLOGGER_VISTA
#pragma warning(push)
#pragma warning(disable:4055) // type cast from data pointer to function pointer
		irp_logger_data.flt_set_transaction_context = (PFLT_SET_TRANSACTION_CONTEXT)FltGetRoutineAddress("FltSetTransactionContext");
		irp_logger_data.flt_get_transaction_context = (PFLT_GET_TRANSACTION_CONTEXT)FltGetRoutineAddress("FltGetTransactionContext");
		irp_logger_data.flt_enlist_in_transaction = (PFLT_ENLIST_IN_TRANSACTION)FltGetRoutineAddress("FltEnlistInTransaction");
#pragma warning(pop)

#endif

		// Read the custom parameters for MiniSpy from the registry
		read_driver_parameters(registry_path);

		//  Now that our global configuration is complete, register with FltMgr.
		status = FltRegisterFilter(driver_object, &filter_registration, &irp_logger_data.filter);

		if (!NT_SUCCESS(status))
			leave;

		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

		if (!NT_SUCCESS(status))
			leave;

		RtlInitUnicodeString(&uni_string, IRPLOGGER_PORT_NAME);

		InitializeObjectAttributes(&oa,
			&uni_string,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			NULL,
			sd);

		status = FltCreateCommunicationPort(irp_logger_data.filter,
			&irp_logger_data.server_port,
			&oa,
			NULL,
			connect,
			disconnect,
			messages,
			1);

		FltFreeSecurityDescriptor(sd);

		if (!NT_SUCCESS(status))
			leave;

		//  We are now ready to start filtering
		status = FltStartFiltering(irp_logger_data.filter);

	}
	finally{
		if (!NT_SUCCESS(status)) {
			 if (NULL != irp_logger_data.server_port)
				 FltCloseCommunicationPort(irp_logger_data.server_port);

			 if (NULL != irp_logger_data.filter)
				 FltUnregisterFilter(irp_logger_data.filter);

			 ExDeleteNPagedLookasideList(&irp_logger_data.free_buf_list);
		}
	}
	return status;
}

NTSTATUS filter_unload(_In_ FLT_FILTER_UNLOAD_FLAGS flags)
/*++
Routine Description:
	This is called when a request has been made to unload the filter.  Unload
	requests from the Operation System (ex: "sc stop minispy" can not be
	failed.  Other unload requests may be failed.
	You can disallow OS unload request by setting the
	FLTREGFL_DO_NOT_SUPPORT_SERVICE_STOP flag in the FLT_REGISTARTION
	structure.
Arguments:
	flags - Flags pertinent to this operation
Return Value:
	Always success
--*/
{
	UNREFERENCED_PARAMETER(flags);

	PAGED_CODE();

	//  Close the server port. This will stop new connections.
	FltCloseCommunicationPort(irp_logger_data.server_port);

	FltUnregisterFilter(irp_logger_data.filter);

	empty_output_buffer_list();
	ExDeleteNPagedLookasideList(&irp_logger_data.free_buf_list);

	return STATUS_SUCCESS;
}

NTSTATUS query_teardown(
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags
)
/*++
Routine Description:
	This allows our filter to be manually detached from a volume.
Arguments:
	FltObjects - Contains pointer to relevant objects for this operation.
		Note that the FileObject field will always be NULL.
	Flags - Flags pertinent to this operation
Return Value:
	STATUS_SUCCESS
--*/
{
	UNREFERENCED_PARAMETER(flt_objects);
	UNREFERENCED_PARAMETER(flags);
	PAGED_CODE();
	return STATUS_SUCCESS;
}

//---------------------------------------------------------------------------
//              Operation filtering routines
//---------------------------------------------------------------------------

#pragma warning(suppress: 6262) // higher than usual stack usage is considered safe in this case
FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_Flt_CompletionContext_Outptr_ PVOID *completion_context
)
/*++
Routine Description (from Microsoft):
	This routine receives ALL pre-operation callbacks for this filter.  It then
	tries to log information about the given operation.  If we are able
	to log information then we will call our post-operation callback  routine.
	NOTE:  This routine must be NON-PAGED because it can be called on the
		   paging path.
Arguments:
	data - Contains information about the given operation.
	flt_objects - Contains pointers to the various objects that are pertinent
		to this operation.
	completion_context - This receives the address of our log buffer for this
		operation.  Our completion routine then receives this buffer address.
Return Value:
	Identifies how processing should continue for this operation
--*/
{
	FLT_PREOP_CALLBACK_STATUS return_status = FLT_PREOP_SUCCESS_NO_CALLBACK; //assume we are NOT going to call our completion routine
	PRECORD_LIST record_list;
	PFLT_FILE_NAME_INFORMATION name_info = NULL;
	UNICODE_STRING default_name;
	PUNICODE_STRING name_to_use;
	NTSTATUS status;

#if IRPLOGGER_VISTA
	PUNICODE_STRING ecp_data_to_use = NULL;
	UNICODE_STRING ecp_data;
	WCHAR ecp_data_buffer[MAX_NAME_SPACE / sizeof(WCHAR)];

#endif
#if IRPLOGGER_NOT_W2K
	WCHAR name[MAX_NAME_SPACE / sizeof(WCHAR)];
#endif
	//  Try and get a log record
	record_list = new_record();

	if (record_list) {
		//  We got a log record, if there is a file object, get its name.
		if (flt_objects->FileObject != NULL) {
			status = FltGetFileNameInformation(data,
				FLT_FILE_NAME_NORMALIZED |
				FLT_FILE_NAME_QUERY_DEFAULT |
				irp_logger_data.name_query_method,
				&name_info);

		}
		else
			//  Can't get a name when there's no file object
			status = STATUS_UNSUCCESSFUL;

		//  Use the name if we got it else use a default name
		if (NT_SUCCESS(status)) {
			name_to_use = &name_info->Name;
			//  Parse the name if requested
			if (FlagOn(irp_logger_data.debug_flags, IRPLOGGER_DEBUG_PARSE_NAMES)) {
#ifdef DBG
				FLT_ASSERT(NT_SUCCESS(FltParseFileNameInformation(name_info)));
#else
				FltParseFileNameInformation(name_info);
#endif

			}
		}
		else {
#if IRPLOGGER_NOT_W2K
			NTSTATUS lstatus;
			PFLT_FILE_NAME_INFORMATION lname_info;

			//  If we couldn't get the "normalized" name try and get the "opened" name
			if (flt_objects->FileObject != NULL) {
				//  Get the opened name
				lstatus = FltGetFileNameInformation(data,
					FLT_FILE_NAME_OPENED |
					FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
					&lname_info);

				if (NT_SUCCESS(lstatus)) {
#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
					(VOID)_snwprintf(name,
						sizeof(name) / sizeof(WCHAR),
						L"<%08x> %wZ",
						status,
						&lname_info->Name);

					FltReleaseFileNameInformation(lname_info);
				}
				else {
					//  If that failed report both NORMALIZED status and OPENED status
#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
					(VOID)_snwprintf(name,
						sizeof(name) / sizeof(WCHAR),
						L"cannot get name"
					);
				}
			}
			else {
#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
				(VOID)_snwprintf(name,
					sizeof(name) / sizeof(WCHAR),
					L"cannot get name"
				);

			}
			name[(sizeof(name) / sizeof(WCHAR)) - 1] = L'\0';

			RtlInitUnicodeString(&default_name, name);
			name_to_use = &default_name;

#else
			RtlInitUnicodeString(&default_name, L"<NO NAME>");
			name_to_use = &default_name;
#endif

#if DBG
			//  Debug support to break on certain errors.
			if (flt_objects->FileObject != NULL) {
				NTSTATUS retry_status;

				if ((break_on != 0) && (status == break_on))
					DbgBreakPoint();

				retry_status = FltGetFileNameInformation(data,
					FLT_FILE_NAME_NORMALIZED |
					irp_logger_data.name_query_method,
					&name_info);

				if (!NT_SUCCESS(retry_status))
					//  We always release name_info, so ignore return value.
					NOTHING;
			}

#endif
		}
#if IRPLOGGER_VISTA
		//  Look for ECPs, but only if it's a create operation
		if (data->Iopb->MajorFunction == IRP_MJ_CREATE) {
			//  Initialize an empty string to receive an ECP data dump
			RtlInitEmptyUnicodeString(&ecp_data,
				ecp_data_buffer,
				MAX_NAME_SPACE / sizeof(WCHAR));

			//  Parse any extra create parameters
			parse_ecps(data, record_list, &ecp_data);
			ecp_data_to_use = &ecp_data;
		}
		//  Store the name and ECP data (if any)
		set_record_name_and_ecp_data(&(record_list->log_record), name_to_use, ecp_data_to_use);
#else
		//  Store the name
		set_record_name(&(record_list->log_record), name_to_use);

#endif
		//  Release the name information structure (if defined)
		if (NULL != name_info)
			FltReleaseFileNameInformation(name_info);

		log_pre_operation_data(data, flt_objects, record_list);

		if (data->Iopb->MajorFunction == IRP_MJ_SHUTDOWN) {
			//  No completion callbacks in IRP_MJ_SHUTDOWN
			post_operation_callback(data, flt_objects, record_list, 0);
			return_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		else {
			*completion_context = record_list;
			return_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
	}

	return return_status;
}


FLT_POSTOP_CALLBACK_STATUS post_operation_callback(
	_Inout_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_In_ PVOID completion_context,
	_In_ FLT_POST_OPERATION_FLAGS flags
)
/*++
Routine Description (from Microsoft):
	This routine receives ALL post-operation callbacks.  This will take
	the log record passed in the context parameter and update it with
	the completion information.  It will then insert it on a list to be
	sent to the usermode component.

	NOTE:  This routine must be NON-PAGED because it can be called at DPC level
Arguments:
	data - Contains information about the given operation.
	flt_objects - Contains pointers to the various objects that are pertinent
		to this operation.
	completion_context - Pointer to the RECORD_LIST structure in which we
		store the information we are logging.  This was passed from the
		pre-operation callback
	flags - Contains information as to why this routine was called.
Return Value:
	Identifies how processing should continue for this operation
--*/
{
	PRECORD_LIST record_list;
	PRECORD_LIST reparse_record_list = NULL;
	PLOG_RECORD reparse_log_record;
	PFLT_TAG_DATA_BUFFER tag_data;
	ULONG copy_length;

	UNREFERENCED_PARAMETER(flt_objects);

	record_list = (PRECORD_LIST)completion_context;
	if (FlagOn(flags, FLTFL_POST_OPERATION_DRAINING)) {
		free_record(record_list);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//  Set completion information into the record
	log_post_operation_data(data, record_list);

	//  Log reparse tag information if specified.
	tag_data = data->TagData;
	if (tag_data) {
		reparse_record_list = new_record();
		if (reparse_record_list) {
			//  only copy the DATA portion of the information
			RtlCopyMemory(&reparse_record_list->log_record.data,
				&record_list->log_record.data,
				sizeof(RECORD_DATA));

			reparse_log_record = &reparse_record_list->log_record;

			copy_length = FLT_TAG_DATA_BUFFER_HEADER_SIZE + tag_data->TagDataLength;
			if (copy_length > MAX_NAME_SPACE)
				copy_length = MAX_NAME_SPACE;

			//  Copy reparse data
			RtlCopyMemory(
				&reparse_record_list->log_record.name[0],
				tag_data,
				copy_length
			);

			reparse_log_record->record_type |= RECORD_TYPE_FILETAG;
			reparse_log_record->length += (ULONG)ROUND_TO_SIZE(copy_length, sizeof(PVOID));
		}
	}

	//  Send the logged information to the user service.
	logging(record_list);

	if (reparse_record_list)
		logging(reparse_record_list);

	if ((flt_objects->Transaction != NULL) &&
		(data->Iopb->MajorFunction == IRP_MJ_CREATE) &&
		(data->IoStatus.Status == STATUS_SUCCESS)) {

		//  Enlist in the transaction.
		enlist_in_transaction(flt_objects);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS enlist_in_transaction(_In_ PCFLT_RELATED_OBJECTS flt_objects)
{
#if IRPLOGGER_VISTA
	PIRPLOGGER_TRANSACTION_CONTEXT transaction_context = NULL;
	PIRPLOGGER_TRANSACTION_CONTEXT old_transaction_context = NULL;
	PRECORD_LIST record_list;
	NTSTATUS status;
	static ULONG sequence = 1;

	if (NULL == irp_logger_data.flt_get_transaction_context)
		return STATUS_SUCCESS;

	status = (*irp_logger_data.flt_get_transaction_context)(flt_objects->Instance,
		flt_objects->Transaction,
		&transaction_context);

	if (NT_SUCCESS(status)) {
		//  Check if we have already enlisted in the transaction. 
		if (FlagOn(transaction_context->flags, IRPLOGGER_ENLISTED_IN_TRANSACTION)) {
			FltReleaseContext(transaction_context);
			return STATUS_SUCCESS;
		}
		//  If we have not enlisted then we need to try and enlist in the transaction.
		goto ENLIST_IN_TRANSACTION;
	}

	if (status != STATUS_NOT_FOUND)
		return status;

	//  Allocate a transaction context.
	status = FltAllocateContext(flt_objects->Filter,
		FLT_TRANSACTION_CONTEXT,
		sizeof(IRPLOGGER_TRANSACTION_CONTEXT),
		PagedPool,
		&transaction_context);

	if (!NT_SUCCESS(status))
		return status;

	//  Set the context into the transaction
	RtlZeroMemory(transaction_context, sizeof(IRPLOGGER_TRANSACTION_CONTEXT));
	transaction_context->count = sequence++;
	FLT_ASSERT(irp_logger_data.flt_set_transaction_context);

	status = (*irp_logger_data.flt_set_transaction_context)(flt_objects->Instance,
		flt_objects->Transaction,
		FLT_SET_CONTEXT_KEEP_IF_EXISTS,
		transaction_context,
		&old_transaction_context);

	if (!NT_SUCCESS(status)) {
		FltReleaseContext(transaction_context);    //this will free the context
		if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED)
			return status;

		FLT_ASSERT(old_transaction_context != NULL);

		if (FlagOn(old_transaction_context->flags, IRPLOGGER_ENLISTED_IN_TRANSACTION)) {
			FltReleaseContext(old_transaction_context);
			return STATUS_SUCCESS;
		}
		transaction_context = old_transaction_context;
	}

ENLIST_IN_TRANSACTION:
	//  Enlist on this transaction for notifications.
	FLT_ASSERT(irp_logger_data.flt_enlist_in_transaction);

	status = (*irp_logger_data.flt_enlist_in_transaction)(flt_objects->Instance,
		flt_objects->Transaction,
		transaction_context,
		FLT_MAX_TRANSACTION_NOTIFICATIONS);

	if (!NT_SUCCESS(status)) {
		if (status == STATUS_FLT_ALREADY_ENLISTED)
			status = STATUS_SUCCESS;
		else
			FltDeleteContext(transaction_context);

		FltReleaseContext(transaction_context);
		return status;
	}

	SetFlagInterlocked(&transaction_context->flags, IRPLOGGER_ENLISTED_IN_TRANSACTION);

	//  The operation succeeded, remove our count
	FltReleaseContext(transaction_context);

	//  Log a record that a new transaction has started.
	record_list = new_record();
	if (record_list) {
		log_transaction_notify(flt_objects, record_list, 0);
		//  Send the logged information to the user service.
		logging(record_list);
	}
#endif
	return STATUS_SUCCESS;
}


#if IRPLOGGER_VISTA

NTSTATUS ktm_notification_callback(
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_In_ PFLT_CONTEXT transaction_context,
	_In_ ULONG transaction_notification
)
{
	PRECORD_LIST record_list;
	UNREFERENCED_PARAMETER(transaction_context);

	//  Try and get a log record
	record_list = new_record();
	if (record_list) {
		log_transaction_notify(flt_objects, record_list, transaction_notification);
		//  Send the logged information to the user service.
		logging(record_list);
	}
	return STATUS_SUCCESS;
}
#endif