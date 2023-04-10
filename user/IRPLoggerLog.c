#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <winioctl.h>
#include "IRPLoggerLog.h"
#include "IRPLoggerUtils.h"
#include "IRPLoggerError.h"

BOOLEAN translate_file_tag(_In_ PLOG_RECORD log_record)
/*++
Routine Description:
    If this is a mount point reparse point, move the given name string to the
    correct position in the log record structure so it will be displayed
    by the common routines.
Arguments:
    logRecord - The log record to update
Return Value:
    TRUE - if this is a mount point reparse point
    FALSE - otherwise
--*/
{
	PFLT_TAG_DATA_BUFFER tag_data;
	ULONG len;

	// The reparse data structure starts in the NAME field, point to it.
	tag_data = (PFLT_TAG_DATA_BUFFER)&log_record->name[0];

	//  See if MOUNT POINT tag
	if (tag_data->file_tag == IO_REPARSE_TAG_MOUNT_POINT) {
		//  calculate how much to copy
		len = min(MAX_NAME_SPACE - sizeof(UNICODE_NULL), tag_data->mountpoint_reparse_buf.substitute_name_len);
		MoveMemory(&log_record->name[0],
			tag_data->mountpoint_reparse_buf.path_buffer,
			len);

		log_record->name[len / sizeof(WCHAR)] = UNICODE_NULL;
		return TRUE;
	}
	return FALSE;
}


DWORD WINAPI retrieve_log_records(_In_ LPVOID params)
/*++
Routine Description:
    This runs as a separate thread.  Its job is to retrieve log records
    from the filter and then output them
Arguments:
    params - Contains context structure for synchronizing with the
        main program thread.
Return Value:
    The thread successfully terminated
--*/
{
    PIRPLOG_CONTEXT context = (PIRPLOG_CONTEXT) params;
    DWORD bytes_returned = 0;
    DWORD used;
    PVOID aligned_buffer[BUFFER_SIZE / sizeof(PVOID)];
    PCHAR buffer = (PCHAR) aligned_buffer;
    HRESULT h_result;
    PLOG_RECORD plog_record;
    PRECORD_DATA precord_data;
    COMMAND_MESSAGE command_msg;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant
    while (TRUE) {
#pragma warning(pop)

        //  Check to see if we should shut down.
        if (context->cleaning_up) 
            break;

        //  Request log data from IRPLogger minifilter.
		command_msg.command = GET_IRPLOGGER_LOG;
		h_result = FilterSendMessage(context->port,
                                     &command_msg,
                                     sizeof(COMMAND_MESSAGE),
                                     buffer,
                                     sizeof(aligned_buffer),
                                     &bytes_returned);

        if (IS_ERROR(h_result)) {
            if (HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) == h_result) {
                print_info(CRITICAL, L"The kernel component of IRPLogger has unloaded. Exiting.");
                ExitProcess(0);
            } 
			else {
                if (h_result != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
					print_info(ERR, L"UNEXPECTED ERROR received: %x", h_result);

                Sleep(POLL_INTERVAL);
            }
            continue;
        }

		plog_record = (PLOG_RECORD) buffer;
        used = 0;

        //  Logic to write record to screen and/or file
        for (;;) {
            if (used+FIELD_OFFSET(LOG_RECORD, name) > bytes_returned)
                break;

            if (plog_record->length < (sizeof(LOG_RECORD)+sizeof(WCHAR))) {
				print_info(ERR, L"UNEXPECTED LOG_RECORD->Length: length=%d expected>=%d",
					plog_record->length,
					(ULONG)(sizeof(LOG_RECORD)+sizeof(WCHAR)));

                break;
            }
            used += plog_record->length;

            if (used > bytes_returned) {
				print_info(ERR, L"UNEXPECTED LOG_RECORD size: used=%d bytesReturned=%d", used, bytes_returned);
                break;
            }

			precord_data = &plog_record->data;

            //  See if a reparse point entry
            if (FlagOn(plog_record->record_type,RECORD_TYPE_FILETAG)) {
                if (!translate_file_tag(plog_record)){
                    // If this is a reparse point that can't be interpreted, move on.
					plog_record = (PLOG_RECORD) Add2Ptr(plog_record, plog_record->length);
                    continue;
                }
            }

            if (context->log_to_file && context->logs_filter(plog_record)) {
				// Replace from volume name to dos name
				WCHAR name[MY_MAX_PATH] = { 0 };
				replace_path(plog_record->name, context->volume_name, context->dos_name, name);

                log_on_file(name,
					precord_data,
					context->output_file);
            }

            if (FlagOn(plog_record->record_type, RECORD_TYPE_FLAG_OUT_OF_MEMORY)) {
                if (context->log_to_file) {
					print_info(WARNING, L"M:\t0x%08X\tSystem Out of Memory",
						plog_record->sequence_number);
                }

            } 
			else if (FlagOn(plog_record->record_type, RECORD_TYPE_FLAG_EXCEED_MEMORY_ALLOWANCE)) {
                if (context->log_to_file) {
					print_info(WARNING, L"M:\t0x%08X\tExceeded Mamimum Allowed Memory Buffers",
						plog_record->sequence_number);
                }
            }
            // Move to next LOG_RECORD
			plog_record = (PLOG_RECORD) Add2Ptr(plog_record, plog_record->length);
        }
        //  If we didn't get any data, pause for 1/2 second
        if (bytes_returned == 0)
            Sleep(POLL_INTERVAL);
    }

	print_info(INFO, L"IRPLoggerLog: shutting down.");
    ReleaseSemaphore(context->shutdown, 1, NULL );
	print_info(INFO, L"IRPLoggerLog: all done.");
    return 0;
}


VOID translate_irp_code(
    _In_ UCHAR major_code,
    _In_ UCHAR minor_code,
    _In_opt_ FILE *output_file
)
/*++
Routine Description:
    Display the operation code
Arguments:
    major_code - Major function code of operation
    minor_code - Minor function code of operation
    output_file - If writing to a file (not the screen) the handle for that file
Return Value:
    None
--*/
{
    CHAR *irp_major_string = NULL, *irp_minor_string = NULL;
	CHAR error_buf[128] = { 0 };

    switch (major_code) {
        case IRP_MJ_CREATE:
			irp_major_string = IRP_MJ_CREATE_STRING;
            break;
        case IRP_MJ_CREATE_NAMED_PIPE:
			irp_major_string = IRP_MJ_CREATE_NAMED_PIPE_STRING;
            break;
        case IRP_MJ_CLOSE:
			irp_major_string = IRP_MJ_CLOSE_STRING;
            break;
        case IRP_MJ_READ:
			irp_major_string = IRP_MJ_READ_STRING;
            switch (minor_code) {
                case IRP_MN_NORMAL:
					irp_minor_string = IRP_MN_NORMAL_STRING;
                    break;
                case IRP_MN_DPC:
					irp_minor_string = IRP_MN_DPC_STRING;
                    break;
                case IRP_MN_MDL:
					irp_minor_string = IRP_MN_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE:
					irp_minor_string = IRP_MN_COMPLETE_STRING;
                    break;
                case IRP_MN_COMPRESSED:
					irp_minor_string = IRP_MN_COMPRESSED_STRING;
                    break;
                case IRP_MN_MDL_DPC:
					irp_minor_string = IRP_MN_MDL_DPC_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL:
					irp_minor_string = IRP_MN_COMPLETE_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL_DPC:
					irp_minor_string = IRP_MN_COMPLETE_MDL_DPC_STRING;
                    break;
                default:
                    sprintf_s(error_buf, sizeof(error_buf),"Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_WRITE:
			irp_major_string = IRP_MJ_WRITE_STRING;
            switch (minor_code) {
                case IRP_MN_NORMAL:
					irp_minor_string = IRP_MN_NORMAL_STRING;
                    break;
                case IRP_MN_DPC:
					irp_minor_string = IRP_MN_DPC_STRING;
                    break;
                case IRP_MN_MDL:
					irp_minor_string = IRP_MN_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE:
					irp_minor_string = IRP_MN_COMPLETE_STRING;
                    break;
                case IRP_MN_COMPRESSED:
					irp_minor_string = IRP_MN_COMPRESSED_STRING;
                    break;
                case IRP_MN_MDL_DPC:
					irp_minor_string = IRP_MN_MDL_DPC_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL:
					irp_minor_string = IRP_MN_COMPLETE_MDL_STRING;
                    break;
                case IRP_MN_COMPLETE_MDL_DPC:
					irp_minor_string = IRP_MN_COMPLETE_MDL_DPC_STRING;
                    break;
                default:
                    sprintf_s(error_buf, sizeof(error_buf),"Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_QUERY_INFORMATION:
			irp_major_string = IRP_MJ_QUERY_INFORMATION_STRING;
            break;
        case IRP_MJ_SET_INFORMATION:
			irp_major_string = IRP_MJ_SET_INFORMATION_STRING;
            break;
        case IRP_MJ_QUERY_EA:
			irp_major_string = IRP_MJ_QUERY_EA_STRING;
            break;
        case IRP_MJ_SET_EA:
			irp_major_string = IRP_MJ_SET_EA_STRING;
            break;
        case IRP_MJ_FLUSH_BUFFERS:
			irp_major_string = IRP_MJ_FLUSH_BUFFERS_STRING;
            break;
        case IRP_MJ_QUERY_VOLUME_INFORMATION:
			irp_major_string = IRP_MJ_QUERY_VOLUME_INFORMATION_STRING;
            break;
        case IRP_MJ_SET_VOLUME_INFORMATION:
			irp_major_string = IRP_MJ_SET_VOLUME_INFORMATION_STRING;
            break;
        case IRP_MJ_DIRECTORY_CONTROL:
			irp_major_string = IRP_MJ_DIRECTORY_CONTROL_STRING;
            switch (minor_code) {
                case IRP_MN_QUERY_DIRECTORY:
					irp_minor_string = IRP_MN_QUERY_DIRECTORY_STRING;
                    break;
                case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
					irp_minor_string = IRP_MN_NOTIFY_CHANGE_DIRECTORY_STRING;
                    break;
                default:
                    sprintf_s(error_buf,sizeof(error_buf),"Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_FILE_SYSTEM_CONTROL:
			irp_major_string = IRP_MJ_FILE_SYSTEM_CONTROL_STRING;
            switch (minor_code) {
                case IRP_MN_USER_FS_REQUEST:
					irp_minor_string = IRP_MN_USER_FS_REQUEST_STRING;
                    break;
                case IRP_MN_MOUNT_VOLUME:
					irp_minor_string = IRP_MN_MOUNT_VOLUME_STRING;
                    break;
                case IRP_MN_VERIFY_VOLUME:
					irp_minor_string = IRP_MN_VERIFY_VOLUME_STRING;
                    break;
                case IRP_MN_LOAD_FILE_SYSTEM:
					irp_minor_string = IRP_MN_LOAD_FILE_SYSTEM_STRING;
                    break;
                case IRP_MN_TRACK_LINK:
					irp_minor_string = IRP_MN_TRACK_LINK_STRING;
                    break;
                default:
                    sprintf_s(error_buf, sizeof(error_buf), "Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_DEVICE_CONTROL:
			irp_major_string = IRP_MJ_DEVICE_CONTROL_STRING;
            switch (minor_code) {
                case IRP_MN_SCSI_CLASS:
					irp_minor_string = IRP_MN_SCSI_CLASS_STRING;
                    break;
                default:
                    sprintf_s(error_buf, sizeof(error_buf), "Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
			irp_major_string = IRP_MJ_INTERNAL_DEVICE_CONTROL_STRING;
            break;
        case IRP_MJ_SHUTDOWN:
			irp_major_string = IRP_MJ_SHUTDOWN_STRING;
            break;
        case IRP_MJ_LOCK_CONTROL:
			irp_major_string = IRP_MJ_LOCK_CONTROL_STRING;
            switch (minor_code) {
                case IRP_MN_LOCK:
					irp_minor_string = IRP_MN_LOCK_STRING;
                    break;
                case IRP_MN_UNLOCK_SINGLE:
					irp_minor_string = IRP_MN_UNLOCK_SINGLE_STRING;
                    break;
                case IRP_MN_UNLOCK_ALL:
					irp_minor_string = IRP_MN_UNLOCK_ALL_STRING;
                    break;
                case IRP_MN_UNLOCK_ALL_BY_KEY:
					irp_minor_string = IRP_MN_UNLOCK_ALL_BY_KEY_STRING;
                    break;
                default:
                    sprintf_s(error_buf, sizeof(error_buf), "Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_CLEANUP:
			irp_major_string = IRP_MJ_CLEANUP_STRING;
            break;
        case IRP_MJ_CREATE_MAILSLOT:
			irp_major_string = IRP_MJ_CREATE_MAILSLOT_STRING;
            break;
        case IRP_MJ_QUERY_SECURITY:
			irp_major_string = IRP_MJ_QUERY_SECURITY_STRING;
            break;
        case IRP_MJ_SET_SECURITY:
			irp_major_string = IRP_MJ_SET_SECURITY_STRING;
            break;
        case IRP_MJ_POWER:
			irp_major_string = IRP_MJ_POWER_STRING;
            switch (minor_code) {
                case IRP_MN_WAIT_WAKE:
					irp_minor_string = IRP_MN_WAIT_WAKE_STRING;
                    break;
                case IRP_MN_POWER_SEQUENCE:
					irp_minor_string = IRP_MN_POWER_SEQUENCE_STRING;
                    break;
                case IRP_MN_SET_POWER:
					irp_minor_string = IRP_MN_SET_POWER_STRING;
                    break;
                case IRP_MN_QUERY_POWER:
					irp_minor_string = IRP_MN_QUERY_POWER_STRING;
                    break;
                default :
                    sprintf_s(error_buf, sizeof(error_buf), "Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_SYSTEM_CONTROL:
			irp_major_string = IRP_MJ_SYSTEM_CONTROL_STRING;
            switch (minor_code) {
                case IRP_MN_QUERY_ALL_DATA:
					irp_minor_string = IRP_MN_QUERY_ALL_DATA_STRING;
                    break;
                case IRP_MN_QUERY_SINGLE_INSTANCE:
					irp_minor_string = IRP_MN_QUERY_SINGLE_INSTANCE_STRING;
                    break;
                case IRP_MN_CHANGE_SINGLE_INSTANCE:
					irp_minor_string = IRP_MN_CHANGE_SINGLE_INSTANCE_STRING;
                    break;
                case IRP_MN_CHANGE_SINGLE_ITEM:
					irp_minor_string = IRP_MN_CHANGE_SINGLE_ITEM_STRING;
                    break;
                case IRP_MN_ENABLE_EVENTS:
					irp_minor_string = IRP_MN_ENABLE_EVENTS_STRING;
                    break;
                case IRP_MN_DISABLE_EVENTS:
					irp_minor_string = IRP_MN_DISABLE_EVENTS_STRING;
                    break;
                case IRP_MN_ENABLE_COLLECTION:
					irp_minor_string = IRP_MN_ENABLE_COLLECTION_STRING;
                    break;
                case IRP_MN_DISABLE_COLLECTION:
					irp_minor_string = IRP_MN_DISABLE_COLLECTION_STRING;
                    break;
                case IRP_MN_REGINFO:
					irp_minor_string = IRP_MN_REGINFO_STRING;
                    break;
                case IRP_MN_EXECUTE_METHOD:
					irp_minor_string = IRP_MN_EXECUTE_METHOD_STRING;
                    break;
                default :
                    sprintf_s(error_buf, sizeof(error_buf),"Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_DEVICE_CHANGE:
			irp_major_string = IRP_MJ_DEVICE_CHANGE_STRING;
            break;
        case IRP_MJ_QUERY_QUOTA:
			irp_major_string = IRP_MJ_QUERY_QUOTA_STRING;
            break;
        case IRP_MJ_SET_QUOTA:
			irp_major_string = IRP_MJ_SET_QUOTA_STRING;
            break;
        case IRP_MJ_PNP:
			irp_major_string = IRP_MJ_PNP_STRING;
            switch (minor_code) {
                case IRP_MN_START_DEVICE:
					irp_minor_string = IRP_MN_START_DEVICE_STRING;
                    break;
                case IRP_MN_QUERY_REMOVE_DEVICE:
					irp_minor_string = IRP_MN_QUERY_REMOVE_DEVICE_STRING;
                    break;
                case IRP_MN_REMOVE_DEVICE:
					irp_minor_string = IRP_MN_REMOVE_DEVICE_STRING;
                    break;
                case IRP_MN_CANCEL_REMOVE_DEVICE:
					irp_minor_string = IRP_MN_CANCEL_REMOVE_DEVICE_STRING;
                    break;
                case IRP_MN_STOP_DEVICE:
					irp_minor_string = IRP_MN_STOP_DEVICE_STRING;
                    break;
                case IRP_MN_QUERY_STOP_DEVICE:
					irp_minor_string = IRP_MN_QUERY_STOP_DEVICE_STRING;
                    break;
                case IRP_MN_CANCEL_STOP_DEVICE:
					irp_minor_string = IRP_MN_CANCEL_STOP_DEVICE_STRING;
                    break;
                case IRP_MN_QUERY_DEVICE_RELATIONS:
					irp_minor_string = IRP_MN_QUERY_DEVICE_RELATIONS_STRING;
                    break;
                case IRP_MN_QUERY_INTERFACE:
					irp_minor_string = IRP_MN_QUERY_INTERFACE_STRING;
                    break;
                case IRP_MN_QUERY_CAPABILITIES:
					irp_minor_string = IRP_MN_QUERY_CAPABILITIES_STRING;
                    break;
                case IRP_MN_QUERY_RESOURCES:
					irp_minor_string = IRP_MN_QUERY_RESOURCES_STRING;
                    break;
                case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
					irp_minor_string = IRP_MN_QUERY_RESOURCE_REQUIREMENTS_STRING;
                    break;
                case IRP_MN_QUERY_DEVICE_TEXT:
					irp_minor_string = IRP_MN_QUERY_DEVICE_TEXT_STRING;
                    break;
                case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
					irp_minor_string = IRP_MN_FILTER_RESOURCE_REQUIREMENTS_STRING;
                    break;
                case IRP_MN_READ_CONFIG:
					irp_minor_string = IRP_MN_READ_CONFIG_STRING;
                    break;
                case IRP_MN_WRITE_CONFIG:
					irp_minor_string = IRP_MN_WRITE_CONFIG_STRING;
                    break;
                case IRP_MN_EJECT:
					irp_minor_string = IRP_MN_EJECT_STRING;
                    break;
                case IRP_MN_SET_LOCK:
					irp_minor_string = IRP_MN_SET_LOCK_STRING;
                    break;
                case IRP_MN_QUERY_ID:
					irp_minor_string = IRP_MN_QUERY_ID_STRING;
                    break;
                case IRP_MN_QUERY_PNP_DEVICE_STATE:
					irp_minor_string = IRP_MN_QUERY_PNP_DEVICE_STATE_STRING;
                    break;
                case IRP_MN_QUERY_BUS_INFORMATION:
					irp_minor_string = IRP_MN_QUERY_BUS_INFORMATION_STRING;
                    break;
                case IRP_MN_DEVICE_USAGE_NOTIFICATION:
					irp_minor_string = IRP_MN_DEVICE_USAGE_NOTIFICATION_STRING;
                    break;
                case IRP_MN_SURPRISE_REMOVAL:
					irp_minor_string = IRP_MN_SURPRISE_REMOVAL_STRING;
                    break;
                case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
					irp_minor_string = IRP_MN_QUERY_LEGACY_BUS_INFORMATION_STRING;
                    break;
                default :
                    sprintf_s(error_buf, sizeof(error_buf), "Unknown Irp minor code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
			irp_major_string = IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION_STRING;
            break;

        case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
			irp_major_string = IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION_STRING;
            break;

        case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
			irp_major_string = IRP_MJ_ACQUIRE_FOR_MOD_WRITE_STRING;
            break;

        case IRP_MJ_RELEASE_FOR_MOD_WRITE:
			irp_major_string = IRP_MJ_RELEASE_FOR_MOD_WRITE_STRING;
            break;

        case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
			irp_major_string = IRP_MJ_ACQUIRE_FOR_CC_FLUSH_STRING;
            break;

        case IRP_MJ_RELEASE_FOR_CC_FLUSH:
			irp_major_string = IRP_MJ_RELEASE_FOR_CC_FLUSH_STRING;
            break;

        case IRP_MJ_NOTIFY_STREAM_FO_CREATION:
			irp_major_string = IRP_MJ_NOTIFY_STREAM_FO_CREATION_STRING;
            break;

        case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
			irp_major_string = IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE_STRING;
            break;

        case IRP_MJ_NETWORK_QUERY_OPEN:
			irp_major_string = IRP_MJ_NETWORK_QUERY_OPEN_STRING;
            break;

        case IRP_MJ_MDL_READ:
			irp_major_string = IRP_MJ_MDL_READ_STRING;
            break;

        case IRP_MJ_MDL_READ_COMPLETE:
			irp_major_string = IRP_MJ_MDL_READ_COMPLETE_STRING;
            break;

        case IRP_MJ_PREPARE_MDL_WRITE:
			irp_major_string = IRP_MJ_PREPARE_MDL_WRITE_STRING;
            break;

        case IRP_MJ_MDL_WRITE_COMPLETE:
			irp_major_string = IRP_MJ_MDL_WRITE_COMPLETE_STRING;
            break;

        case IRP_MJ_VOLUME_MOUNT:
			irp_major_string = IRP_MJ_VOLUME_MOUNT_STRING;
            break;

        case IRP_MJ_VOLUME_DISMOUNT:
			irp_major_string = IRP_MJ_VOLUME_DISMOUNT_STRING;
            break;

        case IRP_MJ_TRANSACTION_NOTIFY:
			irp_major_string = IRP_MJ_TRANSACTION_NOTIFY_STRING;
            switch (minor_code) {
                case 0:
					irp_minor_string = TRANSACTION_BEGIN;
                    break;
                case TRANSACTION_NOTIFY_PREPREPARE_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_PREPREPARE_STRING;
                    break;
                case TRANSACTION_NOTIFY_PREPARE_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_PREPARE_STRING;
                    break;
                case TRANSACTION_NOTIFY_COMMIT_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_COMMIT_STRING;
                    break;
                case TRANSACTION_NOTIFY_COMMIT_FINALIZE_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_COMMIT_FINALIZE_STRING;
                    break;
                case TRANSACTION_NOTIFY_ROLLBACK_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_ROLLBACK_STRING;
                    break;
                case TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_STRING;
                    break;
                case TRANSACTION_NOTIFY_PREPARE_COMPLETE_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_COMMIT_COMPLETE_STRING;
                    break;
                case TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_STRING;
                    break;
                case TRANSACTION_NOTIFY_RECOVER_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_RECOVER_STRING;
                    break;
                case TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_STRING;
                    break;
                case TRANSACTION_NOTIFY_DELEGATE_COMMIT_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_DELEGATE_COMMIT_STRING;
                    break;
                case TRANSACTION_NOTIFY_RECOVER_QUERY_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_RECOVER_QUERY_STRING;
                    break;
                case TRANSACTION_NOTIFY_ENLIST_PREPREPARE_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_ENLIST_PREPREPARE_STRING;
                    break;
                case TRANSACTION_NOTIFY_LAST_RECOVER_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_LAST_RECOVER_STRING;
                    break;
                case TRANSACTION_NOTIFY_INDOUBT_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_INDOUBT_STRING;
                    break;
                case TRANSACTION_NOTIFY_PROPAGATE_PULL_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_PROPAGATE_PULL_STRING;
                    break;
                case TRANSACTION_NOTIFY_PROPAGATE_PUSH_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_PROPAGATE_PUSH_STRING;
                    break;
                case TRANSACTION_NOTIFY_MARSHAL_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_MARSHAL_STRING;
                    break;
                case TRANSACTION_NOTIFY_ENLIST_MASK_CODE:
					irp_minor_string = TRANSACTION_NOTIFY_ENLIST_MASK_STRING;
                    break;
                default:
                    sprintf_s(error_buf, sizeof(error_buf), "Unknown Transaction notication code (%u)", minor_code);
					irp_minor_string = error_buf;
            }
            break;

        default:
            sprintf_s(error_buf, sizeof(error_buf),"Unknown Irp major function (%d)", major_code);
			irp_major_string = error_buf;
            break;
    }

    if (output_file)
		fprintf(output_file, "\t%-35s\t%-35s", irp_major_string, irp_minor_string);
}

VOID log_on_file(
	_In_ WCHAR CONST *name,
    _In_ PRECORD_DATA record_data,
    _In_ FILE *file
    )
/*++
Routine Description:
    Prints a Data log record to the specified file.  The output is in a tab
    delimited format with the fields in the following order:
    SequenceNumber, OriginatingTime, CompletionTime, CallbackMajorId, CallbackMinorId,
    Flags, NoCache, Paging I/O, Synchronous, Synchronous paging, FileName,
    ReturnStatus, FileName
Arguments:
    sequence_number - the sequence number for this log record
    name - the name of the file that this Irp relates to
    record_data - the Data record to print
    file - the file to print to
Return Value:
	None.
--*/
{
    FILETIME local_time;
    SYSTEMTIME system_time;
    CHAR time[TIME_BUFFER_LENGTH];
    static BOOLEAN did_file_header = FALSE;

    // Is this an Irp or a FastIo?
    if (!did_file_header) {
		fprintf(file, "Operation\tTimestamp\tPID\tProcess\tMajor Operation type\tMinor Operation type\tBuffersize\tEntropy\tFilename\n");
		did_file_header = TRUE;
    }

	// Is this an Irp or a FastIo?
	if (record_data->flags & FLT_CALLBACK_DATA_IRP_OPERATION)
		fprintf(file, "IRP");
	else if (record_data->flags & FLT_CALLBACK_DATA_FAST_IO_OPERATION)
		fprintf(file, "FIO");
	else if (record_data->flags & FLT_CALLBACK_DATA_FS_FILTER_OPERATION)
		fprintf(file, "FSF");
	else
		fprintf(file, "ERR");

	// Convert completion time
	FileTimeToLocalFileTime((FILETIME *) &(record_data->completion_time), &local_time);
	FileTimeToSystemTime(&local_time, &system_time);

	if (format_system_time(&system_time, time, TIME_BUFFER_LENGTH))
		fprintf(file, "\t%-12s", time);
	else
		fprintf(file, "\t%-12s", TIME_ERROR);

	fprintf(file, "\t%ld", (DWORD) record_data->process_id);

	// Print process name (from process id)
	fprintf(file, "\t%S", record_data->process_name);
	//print_process_name_from_pid(record_data->process_id, file);

    translate_irp_code(record_data->callback_major_id,
		record_data->callback_minor_id,
		file
	);

	// Print buffersize
	fprintf(file, "\t%ld", (DWORD) record_data->data_len);

	// Print file entropy
	fprintf(file, "\t%1.12lf", record_data->entropy);

	// Print file name
    fprintf(file, "\t%S", name);
    fprintf(file, "\n");
}
