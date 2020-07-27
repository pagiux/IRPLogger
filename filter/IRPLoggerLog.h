#ifndef __IRPLOGGER_LOG_H__
#define __IRPLOGGER_LOG_H__

#include "IRPLogger.h"

// Flags for the known ECPs
#define ECP_TYPE_FLAG_PREFETCH                   0x00000001

#if IRPLOGGER_WIN7

#define ECP_TYPE_FLAG_OPLOCK_KEY                 0x00000002
#define ECP_TYPE_FLAG_NFS                        0x00000004
#define ECP_TYPE_FLAG_SRV                        0x00000008

#endif

#define ADDRESS_STRING_BUFFER_SIZE          64

typedef enum _ECP_TYPE {
	ECP_PREFETCH_OPEN,
	ECP_OPLOCK_KEY,
	ECP_NFS_OPEN,
	ECP_SVR_OPEN,
	ECP_KNOWN_NUMBER
} ECP_TYPE;

#define DEFAULT_MAX_RECORDS_TO_ALLOCATE     500
#define MAX_RECORDS_TO_ALLOCATE             L"MaxRecords"

PRECORD_LIST allocate_buffer(_Out_ PULONG record_type);
VOID free_buffer(_In_ PVOID buffer);
PRECORD_LIST new_record(VOID);
VOID free_record(_In_ PRECORD_LIST record);
#if IRPLOGGER_VISTA
VOID parse_ecps(
	_In_ PFLT_CALLBACK_DATA data,
	_Inout_ PRECORD_LIST record_list,
	_Inout_ PUNICODE_STRING ecp_data
);
VOID build_ecp_data_str(
	_In_ PRECORD_LIST record_list,
	_Inout_ PUNICODE_STRING ecp_data,
	_In_reads_(ecps_known_number) PVOID *context_pointers
);
VOID set_record_name_and_ecp_data(
	_Inout_ PLOG_RECORD log_record,
	_In_ PUNICODE_STRING name,
	_In_opt_ PUNICODE_STRING ecp_data
);
#else
VOID set_record_name(
	_Inout_ PLOG_RECORD log_record,
	_In_ PUNICODE_STRING name
);
#endif
VOID log_pre_operation_data(
	_In_ PFLT_CALLBACK_DATA data,
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_Inout_ PRECORD_LIST record_list
);
VOID log_post_operation_data(
	_In_ PFLT_CALLBACK_DATA data,
	_Inout_ PRECORD_LIST record_list
);
VOID log_transaction_notify(
	_In_ PCFLT_RELATED_OBJECTS flt_objects,
	_Inout_ PRECORD_LIST record_list,
	_In_ ULONG transaction_notification
);
VOID logging(_In_ PRECORD_LIST record_list);
NTSTATUS get_log(
	_Out_writes_bytes_to_(out_buffer_length, *return_out_buffer_length) PUCHAR out_buffer,
	_In_ ULONG out_buffer_length,
	_Out_ PULONG return_out_buffer_length
);
VOID empty_output_buffer_list(VOID);

#endif
