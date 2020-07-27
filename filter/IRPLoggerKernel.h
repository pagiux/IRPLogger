#ifndef __IRPLOGGER_KERNEL_H__
#define __IRPLOGGER_KERNEL_H__

#include <fltKernel.h>
#include <suppress.h>
#include "IRPLogger.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//  Memory allocation tag
#define IRPLOGGER_TAG 'IRPL'

//  Define callback types for Vista
#if IRPLOGGER_VISTA

//  Dynamically imported Filter Mgr APIs
typedef NTSTATUS (*PFLT_SET_TRANSACTION_CONTEXT)
(
    _In_ PFLT_INSTANCE instance,
    _In_ PKTRANSACTION transaction,
    _In_ FLT_SET_CONTEXT_OPERATION operation,
    _In_ PFLT_CONTEXT new_context,
    _Outptr_opt_ PFLT_CONTEXT *old_context
);

typedef NTSTATUS (*PFLT_GET_TRANSACTION_CONTEXT)
(
    _In_ PFLT_INSTANCE instance,
    _In_ PKTRANSACTION transaction,
    _Outptr_ PFLT_CONTEXT *context
);

typedef NTSTATUS (*PFLT_ENLIST_IN_TRANSACTION)
(
    _In_ PFLT_INSTANCE instance,
    _In_ PKTRANSACTION transaction,
    _In_ PFLT_CONTEXT transaction_context,
    _In_ NOTIFICATION_MASK notification_mask
);
#endif

typedef NTSTATUS(*QUERY_INFO_PROCESS) 
(
	__in HANDLE process_handle,
	__in PROCESSINFOCLASS process_information_class,
	__out_bcount(process_information_length) PVOID process_information,
	__in ULONG process_information_length,
	__out_opt PULONG return_length
);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

typedef struct _IRPLOGGER_DATA {
    PDRIVER_OBJECT driver_object;
    PFLT_FILTER filter;
    PFLT_PORT server_port;
    PFLT_PORT client_port;
    //  List of buffers with data to send to user mode.
    KSPIN_LOCK out_buffer_lock;
    LIST_ENTRY out_buffer_list;
    //  Lookaside list used for allocating buffers.
    NPAGED_LOOKASIDE_LIST free_buf_list;
    //  Variables used to throttle how many records buffer we can use
    LONG max_records_to_allocate;
    __volatile LONG records_allocated;
    //  static buffer used for sending an "out-of-memory" message to user mode.
    __volatile LONG static_buffer_in_use;
    PVOID out_of_memory_buf[RECORD_SIZE / sizeof(PVOID)];
    //  Variable and lock for maintaining log_record sequence numbers.
    __volatile LONG log_sequence_number;
    ULONG name_query_method;
    //  Global debug flags
    ULONG debug_flags;

#if IRPLOGGER_VISTA
    //  Dynamically imported Filter Mgr APIs
    PFLT_SET_TRANSACTION_CONTEXT flt_set_transaction_context;
    PFLT_GET_TRANSACTION_CONTEXT flt_get_transaction_context;
    PFLT_ENLIST_IN_TRANSACTION flt_enlist_in_transaction;
#endif
} IRPLOGGER_DATA, *PIRPLOGGER_DATA;

typedef struct _IRPLOGGER_TRANSACTION_CONTEXT {
    ULONG flags;
    ULONG count;
} IRPLOGGER_TRANSACTION_CONTEXT, *PIRPLOGGER_TRANSACTION_CONTEXT;

#define IRPLOGGER_ENLISTED_IN_TRANSACTION 0x01

extern IRPLOGGER_DATA irp_logger_data;

#define DEFAULT_NAME_QUERY_METHOD           FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP
#define NAME_QUERY_METHOD                   L"NameQueryMethod"

#define IRPLOGGER_DEBUG_PARSE_NAMES   0x00000001

extern const FLT_REGISTRATION filter_registration;

FLT_PREOP_CALLBACK_STATUS pre_operation_callback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS flt_objects,
    _Flt_CompletionContext_Outptr_ PVOID *completion_context
);
FLT_POSTOP_CALLBACK_STATUS post_operation_callback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS flt_objects,
    _In_ PVOID completion_context,
    _In_ FLT_POST_OPERATION_FLAGS flags
);
NTSTATUS ktm_notification_callback(
    _In_ PCFLT_RELATED_OBJECTS flt_objects,
    _In_ PFLT_CONTEXT transaction_context,
    _In_ ULONG transaction_notification
);
NTSTATUS filter_unload(_In_ FLT_FILTER_UNLOAD_FLAGS flags);
NTSTATUS query_teardown(
    _In_ PCFLT_RELATED_OBJECTS flt_objects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags
);
VOID read_driver_parameters(_In_ PUNICODE_STRING registry_path);

#endif 

