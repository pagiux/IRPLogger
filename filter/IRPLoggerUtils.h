#ifndef __IRPLOGGER_UTILS_H__
#define __IRPLOGGER_UTILS_H__

VOID read_driver_parameters(_In_ PUNICODE_STRING registry_path);
UCHAR tx_notification_to_minor_code(_In_ ULONG tx_notification);
LONG exception_filter(
	_In_ PEXCEPTION_POINTERS exception_pointer,
	_In_ BOOLEAN accessing_user_buffer
);
VOID delete_txf_context(
	_Inout_ PIRPLOGGER_TRANSACTION_CONTEXT context,
	_In_ FLT_CONTEXT_TYPE context_type
);
NTSTATUS GetProcessImageName(WCHAR *process_image_name);

#endif#pragma once
