#ifndef __IRPLOGGER_CONNECTION_H__
#define __IRPLOGGER_CONNECTION_H__

#include "IRPLogger.h"

NTSTATUS messages(
	_In_ PVOID connection_cookie,
	_In_reads_bytes_opt_(input_buffer_size) PVOID input_buffer,
	_In_ ULONG input_buffer_size,
	_Out_writes_bytes_to_opt_(output_buffer_size, *return_output_buffer_len) PVOID output_buffer,
	_In_ ULONG output_buffer_size,
	_Out_ PULONG return_output_buffer_len
);

NTSTATUS connect(
	_In_ PFLT_PORT client_port,
	_In_ PVOID server_port_cookie,
	_In_reads_bytes_(size_of_context) PVOID connection_context,
	_In_ ULONG size_of_context,
	_Flt_ConnectionCookie_Outptr_ PVOID *connection_cookie
);

VOID disconnect(_In_opt_ PVOID connection_cookie);

#endif
