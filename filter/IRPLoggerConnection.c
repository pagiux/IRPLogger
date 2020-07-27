#include "IRPLoggerKernel.h"
#include "IRPLoggerConnection.h"
#include "IRPLoggerLog.h"
#include "IRPLoggerUtils.h"


NTSTATUS messages(
	_In_ PVOID connection_cookie,
	_In_reads_bytes_opt_(input_buffer_size) PVOID input_buffer,
	_In_ ULONG input_buffer_size,
	_Out_writes_bytes_to_opt_(output_buffer_size, *return_output_buffer_len) PVOID output_buffer,
	_In_ ULONG output_buffer_size,
	_Out_ PULONG return_output_buffer_len
)
/*++
Routine Description:
	This is called whenever a user mode application wishes to communicate
	with this minifilter.
Arguments:
	connection_cookie - unused
	input_buffer - A buffer containing input data, can be NULL if there
		is no input data.
	input_buffer_size - The size in bytes of the input_buffer.
	output_buffer - A buffer provided by the application that originated
		the communication in which to store data to be returned to this
		application.
	output_buffer_size - The size in bytes of the output_buffer.
	return_output_buffer_len - The size in bytes of meaningful data
		returned in the output_buffer.
Return Value:
	Returns the status of processing the message.
--*/
{
	IRPLOGGER_COMMAND cmd;
	NTSTATUS status;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(connection_cookie);

	if ((input_buffer != NULL) &&
		(input_buffer_size >= (FIELD_OFFSET(COMMAND_MESSAGE, command) +
			sizeof(IRPLOGGER_COMMAND)))) {

		try {
			cmd = ((PCOMMAND_MESSAGE)input_buffer)->command;
		}
		except(exception_filter(GetExceptionInformation(), TRUE)) {
			return GetExceptionCode();
		}

		switch (cmd) {
		case GET_IRPLOGGER_LOG:
			//  Return as many log records as can fit into the OutputBuffer
			if ((output_buffer == NULL) || (output_buffer_size == 0)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
#if defined(_WIN64)

			if (IoIs32bitProcess(NULL)) {
				//  Validate alignment for the 32bit process on a 64bit system
				if (!IS_ALIGNED(output_buffer, sizeof(ULONG))) {
					status = STATUS_DATATYPE_MISALIGNMENT;
					break;
				}
			}
			else {

#endif
				if (!IS_ALIGNED(output_buffer, sizeof(PVOID))) {
					status = STATUS_DATATYPE_MISALIGNMENT;
					break;
				}

#if defined(_WIN64)
			}
#endif
			//  Get the log record.
			status = get_log(output_buffer, output_buffer_size, return_output_buffer_len);
			break;

		case GET_IRPLOGGER_VERSION:
			if ((output_buffer_size < sizeof(IRPLOGGERVER)) || (output_buffer == NULL)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!IS_ALIGNED(output_buffer, sizeof(ULONG))) {
				status = STATUS_DATATYPE_MISALIGNMENT;
				break;
			}

			//  Protect access to raw user-mode output buffer with an exception handler
			try {
				((PIRPLOGGERVER)output_buffer)->major = IRPLOGGER_MAJ_VERSION;
				((PIRPLOGGERVER)output_buffer)->minor = IRPLOGGER_MIN_VERSION;
			}
			except(exception_filter(GetExceptionInformation(), TRUE)) {
				return GetExceptionCode();
			}
			*return_output_buffer_len = sizeof(IRPLOGGERVER);
			status = STATUS_SUCCESS;
			break;

		default:
			status = STATUS_INVALID_PARAMETER;
			break;
		}
	}
	else
		status = STATUS_INVALID_PARAMETER;

	return status;
}

NTSTATUS connect(
	_In_ PFLT_PORT client_port,
	_In_ PVOID server_port_cookie,
	_In_reads_bytes_(size_of_context) PVOID connection_context,
	_In_ ULONG size_of_context,
	_Flt_ConnectionCookie_Outptr_ PVOID *connection_cookie
)
/*++
Routine Description
	This is called when user-mode connects to the server
	port - to establish a connection
Arguments
	client_port - This is the pointer to the client port that
		will be used to send messages from the filter.
	server_port_cookie - unused
	connection_context - unused
	size_of_context   - unused
	connection_cookie - unused
Return Value
	STATUS_SUCCESS - to accept the connection
--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(server_port_cookie);
	UNREFERENCED_PARAMETER(connection_context);
	UNREFERENCED_PARAMETER(size_of_context);
	UNREFERENCED_PARAMETER(connection_cookie);

	FLT_ASSERT(irp_logger_data.client_port == NULL);
	irp_logger_data.client_port = client_port;
	return STATUS_SUCCESS;
}


VOID disconnect(_In_opt_ PVOID connection_cookie)
/*++
Routine Description
	This is called when the connection is torn-down. We use it to close our handle to the connection
Arguments
	connection_cookie - unused
Return value
	None
--*/
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(connection_cookie);

	//  Close our handle
	FltCloseClientPort(irp_logger_data.filter, &irp_logger_data.client_port);
}
