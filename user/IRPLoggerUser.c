#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <assert.h>
#include <strsafe.h>
#include <signal.h>
#include <time.h>
#include "IRPLoggerLog.h"
#include "IRPLoggerUtils.h"
#include "IRPLoggerError.h"


#define SUCCESS              0
#define USAGE_ERROR          1
#define EXIT_INTERPRETER     2
#define EXIT_PROGRAM         4

#define INTERPRETER_EXIT_COMMAND1 "go"
#define INTERPRETER_EXIT_COMMAND2 "g"
#define PROGRAM_EXIT_COMMAND      "exit"
#define CMDLINE_SIZE              256
#define NUM_PARAMS                40

static BOOLEAN main_exit = FALSE;
/* OLD
_crt_signal_t handle_signal(int signal)
{
	switch (signal) {
	case SIGINT:
		print_info(DEBUG, L"signal SIGINT caught");
		main_exit = TRUE;
		break;
	default:
		print_info(WARNING, L"caught wrong signal number(%d)\n", signal);
		return;
	}
}
*/

BOOL WINAPI ctrl_handler(DWORD ctrl)
{
	switch (ctrl) {
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		main_exit = TRUE;
		return TRUE;

	default:
		return FALSE;
	}
}
static BOOLEAN logs_filter(PLOG_RECORD record)
{
	PLOG_RECORD plog_record;
	PRECORD_DATA precord_data;

	plog_record = (PLOG_RECORD) record;
	precord_data = &plog_record->data;

	if (GetCurrentProcessId() == (DWORD)(precord_data->process_id))
		return FALSE;

	return TRUE;
}

#pragma warning(push)
#pragma warning(disable:4706) // assignment within conditional expression

int _cdecl main(_In_ int argc, _In_reads_(argc) char *argv[])
/*++
Routine Description:
    Main routine for irplogger
--*/
{
    HANDLE port = INVALID_HANDLE_VALUE;
    HRESULT h_result = S_OK;
    DWORD result;
    ULONG thread_id;
	INT param_index = 0;
    HANDLE thread = NULL;
    IRPLOG_CONTEXT context;

	//  Initialize error logging 
	error_init("irplogger.error.log", DEBUG, 10);

	//  Initialize signal handler
	SetConsoleCtrlHandler(ctrl_handler, TRUE);

	//OLD
	//signal(SIGINT, handle_signal);	

    //  Initialize handle in case of error
    context.shutdown = NULL;
	// Initialize the fields of the LOG_CONTEXT
	context.shutdown = CreateSemaphore(NULL, 0, 1, L"IRPLogger shut down");
	context.cleaning_up = FALSE;
	context.log_to_file = FALSE;
	context.output_file = NULL;
	context.logs_filter = logs_filter;

	if (context.shutdown == NULL) {
		result = GetLastError();
		display_error(result);
		goto MAIN_EXIT;
	}

	print_info(INFO, L"connecting to filter's port...");
	h_result = FilterConnectCommunicationPort(IRPLOGGER_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(h_result)) {
		print_info(CRITICAL, L"could not connect to filter: 0x%08x", h_result);
		display_error(h_result);
		goto MAIN_EXIT;
	}

	context.port = port;

    // Check the valid parameters for startup
    if (argc < 5) {
		list_devices();
		printf("\n\nUsage: %s [/a <drive>] [/f [<file name>]]\n"
			"    [/a <drive>] starts monitoring <drive>\n"
			"    [/f [<file name>]] turns on and off logging to the specified file\n",
			argv[0]);

		goto MAIN_EXIT;
    }
	else {
		for (param_index = 1; param_index < argc - 1; param_index++) {
			PCHAR param;
			CHAR buffer[BUFFER_SIZE];
			DWORD buffer_len;
			WCHAR instance_name[INSTANCE_NAME_MAX_CHARS + 1];
			param = argv[param_index];

			if (param[0] == '/') {
				// Have the beginning of a switch
				switch (param[1]) {
				case 'a':
				case 'A':
					// Attach to the specified drive letter
					param_index++;
					if (param_index >= argc) {
						// Not enough parameters
						goto MAIN_EXIT;
					}
					param = argv[param_index];
					print_info(INFO, L"\tattaching to %s", param);
					buffer_len = MultiByteToWideChar(CP_ACP,
						MB_ERR_INVALID_CHARS,
						param,
						-1,
						(LPWSTR) buffer,
						BUFFER_SIZE / sizeof(WCHAR));

					if (buffer_len == 0) {
						print_info(ERR, L"\tfailed to convert volume name");
						goto MAIN_EXIT;
					}

					wcscpy_s(context.volume_name, buffer_len, (PWSTR) buffer);
					get_dos_name_from_volume_name(context.volume_name, context.dos_name, buffer_len);

					h_result = FilterAttach(IRPLOGGER_NAME,
						(PWSTR)buffer,
						NULL, // instance name
						sizeof(instance_name),
						instance_name);

					if (SUCCEEDED(h_result))
						print_info(INFO, L"\tinstance name: %S", instance_name);
					else {
						print_info(ERR, L"\tcould not attach to device: 0x%08x", h_result);
						display_error(h_result);
					}
					break;

				case 'f':
				case 'F':
					// Output logging results to file
					if (context.log_to_file) {
						print_info(INFO, L"\tstop logging to file");
						context.log_to_file = FALSE;
						assert(context.output_file);
						_Analysis_assume_(context->output_file != NULL);
						fclose(context.output_file);
						context.output_file = NULL;
					}
					else {
						param_index++;
						if (param_index >= argc)
							goto MAIN_EXIT;

						param = argv[param_index];
						print_info(INFO, L"\tlog to file %s", param);

						if (fopen_s(&context.output_file, param, "w") != 0)
							assert(context.output_file);

						context.log_to_file = TRUE;
					}
					break;

				default:
					// Invalid switch, goto exit
					goto MAIN_EXIT;
				}
			}
		}
	}

    // Create the thread to read the log records that are gathered by IRPLogger.sys.
	print_info(INFO, L"creating logging thread...");
	thread = CreateThread(NULL,
		0,
		retrieve_log_records,
		(LPVOID) &context,
		0,
		&thread_id);

	if (!thread) {
		result = GetLastError();
		print_info(CRITICAL, L"could not create logging thread: %d", result);
		display_error(result);
		goto MAIN_CLEANUP;
	}

	while (!main_exit)
		Sleep(POLL_INTERVAL * 5);

MAIN_CLEANUP:
	print_info(INFO, L"cleaning up...");
	context.cleaning_up = TRUE;
	WaitForSingleObject(context.shutdown, INFINITE);
	if (context.log_to_file)
		fclose(context.output_file);

MAIN_EXIT:
	if (context.shutdown)
		CloseHandle(context.shutdown);

	if (thread)
		CloseHandle(thread);

	if (INVALID_HANDLE_VALUE != port)
		CloseHandle(port);

	error_destroy();

	return 0;
}

#pragma warning(pop)