#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <assert.h>
#include <time.h>

#include "IRPLoggerError.h"

typedef struct _ERROR_FILE {
	HANDLE fp;
	ERROR_LEVEL lv;
	int	flushrate;
	int counter;
	HANDLE mux;
} ERROR_FILE, *PERROR_FILE;

static PERROR_FILE error_file = NULL;

INT error_init(LPCSTR filename, ERROR_LEVEL lv, INT flushrate)
{
	assert(filename != NULL);

	if ((error_file = (PERROR_FILE ) calloc(1, sizeof(ERROR_FILE))) == NULL)
		return 1;

	if ((error_file->fp = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return 1;

	error_file->mux = CreateMutex(NULL, FALSE, NULL);

	error_file->flushrate = flushrate;
	error_file->counter = 0;
	error_file->lv = lv;

	return 0;
}

VOID error_destroy(VOID)
{
	assert(error_file != NULL);

	WaitForSingleObject(error_file->mux, INFINITE);
	if (error_file->fp != NULL) {
		FlushFileBuffers(error_file->fp);
		CloseHandle(error_file->fp);
		error_file->fp = NULL;
	}
	CloseHandle(error_file->mux);

	free(error_file);
	error_file = NULL;
}

VOID error_write(ERROR_LEVEL lv, LPCSTR func, INT line, LPCWSTR format, ...)
{
	assert(error_file != NULL);
	assert(format != NULL);

	wchar_t buf[0xFF] = { 0 };
	wchar_t timestamp[0xFF] = { 0 };
	char to_write[0xFF * 3] = { 0 };
	DWORD len = 0, ret = 0;

	wchar_t *level = L"???";
	va_list args;

	if (lv >= error_file->lv) {
		WaitForSingleObject(error_file->mux, INFINITE);
		time_t ct = 0;
		time(&ct);
		struct tm timeinfo;
		localtime_s(&timeinfo, &ct);

		wcsftime(timestamp, 0xFF, L"%Y/%m/%d:%X", &timeinfo);

		switch (lv) {
		case DEBUG:
			level = L"DBG";
			break;
		case WARNING:
			level = L"WAR";
			break;
		case INFO:
			level = L"INF";
			break;
		case ERR:
			level = L"ERR";
			break;
		case CRITICAL:
			level = L"CRT";
			break;
		}

		va_start(args, format);
		vswprintf(buf, 0xFF, format, args);
		va_end(args);

		if (error_file->lv <= DEBUG) {
			_snprintf_s(to_write, (0xFF * 3), (0xFF * 3), "%lu %S [%S] :: %s:%d: %S\n", GetCurrentThreadId(), timestamp, level, func, line, buf);
			len = (int)strnlen_s(to_write, _TRUNCATE);
			WriteFile(error_file->fp, to_write, len, &ret, NULL);
		}
		else {
			_snprintf_s(to_write, 0xFF * 3, 0xFF * 3, "%S [%S] :: %s: %S\n", timestamp, level, func, buf);
			len = (int)strnlen_s(to_write, _TRUNCATE);
			WriteFile(error_file->fp, to_write, len, &ret, NULL);
		}

		if ((++error_file->counter % error_file->flushrate) == 0)
			FlushFileBuffers(error_file->fp);

		ReleaseMutex(error_file->mux);
	}
}
