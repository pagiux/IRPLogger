#ifndef __INC_IRPLOGGER_ERROR_H__
#define __INC_IRPLOGGER_ERROR_H__

#include <wchar.h>

typedef enum _ERROR_LEVEL {
	DEBUG = 0,
	INFO,
	WARNING,
	ERR,
	CRITICAL
} ERROR_LEVEL;

INT error_init(LPCSTR filename, ERROR_LEVEL lv, INT flushrate);
VOID error_write(ERROR_LEVEL lv, LPCSTR func, INT line, LPCWSTR format, ...);
VOID error_destroy(VOID);

#define print_info(lv, fmt, ...) error_write(lv, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

#endif