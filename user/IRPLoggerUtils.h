#ifndef __IRPLOGGER_UTILS_H__
#define __IRPLOGGER_UTILS_H__

VOID display_error(_In_ DWORD code);
ULONG is_attached_to_volume(_In_ LPCWSTR volume_name);
VOID get_dos_name_from_volume_name (
	LPCWSTR volume_name,
	LPWSTR  dos_name,
	DWORD   dos_name_size
);

void list_devices(VOID);
ULONG format_system_time(
	_In_ SYSTEMTIME *system_time,
	_Out_writes_bytes_(buffer_len) CHAR *buffer,
	_In_ ULONG buffer_len
);

VOID replace_path(LPWSTR str, LPWSTR from, LPWSTR to, LPWSTR result);
float shannon_entropy(const unsigned char *data, ULONG data_len);

#endif
