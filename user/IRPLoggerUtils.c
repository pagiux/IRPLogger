#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdlib.h>
#include <windows.h>
#include <assert.h>
#include <strsafe.h>
#include <psapi.h>
#include <math.h>  

#include "IRPLoggerLog.h"
#include "IRPLoggerUtils.h"
#include "IRPLoggerError.h"

#pragma comment(lib, "psapi.lib")

VOID display_error(_In_ DWORD code)
/*++
Routine Description:
   This routine will display an error message based off of the Win32 error
   code that is passed in. This allows the user to see an understandable
   error message instead of just the code.
Arguments:
   code - The error code to be translated.
Return Value:
   None.
--*/
{
	WCHAR buffer[MY_MAX_PATH] = { 0 };
	DWORD count;
	HMODULE module = NULL;
	HRESULT status;

	count = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		code,
		0,
		buffer,
		sizeof(buffer) / sizeof(WCHAR),
		NULL);


	if (count == 0) {
		count = GetSystemDirectory(buffer, sizeof(buffer) / sizeof(WCHAR));

		if (count == 0 || count > sizeof(buffer) / sizeof(WCHAR)) {
			print_info(ERR, L"\tcould not translate error: %d.", code);
			return;
		}

		status = StringCchCat(buffer,
			sizeof(buffer) / sizeof(WCHAR),
			L"\\fltlib.dll");

		if (status != S_OK) {
			print_info(ERR, L"\tcould not translate error: %d", code);
			return;
		}

		module = LoadLibraryExW(buffer, NULL, LOAD_LIBRARY_AS_DATAFILE);

		//  Translate the Win32 error code into a useful message.
		count = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE,
			module,
			code,
			0,
			buffer,
			sizeof(buffer) / sizeof(WCHAR),
			NULL);

		if (module != NULL)
			FreeLibrary(module);

		//  If we still couldn't resolve the message, generate a string
		if (count == 0) {
			print_info(ERR, L"\tcould not translate error: %d", code);
			return;
		}
	}

	//  Display the translated error.
	printf("    %ws\n", buffer);
}

ULONG is_attached_to_volume(_In_ LPCWSTR volume_name)
/*++
Routine Description:
	Determine if our filter is attached to this volume
Arguments:
	volume_name - The volume we are checking
Return Value:
	TRUE - we are attached
	FALSE - we are not attached (or we couldn't tell)
--*/
{
	PWCHAR filtername;
	CHAR buffer[1024];
	PINSTANCE_FULL_INFORMATION data = (PINSTANCE_FULL_INFORMATION) buffer;
	HANDLE volume_iterator = INVALID_HANDLE_VALUE;
	ULONG bytes_returned;
	ULONG instance_count = 0;
	HRESULT h_result;

	//  Enumerate all instances on this volume
	h_result = FilterVolumeInstanceFindFirst(volume_name,
		InstanceFullInformation,
		data,
		sizeof(buffer) - sizeof(WCHAR),
		&bytes_returned,
		&volume_iterator);

	if (IS_ERROR(h_result))
		return instance_count;

	do {
		assert((data->FilterNameBufferOffset + data->FilterNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));
		_Analysis_assume_((data->FilterNameBufferOffset + data->FilterNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));

		filtername = Add2Ptr(data, data->FilterNameBufferOffset);
		filtername[data->FilterNameLength / sizeof(WCHAR)] = L'\0';

		//  Bump the instance count when we find a match
		if (_wcsicmp(filtername, IRPLOGGER_NAME) == 0)
			instance_count++;

	} while (SUCCEEDED(FilterVolumeInstanceFindNext(volume_iterator,
		InstanceFullInformation,
		data,
		sizeof(buffer) - sizeof(WCHAR),
		&bytes_returned)));

	//  Close the handle
	FilterVolumeInstanceFindClose(volume_iterator);
	return instance_count;
}

VOID replace_path(LPWSTR str, LPWSTR from, LPWSTR to, LPWSTR result)
{
	size_t cache_sz_inc = 16;
	const size_t cache_sz_inc_factor = 3;
	const size_t cache_sz_inc_max = 1048576;

	wchar_t *pret = NULL;
	const wchar_t *pstr2, *pstr = str;
	size_t i = 0, count = 0;

	ptrdiff_t *pos_cache_tmp = NULL, *pos_cache = NULL;

	size_t cache_sz = 0;
	size_t cpylen = 0, orglen = 0, retlen = 0, tolen = 0, fromlen = wcslen(from);

	while ((pstr2 = wcsstr(pstr, from)) != NULL) {
		count++;

		if (cache_sz < count) {
			cache_sz += cache_sz_inc;
			pos_cache_tmp = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
			if (pos_cache_tmp == NULL)
				goto CLEANUP_REPLACE;
			else 
				pos_cache = pos_cache_tmp;

			cache_sz_inc *= cache_sz_inc_factor;
			
			if (cache_sz_inc > cache_sz_inc_max)
				cache_sz_inc = cache_sz_inc_max;
		}

		pos_cache[count - 1] = pstr2 - str;
		pstr = pstr2 + fromlen;
	}

	orglen = pstr - str + wcslen(pstr);

	if (count > 0) {
		tolen = wcslen(to);
		retlen = orglen + (tolen - fromlen) * count;
	}
	else	
		retlen = orglen;

	if (result == NULL)
		goto CLEANUP_REPLACE;

	if (count == 0) 
		wcscpy_s(result, MY_MAX_PATH, str);
	else {
		pret = result;
		wmemcpy(pret, str, pos_cache[0]);
		pret += pos_cache[0];
		for (i = 0; i < count; i++) {
			wmemcpy(pret, to, tolen);
			pret += tolen;
			pstr = str + pos_cache[i] + fromlen;
			cpylen = (i == count - 1 ? orglen : pos_cache[i + 1]) - pos_cache[i] - fromlen;
			wmemcpy(pret, pstr, cpylen);
			pret += cpylen;
		}
		result[retlen] = L'\0';
	}

CLEANUP_REPLACE:
	free(pos_cache);
}

VOID get_dos_name_from_volume_name(
	LPCWSTR volume_name,
	LPWSTR  dos_name,
	DWORD   dos_name_size)
{
	UCHAR buffer[1024];
	PFILTER_VOLUME_BASIC_INFORMATION volume_buffer = (PFILTER_VOLUME_BASIC_INFORMATION)buffer;
	HANDLE volume_iterator = INVALID_HANDLE_VALUE;
	ULONG volume_bytes_returned;
	HRESULT h_result = S_OK;
	WCHAR drive_letter[15] = { 0 };

	try {
		//  Find out size of buffer needed
		h_result = FilterVolumeFindFirst(FilterVolumeBasicInformation,
			volume_buffer,
			sizeof(buffer) - sizeof(WCHAR),   //save space to null terminate name
			&volume_bytes_returned,
			&volume_iterator);

		if (IS_ERROR(h_result))
			leave;

		assert(INVALID_HANDLE_VALUE != volume_iterator);

		//  Loop through all of the filters, searching instance information
		do {
			assert((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volume_buffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));
			_Analysis_assume_((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volume_buffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));

			volume_buffer->FilterVolumeName[volume_buffer->FilterVolumeNameLength / sizeof(WCHAR)] = UNICODE_NULL;

			if (lstrcmpW(volume_buffer->FilterVolumeName, volume_name) == 0) {
				wcscpy_s(dos_name, dos_name_size, SUCCEEDED(FilterGetDosName(
					volume_buffer->FilterVolumeName,
					drive_letter,
					sizeof(drive_letter) / sizeof(WCHAR))) ? drive_letter : L"");
				leave;
			}

		} while (SUCCEEDED(h_result = FilterVolumeFindNext(volume_iterator,
			FilterVolumeBasicInformation,
			volume_buffer,
			sizeof(buffer) - sizeof(WCHAR),    //save space to null terminate name
			&volume_bytes_returned)));

		if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == h_result)
			h_result = S_OK;
	}
	finally {
		if (INVALID_HANDLE_VALUE != volume_iterator)
			FilterVolumeFindClose(volume_iterator);

		if (IS_ERROR(h_result)) {
			if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == h_result)
				print_info(ERR, L"no volumes found.");
			else
				print_info(ERR, L"volume listing failed with error: 0x%08x", h_result);
		}
	}

}

void list_devices(VOID)
/*++
Routine Description:
	Display the volumes we are attached to
--*/
{
	UCHAR buffer[1024];
	PFILTER_VOLUME_BASIC_INFORMATION volume_buffer = (PFILTER_VOLUME_BASIC_INFORMATION)buffer;
	HANDLE volume_iterator = INVALID_HANDLE_VALUE;
	ULONG volume_bytes_returned;
	HRESULT h_result = S_OK;
	WCHAR drive_letter[15] = { 0 };
	ULONG instance_count;

	try {
		//  Find out size of buffer needed
		h_result = FilterVolumeFindFirst(FilterVolumeBasicInformation,
			volume_buffer,
			sizeof(buffer) - sizeof(WCHAR),   //save space to null terminate name
			&volume_bytes_returned,
			&volume_iterator);

		if (IS_ERROR(h_result))
			leave;

		assert(INVALID_HANDLE_VALUE != volume_iterator);

		//  Output the header
		printf("\n"
			"Dos Name        Volume Name                            Status \n"
			"--------------  ------------------------------------  --------\n");

		//  Loop through all of the filters, displaying instance information
		do {
			assert((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volume_buffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));
			_Analysis_assume_((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volume_buffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));

			volume_buffer->FilterVolumeName[volume_buffer->FilterVolumeNameLength / sizeof(WCHAR)] = UNICODE_NULL;
			instance_count = is_attached_to_volume(volume_buffer->FilterVolumeName);

			printf("%-14ws  %-36ws  %s",
				(SUCCEEDED(FilterGetDosName(
					volume_buffer->FilterVolumeName,
					drive_letter,
					sizeof(drive_letter) / sizeof(WCHAR))) ? drive_letter : L""),
				volume_buffer->FilterVolumeName,
				(instance_count > 0) ? "Attached" : "");

			if (instance_count > 1)
				printf(" (%d)\n", instance_count);
			else
				printf("\n");
		} while (SUCCEEDED(h_result = FilterVolumeFindNext(volume_iterator,
			FilterVolumeBasicInformation,
			volume_buffer,
			sizeof(buffer) - sizeof(WCHAR),    //save space to null terminate name
			&volume_bytes_returned)));

		if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == h_result)
			h_result = S_OK;
	}
	finally {
		if (INVALID_HANDLE_VALUE != volume_iterator)
			FilterVolumeFindClose(volume_iterator);

		if (IS_ERROR(h_result)) {
			if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == h_result)
				printf("No volumes found.\n");
			else
				printf("Volume listing failed with error: 0x%08x\n", h_result);
		}
	}
}

ULONG format_system_time(
	_In_ SYSTEMTIME *system_time,
	_Out_writes_bytes_(buffer_len) CHAR *buffer,
	_In_ ULONG buffer_len
)
/*++
Routine Description:
	Formats the values in a SystemTime struct into the buffer
	passed in.  The resulting string is NULL terminated.  The format
	for the time is:
		hours:minutes:seconds:milliseconds
Arguments:
	system_time - the struct to format
	buffer - the buffer to place the formatted time in
	buffer_len - the size of the buffer
Return Value:
	The length of the string returned in buffer.
--*/
{
	ULONG return_len = 0;

	if (buffer_len < TIME_BUFFER_LENGTH)
		return 0;


	return_len = sprintf_s(buffer,
		buffer_len,
		"%02d:%02d:%02d:%03d",
		system_time->wHour,
		system_time->wMinute,
		system_time->wSecond,
		system_time->wMilliseconds);

	return return_len;
}

float shannon_entropy(const unsigned char *data, ULONG data_len)
{
	DWORD i = 0;
	double entropy = 0.0;
	ULONG symbols[256] = { 0 };

	for (i = 0; i < data_len; i++)
		symbols[data[i]]++;

	for (i = 0; i < 256; i++) {
		double tmp = 0.0;
		if (symbols[i]) {
			tmp = ((double)symbols[i] / (double)data_len);
			entropy -= tmp * log2(tmp);
		}
	}

	return (float)((entropy * log2(2)) / log2(256));
}

