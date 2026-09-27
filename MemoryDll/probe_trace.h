#pragma once

// Enabled only by the Windows CI probe. Keep this independent of C++ runtime
// initialization so it can report failures from DllMain.
inline void probe_trace(const char* stage, DWORD code = 0)
{
	const DWORD previousError = GetLastError();
	wchar_t path[MAX_PATH];
	const DWORD length = GetEnvironmentVariableW(L"WORKSPACE_DIAGNOSTIC_FILE", path, MAX_PATH);
	if (length == 0 || length >= MAX_PATH)
	{
		SetLastError(previousError);
		return;
	}
	HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file != INVALID_HANDLE_VALUE)
	{
		char line[128];
		DWORD count = 0;
		while (stage[count] && count < sizeof(line) - 24)
		{
			line[count] = stage[count];
			++count;
		}
		line[count++] = ' ';
		char digits[10];
		DWORD digitsCount = 0;
		do
		{
			digits[digitsCount++] = static_cast<char>('0' + code % 10);
			code /= 10;
		} while (code && digitsCount < sizeof(digits));
		while (digitsCount) line[count++] = digits[--digitsCount];
		line[count++] = '\r';
		line[count++] = '\n';
		DWORD written = 0;
		WriteFile(file, line, count, &written, nullptr);
		CloseHandle(file);
	}
	SetLastError(previousError);
}
