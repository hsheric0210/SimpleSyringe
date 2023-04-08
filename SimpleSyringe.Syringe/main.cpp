#define _CRT_SECURE_NO_WARNINGS
#include "includes.h"
//#include "BasicDLLInjection.h"
#include "ReflectiveDLLInjection.h"

int wmain(int argc, WCHAR *argv[])
{
	if (argc < 3)
	{
		std::cout << "Usage: " << argv[0] << " <pid> <dllPath>\n";
		return 0;
	}

	std::wcout << "pidparam: '" << argv[1] << "'\n";
	PWSTR end;
	//DWORD pid = wcstol(argv[1], &end, 10);
	PWCHAR currentDir = new WCHAR[32768];
	GetCurrentDirectoryW(32768, currentDir);
	PROCESS_INFORMATION procinfo = { 0 };
	STARTUPINFOW si = { 0 };
	if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, currentDir, &si, &procinfo))
	{
		std::cout << "Failed to create process error code " << GetLastError() << '\n';
		return 0;
	}
	//DLLInjection(pid, argv[2]);

	/*

	cout << "DLLInj: Finding process with pid " << pid << '\n';

	// Open process
	process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	cout << "DLLInj: Process handle=" << process << ", error code " << GetLastError() << '\n';
	if (!process)
		return FALSE;

*/
//Basic_DLLInjection(procinfo.dwProcessId, procinfo.hProcess, argv[2]);
	Reflective_DLLInjection(procinfo.dwProcessId, procinfo.hProcess, argv[2]);
	CloseHandle(procinfo.hProcess);

	return 0;
}