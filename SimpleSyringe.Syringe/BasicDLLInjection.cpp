#include "BasicDLLInjection.h"

BOOL Basic_DLLInjection(DWORD pid, HANDLE process, LPWSTR moduleName)
{
	using namespace std;
	BOOL state = TRUE;
	HANDLE thread = nullptr;
	HMODULE kernel32 = nullptr;
	LPVOID buffer = nullptr;
	DWORD threadId = 0;
	LPTHREAD_START_ROUTINE loadEP;
	LPTHREAD_START_ROUTINE freeEP;

	size_t bufferSize = (wcsnlen(moduleName, 32768) + 1) * sizeof(WCHAR); // +1 for the null terminator
	cout << "[DLL Injection] Remote thread parameter block size=" << bufferSize << '\n';

	buffer = VirtualAllocEx(process, nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	cout << "[DLL Injection] Allocated the process memory " << buffer << " with error code " << GetLastError() << '\n';
	if (!buffer)
		return FALSE;

	WriteProcessMemory(process, buffer, (LPVOID)moduleName, bufferSize, nullptr);
	wcout << "[DLL Injection] Wrote dll location " << moduleName << " to the process memory " << buffer << " with error code " << GetLastError() << '\n';

	kernel32 = GetModuleHandleW(L"kernel32.dll");
	cout << "[DLL Injection] Kernel32.dll module address: " << static_cast<void *>(kernel32) << ", error code " << GetLastError() << '\n';
	if (!kernel32)
		return FALSE;

	loadEP = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryW");
	cout << "[DLL Injection] LoadLibraryW proc address: " << loadEP << ", error code " << GetLastError() << '\n';
	if (!loadEP)
		return FALSE;

	thread = CreateRemoteThread(process, nullptr, 0, loadEP, buffer, 0, &threadId);
	cout << "[DLL Injection] Created loader thread " << thread << " with thread id " << threadId << ", and error code " << GetLastError() << '\n';
	if (!thread)
		return FALSE;

	WaitForSingleObject(thread, INFINITE);
	DWORD hmod;
	if (!GetExitCodeThread(thread, &hmod))
		return FALSE;
	CloseHandle(thread);

	cout << "[DLL Injection] They loaded the DLL at " << (LPVOID)(hmod) << '\n';
	VirtualFreeEx(process, buffer, 0, MEM_RELEASE);

	cout << "[DLL Injection] Trying to execute remote function\n";
	LPCWSTR param = L"SimpleSyringe injected using basic DLL-injection!";
	DWORD paramLen = (wcslen(param) + 1) * sizeof(WCHAR);
	DWORD retcode = CallInjectedFunc(pid, moduleName, "TestFunction", paramLen, (LPVOID)param);
	cout << "the remote function returned code " << retcode << '\n';

	MODULEENTRY32W mEnt;
	if (FindModule(pid, moduleName, &mEnt))
	{
		cout << "Found module at " << (PVOID)mEnt.modBaseAddr << ", now trying to unload.\n";

		freeEP = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "FreeLibrary");
		cout << "[DLL Injection] FreeLibrary proc address: " << freeEP << ", error code " << GetLastError() << '\n';
		if (!freeEP)
			return FALSE;


		thread = CreateRemoteThread(process, nullptr, 0, freeEP, (LPVOID)mEnt.modBaseAddr, 0, &threadId);
		cout << "[DLL Injection] Created loader thread " << thread << " with thread id " << threadId << ", and error code " << GetLastError() << '\n';
		if (!thread)
			return FALSE;

		DWORD state;
		if (!GetExitCodeThread(thread, &state))
			return FALSE;

		cout << "[DLL Injection] Finshed unloading. State=" << state << '\n';
		CloseHandle(thread);
	}
	return TRUE;
}
