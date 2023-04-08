#include "BasicDLLInjection.h"

BOOL DLLInjection(DWORD pid, LPWSTR moduleName)
{
	using namespace std;
	BOOL state = TRUE;
	HANDLE process = nullptr;
	HANDLE thread = nullptr;
	HMODULE kernel32 = nullptr;
	LPVOID buffer = nullptr;
	DWORD threadId = 0;
	LPTHREAD_START_ROUTINE loadEP;
	LPTHREAD_START_ROUTINE freeEP;

	cout << "DLLInj: Finding process with pid " << pid << '\n';

	// Open process
	process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	cout << "DLLInj: Process handle=" << process << ", error code " << GetLastError() << '\n';
	if (!process)
		return FALSE;

	size_t bufferSize = (wcsnlen(moduleName, 32768) + 1) * sizeof(WCHAR); // +1 for the null terminator
	cout << "DLLInj: Remote thread parameter block size=" << bufferSize << '\n';

	buffer = VirtualAllocEx(process, nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	cout << "DLLInj: Allocated the process memory " << buffer << " with error code " << GetLastError() << '\n';
	if (!buffer)
		return FALSE;

	WriteProcessMemory(process, buffer, (LPVOID)moduleName, bufferSize, nullptr);
	wcout << "DLLInj: Wrote dll location " << moduleName << " to the process memory " << buffer << " with error code " << GetLastError() << '\n';

	kernel32 = GetModuleHandleW(L"kernel32.dll");
	cout << "DLLInj: Kernel32.dll module address: " << static_cast<void *>(kernel32) << ", error code " << GetLastError() << '\n';
	if (!kernel32)
		return FALSE;

	loadEP = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryW");
	cout << "DLLInj: LoadLibraryW proc address: " << loadEP << ", error code " << GetLastError() << '\n';
	if (!loadEP)
		return FALSE;

	thread = CreateRemoteThread(process, nullptr, 0, loadEP, buffer, 0, &threadId);
	cout << "DLLInj: Created loader thread " << thread << " with thread id " << threadId << ", and error code " << GetLastError() << '\n';
	if (!thread)
		return FALSE;

	WaitForSingleObject(thread, INFINITE);
	DWORD hmod;
	if (!GetExitCodeThread(thread, &hmod))
		return FALSE;
	cout << "DLLInj: They loaded the DLL at " << (LPVOID)(hmod) << '\n';
	VirtualFreeEx(process, buffer, 0, MEM_RELEASE);

	cout << "DLLInj: Trying to execute remote function\n";
	LPCWSTR param = L"MySimpleSyringe Injected!";
	DWORD paramLen = (wcslen(param) + 1) * sizeof(WCHAR);
	DWORD retcode = CallInjectedFunc(pid, moduleName, "TestFunction", paramLen, (LPVOID)param);
	cout << "the remote function returned code " << retcode << '\n';
	return TRUE;
}
