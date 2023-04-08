#include "CodeInjection.h"
#include "utils.h"

//https://ch4njun.tistory.com/140
DWORD CodeInjection(HANDLE process, size_t codeSize, FARPROC code, size_t funcParamSize, LPVOID funcParam)
{
	using namespace std;

	LPVOID paramBuffer = WriteProcessMem(process, funcParamSize, funcParam, PAGE_READWRITE);
	cout << "[Code Injection] Wrote target process memory 0x" << paramBuffer << " the function parameter / error code " << GetLastError() << '\n';
	if (!paramBuffer)
		return -1;

	LPVOID codeBuffer = WriteProcessMem(process, codeSize, code, PAGE_EXECUTE_READWRITE);
	cout << "[Code Injection] Wrote target process memory 0x" << codeBuffer << " the code / error code " << GetLastError() << '\n';
	if (!codeBuffer)
		return -1;

	DWORD tid;
	HANDLE thread = CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)codeBuffer, paramBuffer, 0, &tid);
	cout << "[Code Injection] Remote thread 0x" << thread << " created with tid " << tid << " / error code " << GetLastError() << '\n';
	if (!thread)
		return -1;

	WaitForSingleObject(thread, INFINITE);

	DWORD exit;
	if (!GetExitCodeThread(thread, &exit))
		return -1;

	cout << "[Code Injection] Remote thread exit code " << exit << " (0x" << hex << exit << dec << ")\n";
	VirtualFreeEx(process, paramBuffer, 0, MEM_RELEASE);
	VirtualFreeEx(process, codeBuffer, 0, MEM_RELEASE);
	CloseHandle(thread);
}
