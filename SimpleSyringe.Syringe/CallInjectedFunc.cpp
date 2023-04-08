#include "CallInjectedFunc.h"
#include "utils.h"

//from https://github.com/ChadSki/SharpNeedle/blob/master/src/Launcher/Injection.cpp
DWORD CallInjectedFunc(DWORD pid, LPWSTR moduleName, std::string funcName, size_t funcParamSize, LPVOID funcParam)
{
	using namespace std;

	MODULEENTRY32W moduleEntry = { sizeof(MODULEENTRY32W) };
	if (!FindModule(pid, moduleName, &moduleEntry))
	{
		cout << "[CallInjectedFunc] Specified module not found. (maybe not loaded yet)\n";
		return FALSE;
	}

	// Load the DLL to find target procedure address
	HMODULE myModule = LoadLibraryExW(moduleName, nullptr, DONT_RESOLVE_DLL_REFERENCES);
	cout << "[CallInjectedFunc] Loaded your dll with error code " << GetLastError() << '\n';
	if (!myModule)
		return FALSE;

	auto threadProc = (PTHREAD_START_ROUTINE)FindProcAddress((PVOID)myModule, (PVOID)moduleEntry.modBaseAddr, funcName);
	if (!threadProc)
	{
		cout << "[CallInjectedFunc] Failed to calculate new proc address.";
		return FALSE;
	}

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	cout << "[CallInjectedFunc] Opened target process " << pid << " with error code " << GetLastError() << '\n';
	if (!process)
		return FALSE;

	LPVOID buffer = VirtualAllocEx(process, nullptr, funcParamSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	cout << "[CallInjectedFunc] Allocated target process memory " << funcParamSize << " bytes with error code " << GetLastError() << '\n';
	if (!buffer)
		return FALSE;

	BOOL state = WriteProcessMemory(process, buffer, funcParam, funcParamSize, nullptr);
	cout << "[CallInjectedFunc] Wrote target process memory with error code " << GetLastError() << '\n';
	if (!state)
		return FALSE;

	DWORD tid;
	HANDLE remoteThread = CreateRemoteThread(process, nullptr, 0, threadProc, buffer, 0, &tid);
	cout << "[CallInjectedFunc] Created remote thread " << remoteThread << " with thread id " << tid << " with error code " << GetLastError() << '\n';
	if (!remoteThread)
		return FALSE;

	WaitForSingleObject(remoteThread, INFINITE);

	VirtualFreeEx(process, buffer, 0, MEM_RELEASE);

	DWORD exitCode;
	if (!GetExitCodeThread(remoteThread, &exitCode))
	{
		cout << "[CallInjectedFunc] ERROR - Failed to acquire remote thread exit code\n";
		return FALSE;
	}

	return exitCode;
}
