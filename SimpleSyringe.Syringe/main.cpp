#define _CRT_SECURE_NO_WARNINGS
#include<Windows.h>
#include<TlHelp32.h>
#include<iostream>
#include<algorithm>

typedef HMODULE(WINAPI *myLoadLibrary)(LPCWSTR FileName);
typedef INT(WINAPI *myMessageBoxW)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
typedef FARPROC(WINAPI *myGetProcAddress)(HMODULE module, LPCSTR funcName);
typedef INT(WINAPIV *mywsprintfW)(LPWSTR buffer, LPCWSTR format, ...); // user32.dll
typedef LPVOID(WINAPI *myVirtualAlloc)(LPVOID address, size_t size, DWORD allocType, DWORD protect);
typedef LPVOID(WINAPI *myVirtualFree)(LPVOID address, size_t size, DWORD freeType);
typedef HANDLE(WINAPI *myCreateMailslotW)(LPCWSTR name, DWORD maxMsgSize, DWORD readTimeout, LPSECURITY_ATTRIBUTES secAttrs);

typedef BOOL(WINAPI *myFreeLibrary)(HMODULE Module);
typedef DWORD(WINAPI *myGetLastError)();

typedef struct _CODEINJ_DLL_LOAD_PARAM
{
	// 0 - LoadLibraryW
	// 1 - GetProcAddress
	// 2 - VirtualAlloc
	// 3 - VirtualFree
	// 4 - CreateFile
	// 5 - WriteFile
	FARPROC procs[4];

	// Code Injection 시, 해당 함수 내에는 코드를 제외한 그 어떤 리터럴도 포함할 수 없음. 문자열 리터럴 ("", L"")도 여기에 포함됨.
	CHAR aliterals[2][256];
	WCHAR wliterals[5][1024];
} CODEINJ_DLL_LOAD_PARAM, *PCODEINJ_DLL_LOAD_PARAM;

DWORD CodeInj_DllLoad(LPVOID lpParam)
{
	PCODEINJ_DLL_LOAD_PARAM param = reinterpret_cast<PCODEINJ_DLL_LOAD_PARAM>(lpParam);
	HMODULE usr32 = ((myLoadLibrary)param->procs[0])(param->wliterals[0]); // load user32.dll
	HMODULE mod = ((myLoadLibrary)param->procs[0])(param->wliterals[1]); // load my dll
	LPVOID mem = ((myVirtualAlloc)param->procs[2])(nullptr, 16384, MEM_COMMIT, PAGE_READWRITE); // allocate memory

	((mywsprintfW)(((myGetProcAddress)param->procs[1])(usr32, param->aliterals[0])))((LPWSTR)mem, param->wliterals[2], mod);
	((myMessageBoxW)(((myGetProcAddress)param->procs[1])(usr32, param->aliterals[1])))(nullptr, (LPCWSTR)mem, param->wliterals[3], 0); // print module handle
	((myVirtualFree)param->procs[3])(mem, 0, MEM_RELEASE);

	// return (DWORD)mod; // We can't use return value because HMODULE is HANDLE, which is 64-bit when the x64
	// We should try different way.

	// We'll use Mailslot system
	//https://learn.microsoft.com/ko-kr/windows/win32/ipc/creating-a-mailslot
	//https://hwan-shell.tistory.com/143


}

void CodeInj_DllLoad_End()
{}

typedef struct _CODEINJ_DLL_UNLOAD_PARAM
{
	FARPROC funcs[2];
	HMODULE hmod;
} CODEINJ_DLL_UNLOAD_PARAM, *PCODEINJ_DLL_UNLOAD_PARAM;

DWORD CodeInj_DllUnload(LPVOID lpParam)
{
	PCODEINJ_DLL_UNLOAD_PARAM param = reinterpret_cast<PCODEINJ_DLL_UNLOAD_PARAM>(lpParam);
	((myFreeLibrary)param->funcs[0])(param->hmod);
	return ((myGetLastError)param->funcs[1])();
}

void CodeInj_DllUnload_End()
{}

//https://ch4njun.tistory.com/140
DWORD CodeInjection(HANDLE process, size_t codeSize, FARPROC code, size_t funcParamSize, LPVOID funcParam)
{
	using namespace std;

	LPVOID paramBuffer = VirtualAllocEx(process, nullptr, funcParamSize, MEM_COMMIT, PAGE_READWRITE);
	cout << "CodeInj: Allocated target process memory " << paramBuffer << " for parameter buffer with error code " << GetLastError() << '\n';
	if (!paramBuffer)
		return -1;

	BOOL state = WriteProcessMemory(process, paramBuffer, funcParam, funcParamSize, nullptr);
	cout << "CodeInj: Wrote target process memory " << paramBuffer << " for parameter buffer with error code " << GetLastError() << '\n';
	if (!state)
		return -1;

	LPVOID codeBuffer = VirtualAllocEx(process, nullptr, codeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	cout << "CodeInj: Allocated target process memory " << codeBuffer << " for code with error code " << GetLastError() << '\n';
	if (!codeBuffer)
		return -1;

	state = WriteProcessMemory(process, codeBuffer, (LPCVOID)code, codeSize, nullptr);
	cout << "CodeInj: Wrote target process memory " << codeBuffer << " for code with error code " << GetLastError() << '\n';
	if (!state)
		return -1;

	DWORD tid;
	HANDLE thread = CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)codeBuffer, paramBuffer, 0, &tid);
	cout << "CodeInj: Started remote thread " << thread << " with tid " << tid << " with error code " << GetLastError() << '\n';
	if (!thread)
		return -1;

	WaitForSingleObject(thread, INFINITE);

	DWORD exit;
	if (!GetExitCodeThread(thread, &exit))
		return -1;

	cout << "CodeInj: Success - exit code " << exit << "\n";
	VirtualFreeEx(process, paramBuffer, 0, MEM_RELEASE);
	VirtualFreeEx(process, codeBuffer, 0, MEM_RELEASE);
	CloseHandle(thread);
	CloseHandle(process);
}

DWORD CodeInjection_DLL_Load(HANDLE process, LPCWSTR dll)
{
	HMODULE krnl32 = LoadLibraryW(L"kernel32.dll");
	CODEINJ_DLL_LOAD_PARAM param = { 0 };
	param.procs[0] = GetProcAddress(krnl32, "LoadLibraryW");
	param.procs[1] = GetProcAddress(krnl32, "GetProcAddress");
	param.procs[2] = GetProcAddress(krnl32, "VirtualAlloc");
	param.procs[3] = GetProcAddress(krnl32, "VirtualFree");
	param.procs[4] = GetProcAddress(krnl32, "CreateFile");
	param.procs[5] = GetProcAddress(krnl32, "WriteFile");
	strcpy(param.aliterals[0], "wsprintfW");
	strcpy(param.aliterals[1], "MessageBoxW");

	wcscpy(param.wliterals[0], L"user32.dll");
	wmemcpy(param.wliterals[1], dll, wcslen(dll) + 1);
	wcscpy(param.wliterals[2], L"DLL Load @ %p");
	wcscpy(param.wliterals[3], L"DLL-Injection by Code Injection");

	HANDLE pipe = CreateNamedPipeW(L"\\.\\pipe\\SimpleSyringeInjected", PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE, 1, 1024, 1024, 1000, nullptr);
	if (pipe == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to create pipe\n";
		return -1;
	}

	CodeInjection(process, (DWORD)CodeInj_DllLoad_End - (DWORD)CodeInj_DllLoad, (FARPROC)CodeInj_DllLoad, sizeof(CODEINJ_DLL_LOAD_PARAM), (LPVOID)&param);

	ULONGLONG *buffer = new ULONGLONG[1024];
	ReadFile(pipe, buffer, 1024, nullptr, nullptr);
}


DWORD CodeInjection_DLL_Unload(HANDLE process, HMODULE mod)
{
	HMODULE krnl32 = LoadLibraryW(L"kernel32.dll");
	CODEINJ_DLL_UNLOAD_PARAM param = { 0 };
	param.funcs[0] = GetProcAddress(krnl32, "FreeLibrary");
	param.funcs[1] = GetProcAddress(krnl32, "GetLastError");
	param.hmod = mod;

	return CodeInjection(process, (DWORD)CodeInj_DllUnload_End - (DWORD)CodeInj_DllUnload, (FARPROC)CodeInj_DllUnload, sizeof(CODEINJ_DLL_UNLOAD_PARAM), (LPVOID)&param);
}

//from https://github.com/ChadSki/SharpNeedle/blob/master/src/Launcher/Injection.cpp
DWORD CallInjectedFunction(DWORD pid, LPWSTR moduleName, std::string funcName, size_t funcParamSize, LPVOID funcParam)
{
	using namespace std;

	// Find target function address from the target process
	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	cout << "DLLInj_CallFunc: Enumerating modules of the target process. error code " << GetLastError() << '\n';
	if (moduleSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	MODULEENTRY32W moduleEntry = { sizeof(MODULEENTRY32W) };
	BOOL found = FALSE;

	LPWSTR moduleNameCopy = new WCHAR[wcslen(moduleName) + 1];
	lstrcpyW(moduleNameCopy, moduleName);
	_wcslwr_s(moduleNameCopy, wcslen(moduleName) + 1);
	wstring targetModulePath(moduleNameCopy);
	for (BOOL hasNext = Module32FirstW(moduleSnapshot, &moduleEntry); hasNext; hasNext = Module32NextW(moduleSnapshot, &moduleEntry))
	{
		wstring modulePath(_wcslwr(moduleEntry.szExePath));
		wcout << "DLLInj_CallFunc: Target process module found - " << modulePath << '\n';
		if (targetModulePath == modulePath)
		{
			found = TRUE;
			break;
		}
	}

	if (!found)
	{
		cout << "DLLInj_CallFunc: Module not found.\n";
		return FALSE;
	}

	PBYTE moduleBase = moduleEntry.modBaseAddr;
	// end Find target function address from the target process

	// find function address
	HMODULE myDLL = LoadLibraryExW(moduleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	cout << "DLLInj_CallFunc: Loaded your dll with error code " << GetLastError() << '\n';
	if (!myDLL)
		return FALSE;

	PVOID myModule = static_cast<PVOID>(myDLL);
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(static_cast<HMODULE>(myModule));
	if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cout << "DLLInj_CallFunc: The DLL has an invalid DOS header\n";
		return FALSE;
	}

	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PCHAR>(myModule) + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "DLLInj_CallFunc: The DLL has an invalid NT header\n";
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<PBYTE>(myDLL) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (exportDirectory->AddressOfNames == NULL)
	{
		cout << "DLLInj_CallFunc: The DLL symbol names missing entirely\n";
		return FALSE;
	}

	PDWORD nameRVAs = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(myModule) + exportDirectory->AddressOfNames);
	PWORD nameOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(myModule) + exportDirectory->AddressOfNameOrdinals);
	PDWORD funcAddresses = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(myModule) + exportDirectory->AddressOfFunctions);

	FARPROC exportAddress = NULL;
	for (DWORD i = 0, j = exportDirectory->NumberOfNames; i < j; i++)
	{
		PSTR thisFuncName = reinterpret_cast<PSTR>(reinterpret_cast<PBYTE>(myModule) + nameRVAs[i]);
		if (funcName != thisFuncName) continue;
		WORD ord = nameOrdinals[i];
		exportAddress = reinterpret_cast<FARPROC>(reinterpret_cast<PBYTE>(myModule) + funcAddresses[ord]);
	}
	// end find function address

	// Relocate pointer (exportFunctionAddress - loadedModuleBase) + targetProcessModuleBase
	PTHREAD_START_ROUTINE threadEP = reinterpret_cast<PTHREAD_START_ROUTINE>((reinterpret_cast<DWORD_PTR>(exportAddress) - reinterpret_cast<DWORD_PTR>(myModule)) + reinterpret_cast<DWORD_PTR>(moduleBase));


	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	cout << "DLLInj_CallFunc: Opened target process " << pid << " with error code " << GetLastError() << '\n';
	if (!process)
		return FALSE;

	LPVOID buffer = VirtualAllocEx(process, nullptr, funcParamSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	cout << "DLLInj_CallFunc: Allocated target process memory " << funcParamSize << " bytes with error code " << GetLastError() << '\n';
	if (!buffer)
		return FALSE;

	BOOL state = WriteProcessMemory(process, buffer, funcParam, funcParamSize, nullptr);
	cout << "DLLInj_CallFunc: Wrote target process memory with error code " << GetLastError() << '\n';
	if (!state)
		return FALSE;

	DWORD tid;
	HANDLE remoteThread = CreateRemoteThread(process, nullptr, 0, threadEP, buffer, 0, &tid);
	cout << "DLLInj_CallFunc: Created remote thread " << remoteThread << " with thread id " << tid << " with error code " << GetLastError() << '\n';
	if (!remoteThread)
		return FALSE;

	WaitForSingleObject(remoteThread, INFINITE);

	DWORD exitCode;
	if (!GetExitCodeThread(remoteThread, &exitCode))
	{
		cout << "DLLInj_CallFunc: ERROR - Failed to acquire remote thread exit code\n";
		return FALSE;
	}

	return exitCode;
}

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
	DWORD retcode = CallInjectedFunction(pid, moduleName, "TestFunction", paramLen, (LPVOID)param);
	cout << "the remote function returned code " << retcode << '\n';

	cout << "DLLInj: Trying clean up anything\n";

	freeEP = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "FreeLibrary");
	cout << "DLLInj: FreeLibrary proc address: " << freeEP << ", error code " << GetLastError() << '\n';
	if (!freeEP)
		return FALSE;

	CloseHandle(thread);

	CodeInjection_DLL_Unload(process, (HMODULE)hmod);

	// thread = CreateRemoteThread(process, nullptr, 0, freeEP, (LPVOID)hmod, 0, &threadId);
	// cout << "DLLInj: Created unloader thread " << thread << " with thread id " << threadId << ", and error code " << GetLastError() << '\n';
	// if (!thread)
	// 	return FALSE;
	// 
	// WaitForSingleObject(thread, INFINITE);
	// 
	// GetExitCodeThread(thread, &hmod);
	// cout << "DLLInj: Library unloader success: " << hmod << '\n';

	CloseHandle(process);

	return TRUE;
}

BOOL Code_DLLInjection(HANDLE process, LPWSTR moduleName)
{
	using namespace std;
	BOOL state = TRUE;
	HANDLE thread = nullptr;
	HMODULE kernel32 = nullptr;
	LPVOID buffer = nullptr;
	DWORD threadId = 0;
	LPTHREAD_START_ROUTINE loadEP;
	LPTHREAD_START_ROUTINE freeEP;

	DWORD ret = CodeInjection_DLL_Load(process, moduleName);

	cout << "DLLInj: They loaded the DLL at " << (LPVOID)(ret) << '\n';
	VirtualFreeEx(process, buffer, 0, MEM_RELEASE);

	cout << "DLLInj: Trying to execute remote function\n";
	LPCWSTR param = L"MySimpleSyringe Injected!";
	DWORD paramLen = (wcslen(param) + 1) * sizeof(WCHAR);
	DWORD retcode = CallInjectedFunction(GetProcessId(process), moduleName, "TestFunction", paramLen, (LPVOID)param);
	cout << "the remote function returned code " << retcode << '\n';

	cout << "DLLInj: Trying clean up anything\n";

	freeEP = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "FreeLibrary");
	cout << "DLLInj: FreeLibrary proc address: " << freeEP << ", error code " << GetLastError() << '\n';
	if (!freeEP)
		return FALSE;

	CloseHandle(thread);

	CodeInjection_DLL_Unload(process, (HMODULE)ret);

	// thread = CreateRemoteThread(process, nullptr, 0, freeEP, (LPVOID)hmod, 0, &threadId);
	// cout << "DLLInj: Created unloader thread " << thread << " with thread id " << threadId << ", and error code " << GetLastError() << '\n';
	// if (!thread)
	// 	return FALSE;
	// 
	// WaitForSingleObject(thread, INFINITE);
	// 
	// GetExitCodeThread(thread, &hmod);
	// cout << "DLLInj: Library unloader success: " << hmod << '\n';

	CloseHandle(process);

	return TRUE;
}

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
	Code_DLLInjection(procinfo.hProcess, argv[2]);
	CloseHandle(procinfo.hProcess);

	return 0;
}