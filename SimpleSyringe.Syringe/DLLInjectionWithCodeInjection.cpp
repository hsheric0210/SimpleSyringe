#include "DLLInjectionWithCodeInjection.h"

DWORD CodeInj_DllLoad(LPVOID lpParam)
{
	PCODEINJ_DLL_LOAD_PARAM param = reinterpret_cast<PCODEINJ_DLL_LOAD_PARAM>(lpParam);
	HMODULE usr32 = ((myLoadLibrary)param->procs[0])(param->wliterals[0]); // load user32.dll
	HMODULE mod = ((myLoadLibrary)param->procs[0])(param->wliterals[1]); // load my dll
	LPVOID mem = ((myVirtualAlloc)param->procs[2])(nullptr, 16384, MEM_COMMIT, PAGE_READWRITE); // allocate memory

	((mywsprintfW)(((myGetProcAddress)param->procs[1])(usr32, param->aliterals[0])))((LPWSTR)mem, param->wliterals[2], mod);
	((MyMessageBoxW)(((myGetProcAddress)param->procs[1])(usr32, param->aliterals[1])))(nullptr, (LPCWSTR)mem, param->wliterals[3], 0); // print module handle
	((myVirtualFree)param->procs[3])(mem, 0, MEM_RELEASE);

	return (DWORD)mod; // We can't use return value because on 64-bit systems, we'll hit a pointer truncation problem
	// We should try different way.
}

void CodeInj_DllLoad_End()
{}

DWORD CodeInj_DllUnload(LPVOID lpParam)
{
	PCODEINJ_DLL_UNLOAD_PARAM param = reinterpret_cast<PCODEINJ_DLL_UNLOAD_PARAM>(lpParam);
	((myFreeLibrary)param->funcs[0])((HMODULE)param->moduleBase);
	return ((myGetLastError)param->funcs[1])();
}

void CodeInj_DllUnload_End()
{}

DWORD CodeInjection_DLL_Load(HANDLE process, LPCWSTR dll)
{
	HMODULE krnl32 = LoadLibraryW(L"kernel32.dll");
	CODEINJ_DLL_LOAD_PARAM param = { 0 };
	param.procs[0] = GetProcAddress(krnl32, "LoadLibraryW");
	param.procs[1] = GetProcAddress(krnl32, "GetProcAddress");
	param.procs[2] = GetProcAddress(krnl32, "VirtualAlloc");
	param.procs[3] = GetProcAddress(krnl32, "VirtualFree");
	strcpy_s(param.aliterals[0], 256, "wsprintfW");
	strcpy_s(param.aliterals[1], 256, "MessageBoxW");

	wcscpy_s(param.wliterals[0], 1024, L"user32.dll");
	wcscpy_s(param.wliterals[1], 1024, dll);
	wcscpy_s(param.wliterals[2], 1024, L"DLL loaded at memory 0x%p");
	wcscpy_s(param.wliterals[3], 1024, L"DLL-Injection by Code Injection");

	//DWORD size = (DWORD)CodeInj_DllLoad_End - (DWORD)CodeInj_DllLoad; // This sometimes returns very big value
	DWORD size = 32768;
	return CodeInjection(process, size, (FARPROC)CodeInj_DllLoad, sizeof(CODEINJ_DLL_LOAD_PARAM), (LPVOID)&param);
}

DWORD CodeInjection_DLL_Unload(HANDLE process, ULONGLONG moduleBase)
{
	HMODULE krnl32 = LoadLibraryW(L"kernel32.dll");
	CODEINJ_DLL_UNLOAD_PARAM param = { 0 };
	param.funcs[0] = GetProcAddress(krnl32, "FreeLibrary");
	param.funcs[1] = GetProcAddress(krnl32, "GetLastError");
	param.moduleBase = moduleBase;

	//DWORD size = (DWORD)CodeInj_DllUnload_End - (DWORD)CodeInj_DllUnload;
	DWORD size = 16384;
	return CodeInjection(process, size, (FARPROC)CodeInj_DllUnload, sizeof(CODEINJ_DLL_UNLOAD_PARAM), (LPVOID)&param);
}

BOOL Code_DLLInjection(DWORD pid, HANDLE process, LPWSTR moduleName)
{
	using namespace std;
	cout << "[DLLInj w/ CodeInj] Trying to inject...\n";
	CodeInjection_DLL_Load(process, moduleName);
	cout << "[DLLInj w/ CodeInj] DLL loaded\n";

	LPCWSTR param = L"SimpleSyringe injected using Code-injection driven DLL-injection!";
	DWORD paramLen = (wcslen(param) + 1) * sizeof(WCHAR);
	DWORD retcode = CallInjectedFunc(pid, moduleName, "TestFunction", paramLen, (LPVOID)param);
	cout << "[DLLInj w/ CodeInj] Execution of remote function finished with code " << retcode << '\n';

	// 64 비트 시스템에서는 포인터도 64 비트이다.
	// 이말즉은, HMODULE도 64 비트이고, 쓰레드의 종료 코드는 항상 DWORD(32 비트)이기에 앞쪽이 잘려나가 제대로 된 모듈 핸들이 아니게 된다.
	// 굳이 FreeLibrary를 하고 싶으면, FindModule로 모듈을 찾은 뒤 하는 것이 가장 간단하다.
	//CodeInjection_DLL_Unload(process, (HMODULE)ret);
	MODULEENTRY32W mEntry = { 0 };
	if (FindModule(pid, moduleName, &mEntry))
	{
		cout << "[DLLInj w/ CodeInj] Injected module found. Trying to unload...\n";
		CodeInjection_DLL_Unload(process, (ULONGLONG)mEntry.modBaseAddr);
	}

	return TRUE;
}
