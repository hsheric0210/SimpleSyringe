// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

DWORD WINAPI tp(LPVOID lp)
{
	MessageBoxA(nullptr, "Injectio", "P Hello, world!", 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
		case DLL_PROCESS_ATTACH:
			HANDLE ht = CreateThread(nullptr, 0, tp, nullptr, 0, nullptr);
			CloseHandle(ht);
			break;
	}
	return TRUE;
}

