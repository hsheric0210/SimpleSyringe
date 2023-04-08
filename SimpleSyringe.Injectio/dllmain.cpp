// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#define DllExport extern "C" __declspec(dllexport)

DllExport DWORD TestFunction(LPWSTR message)
{
	LPWSTR concat = new WCHAR[1024];
	wsprintfW(concat, L"Test function called with message: %s", message); // this could cause buffer overflow, but i don't care cuz it is an test program
	MessageBoxW(nullptr, concat, L"TestFunction", MB_OK | MB_ICONINFORMATION);
	delete[] concat;
	return 1337;
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
			break;
	}
	return TRUE;
}

