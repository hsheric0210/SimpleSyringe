// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "ReflectiveLoaderDefs.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_ATTACH:
		{
			LPWSTR concat = new WCHAR[1024];
			wsprintfW(concat, L"Test function called with message: %s", (LPWSTR)lpReserved); // this could cause buffer overflow, but i don't care cuz it is an test program
			MessageBoxW(nullptr, concat, L"TestFunction", MB_OK | MB_ICONINFORMATION);
			delete[] concat;
			break;
		}
		case DLL_QUERY_HMODULE:
		{
			if (lpReserved)
				*(HMODULE *)lpReserved = hModule;
			break;
		}
	}
	return TRUE;
}

