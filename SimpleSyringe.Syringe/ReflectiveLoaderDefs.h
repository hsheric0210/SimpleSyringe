#pragma once
#include "includes.h"

#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6

typedef ULONG_PTR(WINAPI *MyReflectiveLoader)(VOID);
typedef BOOL(WINAPI *MyDllMain)(HINSTANCE, DWORD, LPVOID);
