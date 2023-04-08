#pragma once
#include "includes.h"
typedef DWORD(WINAPI *TestFunction)(LPVOID message);
BOOL Reflective_DLLInjection(DWORD pid, HANDLE process, LPWSTR moduleName);