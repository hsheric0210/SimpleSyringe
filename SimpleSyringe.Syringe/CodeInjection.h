#pragma once
#include "includes.h"
DWORD CodeInjection(HANDLE process, size_t codeSize, FARPROC code, size_t funcParamSize, LPVOID funcParam);
