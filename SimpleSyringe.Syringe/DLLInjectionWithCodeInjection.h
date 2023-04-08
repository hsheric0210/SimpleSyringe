#pragma once
#include "includes.h"
#include "CodeInjection.h"
#include "CallInjectedFunc.h"
#include "utils.h"

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
	FARPROC procs[4];

	// Code Injection ��, �ش� �Լ� ������ �ڵ带 ������ �� � ���ͷ��� ������ �� ����. ���ڿ� ���ͷ� ("", L"")�� ���⿡ ���Ե�.
	CHAR aliterals[2][256];
	WCHAR wliterals[5][1024];
} CODEINJ_DLL_LOAD_PARAM, *PCODEINJ_DLL_LOAD_PARAM;

typedef struct _CODEINJ_DLL_UNLOAD_PARAM
{
	// 0 - FreeLibrary
	// 1 - GetLastError
	FARPROC funcs[2];
	ULONGLONG moduleBase;
} CODEINJ_DLL_UNLOAD_PARAM, *PCODEINJ_DLL_UNLOAD_PARAM;


DWORD CodeInj_DllLoad(LPVOID lpParam);
void CodeInj_DllLoad_End();

DWORD CodeInj_DllUnload(LPVOID lpParam);
void CodeInj_DllUnload_End();


BOOL Code_DLLInjection(DWORD pid, HANDLE process, LPWSTR moduleName);