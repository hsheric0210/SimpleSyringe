#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

BOOL Go_Injection(DWORD hwPID, LPCSTR DllPath)
{
	HANDLE hProcess = NULL;		//프로세스 핸들 
	HANDLE hThread = NULL;		//쓰레드 핸들
	HMODULE hMod = NULL;		//모듈 핸들

	LPVOID pRemoteBuf = NULL;	//DLL경로를 기록한 메모리 주소를 넣을 포인터변수

	//쓰레드 시작 루틴 함수주소를 저장할 변수
	LPTHREAD_START_ROUTINE pThreadProc;

	//인젝션 할 프로세스 제어권 얻기
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hwPID);
	printf(" [+] 프로세스의 핸들(hProcess) : %d\n", hProcess);
	printf(" [+] openp LastError : %d\n", GetLastError());

	//DLL경로의 길이 얻기
	DWORD dwBufSize = (DWORD)(strlen(DllPath) + 1);// *sizeof(TCHAR);
	printf(" [+] DLL의 길이 : %d byte\n", dwBufSize);

	//인젝션 할 DLL 경로를 해당 프로세스에 기록
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf(" [+] alloc LastError : %d\n", GetLastError());
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)DllPath, dwBufSize, NULL);
	printf(" [+] 인젝션할 프로세스 내 할당받은 메모리주소 : 0x%p\n", pRemoteBuf);
	printf(" [+] 할당받은 주소에 작성할 DLL의 경로 : %s\n", DllPath);
	printf(" [+] write LastError : %d\n", GetLastError());

	//Write한 DLL을 프로세스에서 로드하기 위한 작업
	hMod = GetModuleHandleA("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	printf(" [+] 스레드의 시작주소(LoadLibrary) : 0x%p\n", pThreadProc);
	printf(" [+] LastError : %d\n", GetLastError());

	//Write한 DLL을 인젝션할 프로세스에 스레드 생성 후 스레드의 시작주소로 LoadLibraryA를 지정
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	printf(" [+] 인젝션한 프로세스에서 실행한 스레드 식별자 : %d\n", hThread);
	printf(" [+] LastError : %d\n", GetLastError());


	//쓰레드가 실행될 때까지 무한정 대기
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 1;
}

int main(int argc, CHAR *argv[])
{
	if (argc != 3)
	{
		printf(" [-] Usage : %s [Process_Name] [DLL_Path] \n", argv[0]);
		//argv[0] = 인젝션시킬프로그램,  argv[1] = 인젝션할 프로세스이름, argv[2]  = dll경로
		return 0;
	}

	DWORD dwPID = 0xFFFFFFFF;		//PID = -1

	HWND hWnd = FindWindowA(NULL, argv[1]);
	printf(" [+] 프로세스의 창 번호(hWnd) : %d\n", hWnd);

	GetWindowThreadProcessId(hWnd, &dwPID);
	printf(" [+] 프로세스 식별자(PID) : %d\n", dwPID);

	//Go_Injection 함수의 인자로 PID와 DLL의 경로를 넘겨줌
	//Go_Injection함수 정상동작 시 True반환
	BOOL flag = Go_Injection(dwPID, argv[2]);

	//if (flag) {
	//	printf(" [+] Success \n");
	//}
	//else {
	//	printf(" [-] Fail\n");
	//}

	return 0;
}