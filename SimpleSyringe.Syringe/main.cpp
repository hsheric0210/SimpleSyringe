#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

BOOL Go_Injection(DWORD hwPID, LPCSTR DllPath)
{
	HANDLE hProcess = NULL;		//���μ��� �ڵ� 
	HANDLE hThread = NULL;		//������ �ڵ�
	HMODULE hMod = NULL;		//��� �ڵ�

	LPVOID pRemoteBuf = NULL;	//DLL��θ� ����� �޸� �ּҸ� ���� �����ͺ���

	//������ ���� ��ƾ �Լ��ּҸ� ������ ����
	LPTHREAD_START_ROUTINE pThreadProc;

	//������ �� ���μ��� ����� ���
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hwPID);
	printf(" [+] ���μ����� �ڵ�(hProcess) : %d\n", hProcess);
	printf(" [+] openp LastError : %d\n", GetLastError());

	//DLL����� ���� ���
	DWORD dwBufSize = (DWORD)(strlen(DllPath) + 1);// *sizeof(TCHAR);
	printf(" [+] DLL�� ���� : %d byte\n", dwBufSize);

	//������ �� DLL ��θ� �ش� ���μ����� ���
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf(" [+] alloc LastError : %d\n", GetLastError());
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)DllPath, dwBufSize, NULL);
	printf(" [+] �������� ���μ��� �� �Ҵ���� �޸��ּ� : 0x%p\n", pRemoteBuf);
	printf(" [+] �Ҵ���� �ּҿ� �ۼ��� DLL�� ��� : %s\n", DllPath);
	printf(" [+] write LastError : %d\n", GetLastError());

	//Write�� DLL�� ���μ������� �ε��ϱ� ���� �۾�
	hMod = GetModuleHandleA("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	printf(" [+] �������� �����ּ�(LoadLibrary) : 0x%p\n", pThreadProc);
	printf(" [+] LastError : %d\n", GetLastError());

	//Write�� DLL�� �������� ���μ����� ������ ���� �� �������� �����ּҷ� LoadLibraryA�� ����
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	printf(" [+] �������� ���μ������� ������ ������ �ĺ��� : %d\n", hThread);
	printf(" [+] LastError : %d\n", GetLastError());


	//�����尡 ����� ������ ������ ���
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
		//argv[0] = �����ǽ�ų���α׷�,  argv[1] = �������� ���μ����̸�, argv[2]  = dll���
		return 0;
	}

	DWORD dwPID = 0xFFFFFFFF;		//PID = -1

	HWND hWnd = FindWindowA(NULL, argv[1]);
	printf(" [+] ���μ����� â ��ȣ(hWnd) : %d\n", hWnd);

	GetWindowThreadProcessId(hWnd, &dwPID);
	printf(" [+] ���μ��� �ĺ���(PID) : %d\n", dwPID);

	//Go_Injection �Լ��� ���ڷ� PID�� DLL�� ��θ� �Ѱ���
	//Go_Injection�Լ� ������ �� True��ȯ
	BOOL flag = Go_Injection(dwPID, argv[2]);

	//if (flag) {
	//	printf(" [+] Success \n");
	//}
	//else {
	//	printf(" [-] Fail\n");
	//}

	return 0;
}