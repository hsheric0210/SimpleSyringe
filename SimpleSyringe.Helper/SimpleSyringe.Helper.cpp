// SimpleSyringe.Helper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>

#define OBSCURED_GETPROCADDRESS_NAME "GetProcAddressSilentObscured"
#define XOR_KEY 'G'

int main()
{
	using namespace std;
	cout << "Type function call to XOR encrypt, in following format: <LIB>!<FUNC>\n";
	cout << "Example: user32.dll!MessageBoxW\n";
	LPSTR inBuffer = new CHAR[4096];
	LPSTR procName = new CHAR[4096];
	while (1)
	{
		cin.getline(inBuffer, 4096);
		LPSTR dllName = strtok_s(inBuffer, "!", &procName);
		if (!procName[0])
		{
			cout << "Invalid syntax.\n";
			continue;
		}
		cout << "DLL name: '" << dllName << "'\n";
		cout << "Proc name: '" << procName << "'\n";

		LPSTR hexConvBuffer = new CHAR[4096]{ 0 };
		LPSTR dllNameHex = new CHAR[16384]{ 0 };
		LPSTR procNameHex = new CHAR[16384]{ 0 };
		size_t dllLen = strlen(dllName);
		size_t procLen = strlen(procName);
		int i;
		for (i = 0; i < dllLen; i++)
			dllName[i] ^= XOR_KEY;
		for (i = 0; i < dllLen; i++)
		{
			sprintf_s(hexConvBuffer, 4096, "\\x%02X", dllName[i]);
			strcat_s(dllNameHex, 16384, hexConvBuffer);
		}
		for (i = 0; i < procLen; i++)
			procName[i] ^= XOR_KEY;
		for (i = 0; i < procLen; i++)
		{
			sprintf_s(hexConvBuffer, 4096, "\\x%02X", procName[i]);
			strcat_s(procNameHex, 16384, hexConvBuffer);
		}
		sprintf_s(inBuffer, 16384, "%s(%zd, L\"%s\", %zd, \"%s\")", OBSCURED_GETPROCADDRESS_NAME, dllLen, dllNameHex, procLen, procNameHex);
		cout << inBuffer << '\n';
		delete[] hexConvBuffer;
		delete[] dllNameHex;
		delete[] procNameHex;
	}
	delete[] inBuffer;
	delete[] procName;
	return 0;
}
