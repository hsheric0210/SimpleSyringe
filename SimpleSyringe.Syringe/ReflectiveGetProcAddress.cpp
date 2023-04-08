#include "ReflectiveGetProcAddress.h"

// We implement a minimal GetProcAddress to avoid using the native kernel32!GetProcAddress which
// wont be able to resolve exported addresses in reflectivly loaded librarys.
// How I can use this? If someone know the answer, please tell me.
FARPROC WINAPI GetProcAddressR(HANDLE moduleHandle, LPCSTR procName)
{
	using namespace std;
	FARPROC procResult = nullptr;

	if (!moduleHandle)
	{
		std::cout << "[GetProcAddressR] Invalid module handle\n";
		return nullptr;
	}

	// a module handle is really its base address
	UINT_PTR moduleBase = (UINT_PTR)moduleHandle;

	__try
	{
		cout << "[GetProcAddressR] Base address " << (PVOID)moduleBase << '\n';

		// get the VA of the modules NT Header
		auto ntHeader = (PIMAGE_NT_HEADERS)(moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
		cout << "[GetProcAddressR] NT header " << ntHeader << '\n';

		auto exportDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// get the VA of the export directory
		auto exportDirectoryVA = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + exportDirectory->VirtualAddress);
		cout << "[GetProcAddressR] Exports directory VA " << exportDirectoryVA << '\n';

		// get the VA for the array of addresses
		UINT_PTR addresses = (moduleBase + exportDirectoryVA->AddressOfFunctions);
		cout << "[GetProcAddressR] Export proc address begin " << addresses << '\n';

		// get the VA for the array of name pointers
		UINT_PTR names = (moduleBase + exportDirectoryVA->AddressOfNames);
		cout << "[GetProcAddressR] Export proc name begin " << exportDirectoryVA << '\n';

		// get the VA for the array of name ordinals
		UINT_PTR nameOrdinals = (moduleBase + exportDirectoryVA->AddressOfNameOrdinals);
		cout << "[GetProcAddressR] Export proc name ordinal begin " << exportDirectoryVA << '\n';

		// test if we are importing by name or by ordinal...
		if (!((DWORD_PTR)procName >> 16))
		{
			cout << "[GetProcAddressR] By-ordinal\n";
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			addresses += ((IMAGE_ORDINAL((DWORD)procName) - exportDirectoryVA->Base) * sizeof(DWORD));

			// resolve the address for this imported function
			procResult = (FARPROC)(moduleBase + DEREF_32(addresses));
		}
		else
		{
			cout << "[GetProcAddressR] By-name\n";
			// import by name...
			DWORD nameCount = exportDirectoryVA->NumberOfNames;
			cout << "[GetProcAddressR] Available names " << nameCount << '\n';
			while (nameCount--)
			{
				auto funcName = (PSTR)(moduleBase + DEREF_32(names));
				cout << "[GetProcAddressR] Found func: " << funcName << '\n';

				// test if we have a match...
				if (!strcmp(funcName, procName))
				{
					// use the functions name ordinal as an index into the array of name pointers
					addresses += (DEREF_16(nameOrdinals) * sizeof(DWORD));

					// calculate the virtual address for the function
					procResult = (FARPROC)(moduleBase + DEREF_32(addresses));

					// finish...
					break;
				}

				// get the next exported function name
				names += sizeof(DWORD);

				// get the next exported function name ordinal
				nameOrdinals += sizeof(WORD);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		std::cout << "[GetProcAddressR] Exception occurred.\n";
		procResult = nullptr;
	}

	return procResult;
}
