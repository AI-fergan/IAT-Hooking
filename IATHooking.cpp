#include "pch.h"
#include "hook.h"

#define LEN 20
#define FILENAME "file.txt"

int main() {
	//create file data
	HANDLE hFile;
	CHAR buffer[LEN];
	DWORD num;
	LPDWORD numread = &num;

	//hook data
	PCSTR func_to_hook = "CreateFileA";
	PCSTR DLL_to_hook = "KERNEL32.dll";
	_IMAGE_THUNK_DATA64 new_entry_data;
	new_entry_data.u1.Function = (ULONGLONG)&ShowMsgHook;

	//hook CreateFileA function by its LOOKUP NAME with the ShowMsgHook function addr
	hook(func_to_hook, DLL_to_hook, new_entry_data);

	//open file Handler
	hFile = CreateFileA(FILENAME,   // file name
		GENERIC_READ,           // open for read
		0,                      // do not share
		NULL,                   // default security
		OPEN_EXISTING,          // open only if exists
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	//check if the file opened correctly
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		printf("Error code: %d\n", error);
		return 0;
	}

	//read file content (LEN bytes)
	BOOL result = ReadFile(hFile,   // handle to open file
		buffer,						// pointer to buffer to store data
		LEN - 1,					// bytes to read
		numread,					// return value - bytes actually read
		NULL);						// overlapped
	buffer[*numread] = 0;

	//print file content
	cout << buffer << endl;

	//close file Handler
	CloseHandle(hFile);

	return 0;
};
