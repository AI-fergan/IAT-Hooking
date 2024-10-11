// IAT Hooking, Barak Gonen Aug 2020

#include "pch.h"

#define LEN 20
#define FILENAME "file.txt"

int main()
{
	HANDLE hFile;
	CHAR buffer[LEN];
	DWORD num;
	LPDWORD numread = &num;

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

	//PRINT FILE CONTENT
	printf("%s\n", buffer);

	//close file Handler
	CloseHandle(hFile);

	return 0;
};
