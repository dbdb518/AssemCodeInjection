#include <iostream>
#include "windows.h"
#include "stdio.h"

typedef struct _THREAD_PARAM
{
	FARPROC pFunc[2];
} THREAD_PARAM, *PTHREAD_PARAM;

BYTE g_InjectionCode[] = {
		0x55, 0x8B, 0xEC, 0x8B, 0x75, 0x08, 0x68, 0x6C, 0x6C, 0x00,
		0x00, 0x68, 0x33, 0x32, 0x2E, 0x64, 0x68, 0x75, 0x73, 0x65,
		0x72, 0x54, 0xFF, 0x16, 0x68, 0x6F, 0x78, 0x41, 0x00, 0x68,
		0x61, 0x67, 0x65, 0x42, 0x68, 0x4D, 0x65, 0x73, 0x73, 0x54,
		0x50, 0xFF, 0x56, 0x04, 0x6A, 0x00, 0xE8, 0x0C, 0x00, 0x00,
		0x00, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x43, 0x6F,
		0x72, 0x65, 0x00, 0xE8, 0x14, 0x00, 0x00, 0x00, 0x77, 0x77,
		0x77, 0x2E, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x63,
		0x6F, 0x72, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x6A, 0x00,
		0xFF, 0xD0, 0x33, 0xC0, 0x8B, 0xE5, 0x5D, 0xC3
};

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,           // lookup privilege on local system
		lpszPrivilege,  // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp, 
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}
	 
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

BOOL InjectCode(DWORD dwPID)
{
	HMODULE hMode = NULL;
	THREAD_PARAM param = { 0, };
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID pRemoteBuf[2] = { 0, };

	hMode = GetModuleHandleA("kernel32.dll");

	param.pFunc[0] = GetProcAddress(hMode, "LoadLibrary");
	param.pFunc[1] = GetProcAddress(hMode, "GetProcAddress");

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		printf("OpenProcess Error(%d)", GetLastError());
		return FALSE;
	}
		

	if (!(pRemoteBuf[0] = VirtualAllocEx(hProcess, NULL, sizeof(THREAD_PARAM), MEM_COMMIT, PAGE_READWRITE)))
	{
		printf("VirtualAllocEx(Parameter) Error(%d)", GetLastError());
		return FALSE;
	}

	if (!(WriteProcessMemory(hProcess, pRemoteBuf[0], (LPVOID)&param, sizeof(THREAD_PARAM), NULL)))
	{
		printf("WriteProcessMemory(Parameter) Error(%d)", GetLastError());
		return FALSE;
	}

	OutputDebugStringA("WriteProcessMemory(Parameter) - Success");


	if (!(pRemoteBuf[1] = VirtualAllocEx(hProcess, NULL, sizeof(g_InjectionCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		printf("VirtualAllocEx(Function) Error(%d)", GetLastError());
		return FALSE;
	}

	if (!(WriteProcessMemory(hProcess, pRemoteBuf[1], (LPVOID)&g_InjectionCode, sizeof(g_InjectionCode), NULL)))
	{
		printf("WriteProcessMemory(Function) Error(%d)", GetLastError());
		return FALSE;
	}

	OutputDebugStringA("WriteProcessMemory(Function) - Success");

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf[1], pRemoteBuf[0], 0, NULL)))
	{
		printf("CreateRemoteThread Error(%d)", GetLastError());
		return FALSE;
	}

	OutputDebugStringA("CreateRemoteThread - Success");

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

int main(int argc, char *argv[])
{
	DWORD dwPID = 0;

	if (argc < 2)
	{
		printf("\nUSAGE : %s <PID>\n", argv[0]);
		return -1;
	}

	if (!SetPrivilege(SE_DEBUG_NAME, TRUE)) return -1;


	dwPID = (DWORD)atol(argv[1]);
	
	if (InjectCode(dwPID)) 
	{
		printf("InjectCode Success.\n");
	}
	else
	{
		printf("InjectCode Failed.\n");
	}
}

