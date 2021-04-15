#pragma once
#include <stdio.h>
#include <Windows.h>

#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

DWORD ReadPEFile(IN LPSTR lpszFile, IN DWORD offset, OUT LPVOID* pFileBuffer);//读取文件
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);//复制FileBuffer到ImageBuffer
void TcharToChar(const TCHAR* tchar, char* _char);//TCHAR数组转为CHAR数组
BOOL GetSrcInfo(LPVOID pFileBuffer, DWORD* SizeOfLastSec, DWORD* SrcImageBase, DWORD* SrcOEP, LPVOID* pSrcFileBuffer);//获取源文件的信息
PROCESS_INFORMATION CreateProcessSuspend(LPSTR processName);//以挂起的方式创建进程
DWORD UnmapShell(HANDLE hProcess, DWORD shellImageBase);//卸载进程内容
CONTEXT GetThreadContext(HANDLE hThread);//获取线程Context信息
LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t);//创建内存到指定位置
DWORD GetProcessImageBase(PROCESS_INFORMATION procInfo);//获取进程基址
CONTEXT GetThreadContext(HANDLE hThread);//获取线程Context信息
LPVOID Xor(IN LPVOID pBuffer, DWORD size);//异或解密源文件