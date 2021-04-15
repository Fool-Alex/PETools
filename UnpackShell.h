#pragma once
#include "PETools.h"

BOOL CALLBACK UnpackShellDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
);

void InitUnpackListView(HWND hwndDlg);//初始化listControl
VOID Unpacking(LPVOID pShellBuffer, DWORD ShellSize, LPVOID* pSourceFileBuffer, DWORD* SourceFileSize);//从最后的节提取源文件
void ShowInfoUnpack(LPWSTR string);//输出信息