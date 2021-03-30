#pragma once
#include "PETools.h"

void InitListView(HWND hwndDlg);//初始化ListView
void ShowInfo(LPWSTR string);//输出信息到ListView
DWORD Align(DWORD Num, DWORD Ali);//返回对齐后的值
BOOL MeneryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);//将内存中的数据写入硬盘中
VOID AddSection(LPVOID pSourceBuffer, DWORD SourceSize, LPVOID pAddBuffer, DWORD AddSize);//添加新节

BOOL CALLBACK AddShellDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
);