#pragma once
#include "PETools.h"

void InitListView(HWND hwndDlg);//初始化ListView
void ShowInfo(HWND hListShell, LPWSTR string);//输出信息到ListView

BOOL CALLBACK AddShellDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
);