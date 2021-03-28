#pragma once
#include "PETools.h"

DWORD ReadPEFile(IN LPSTR lpszFile, IN DWORD offset, OUT LPVOID* pFileBuffer);//读取文件
void SetEditText(HWND hDlg, int dwEditId, TCHAR* text);//设置Edit Control控件的内容
void TcharToChar(const TCHAR* tchar, char* _char);//TCHAR数组转为CHAR数组
void ShowDirectory(HWND HwndDirectoryDlg);//显示数据目录
void ShowSectionTable(HWND hListProcess);//获取PE区块信息
void GetPEHeader(IN LPSTR lpszFile);//获取PE头信息
void InitSectionTableListView(HWND hwndDlg);//初始化区段表的List Control
BOOL CALLBACK PEDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
);
BOOL CALLBACK SectionTableDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
);
BOOL CALLBACK DirectoryDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
);