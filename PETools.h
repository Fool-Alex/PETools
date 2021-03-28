#pragma once
#define WIN32_LEAN_AND_MEAN           // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
#include <windows.h>
// C 运行时头文件
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <commdlg.h>
#include <CommCtrl.h>
#include <Tlhelp32.h>
//各个模块的头文件
#include "resource.h"
#include "EnumProcessAndMoudle.h"
#include "ShowPE.h"
#include "AddShell.h"

//全局变量
extern HINSTANCE hAppInstance;
extern TCHAR szFileName[256];//打开的文件名
extern HWND hwndPEDialog;
extern HWND hDirDlg;
extern HWND hAddShellDlg;

//公用函数
extern DWORD ReadPEFile(IN LPSTR lpszFile, IN DWORD offset, OUT LPVOID* pFileBuffer);//读取文件
