// PETools.cpp : 定义应用程序的入口点。
#include "PETools.h"

// 全局变量:
HINSTANCE hAppInstance;
HWND hwndPEDialog;
HWND hDirDlg;
HWND hAddShellDlg;
TCHAR szFileName[256];//打开的文件名
char pwd[256];//当前工作目录


BOOL CALLBACK AboutDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
)//关于界面的回调函数
{
	switch (uMsg)
	{
	case  WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}
	}
	return FALSE;
}

BOOL CALLBACK MainDlgProc(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
)//主界面的回调函数
{
	HICON hBigIcon;
	HICON hSmallIcon;
	OPENFILENAME stOpenFile;

	switch (uMsg)
	{
	case  WM_INITDIALOG:
	{
		hBigIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_APP));
		hSmallIcon = LoadIcon(hAppInstance, MAKEINTRESOURCE(IDI_ICON_APP));
		SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (DWORD)hBigIcon);
		SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (DWORD)hSmallIcon);
		InitProcessListView(hwndDlg);
		InitMoudleListView(hwndDlg);
		GetCurrentDirectoryA(sizeof(pwd), pwd);
		return TRUE;
	}

	case  WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	case WM_NOTIFY:
	{
		NMHDR* pNMHER = (NMHDR*)lParam;
		if (wParam == IDC_LIST_PROCESS && pNMHER->code == NM_CLICK)
		{
			EnumMoudle(GetDlgItem(hwndDlg, IDC_LIST_PROCESS), GetDlgItem(hwndDlg, IDC_LIST_PROCESS2));
		}
		break;
	}

	case  WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case   IDC_BUTTON_SHOWPE:
		{
			TCHAR szPeFileExt[100] = L"*.exe;*.dll;*.ocx;*.drv;*.sys";
			memset(szFileName, 0, sizeof(szFileName));
			memset(&stOpenFile, 0, sizeof(OPENFILENAME));
			stOpenFile.lStructSize = sizeof(OPENFILENAME);
			stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			stOpenFile.hwndOwner = hwndDlg;
			stOpenFile.lpstrFilter = szPeFileExt;
			stOpenFile.lpstrFile = szFileName;
			stOpenFile.nMaxFile = MAX_PATH;

			GetOpenFileName(&stOpenFile);
			if (*szFileName)
			{
				//打开新的对话框
				DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_PE), hwndDlg, PEDlg);
			}
			else
			{
				return TRUE;
			}
			return TRUE;
		}
		case   IDC_BUTTON_AddShellMeau:
		{
			DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_AddShell), hwndDlg, AddShellDlg);
			return TRUE;
		}
		case   IDC_BUTTON_ABOUT:
		{
			DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_ABOUTBOX), hwndDlg, AboutDlg);
			return TRUE;
		}

		case   IDC_BUTTON_EXIT:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		}
		break;
	}
	}
	return FALSE;
}


int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR    lpCmdLine,
                     int       nCmdShow)
{
	hAppInstance = hInstance;
	DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDlgProc);//初始化主界面
    return 0;
}
