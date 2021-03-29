#include "AddShell.h"

HWND hListShell;
int Item = 0;

BOOL CALLBACK AddShellDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
)
{
	//为全局变量赋值
	hAddShellDlg = hwndDlg;
	OPENFILENAME stOpenFile;
	TCHAR string[256];
	switch (uMsg)
	{
	case  WM_INITDIALOG:
	{
		InitListView(hwndDlg);
		break;
	}

	case  WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
		break;
	}

	case  WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_Src:
		{
			TCHAR szPeFileExt[100] = L"*.exe;*.dll;*.scr;*.drv;*.sys";
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
				ShowInfo(hListShell, TEXT("选取源程序成功！"));
				//将源程序显示到EditControl
				SetEditText(hListShell, IDC_EDIT_Src, szFileName);
			}
			else
			{
				ShowInfo(hListShell, TEXT("选取源程序失败！请重试！"));
				return TRUE;
			}
			return TRUE;
		}
		case IDC_BUTTON_CLOSEPE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		case IDC_BUTTON_AddShell:
		{
			memset(string, 0, sizeof(string));
			GetEditText(hListShell, IDC_EDIT_Src, string);
			if (lstrcmp(string, szFileName))
			{
				ShowInfo(hListShell, TEXT("开始加壳！"));

			}
			else
			{
				ShowInfo(hListShell, TEXT("请先选择源程序，再加壳！"));
				return TRUE;
			}
			return TRUE;
		}
		}
		break;
	}
	}
	return FALSE;
}

//初始化ListView
void InitListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	//初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	//获取IDC_LIST_ShowShell句柄
	hListShell = GetDlgItem(hwndDlg, IDC_LIST_ShowShell);
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("输出信息");		//列标题				
	lv.cx = 564;					//列宽
	lv.iSubItem = 0;				//第几列
	ListView_InsertColumn(hListShell, 0, &lv);//该宏等价于下面的SendMessage				
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	ShowInfo(hListShell, TEXT("请选择需要加壳的源程序！"));
}

//输出信息到ListView
void ShowInfo(HWND hListShell, LPWSTR string)
{
	LV_ITEM vitem;
	//初始化						
	memset(&vitem, 0, sizeof(LV_ITEM));
	vitem.mask = LVIF_TEXT;
	vitem.pszText = string;
	vitem.iItem = Item;
	vitem.iSubItem = 0;
	SendMessage(hListShell, LVM_INSERTITEM, 0, (DWORD)&vitem);
	Item++;
}