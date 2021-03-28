#include "AddShell.h"

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
		/*switch (LOWORD(wParam))
		{
		case IDC_BUTTON_SECTION:
		{
			DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_Section), hwndDlg, SectionTableDlg);
			return TRUE;
		}
		case IDC_BUTTON_CLOSEPE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		case IDC_BUTTON_DATADIR:
		{
			DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DIRECTORY), hwndDlg, DirectoryDlg);
			return TRUE;
		}
		}*/
		break;
	}
	}
	return FALSE;
}

//初始化ListView
void InitListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListShell;
	//初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	//获取IDC_LIST_ShowShell句柄
	hListShell = GetDlgItem(hwndDlg, IDC_LIST_ShowShell);
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
}