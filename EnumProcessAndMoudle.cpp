#include "EnumProcessAndMoudle.h"

//遍历进程
void EnumProcess(HWND hListProcess)
{
	LV_ITEM vitem;
	//初始化						
	memset(&vitem, 0, sizeof(LV_ITEM));
	vitem.mask = LVIF_TEXT;
	//遍历进程
	//创建进程快照
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);
	int Item = 0;
	if (hSnapshot != INVALID_HANDLE_VALUE && Process32First(hSnapshot, &pe))
	{
		do
		{
			vitem.pszText = pe.szExeFile;
			vitem.iItem = Item;
			vitem.iSubItem = 0;
			//ListView_InsertItem(hListProcess, &vitem);						
			SendMessage(hListProcess, LVM_INSERTITEM, 0, (DWORD)&vitem);


			//将PID转换为TCHAR数组
			wsprintf(vitem.pszText, L"%d", pe.th32ProcessID);
			vitem.iItem = Item;
			vitem.iSubItem = 1;
			ListView_SetItem(hListProcess, &vitem);

			wsprintf(vitem.pszText, L"%d", pe.pcPriClassBase);
			vitem.iItem = Item;
			vitem.iSubItem = 2;
			ListView_SetItem(hListProcess, &vitem);

			wsprintf(vitem.pszText, L"%d", pe.cntThreads);
			vitem.iItem = Item;
			vitem.iSubItem = 3;
			ListView_SetItem(hListProcess, &vitem);

			Item++;
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
}


//遍历模块
void EnumMoudle(HWND hListProcess, HWND hListModules)
{
	DWORD dwRowid;
	wchar_t szPid[0x20] = { 0 };
	LV_ITEM lv;
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	DWORD dwPid = 0;
	int Item = 0;
	//初始化						
	memset(&lv, 0, sizeof(LV_ITEM));
	memset(szPid, 0, 0x20);
	//获取选择行
	dwRowid = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowid == -1)
	{
		MessageBox(NULL, TEXT("请选择进程"), TEXT("ERROR"), MB_OK);
		return;
	}

	// 清空所有数据行
	ListView_DeleteAllItems(hListModules);

	//获取PID
	lv.iSubItem = 1;
	lv.pszText = szPid;
	lv.cchTextMax = 0x20;
	SendMessage(hListProcess, LVM_GETITEMTEXT, (WPARAM)dwRowid, (LPARAM)&lv);

	//将PID转换为DWORD
	swscanf_s(szPid, L"%d", &dwPid);

	// 1. 创建一个模块相关的快照句柄
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);


	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return;
	}
	MODULEENTRY32 mo;
	mo.dwSize = sizeof(MODULEENTRY32);

	// 2. 通过模块快照句柄获取第一个模块信息
	if (Module32First(hModuleSnap, &mo))
	{
		//3. 遍历模块
		do
		{
			lv.pszText = mo.szModule;
			lv.iItem = Item;
			lv.iSubItem = 0;
			//ListView_InsertItem(hListProcess, &vitem);						
			SendMessage(hListModules, LVM_INSERTITEM, 0, (DWORD)&lv);

			lv.pszText = mo.szExePath;
			lv.iItem = Item;
			lv.iSubItem = 1;
			ListView_SetItem(hListModules, &lv);

			Item++;
		} while (Module32Next(hModuleSnap, &mo));
	}

	CloseHandle(hModuleSnap);
	return;
}

//初始化进程的ListControl
void InitProcessListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;
	//初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);
	//设置整行选中
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	//第一列								
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("进程");		//列标题				
	lv.cx = 205;					//列宽
	lv.iSubItem = 0;				//第几列
	ListView_InsertColumn(hListProcess, 0, &lv);//该宏等价于下面的SendMessage										
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	//第二列								
	lv.pszText = TEXT("PID");
	lv.cx = 64;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess, 1, &lv);
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	//第三列								
	lv.pszText = TEXT("线程优先级");
	lv.cx = 110;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess, 2, &lv);
	//第四列								
	lv.pszText = TEXT("线程数");
	lv.cx = 110;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess, 3, &lv);
	EnumProcess(hListProcess);
}

//初始化模块的ListControl
void InitMoudleListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;
	//初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS2);
	//设置整行选中
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	//第一列								
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("模块名称");		//列标题				
	lv.cx = 180;						//列宽
	lv.iSubItem = 0;					//第几列
	ListView_InsertColumn(hListProcess, 0, &lv);//该宏等价于下面的SendMessage										
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	//第二列								
	lv.pszText = TEXT("模块位置");
	lv.cx = 326;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess, 1, &lv);
}