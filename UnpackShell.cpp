#include "UnpackShell.h"

HWND hListUnpack;
int Count = 0;

BOOL CALLBACK UnpackShellDlg(
	HWND hwndDlg,  // handle to dialog box			
	UINT uMsg,     // message						
	WPARAM wParam, // first message parameter			
	LPARAM lParam  // second message parameter			
)
{
	//为全局变量赋值
	hUnpackShellDlg = hwndDlg;
	HWND UnpackShellButton = GetDlgItem(hUnpackShellDlg, IDC_BUTTON_UnpackShell);
	OPENFILENAME stOpenFile;
	CHAR SrcPathA[256];
	switch (uMsg)
	{
	case  WM_INITDIALOG:
	{
		InitUnpackListView(hwndDlg);
		EnableWindow(UnpackShellButton, FALSE);
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
		case IDC_BUTTON_UnpackSrc:
		{
			TCHAR szPeFileExt[100] = L"*.exe;*.dll;*.ocx;*.sys";
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
				TCHAR drive[_MAX_DRIVE];
				TCHAR dir[_MAX_DIR];
				TCHAR fname[_MAX_FNAME];
				TCHAR ext[_MAX_EXT];
				_wsplitpath(szFileName, drive, dir, fname, ext);
				//判断后缀是否为合法文件
				if (!wcscmp(ext, L".exe") || !wcscmp(ext, L".dll") || !wcscmp(ext, L".ocx") || !wcscmp(ext, L".sys"))
				{
					ShowInfoUnpack(TEXT("选取程序成功！"));
					//将源程序显示到EditControl
					SetEditText(hUnpackShellDlg, IDC_EDIT_UnpackSrc, szFileName);
					EnableWindow(UnpackShellButton, TRUE);
				}
				else
				{
					ShowInfoUnpack(TEXT("选取的程序格式有误！请重新选取！"));
					SetEditText(hUnpackShellDlg, IDC_EDIT_UnpackSrc, TEXT(""));
					EnableWindow(UnpackShellButton, FALSE);
				}
			}
			else
			{
				ShowInfoUnpack(TEXT("选取程序失败！请重试！"));
				SetEditText(hUnpackShellDlg, IDC_EDIT_UnpackSrc, TEXT(""));
				EnableWindow(UnpackShellButton, FALSE);
				return TRUE;
			}
			return TRUE;
		}
		case IDC_BUTTON_CLOSEPE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		case IDC_BUTTON_UnpackShell:
		{
			//开始脱壳
			ShowInfoUnpack(TEXT("开始脱壳！请稍侯！"));
			LPVOID pShellFileBuffer = NULL;
			LPVOID pSrcFileBuffer = NULL;
			DWORD SourceFileSize = 0;
			BOOL isok = false;
			// 读取文件
			memset(SrcPathA, 0, sizeof(SrcPathA));
			TcharToChar(szFileName, SrcPathA);
			size_t File_Size_Shell = ReadPEFile(SrcPathA, 0, &pShellFileBuffer);
			ShowInfoUnpack(TEXT("正在脱壳中！请稍候！"));
			//提取加密后的源文件
			Unpacking(pShellFileBuffer, File_Size_Shell, &pSrcFileBuffer, &SourceFileSize);
			//解密源程序
			ShowInfoUnpack(TEXT("正在解密源文件！请稍侯！"));
			LPVOID pDncryptSrc = Xor(pSrcFileBuffer, SourceFileSize);
			ShowInfoUnpack(TEXT("解密源文件完毕！"));
			char OutputFile[256] = { 0 };
			strcpy(OutputFile, pwd);
			strcat(OutputFile, "\\UnpackedFile.exe");
			isok = MeneryToFile(pDncryptSrc, SourceFileSize, OutputFile);
			if (isok)
			{
				ShowInfoUnpack(TEXT("脱壳完毕，脱壳后文件名为：UnpackedFile.exe"));
			}
			else
			{
				ShowInfoUnpack(TEXT("脱壳失败！请重试！"));
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
void InitUnpackListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	//初始化
	memset(&lv, 0, sizeof(LV_COLUMN));
	//获取IDC_LIST_ShowShell句柄
	hListUnpack = GetDlgItem(hwndDlg, IDC_LIST_ShowUnpack);
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("输出信息");		//列标题				
	lv.cx = 564;					//列宽
	lv.iSubItem = 0;				//第几列
	ListView_InsertColumn(hListUnpack, 0, &lv);//该宏等价于下面的SendMessage				
	//SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	ShowInfoUnpack(TEXT("请选择需要脱壳的程序！"));
}

VOID Unpacking(LPVOID pShellBuffer, DWORD ShellSize, LPVOID* pSourceFileBuffer, DWORD* SourceFileSize)
{
	LPVOID pNewBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	BOOL isok = false;
	int i = 0;
	pDosHeader = (PIMAGE_DOS_HEADER)pShellBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pShellBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//获取最后一个节的地址并回传
	*pSourceFileBuffer = (char*)pShellBuffer + (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData;
	*SourceFileSize = (pSectionHeader + pPEHeader->NumberOfSections - 1)->Misc.VirtualSize;
	return;
}

//输出信息到ListView
void ShowInfoUnpack(LPWSTR string)
{
	LV_ITEM vitem;
	//初始化						
	memset(&vitem, 0, sizeof(LV_ITEM));
	vitem.mask = LVIF_TEXT;
	vitem.pszText = string;
	vitem.iItem = Count;
	vitem.iSubItem = 0;
	SendMessage(hListUnpack, LVM_INSERTITEM, 0, (DWORD)&vitem);
	Count++;
}