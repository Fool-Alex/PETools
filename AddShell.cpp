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
	CHAR ShellFilePath[12] = "./Shell.exe";
	TCHAR SrcPathW[256];
	CHAR SrcPathA[256];
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
				ShowInfo(TEXT("选取源程序成功！"));
				//将源程序显示到EditControl
				SetEditText(hAddShellDlg, IDC_EDIT_Src, szFileName);
			}
			else
			{
				ShowInfo(TEXT("选取源程序失败！请重试！"));
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
			memset(SrcPathW, 0, sizeof(SrcPathW));
			GetEditText(hAddShellDlg, IDC_EDIT_Src, SrcPathW);
			if (!lstrcmp(SrcPathW, szFileName))
			{
				ShowInfo(TEXT("开始加壳！"));
				//开始加壳
				LPVOID pShellFileBuffer = NULL;
				LPVOID pSrcFileBuffer = NULL;
				BOOL isok = false;
				// 读取源文件
				memset(SrcPathA, 0, sizeof(SrcPathA));
				TcharToChar(SrcPathW, SrcPathA);
				DWORD File_Size_Src = ReadPEFile(SrcPathA, 0, &pSrcFileBuffer);
				//内存中加密，获取大小

				//获取加密后的文件大小传入offset
				DWORD File_Size_Shell = ReadPEFile(ShellFilePath, 0, &pShellFileBuffer);
				//加壳并存盘
				AddSection(pShellFileBuffer, File_Size_Src + File_Size_Shell, pSrcFileBuffer, File_Size_Src);
			}
			else
			{
				ShowInfo(TEXT("请先选择源程序，再加壳！"));
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
	ShowInfo(TEXT("请选择需要加壳的源程序！"));
}

//输出信息到ListView
void ShowInfo(LPWSTR string)
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

//返回对齐后的值
DWORD Align(DWORD Num, DWORD Ali)
{
	int a = Num / Ali;
	return (a + 1) * Ali;
}

//新增一个节到PE文件中
VOID AddSection(LPVOID pSourceBuffer, DWORD AllSize, LPVOID pAddBuffer, DWORD AddFileSize)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pNewSec = NULL;//新节表结构
	BOOL isok = false;
	int i = 0;
	pDosHeader = (PIMAGE_DOS_HEADER)pSourceBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pSourceBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	DWORD SourceSize = Align(AllSize, pOptionHeader->SectionAlignment);
	DWORD AddSize = Align(AddFileSize, pOptionHeader->SectionAlignment);
	//判断节表后是否有多余空间添加节表
	for (; i < 80; i++)
	{
		if (*((char*)(pSectionHeader + pPEHeader->NumberOfSections) + i) != 0)
		{
			ShowInfo(TEXT("节表后无多余空间，将会提升PE头创造空闲空间！"));
			//覆盖DOS头和NT头之间的无用数据
			memmove((char*)pSourceBuffer + 0x40, (char*)pSourceBuffer + pDosHeader->e_lfanew, (DWORD)(pSectionHeader + pPEHeader->NumberOfSections) - (DWORD)pSourceBuffer - pDosHeader->e_lfanew);
			//更改pDosHeader->e_lfanew
			int x = pDosHeader->e_lfanew;
			pDosHeader->e_lfanew = 0x40;
			//重新给头指针赋值
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pSourceBuffer + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			//将覆盖后的冗余数据置0
			memset(pSectionHeader + pPEHeader->NumberOfSections, 0, x - 0x40);
			break;
		}
	}
	//新增节表结构
	pNewSec = (PIMAGE_SECTION_HEADER)(pSectionHeader + pPEHeader->NumberOfSections);
	//填写新增节表的属性
	unsigned char arr[8] = ".Shell";
	memcpy(pNewSec->Name, arr, 8);
	pNewSec->Misc.VirtualSize = AddSize;
	if (pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize > pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData)
	{
		pNewSec->VirtualAddress = Align(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize, pOptionHeader->SectionAlignment);
	}
	else {
		pNewSec->VirtualAddress = Align(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData, pOptionHeader->SectionAlignment);
	}
	pNewSec->SizeOfRawData = AddSize;
	pNewSec->PointerToRawData = (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData + (pSectionHeader + pPEHeader->NumberOfSections - 1)->SizeOfRawData;
	pNewSec->PointerToRelocations = 0;
	pNewSec->PointerToLinenumbers = 0;
	pNewSec->NumberOfRelocations = 0;
	pNewSec->NumberOfLinenumbers = 0;
	pNewSec->Characteristics = 0x60000020;
	pOptionHeader->SizeOfImage += AddSize;
	pPEHeader->NumberOfSections++;
	//添加节在最后
	memcpy((void*)((DWORD)pSourceBuffer + pNewSec->PointerToRawData), pAddBuffer, AddSize);
	isok = MeneryToFile(pSourceBuffer, SourceSize, "./AddShellFile.exe");
	if (isok)
	{
		ShowInfo(TEXT("加壳完毕，加壳后文件名为：AddShellFile.exe"));
	}
	else
	{
		ShowInfo(TEXT("加壳失败！请重试！"));
	}
	free(pSourceBuffer);
	free(pAddBuffer);
	return;
}

//将内存中的数据写入硬盘中
BOOL MeneryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	//检测传入指针是否为空
	if (!pMemBuffer)
	{
		printf("缓存区指针无效");
		return 0;
	}
	FILE* pFile = NULL;
	if ((pFile = fopen(lpszFile, "wb+")) == NULL)
	{
		printf("file open error\n");
		return 0;
	}
	fwrite(pMemBuffer, 1, size, pFile);
	fclose(pFile);
	pFile = NULL;
	return size;
}