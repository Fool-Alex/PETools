#pragma once
#include <stdio.h>
#include <stdlib.h> 
#include <malloc.h>
#include <memory.h>
#include <windows.h>
#include <winnt.h>
#include <string.h>

#define FILEPATH_IN "F:/VS_Project/Win_App/Debug/Win_App.exe"
#define FILEPATH_OUT "F:/RE/Windows/RE_test/Test2.exe"
#define SHELLCODELENGTH 0x12
#define MESSAGEBOXADDR 0x77D5050B
#define SIZEOFADDSECTION 0x1000

BYTE ShellCode[] =
{ 0x6A,00,0x6A,00,0x6A,00,0x6A,00,
	0xE8,00,00,00,00,
	0xE9,00,00,00,00 };

//返回对齐后的值
DWORD Align(DWORD Num, DWORD Ali)
{
	int a = Num / Ali;
	return (a + 1) * Ali;
}



//复制FileBuffer到ImageBuffer
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	//检测传入指针是否为空
	if (!pFileBuffer)
	{
		printf("缓存区指针无效");
		return 0;
	}
	//初始化dos、标准PE、可选PE和节表4个结构体指针
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//判断是否是有效的MZ标志
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//分配ImageBuffer内存
	*pImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (!pImageBuffer)
	{
		printf("分配ImageBuffer错误");
		free(pImageBuffer);
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	//从FileBuffer复制到ImageBuffer
	char* temppFileBuffer = (char*)pFileBuffer;
	char* temppImageBuffer = (char*)*pImageBuffer;
	memcpy(temppImageBuffer, temppFileBuffer, pOptionHeader->SizeOfHeaders);
	temppFileBuffer = (char*)pFileBuffer;
	temppImageBuffer = (char*)*pImageBuffer;
	for (int j = 0; j < (signed)pPEHeader->NumberOfSections; j++)
	{
		memcpy(temppImageBuffer + pSectionHeader->VirtualAddress, temppFileBuffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	temppFileBuffer = NULL;
	temppImageBuffer = NULL;
	return pOptionHeader->SizeOfImage;
}

//将ImageBuffer复制到NewBuffer
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
{
	//检测传入指针是否为空
	if (!pImageBuffer)
	{
		printf("缓存区指针无效");
		return 0;
	}
	//初始化dos、标准PE、可选PE和节表4个结构体指针
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//判断是否是有效的MZ标志
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pImageBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//分配ImageBuffer内存
	//获取pNewBuffer的大小
	DWORD NewBuffer_size = pSectionHeader[pPEHeader->NumberOfSections - 1].PointerToRawData;
	NewBuffer_size += pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData;
	*pNewBuffer = malloc(NewBuffer_size);
	if (!*pNewBuffer)
	{
		printf("分配NewBuffer错误");
		free(pImageBuffer);
		return 0;
	}
	memset(*pNewBuffer, 0, NewBuffer_size);
	//从FileBuffer复制到ImageBuffer
	char* temppImageBuffer = (char*)pImageBuffer;
	char* temppNewBuffer = (char*)*pNewBuffer;
	memcpy(temppNewBuffer, temppImageBuffer, pOptionHeader->SizeOfHeaders);
	temppImageBuffer = (char*)pImageBuffer;
	temppNewBuffer = (char*)*pNewBuffer;
	for (int j = 0; j < (signed)pPEHeader->NumberOfSections; j++)
	{
		memcpy(temppNewBuffer + pSectionHeader->PointerToRawData, temppImageBuffer + pSectionHeader->VirtualAddress, pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	temppImageBuffer = NULL;
	temppNewBuffer = NULL;
	return NewBuffer_size;
}

//将内存偏移转化为文件偏移
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva)
{
	//检测传入指针是否为空
	if (!pFileBuffer)
	{
		printf("缓存区指针无效");
		return 0;
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//判断是否是有效的MZ标志
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		DWORD dwBlockCount = pSectionHeader[i].SizeOfRawData / pOptionHeader->SectionAlignment;
		dwBlockCount += pSectionHeader[i].SizeOfRawData % pOptionHeader->SectionAlignment ? 1 : 0;
		if (dwRva >= pSectionHeader[i].VirtualAddress && dwRva < (pSectionHeader[i].VirtualAddress + (dwBlockCount * pOptionHeader->SectionAlignment)))
		{
			return (pSectionHeader[i].PointerToRawData + (dwRva - pSectionHeader[i].VirtualAddress));
		}
		else if (dwRva < pSectionHeader[0].VirtualAddress)
		{
			return dwRva;
		}
	}
	return 0;
}

//将文件偏移转化为内存偏移
DWORD FoaToRva(IN LPVOID pFileBuffer, IN DWORD dwFoa)
{
	//检测传入指针是否为空
	if (!pFileBuffer)
	{
		printf("缓存区指针无效");
		return 0;
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//判断是否是有效的MZ标志
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (dwFoa >= pSectionHeader[i].PointerToRawData && dwFoa < (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData))
		{
			return (pSectionHeader[i].VirtualAddress + (dwFoa - pSectionHeader[i].PointerToRawData));
		}
		else if (dwFoa < pSectionHeader[0].PointerToRawData)
		{
			return dwFoa;
		}
	}
	return 0;
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

//添加shellcode到代码段空闲区
VOID TestAddCodeInCodeSec()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PBYTE CodeBegin = NULL;
	BOOL isok = false;
	DWORD size = 0;
	//读取文件
	ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败");
		return;
	}
	//复制FileBuffer到ImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer)
	{
		printf("复制FileBuffer到ImageBuffer失败");
		free(pFileBuffer);
		return;
	}
	//判断代码段空闲区是否有足够空间填充ShellCode
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (SHELLCODELENGTH > (pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize))
	{
		printf("代码段空闲区没有足够空间");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	//开始往代码段空闲区填充shellcode
	CodeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(CodeBegin, ShellCode, SHELLCODELENGTH);
	//改E8
	DWORD CallAddr = MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + 0xD) - (DWORD)pImageBuffer));
	*(PDWORD)(CodeBegin + 0x9) = CallAddr;
	//改E9
	DWORD JmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + SHELLCODELENGTH) - (DWORD)pImageBuffer));
	*(PDWORD)(CodeBegin + 0xE) = JmpAddr;
	//改EntryPoint
	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)pImageBuffer;
	//复制ImageBuffer到NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || !pNewBuffer)
	{
		printf("复制ImageBuffer到NewBuffer失败");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	//将NewBuffer写入硬盘
	isok = MeneryToFile(pNewBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！");
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
	return;
}

//向任意指定节中添加shellcode
VOID TestAddCodeInAnyCodeSec(int x)
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PBYTE CodeBegin = NULL;
	BOOL isok = false;
	DWORD size = 0;
	//读取文件
	ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败");
		return;
	}
	//复制FileBuffer到ImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer)
	{
		printf("复制FileBuffer到ImageBuffer失败");
		free(pFileBuffer);
		return;
	}
	//判断代码段空闲区是否有足够空间填充ShellCode
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	if (x > pPEHeader->NumberOfSections || x < 1)
	{
		printf("指定节数不合法");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	pSectionHeader += (x - 1);
	if (pSectionHeader->Misc.VirtualSize > pSectionHeader->SizeOfRawData || SHELLCODELENGTH > (pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize))
	{
		printf("代码段空闲区没有足够空间");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	//开始往代码段空闲区填充shellcode
	CodeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(CodeBegin, ShellCode, SHELLCODELENGTH);
	//改E8
	DWORD CallAddr = MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + 0xD) - (DWORD)pImageBuffer));
	*(PDWORD)(CodeBegin + 0x9) = CallAddr;
	//改E9
	DWORD JmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(CodeBegin + SHELLCODELENGTH) - (DWORD)pImageBuffer));
	*(PDWORD)(CodeBegin + 0xE) = JmpAddr;
	//改OEP
	pOptionHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)pImageBuffer;
	//修改任意区的数据为可执行
	DWORD a = pSectionHeader->Characteristics;
	DWORD b = (pSectionHeader - (x - 1))->Characteristics;
	pSectionHeader->Characteristics = a | b;
	//复制ImageBuffer到NewBuffer
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || !pNewBuffer)
	{
		printf("复制ImageBuffer到NewBuffer失败");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	//将NewBuffer写入硬盘
	isok = MeneryToFile(pNewBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！");
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
	return;
}

//新增一个节到PE文件中
VOID AddSection()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	BOOL isok = false;
	DWORD size = 0;
	int i = 0;
	//读取文件
	size = ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//判断节表后是否有多余空间添加节表
	for (; i < 80; i++)
	{
		if (*((char*)(pSectionHeader + pPEHeader->NumberOfSections) + i) != 0)
		{
			printf("节表后无多余空间，将会提升PE头创造空闲空间\n");
			//覆盖DOS头和NT头之间的无用数据
			memmove((char*)pFileBuffer + 0x40, (char*)pFileBuffer + pDosHeader->e_lfanew, (DWORD)(pSectionHeader + pPEHeader->NumberOfSections) - (DWORD)pFileBuffer - pDosHeader->e_lfanew);
			//更改pDosHeader->e_lfanew
			int x = pDosHeader->e_lfanew;
			pDosHeader->e_lfanew = 0x40;
			//重新给头指针赋值
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			//将覆盖后的冗余数据置0
			memset(pSectionHeader + pPEHeader->NumberOfSections, 0, x - 0x40);
			break;
		}
	}
	//添加节表
	if (i == 80)
	{
		printf("节表后有多余空间，直接添加新节表\n");
	}
	pOptionHeader->SizeOfImage += SIZEOFADDSECTION;
	pPEHeader->NumberOfSections++;
	unsigned char arr[8] = "export";
	memcpy((pSectionHeader + pPEHeader->NumberOfSections - 1)->Name, arr, 8);
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->Misc.VirtualSize = SIZEOFADDSECTION;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->VirtualAddress = (pSectionHeader + pPEHeader->NumberOfSections - 2)->VirtualAddress + (pSectionHeader + pPEHeader->NumberOfSections - 2)->SizeOfRawData;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->SizeOfRawData = SIZEOFADDSECTION;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData = (pSectionHeader + pPEHeader->NumberOfSections - 2)->PointerToRawData + (pSectionHeader + pPEHeader->NumberOfSections - 2)->SizeOfRawData;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRelocations = 0;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToLinenumbers = 0;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->NumberOfRelocations = 0;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->NumberOfLinenumbers = 0;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->Characteristics = pSectionHeader->Characteristics;
	//添加节在最后
	memset((void*)((DWORD)pFileBuffer + (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData), 0, SIZEOFADDSECTION);
	//将FileBuffer写入硬盘
	size += SIZEOFADDSECTION;
	isok = MeneryToFile(pFileBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！\n");
	}
	free(pFileBuffer);
	return;
}

//扩大最后一个节并添加代码
VOID AddSectionToLastSec()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	BOOL isok = false;
	DWORD size = 0;
	//读取文件
	size = ReadPEFile(FILEPATH_IN, SIZEOFADDSECTION, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//添加代码到最后一个节的后面
	memset((void*)((DWORD)pFileBuffer + (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData + (pSectionHeader + pPEHeader->NumberOfSections - 1)->SizeOfRawData), 0, SIZEOFADDSECTION);
	//修改节表和大小
	pOptionHeader->SizeOfImage += SIZEOFADDSECTION;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->Misc.VirtualSize += SIZEOFADDSECTION;
	(pSectionHeader + pPEHeader->NumberOfSections - 1)->SizeOfRawData += SIZEOFADDSECTION;
	//将FileBuffer写入硬盘
	size += SIZEOFADDSECTION;
	isok = MeneryToFile(pFileBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！\n");
	}
	free(pFileBuffer);
	return;
}

//合并节
VOID AddSectionToOneSec()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	BOOL isok = false;
	DWORD size = 0;
	//读取文件
	ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	//复制FileBuffer到ImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer)
	{
		printf("复制FileBuffer到ImageBuffer失败");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//修改第一个节的vs和soraw
	pSectionHeader->SizeOfRawData = pOptionHeader->SizeOfImage - pSectionHeader->VirtualAddress;
	pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData;
	for (int i = 1; i < pPEHeader->NumberOfSections; i++)
	{
		pSectionHeader->Characteristics |= (pSectionHeader + i)->Characteristics;
	}
	pPEHeader->NumberOfSections = 0x1;
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewBuffer);
	if (size == 0 || !pNewBuffer)
	{
		printf("复制ImageBuffer到NewBuffer失败");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	//将FileBuffer写入硬盘
	isok = MeneryToFile(pNewBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！\n");
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
	pFileBuffer = NULL;
	pImageBuffer = NULL;
	pNewBuffer = NULL;
	return;
}

//打印数据目录
VOID PrintImage_Data_Directory()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	//读取文件
	ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)&pOptionHeader->NumberOfRvaAndSizes + 4);
	printf("------导出表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", pDataDirectory->VirtualAddress, pDataDirectory->Size);
	printf("------导出表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 1)->VirtualAddress, (pDataDirectory + 1)->Size);
	printf("------资源表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 2)->VirtualAddress, (pDataDirectory + 2)->Size);
	printf("------异常信息表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 3)->VirtualAddress, (pDataDirectory + 3)->Size);
	printf("------安全证书表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 4)->VirtualAddress, (pDataDirectory + 4)->Size);
	printf("------重定位表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 5)->VirtualAddress, (pDataDirectory + 5)->Size);
	printf("------调试信息表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 6)->VirtualAddress, (pDataDirectory + 6)->Size);
	printf("------版权所有表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 7)->VirtualAddress, (pDataDirectory + 7)->Size);
	printf("------全局指针表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 8)->VirtualAddress, (pDataDirectory + 8)->Size);
	printf("------TLS表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 9)->VirtualAddress, (pDataDirectory + 9)->Size);
	printf("------加载配置表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 10)->VirtualAddress, (pDataDirectory + 10)->Size);
	printf("------绑定导入表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 11)->VirtualAddress, (pDataDirectory + 11)->Size);
	printf("------IAT表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 12)->VirtualAddress, (pDataDirectory + 12)->Size);
	printf("------延迟导入表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 13)->VirtualAddress, (pDataDirectory + 13)->Size);
	printf("------COM信息表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 14)->VirtualAddress, (pDataDirectory + 14)->Size);
	printf("------保留表------\n");
	printf("VirtualAddress:%x\nSize:%x\n", (pDataDirectory + 15)->VirtualAddress, (pDataDirectory + 15)->Size);
	free(pFileBuffer);
	pFileBuffer = NULL;
	return;
}


//通过函数名获取函数地址
DWORD GetFunctionAddrByName(LPVOID pFileBuffer, LPSTR FunctionName)
{
	int** paddress_of_names = NULL;
	short* paddress_of_namesordinals = NULL;
	int* paddress_of_functions = NULL;
	unsigned int index_addr = 0;
	unsigned int AddressOfFunctions = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pDirEntryExport = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pDirEntryExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory->VirtualAddress));
	paddress_of_names = (int**)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDirEntryExport->AddressOfNames));
	paddress_of_namesordinals = (short*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDirEntryExport->AddressOfNameOrdinals));
	paddress_of_functions = (int*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDirEntryExport->AddressOfFunctions));
	*paddress_of_names = (int*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, (DWORD)*paddress_of_names));
	//匹配输入字符串和函数名
	for (; index_addr < pDirEntryExport->NumberOfNames; index_addr++)
	{
		if (!strcmp((char*)(*paddress_of_names), FunctionName))
		{
			break;
		}
		(*paddress_of_names)++;
	}
	AddressOfFunctions = (DWORD) * (paddress_of_functions + *(paddress_of_namesordinals + index_addr));
	free(pFileBuffer);
	return AddressOfFunctions;
}


//通过函数序号获取函数地址
DWORD GetFunctionAddrByOrdinals(LPVOID pFileBuffer, int AddrNum)
{
	unsigned int AddressOfFunctions = 0;
	int* paddress_of_functions = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pDirEntryExport = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pDirEntryExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory->VirtualAddress));
	paddress_of_functions = (int*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDirEntryExport->AddressOfFunctions));
	AddressOfFunctions = (DWORD) * (paddress_of_functions + (AddrNum - pDirEntryExport->Base));
	free(pFileBuffer);
	return AddressOfFunctions;
}

//打印重定位表
VOID PrintBASERELOC(LPVOID pFileBuffer)
{
	DWORD NumOfReloc = 1;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBasereloc = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pBasereloc = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory[5].VirtualAddress));
	short* pRva = NULL;
	//打印所有数据偏移信息
	printf("打印重定位表\n");
	while (pBasereloc->VirtualAddress && pBasereloc->SizeOfBlock)
	{
		pRva = (short*)((char*)pBasereloc + 8);
		printf("------第%d块------\n", NumOfReloc);
		for (unsigned int i = 0; i < (pBasereloc->SizeOfBlock - 8) / 2; i++)
		{
			if ((*pRva & 0xf000) == 0x3000)
			{
				printf("第%d项	地址：%x\n", i + 1, (*pRva & 0xfff) + pBasereloc->VirtualAddress);
			}
			pRva++;
		}
		pBasereloc = (PIMAGE_BASE_RELOCATION)((DWORD)pBasereloc + pBasereloc->SizeOfBlock);
		NumOfReloc++;
	}
	free(pFileBuffer);
	return;
}

//移动导出表到新建节
VOID MovExport()
{
	LPVOID pFileBuffer = NULL;
	int** paddress_of_names = NULL;
	short* paddress_of_nameordinals = NULL;
	int* paddress_of_functions = NULL;
	BOOL isok = false;
	DWORD size = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pNewSec = NULL;//新节表结构
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pDirEntryExport = NULL;
	PIMAGE_EXPORT_DIRECTORY pNewDirEntryExport = NULL;
	size_t i = 0;
	//读取文件
	size = ReadPEFile(FILEPATH_IN, SIZEOFADDSECTION, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pDirEntryExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory->VirtualAddress));
	paddress_of_names = (int**)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDirEntryExport->AddressOfNames));
	paddress_of_nameordinals = (short*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDirEntryExport->AddressOfNameOrdinals));
	paddress_of_functions = (int*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDirEntryExport->AddressOfFunctions));
	//判断节表后是否有多余空间添加节表
	for (; i < 80; i++)
	{
		if (*((char*)(pSectionHeader + pPEHeader->NumberOfSections) + i) != 0)
		{
			printf("节表后无多余空间，将会提升PE头创造空闲空间\n");
			//覆盖DOS头和NT头之间的无用数据
			memmove((char*)pFileBuffer + 0x40, (char*)pFileBuffer + pDosHeader->e_lfanew, (DWORD)(pSectionHeader + pPEHeader->NumberOfSections) - (DWORD)pFileBuffer - pDosHeader->e_lfanew);
			//更改pDosHeader->e_lfanew
			int x = pDosHeader->e_lfanew;
			pDosHeader->e_lfanew = 0x40;
			//重新给头指针赋值
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			//将覆盖后的冗余数据置0
			memset(pSectionHeader + pPEHeader->NumberOfSections, 0, x - 0x40);
			break;
		}
	}
	//添加节表
	if (i == 80)
	{
		printf("节表后有多余空间，直接添加新节表\n");
	}
	//新增节表结构
	pNewSec = (PIMAGE_SECTION_HEADER)(pSectionHeader + pPEHeader->NumberOfSections);
	//填写新增节表的属性
	unsigned char arr[8] = ".export";
	memcpy(pNewSec->Name, arr, 8);
	pNewSec->Misc.VirtualSize = SIZEOFADDSECTION;
	if (pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize > pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData)
	{
		pNewSec->VirtualAddress = Align(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize, pOptionHeader->SectionAlignment);
	}
	else {
		pNewSec->VirtualAddress = Align(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData, pOptionHeader->SectionAlignment);
	}
	pNewSec->SizeOfRawData = SIZEOFADDSECTION;
	pNewSec->PointerToRawData = (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData + (pSectionHeader + pPEHeader->NumberOfSections - 1)->SizeOfRawData;
	pNewSec->PointerToRelocations = 0;
	pNewSec->PointerToLinenumbers = 0;
	pNewSec->NumberOfRelocations = 0;
	pNewSec->NumberOfLinenumbers = 0;
	pNewSec->Characteristics = 0x60000020;
	pOptionHeader->SizeOfImage += SIZEOFADDSECTION;
	pPEHeader->NumberOfSections++;
	//记录新的函数地址表地址
	int* Newaddr_of_functions = (int*)((DWORD)pFileBuffer + pNewSec->PointerToRawData);
	//拷贝AddressOfFunctions到新节
	memcpy(Newaddr_of_functions, paddress_of_functions, 4 * pDirEntryExport->NumberOfFunctions);
	//记录新的函数序号表地址
	short* Newaddr_of_nameordinals = (short*)((DWORD)Newaddr_of_functions + 4 * pDirEntryExport->NumberOfFunctions);
	//拷贝address_of_nameordinals到新节
	memcpy(Newaddr_of_nameordinals, paddress_of_nameordinals, 2 * pDirEntryExport->NumberOfNames);
	//记录新的函数名称表地址
	int** Newaddr_of_names = (int**)((DWORD)Newaddr_of_nameordinals + 2 * pDirEntryExport->NumberOfNames);
	//拷贝address_of_name到新节
	memcpy(Newaddr_of_names, paddress_of_names, 4 * pDirEntryExport->NumberOfNames);
	//记录首个函数名的地址
	char* AdderessOfString = (char*)((DWORD)Newaddr_of_names + 4 * pDirEntryExport->NumberOfNames);
	//开始复制函数名同时改写函数名的地址表
	for (size_t j = 0; j < pDirEntryExport->NumberOfNames; j++)
	{
		LPSTR name = (char*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, (DWORD)(*(paddress_of_names + j))));
		i = strlen(name) + 1;
		memcpy(AdderessOfString, name, i);
		*(Newaddr_of_names + j) = (int*)FoaToRva(pFileBuffer, (DWORD)AdderessOfString - (DWORD)pFileBuffer);
		AdderessOfString += i;
	}
	//记录导出表结构首地址
	pNewDirEntryExport = (PIMAGE_EXPORT_DIRECTORY)AdderessOfString;
	//复制导出表结构
	memcpy(pNewDirEntryExport, pDirEntryExport, pDataDirectory->Size);
	//修复IMAGE_EXPORT_DIRECTORY结构
	pNewDirEntryExport->AddressOfFunctions = FoaToRva(pFileBuffer, (DWORD)Newaddr_of_functions - (DWORD)pFileBuffer);
	pNewDirEntryExport->AddressOfNameOrdinals = FoaToRva(pFileBuffer, (DWORD)Newaddr_of_nameordinals - (DWORD)pFileBuffer);
	pNewDirEntryExport->AddressOfNames = FoaToRva(pFileBuffer, (DWORD)Newaddr_of_names - (DWORD)pFileBuffer);

	//修改数据目录的导出表地址
	pDataDirectory->VirtualAddress = FoaToRva(pFileBuffer, (DWORD)pNewDirEntryExport - (DWORD)pFileBuffer);
	//存盘
	isok = MeneryToFile(pFileBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！\n");
	}
	free(pFileBuffer);
	pFileBuffer = NULL;
	return;
}

//移动重定位表到新建节
VOID MovRelocation()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pNewSec = NULL;//新节表结构
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBasereloc = NULL;
	PIMAGE_BASE_RELOCATION pNewBasereloc = NULL;
	BOOL isok = false;
	DWORD size = 0;
	size_t i = 0;
	//读取文件
	size = ReadPEFile(FILEPATH_IN, SIZEOFADDSECTION, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pBasereloc = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory[5].VirtualAddress));
	//判断节表后是否有多余空间添加节表
	for (; i < 80; i++)
	{
		if (*((char*)(pSectionHeader + pPEHeader->NumberOfSections) + i) != 0)
		{
			printf("节表后无多余空间，将会提升PE头创造空闲空间\n");
			//覆盖DOS头和NT头之间的无用数据
			memmove((char*)pFileBuffer + 0x40, (char*)pFileBuffer + pDosHeader->e_lfanew, (DWORD)(pSectionHeader + pPEHeader->NumberOfSections) - (DWORD)pFileBuffer - pDosHeader->e_lfanew);
			//更改pDosHeader->e_lfanew
			int x = pDosHeader->e_lfanew;
			pDosHeader->e_lfanew = 0x40;
			//重新给头指针赋值
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			//将覆盖后的冗余数据置0
			memset(pSectionHeader + pPEHeader->NumberOfSections, 0, x - 0x40);
			break;
		}
	}
	//添加节表
	if (i == 80)
	{
		printf("节表后有多余空间，直接添加新节表\n");
	}
	//新增节表结构
	pNewSec = (PIMAGE_SECTION_HEADER)(pSectionHeader + pPEHeader->NumberOfSections);
	//填写新增节表的属性
	unsigned char arr[8] = ".reloca";
	memcpy(pNewSec->Name, arr, 8);
	pNewSec->Misc.VirtualSize = SIZEOFADDSECTION;
	if (pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize > pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData)
	{
		pNewSec->VirtualAddress = Align(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize, pOptionHeader->SectionAlignment);
	}
	else {
		pNewSec->VirtualAddress = Align(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData, pOptionHeader->SectionAlignment);
	}
	pNewSec->SizeOfRawData = SIZEOFADDSECTION;
	pNewSec->PointerToRawData = (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData + (pSectionHeader + pPEHeader->NumberOfSections - 1)->SizeOfRawData;
	pNewSec->PointerToRelocations = 0;
	pNewSec->PointerToLinenumbers = 0;
	pNewSec->NumberOfRelocations = 0;
	pNewSec->NumberOfLinenumbers = 0;
	pNewSec->Characteristics = 0x60000020;
	pOptionHeader->SizeOfImage += SIZEOFADDSECTION;
	pPEHeader->NumberOfSections++;
	//移动重定位表
	pNewBasereloc = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + pNewSec->PointerToRawData);
	LPVOID Temp = pNewBasereloc;
	while (pBasereloc->VirtualAddress && pBasereloc->SizeOfBlock)
	{
		memcpy(Temp, pBasereloc, pBasereloc->SizeOfBlock);
		Temp = (PIMAGE_BASE_RELOCATION)((DWORD)Temp + pBasereloc->SizeOfBlock);
		pBasereloc = (PIMAGE_BASE_RELOCATION)((DWORD)pBasereloc + pBasereloc->SizeOfBlock);
	}
	//修改数据目录的重定位表地址
	pDataDirectory[5].VirtualAddress = FoaToRva(pFileBuffer, (DWORD)pNewBasereloc - (DWORD)pFileBuffer);
	//存盘
	isok = MeneryToFile(pFileBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！\n");
	}
	free(pFileBuffer);
	pFileBuffer = NULL;
	return;
}

//重载DLL并修改重定位表函数地址
VOID ReloadDll(DWORD RelocateImageBase)
{
	LPVOID pFileBuffer = NULL;
	int ImageOffset = 0;
	DWORD NumOfReloc = 1;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBasereloc = NULL;
	DWORD size = 0;
	//读取文件
	size = ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pBasereloc = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory[5].VirtualAddress));
	BOOL isok = false;
	short* pRva = NULL;
	//算出重载后的ImageBase偏移
	ImageOffset = (signed)RelocateImageBase - (signed)pOptionHeader->ImageBase;
	//修改ImageBase
	pOptionHeader->ImageBase = RelocateImageBase;
	//修改所有偏移指向的地址信息
	while (pBasereloc->VirtualAddress && pBasereloc->SizeOfBlock)
	{
		pRva = (short*)((char*)pBasereloc + 8);
		printf("------第%d块------\n", NumOfReloc);
		for (unsigned int i = 0; i < (pBasereloc->SizeOfBlock - 8) / 2; i++)
		{
			if ((*pRva & 0xf000) == 0x3000)
			{
				//需要修改的地址
				int* AddressOffset = (int*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, ((*pRva & 0xfff) + pBasereloc->VirtualAddress)));
				*AddressOffset += ImageOffset;
				printf("第%d项：%x	已修改\n", i + 1, (*pRva & 0xfff) + pBasereloc->VirtualAddress);
			}
			pRva++;
		}
		pBasereloc = (PIMAGE_BASE_RELOCATION)((DWORD)pBasereloc + pBasereloc->SizeOfBlock);
		NumOfReloc++;
	}
	//存盘
	isok = MeneryToFile(pFileBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！\n");
	}
	free(pFileBuffer);
	pFileBuffer = NULL;
	return;
}

//打印导入表
VOID PrintImport()
{
	LPVOID pFileBuffer;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	//读取文件
	ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory[1].VirtualAddress));
	unsigned int* pOriginalFirstThunk = NULL;
	unsigned int* pFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
	printf("---打印导入表---\n");
	while (pImportDescriptor->OriginalFirstThunk != 0)
	{
		printf("模块名：%s----------------------\n", (char*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pImportDescriptor->Name)));
		printf("OriginalFirstThunk:%x\n", pImportDescriptor->OriginalFirstThunk);
		printf("TimeDateStamp:%x\n", pImportDescriptor->TimeDateStamp);
		printf("ForwarderChain:%x\n", pImportDescriptor->ForwarderChain);
		printf("Name:%x\n", pImportDescriptor->Name);
		printf("FirstThunk:%x\n", pImportDescriptor->FirstThunk);
		pOriginalFirstThunk = (unsigned int*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pImportDescriptor->OriginalFirstThunk));
		printf("----------打印INT表（OriginalFirstThunk）----------\n");
		while (*pOriginalFirstThunk != 0)
		{
			if (*pOriginalFirstThunk & 0x80000000)
			{
				printf("函数导出序号：%x\n", (*pOriginalFirstThunk & 0x7fffffff));
			}
			else
			{
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, *pOriginalFirstThunk));
				printf("Hint：%x\n", pImportByName->Hint);
				printf("函数名：%s\n", pImportByName->Name);
			}
			pOriginalFirstThunk++;
		}
		pFirstThunk = (unsigned int*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pImportDescriptor->FirstThunk));
		printf("----------打印IAT表（FirstThunk）----------\n");
		while (*pFirstThunk != 0)
		{
			if (*pFirstThunk & 0x80000000)
			{
				printf("函数导出序号：%x\n", (*pFirstThunk & 0x7fffffff));
			}
			else
			{
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, *pFirstThunk));
				printf("Hint：%x\n", pImportByName->Hint);
				printf("函数名：%s\n", pImportByName->Name);
			}
			pFirstThunk++;
		}
		pImportDescriptor++;
	}
	free(pFileBuffer);
	return;
}

//打印绑定导入表
VOID PrintBoundImport()
{
	LPVOID pFileBuffer;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImport = NULL;
	PIMAGE_BOUND_FORWARDER_REF pBoundForwarder = NULL;
	//读取文件
	ReadPEFile(FILEPATH_IN, 0, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory[11].VirtualAddress));
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pFirstDescriptor = pBoundImport;
	printf("打印绑定导入表\n");
	while (pBoundImport->TimeDateStamp)
	{
		if (pBoundImport == pFirstDescriptor)
		{
			printf("TimeDateStamp:%x\n", pFirstDescriptor->TimeDateStamp);
			printf("OffsetModuleName:%s\n", (char*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pFirstDescriptor->OffsetModuleName)));
			printf("NumberOfModuleForwarderRefs:%x\n", pFirstDescriptor->NumberOfModuleForwarderRefs);
		}
		else
		{
			printf("TimeDateStamp:%x\n", pBoundImport->TimeDateStamp);
			printf("OffsetModuleName:%s\n", (char*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, (pBoundImport->OffsetModuleName + pFirstDescriptor->OffsetModuleName))));
			printf("NumberOfModuleForwarderRefs:%x\n", pBoundImport->NumberOfModuleForwarderRefs);
		}
		pBoundForwarder = (PIMAGE_BOUND_FORWARDER_REF)(pBoundImport + 1);
		printf("----------\n");
		for (size_t i = 0; i < pBoundImport->NumberOfModuleForwarderRefs; i++)
		{
			printf("TimeDateStamp:%x\n", pBoundForwarder->TimeDateStamp);
			printf("OffsetModuleName:%s\n", (char*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, (pBoundForwarder->OffsetModuleName + pFirstDescriptor->OffsetModuleName))));
			printf("NumberOfModuleForwarderRefs:%x\n", pBoundForwarder->Reserved);
			pBoundForwarder++;
		}
		pBoundImport = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)pBoundForwarder;
	}
	free(pFileBuffer);
	return;
}

//导入表注入
VOID ImportInject()
{
	LPVOID pFileBuffer;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pNewSec = NULL;//新节表结构
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pNewImportDescriptor = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pInjectImport = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
	size_t i = 0;
	DWORD size = 0;
	BOOL isok = false;
	//读取文件
	size = ReadPEFile(FILEPATH_IN, SIZEOFADDSECTION, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory[1].VirtualAddress));
	DWORD NumOfDll = 0;
	//遍历导入表
	while (pImportDescriptor[NumOfDll].OriginalFirstThunk)
	{
		NumOfDll++;
	}
	DWORD NeedSize = (sizeof(*pImportDescriptor) * (NumOfDll + 1)) + 20 + 16 + 44;
	//判断节表后是否有多余空间添加节表
	for (; i < 80; i++)
	{
		if (*((char*)(pSectionHeader + pPEHeader->NumberOfSections) + i) != 0)
		{
			printf("节表后无多余空间，将会提升PE头创造空闲空间\n");
			//覆盖DOS头和NT头之间的无用数据
			memmove((char*)pFileBuffer + 0x40, (char*)pFileBuffer + pDosHeader->e_lfanew, (DWORD)(pSectionHeader + pPEHeader->NumberOfSections) - (DWORD)pFileBuffer - pDosHeader->e_lfanew);
			//更改pDosHeader->e_lfanew
			int x = pDosHeader->e_lfanew;
			pDosHeader->e_lfanew = 0x40;
			//重新给头指针赋值
			pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
			//将覆盖后的冗余数据置0
			memset(pSectionHeader + pPEHeader->NumberOfSections, 0, x - 0x40);
			break;
		}
	}
	//添加节表
	if (i == 80)
	{
		printf("节表后有多余空间，直接添加新节表\n");
	}
	//新增节表结构
	pNewSec = (PIMAGE_SECTION_HEADER)(pSectionHeader + pPEHeader->NumberOfSections);
	//填写新增节表的属性
	unsigned char arr[8] = ".Inject";
	memcpy(pNewSec->Name, arr, 8);
	pNewSec->Misc.VirtualSize = SIZEOFADDSECTION;
	if (pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize > pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData)
	{
		pNewSec->VirtualAddress = Align((pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].Misc.VirtualSize), pOptionHeader->SectionAlignment);
	}
	else {
		pNewSec->VirtualAddress = Align(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress + pSectionHeader[pPEHeader->NumberOfSections - 1].SizeOfRawData, pOptionHeader->SectionAlignment);
	}
	pNewSec->SizeOfRawData = SIZEOFADDSECTION;
	pNewSec->PointerToRawData = (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData + (pSectionHeader + pPEHeader->NumberOfSections - 1)->SizeOfRawData;
	pNewSec->PointerToRelocations = 0;
	pNewSec->PointerToLinenumbers = 0;
	pNewSec->NumberOfRelocations = 0;
	pNewSec->NumberOfLinenumbers = 0;
	pNewSec->Characteristics = 0xC0000040;
	pOptionHeader->SizeOfImage += SIZEOFADDSECTION;
	pPEHeader->NumberOfSections++;
	//DWORD i = 0;//记录要添加节的位置
	////判断各节后是否有空间添加
	//for (; i < pPEHeader->NumberOfSections; i++)
	//{
	//	DWORD j = 0;
	//	for (; j < NeedSize; j++)
	//	{
	//		if (pSectionHeader[i].Misc.VirtualSize > pSectionHeader[i].SizeOfRawData || *((char*)pFileBuffer + pSectionHeader[i].PointerToRawData + pSectionHeader[i].Misc.VirtualSize + 16))
	//		{
	//			printf("第%d个节没有空间移动导入表！\n", i+1);
	//			break;
	//		}
	//	}
	//	if (j == NeedSize)
	//	{
	//		printf("第%d个节有空间，在此节移动导入表！\n", i+1);
	//		break;
	//	}
	//}
	//if (i == pPEHeader->NumberOfSections)
	//{
	//	printf("没有空余节，将新增节移动导入表！\n");
	//	free(pFileBuffer);
	//	return;
	//}
	//给新导入表地址赋值
	pNewImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + pNewSec->PointerToRawData);
	//开始移动导入表
	memcpy((char*)pNewImportDescriptor, (char*)pImportDescriptor, (sizeof(*pImportDescriptor) * NumOfDll));//移动原来的导入表到空闲节后
	//记录注入的导入表以及INT表和IAT表和名字表
	pInjectImport = pNewImportDescriptor + NumOfDll;
	PDWORD pINT = (PDWORD)(pInjectImport + 2);
	PDWORD pIAT = (PDWORD)(pINT + 2);
	pImportByName = (PIMAGE_IMPORT_BY_NAME)(pIAT + 2);
	char FounctionName[] = "ExportFunction";
	char DllName[] = "InjectDll.dll";
	//拷贝函数名到名字表
	strcpy((char*)pImportByName + 2, FounctionName);
	//拷贝dll名
	strcpy((char*)pImportByName + 3 + strlen(FounctionName), DllName);
	//往导入表填充值
	pInjectImport->OriginalFirstThunk = FoaToRva(pFileBuffer, (DWORD)pINT - (DWORD)pFileBuffer);
	pInjectImport->Name = FoaToRva(pFileBuffer, (DWORD)pImportByName + 3 + strlen(FounctionName) - (DWORD)pFileBuffer);
	pInjectImport->FirstThunk = FoaToRva(pFileBuffer, (DWORD)pIAT - (DWORD)pFileBuffer);
	*pINT = FoaToRva(pFileBuffer, (DWORD)pImportByName - (DWORD)pFileBuffer);
	*pIAT = FoaToRva(pFileBuffer, (DWORD)pImportByName - (DWORD)pFileBuffer);
	//修改数据目录导入表的值
	pDataDirectory[1].VirtualAddress = FoaToRva(pFileBuffer, (DWORD)pNewImportDescriptor - (DWORD)pFileBuffer);
	pDataDirectory[1].Size += 20;
	//将注入后的exe保存到硬盘中
	isok = MeneryToFile(pFileBuffer, size, FILEPATH_OUT);
	if (isok)
	{
		printf("存盘成功！\n");
	}
	free(pFileBuffer);
	pFileBuffer = NULL;
	return;
}

//查找资源表
void SreachResource()
{
	LPVOID pFileBuffer;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_RESOURCE_DIRECTORY pResourceType = NULL;//资源类型表
	PIMAGE_RESOURCE_DIRECTORY pResourceNumber = NULL;//资源的编号表
	PIMAGE_RESOURCE_DIRECTORY pResourceDirCodePage = NULL;//代码页表
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL;//资源目录项
	PIMAGE_RESOURCE_DATA_ENTRY pResourceData = NULL;//资源节点指针表
	PIMAGE_RESOURCE_DIR_STRING_U pNamew = NULL;
	DWORD size = 0;
	//读取文件
	size = ReadPEFile(FILEPATH_IN, SIZEOFADDSECTION, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("读取文件失败\n");
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionHeader->DataDirectory);
	pResourceType = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pDataDirectory[2].VirtualAddress));
	printf("资源类型总数为：%d\n", pResourceType->NumberOfNamedEntries + pResourceType->NumberOfIdEntries);
	//遍历资源类型表
	for (int i = 0; i < (pResourceType->NumberOfNamedEntries + pResourceType->NumberOfIdEntries); i++)
	{
		pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceType + sizeof(*pResourceType) + (i * 8));
		if (pResourceEntry->NameIsString)
		{
			pNamew = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pResourceEntry->NameOffset));
			wprintf(L"资源类型：%s\n", pNamew->NameString);
		}
		else
		{
			printf("资源类型：%d\n", pResourceEntry->NameOffset);
		}
		pResourceNumber = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceType + pResourceEntry->OffsetToDirectory);
		printf("该类资源数目为：%d\n", pResourceNumber->NumberOfNamedEntries + pResourceNumber->NumberOfIdEntries);
		//遍历资源编号表
		for (int j = 0; j < (pResourceNumber->NumberOfIdEntries + pResourceNumber->NumberOfNamedEntries); j++)
		{
			pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceNumber + sizeof(*pResourceNumber) + (j * 8));
			if (pResourceEntry->NameIsString)
			{
				pNamew = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pResourceEntry->NameOffset));
				wprintf(L"资源编号：%s\n", pNamew->NameString);
			}
			else
			{
				printf("资源编号：%d\n", pResourceEntry->NameOffset);
			}
			pResourceDirCodePage = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceType + pResourceEntry->OffsetToDirectory);
			//遍历代码页表
			for (int k = 0; k < (pResourceDirCodePage->NumberOfIdEntries + pResourceDirCodePage->NumberOfNamedEntries); k++)
			{
				pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceDirCodePage + sizeof(*pResourceDirCodePage) + (k * 8));
				if (pResourceEntry->NameIsString)
				{
					pNamew = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pResourceEntry->NameOffset));
					wprintf(L"代码页：%s\n", pNamew->NameString);
				}
				else
				{
					printf("代码页：%d\n", pResourceEntry->NameOffset);
				}
				//打印真正的资源地址
				pResourceData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResourceType + pResourceEntry->OffsetToDirectory);
				printf("资源地址：%x", pResourceData->OffsetToData);
				printf("资源大小：%x\n", pResourceData->Size);
			}
			printf("-----------------------------------------------------\n");
		}
		printf("-----------------------------------------------------\n");
	}
	free(pFileBuffer);
	pFileBuffer = NULL;
	return;
}
