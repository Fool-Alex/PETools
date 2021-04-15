#include "Shell.h"

#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )


HANDLE hProcess = 0;
HANDLE hThread = 0;

// 顶级异常筛选函数，不能把功能代码放在这个函数内（会死循环）,非调试模式下回运行这里的代码
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS pExcept)
{
	// 跳过下面两行代码：
	// 8900    MOV DWORD PTR DS:[EAX], EAX  
	// FFE0    JMP EAX  
	pExcept->ContextRecord->Eip += 4;

	// 忽略异常，否则程序会退出
	return EXCEPTION_CONTINUE_EXECUTION;
}

//将内存中的数据写入硬盘中
BOOL MeneryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	//检测传入指针是否为空
	if (!pMemBuffer)
	{
		MessageBox(NULL, L"缓存区指针无效！", L"错误", MB_OK);
		return 0;
	}
	FILE* pFile = NULL;
	if ((pFile = fopen(lpszFile, "wb+")) == NULL)
	{
		MessageBox(NULL, L"无法打开文件！", L"错误", MB_OK);
		return 0;
	}
	fwrite(pMemBuffer, 1, size, pFile);
	fclose(pFile);
	pFile = NULL;
	return size;
}

int main()
{
	//反调试
	// 接管顶级异常处理程序
	SetUnhandledExceptionFilter(ExceptionFilter);
	// 主动制造 "非法地址" 异常，防止程序被调试	mov dword ptr [eax], eax
	__asm {
		xor eax, eax
		mov dword ptr[eax], eax
		jmp eax
	}
    LPVOID pFileBuffer = NULL;
    DWORD file_size = 0;
    TCHAR FilePathSelfW[MAX_PATH];//获取自身路径
	char FilePathSelfA[MAX_PATH];
    GetModuleFileName(NULL, FilePathSelfW, MAX_PATH);
	TcharToChar(FilePathSelfW, FilePathSelfA);
	file_size = ReadPEFile(FilePathSelfA, 0, &pFileBuffer);
	DWORD SizeOfLastSec = 0;
	DWORD SrcImageBase = 0;
	LPVOID pSrcFileBuffer = NULL;
	LPVOID pSrcImageBuffer = NULL;
	DWORD SrcOEP = 0;
	//获取源文件的信息
	BOOL HasRolocationTable = GetSrcInfo(pFileBuffer, &SizeOfLastSec, &SrcImageBase, &SrcOEP, &pSrcFileBuffer);
	//创建进程
	PROCESS_INFORMATION src_pi = { 0 };
	src_pi = CreateProcessSuspend(FilePathSelfA);
	hProcess = src_pi.hProcess;
	hThread = src_pi.hThread;
	if (hProcess == hThread)
		return 0;

	UnmapShell(hProcess, GetProcessImageBase(src_pi));
	LPVOID lpAddress = VirtualAllocate(hProcess, (PVOID)GetProcessImageBase(src_pi), SizeOfLastSec);
	if (lpAddress)
	{
		if ((DWORD)lpAddress == SrcImageBase)
			printf("初始ImageBase申请内存成功, 修改baseAddress, EntryPoint.\n");
		else
		{
			printf("申请成功, 但ImageBase改变了\n");
			if (!HasRolocationTable)
				printf("当前文件无重定位表, 无需修改.\n");
			else
			{
				printf("当前文件需要修复重定位表，暂时无法加壳！");
				free(pFileBuffer);
				free(pSrcFileBuffer);
				free(pSrcImageBuffer);
				free(lpAddress);
				return 0;
				//RestoreRelocation((DWORD)lpAddress);
				//printf("已修复重定位表.\n");
			}
		}
		//将文件Buffer转化为ImageBuffer
		DWORD SizeOfSrcImage = 0;
		SizeOfSrcImage = CopyFileBufferToImageBuffer(pSrcFileBuffer, &pSrcImageBuffer);
		DWORD sizeOfWritten = 0;
		if (!WriteProcessMemory(hProcess, lpAddress, pSrcImageBuffer, SizeOfSrcImage, &sizeOfWritten))
		{
			printf("文件写入失败. 原因: %d\n", (int)GetLastError());
			free(pFileBuffer);
			free(pSrcFileBuffer);
			free(pSrcImageBuffer);
			return 0;
		}
		//修改ImageBase EntryPoint
		CONTEXT context = GetThreadContext(hThread);
		WriteProcessMemory(hProcess, (LPVOID)(context.Ebx + 8), &lpAddress, 4, NULL);
		context.Eax = SrcOEP + (DWORD)lpAddress;
		context.ContextFlags = CONTEXT_FULL;
		SetThreadContext(hThread, &context);
		ResumeThread(hThread);
		printf("GetLastError: %d\n", (int)GetLastError());
		CloseHandle(src_pi.hProcess);
		CloseHandle(src_pi.hThread);
		free(pFileBuffer);
		free(pSrcFileBuffer);
		free(pSrcImageBuffer);
		return 0;
	}
	else
		printf("没有足够空间, 程序退出.");
	CloseHandle(src_pi.hProcess);
	CloseHandle(src_pi.hThread);
	return 0;
}

//TCHAR数组转为CHAR数组
void TcharToChar(const TCHAR* tchar, char* _char)
{
	int iLength;
	//获取字节长度   
	iLength = WideCharToMultiByte(CP_ACP, 0, tchar, -1, NULL, 0, NULL, NULL);
	//将tchar值赋给_char    
	WideCharToMultiByte(CP_ACP, 0, tchar, -1, _char, iLength, NULL, NULL);
}

//读取文件
DWORD ReadPEFile(IN LPSTR lpszFile, IN DWORD offset, OUT LPVOID* pFileBuffer)
{
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	//打开文件
	pFile = fopen(lpszFile, "rb");
	if (!pFile)
	{
		MessageBox(NULL, L"无法打开EXE文件！", L"错误", MB_OK);
		return 0;
	}
	//读取文件大小
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile) + offset;
	fseek(pFile, 0, SEEK_SET);
	//分配缓冲区
	*pFileBuffer = malloc(fileSize);
	memset(*pFileBuffer, 0, fileSize);
	if (!(*pFileBuffer))
	{
		MessageBox(NULL, L"分配空间失败！", L"错误", MB_OK);
		fclose(pFile);
		return 0;
	}
	//将文件数据读取到缓冲区
	size_t n = fread(*pFileBuffer, fileSize - offset, 1, pFile);
	if (!n)
	{
		MessageBox(NULL, L"读取数据失败！", L"错误", MB_OK);
		free(*pFileBuffer);
		fclose(pFile);
		return 0;
	}
	//关闭文件
	fclose(pFile);
	pFile = NULL;
	return fileSize;
}


//复制FileBuffer到ImageBuffer
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	LPVOID pNewBuffer = NULL;
	//检测传入指针是否为空
	if (!pFileBuffer)
	{
		MessageBox(NULL, L"缓存区指针无效！", L"错误", MB_OK);
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
		MessageBox(NULL, L"不是有效MZ标志！", L"错误", MB_OK);
		free(pFileBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//分配ImageBuffer内存
	*pImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (!*pImageBuffer)
	{
		MessageBox(NULL, L"分配ImageBuffer错误！", L"错误", MB_OK);
		free(*pImageBuffer);
		return 0;
	}
	pNewBuffer = *pImageBuffer;
	memset(pNewBuffer, 0, pOptionHeader->SizeOfImage);
	//从FileBuffer复制到ImageBuffer
	memcpy(pNewBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	for (DWORD j = 0; j < pPEHeader->NumberOfSections; j++)
	{
		memcpy((char*)pNewBuffer + pSectionHeader->VirtualAddress, (char*)pFileBuffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	return (pOptionHeader->SizeOfImage);
}


//获取源文件的信息
BOOL GetSrcInfo(LPVOID pFileBuffer, DWORD* SizeOfLastSec, DWORD* SrcImageBase, DWORD* SrcOEP, LPVOID* pSrcFileBuffer)
{
	//检测传入指针是否为空
	if (!pFileBuffer)
	{
		MessageBox(NULL, L"缓存区指针无效！", L"错误", MB_OK);
		return 0;
	}
	//初始化dos、标准PE、可选PE和节表4个结构体指针
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	//判断是否是有效的MZ标志
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		MessageBox(NULL, L"不是有效MZ标志！", L"错误", MB_OK);
		free(pFileBuffer);
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)&pOptionHeader->NumberOfRvaAndSizes + 4);
	//获取源文件的buffer
	LPVOID EncryptedSrc = NULL;
	LPVOID DecryptedSrc = NULL;
	EncryptedSrc = (LPBYTE)pFileBuffer + (pSectionHeader + pPEHeader->NumberOfSections - 1)->PointerToRawData;
	//解密数据
	DecryptedSrc = Xor(EncryptedSrc, (pSectionHeader + pPEHeader->NumberOfSections - 1)->Misc.VirtualSize);
	if (!(*(CHAR*)DecryptedSrc))
	{
		MessageBox(NULL, L"解密文件失败！", L"错误", MB_OK);
		free(pFileBuffer);
		return 0;
	}
	//Sleep(1000);
	*pSrcFileBuffer = DecryptedSrc;
	//获取源程序信息
	pDosHeader = (PIMAGE_DOS_HEADER)DecryptedSrc;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)DecryptedSrc + pDosHeader->e_lfanew + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	*SizeOfLastSec = pOptionHeader->SizeOfImage;
	*SrcImageBase = pOptionHeader->ImageBase;
	*SrcOEP = pOptionHeader->AddressOfEntryPoint;
	if (*(DWORD*)(pOptionHeader->DataDirectory + 5))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
// 
//以挂起的方式创建进程
PROCESS_INFORMATION CreateProcessSuspend(LPSTR processName)
{
	STARTUPINFOA src_si = { 0 };
	PROCESS_INFORMATION src_pi;
	src_si.cb = sizeof(src_si);

	//以挂起的方式创建进程						
	CreateProcessA(
		NULL,                    // name of executable module					
		processName,                // command line string					
		NULL, 					 // SD
		NULL,  		             // SD			
		FALSE,                   // handle inheritance option					
		CREATE_SUSPENDED,     	 // creation flags  				
		NULL,                    // new environment block					
		NULL,                    // current directory name					
		&src_si,                  // startup information					
		&src_pi                   // process information					
	);
	return src_pi;
}

//卸载进程内容
DWORD UnmapShell(HANDLE hProcess, DWORD shellImageBase)
{
	HMODULE hModuleNt = LoadLibraryA("ntdll.dll");
	if (!hModuleNt)
	{
		printf("获取ntdll失败\n");
		TerminateProcess(hProcess, 1);
		return 0;
	}

	// 调用 ZwUnmapViewOfSection 卸载新进程内存镜像
	NtUnmapViewOfSection(hProcess, (PVOID)shellImageBase);
	FreeLibrary(hModuleNt);
	return 1;
}

//获取进程基址
DWORD GetProcessImageBase(PROCESS_INFORMATION procInfo)
{
	char* baseAddress = (CHAR*)GetThreadContext(procInfo.hThread).Ebx + 8;
	DWORD ImageBase = 0;

	ReadProcessMemory(procInfo.hProcess, baseAddress, &ImageBase, 4, NULL);
	return ImageBase;
}

//获取线程Context信息
CONTEXT GetThreadContext(HANDLE hThread)
{
	CONTEXT ct;

	ct.ContextFlags = CONTEXT_FULL;
	//获取主线程信息 ImageBase 入口点	
	GetThreadContext(hThread, &ct);
	return ct;
}

//创建内存到指定位置
LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t)
{
	HMODULE hModuleKernel = LoadLibraryA("kernel32.dll");
	if (!hModuleKernel)
	{
		printf("获取kernel失败\n");
		TerminateProcess(hProcess, 1);
		return NULL;
	}
	typedef void* (__stdcall* pfVirtualAllocEx)(
		HANDLE hProcess,
		LPVOID lpAddress,
		DWORD dwSize,
		DWORD flAllocationType,
		DWORD flProtect);
	pfVirtualAllocEx VirtualAllocEx = NULL;
	VirtualAllocEx = (pfVirtualAllocEx)GetProcAddress((hModuleKernel), "VirtualAllocEx");
	if (!VirtualAllocEx(
		hProcess,
		pAddress,
		size_t,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	))
	{
		//如果不成功, 这里会报487内存访问错误, 很正常, 因为申请源地址有东西
		printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase被占用, 将随机申请空间. 请修复重定位表");
		LPVOID newImageBase = NULL;
		if ((newImageBase = VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		printf("没有足够空间");
		return NULL;
	}

	FreeLibrary(hModuleKernel);
	return pAddress;
}

LPVOID Xor(IN LPVOID pBuffer, DWORD size)
{
	//DWORD count = 0;
	char* pNewBuffer = NULL;
	if (!(pNewBuffer = (char*)malloc(size)))
		return NULL;
	char* pTmp = (char*)pBuffer;
	for (DWORD i = 0; i < size; i++)
	{
		*pNewBuffer = *((char*)pTmp) ^ 0x2;
		pTmp++;
		pNewBuffer++;
	}
	return (LPVOID)((DWORD)pNewBuffer - size);
}

