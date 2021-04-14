#pragma once
#include "PETools.h"

void InitProcessListView(HWND hwndDlg);//初始化进程的ListControl
void InitMoudleListView(HWND hwndDlg);//初始化模块的ListControl
void EnumProcess(HWND hListProcess);//遍历进程
void EnumMoudle(HWND hListProcess, HWND hListModules);//遍历模块

