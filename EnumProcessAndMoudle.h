#pragma once
#include "PETools.h"

void InitProcessListView(HWND hwndDlg);//初始化进程的ListView
void InitMoudleListView(HWND hwndDlg);//初始化模块的ListView
void EnumProcess(HWND hListProcess);//遍历进程
void EnumMoudle(HWND hListProcess, HWND hListModules);//遍历模块

