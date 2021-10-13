#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include <string>
#include <map>
#include <iomanip>
#include <fstream>

using namespace std;

char* File_Read(const char* p);
void createExeData(char* pb, int len);
char* int2Hex(int num);
int Read_PE_Header();
void Read_PE(const char *);
void Read_NT_Header(int offset);
void Read_DataDirectory(IMAGE_OPTIONAL_HEADER optionHeader, int num, int offset);
