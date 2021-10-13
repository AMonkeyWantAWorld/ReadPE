#include "PE.h"

map<DWORD, IMAGE_SECTION_HEADER*> *sectionMap;
DWORD importVA = NULL;
char* pb;

int File_Length(FILE* pf) {
	fseek(pf, 0, SEEK_END);
	int num = ftell(pf);
	fseek(pf, 0, SEEK_SET);
	return num;
}

char* File_Read(const char* p) {
	FILE* pf = fopen(p, "rb");
	int length = File_Length(pf);
	char* pb = (char*)malloc(sizeof(char) * length);
	fread(pb, length, 1, pf);
	createExeData(pb, length);
	return pb;
}

void createExeData(char *pb, int len) {
	std::fstream ioFile;
	char* fileFlag = pb;
	ioFile.open("C:/Users/lenovo/Desktop/data.txt", std::ios::app);
	for (int i = 1; i <= len; i++) {
		char* result = int2Hex(*fileFlag);
		ioFile << result[0] << result[1];
		if ((i % 16) == 0 && i != 0) {
			ioFile << std::endl;
		}
		if ((i % 2) == 0 && i != 0 && (i % 16) != 0) {
			ioFile << " ";
		}
		fileFlag += 1;
	}
	ioFile.close();
}

char *int2Hex(int num) {
	if (num < 0) {
		num = num & 255;
	}

	char* result = new char[2];
	int rounding = floor(num / 16);
	unsigned char highHalf = NULL;
	rounding > 9 && rounding < 16? highHalf = (char)(rounding + 55): highHalf = rounding + '0';
	result[0] = highHalf;

	int remainding = num % 16;
	unsigned char lowHalf = NULL;
	remainding > 9 && remainding < 16? lowHalf = (char)(remainding + 55) : lowHalf = remainding + '0';
	result[1] = lowHalf;
	
	return result;
}

void DirectoryString(DWORD dwIndex)
{
	switch (dwIndex)
	{
	case 0:printf("�����:\t\t");
		break;
	case 1:printf("�����:\t\t");
		break;
	case 2:printf("��Դ:\t\t");
		break;
	case 3:printf("�쳣:\t\t");
		break;
	case 4:printf("��ȫ:\t\t");
		break;
	case 5:printf("�ض�λ:\t\t");
		break;
	case 6:printf("����:\t\t");
		break;
	case 7:printf("��Ȩ:\t\t");
		break;
	case 8:printf("ȫ��ָ��:\t");
		break;
	case 9:printf("TLS��:\t\t");
		break;
	case 10:printf("��������:\t");
		break;
	case 11:printf("���뷶Χ:\t");
		break;
	case 12:printf("IAT:\t\t");
		break;
	case 13:printf("�ӳ�����:\t");
		break;
	case 14:printf("COM:\t\t");
		break;
	case 15:printf("����:\t\t");
		break;
	}
}

//ͨ��RVA����FOA
DWORD Caculer_FOA(DWORD RVA) {
	if (sectionMap->size() == 0) {
		return NULL;
	}
	DWORD FOA;
	map<DWORD, IMAGE_SECTION_HEADER*>::iterator iter;
	iter = sectionMap->begin();
	while (iter != sectionMap->end()) {
		if (RVA < iter->first) {
			iter++;
			continue;
		}
		IMAGE_SECTION_HEADER* sectionTemp = (IMAGE_SECTION_HEADER*)iter->second;
		if (RVA > (sectionTemp->VirtualAddress + sectionTemp->SizeOfRawData)) {
			iter++;
			continue;
		}

		DWORD RSA = RVA - sectionTemp->VirtualAddress;
		FOA = RSA + sectionTemp->PointerToRawData;

		iter++;
	}

	return FOA;
}

//��ȡ�����
void Read_Import() {

	DWORD FOA = Caculer_FOA(importVA);
	cout << "========================�����ͷ========================" << endl;
	printf("dll����\t\t\t\t\t\t   IAT\n");
	int i = 0;
	IMAGE_IMPORT_DESCRIPTOR* importDescription = (IMAGE_IMPORT_DESCRIPTOR*)(pb + FOA);
	while (importDescription[i].Name != 0 && importDescription[i].FirstThunk != 0) {

		DWORD FOA = Caculer_FOA(importDescription[i].Name);
		char* name = (char*)(pb + FOA);

		cout << setw(35) << setiosflags(ios::left) << name;
		cout << hex << "                " << importDescription[i].FirstThunk << endl;
		i ++;
	}

}

//��ȡdos���ݣ���ƫ����
int Read_PE_Header() {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pb;
	cout << "========================DOSͷ========================" << endl;
	cout << "e_magic:" << dosHeader->e_magic << endl;
	cout << "e_lfanew:" << hex << dosHeader->e_lfanew << endl;
	return dosHeader->e_lfanew;
}

//��ȡ������
void Read_Section_Header(int offset, int nums) {
	sectionMap = new map<DWORD, IMAGE_SECTION_HEADER*>();
	IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(pb + offset + sizeof(IMAGE_NT_HEADERS));
	cout << "========================��Ŀ¼========================" << endl;
	printf("������\t\t  RAV\t\t  �ڴ�С\t  ���ڴ����ƫ��\t  �ļ���ʼλ��\n");
	for (int i = 0; i < nums; i++) {
		cout << hex << sectionHeader[i].Name << "\t\t  " << sectionHeader[i].VirtualAddress << "\t\t  " <<
			sectionHeader[i].SizeOfRawData << "\t\t  " << (sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData) << "\t\t\t  " << sectionHeader[i].PointerToRawData << endl;
		sectionMap->insert(map<DWORD, IMAGE_SECTION_HEADER*>::value_type(sectionHeader[i].VirtualAddress, sectionHeader + i));
	}
}

//��ȡntͷ
void Read_NT_Header(int offset) {
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(pb + offset);
	IMAGE_FILE_HEADER fileHeader = ntHeader->FileHeader;
	IMAGE_OPTIONAL_HEADER optionHeader = ntHeader->OptionalHeader;

	cout << "========================NTͷ========================" << endl;
	cout << "NumberOfSections:" << hex << fileHeader.NumberOfSections << endl;
	cout << "AddressOfEntryPoint:" << hex << optionHeader.AddressOfEntryPoint << endl;
	cout << "ImageBase:" << optionHeader.ImageBase << endl;
	cout << "SizeOfImage:" << optionHeader.SizeOfImage << endl;

	Read_DataDirectory(optionHeader, fileHeader.NumberOfSections, offset);
}

//��ȡĿ¼��
void Read_DataDirectory(IMAGE_OPTIONAL_HEADER optionHeader, int num, int offset) {
	cout << "========================Ŀ¼��========================" << endl;
	printf("\t\t  RAV\t\t  ��С\n");
	//����Ŀ¼��
	IMAGE_DATA_DIRECTORY* dataDirectory = optionHeader.DataDirectory;
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		DirectoryString(i);
		if (i == 1) {
			importVA = (dataDirectory + i)->VirtualAddress;
		}
		cout << (dataDirectory + i)->VirtualAddress << "\t\t" << (dataDirectory + i)->Size << endl;
	}

	Read_Section_Header(offset, num);
}

//��ӡ������
void Read_PE(const char *path) {

	FILE *fp = fopen(path, "rb");
	int length = File_Length(fp);
	pb = (char*)malloc(sizeof(char) * length);
	fread(pb, length, 1, fp);

	int offset = Read_PE_Header();

	Read_NT_Header(offset);
	
	Read_Import();
}
