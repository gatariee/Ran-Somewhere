# Overview
This directory contains the source files used to generate the files in `dist`, the MSVC solution file has been omitted, you may need to specify the resource header file manually if you wish to compile the project yourself.

## Shellcode
The shellcode simply uses the `winsock2` library to send an HTTP GET request to `https://pastebin.com/raw/2xzffw3K` to retrieve a key and searches for a `flag.txt` and XORs the file contents.

This is compiled into position independent shellcode using Donut & [exe2c_sh](https://github.com/gatariee/exe2c_sh) (which is a wrapper around Donut)

The compiled shellcode can be found in C format here: [./implant/shellcode.cpp](./implant/shellcode.cpp)
- This makes it a lot easier to inject using the loader

## Implant
The implant is a shellcode loader that was intentionally broken to prevent it from fully executing, the loader uses the following Win32 API functions:
- `OpenProcess`
    ```cpp
    HANDLE OpenProcess(
        [in] DWORD dwDesiredAccess,
        [in] BOOL  bInheritHandle,
        [in] DWORD dwProcessId
    );
    ```
- `VirtualAllocEx`
    ```cpp
    LPVOID VirtualAllocEx(
        [in]           HANDLE hProcess,
        [in, optional] LPVOID lpAddress,
        [in]           SIZE_T dwSize,
        [in]           DWORD  flAllocationType,
        [in]           DWORD  flProtect
    );
    ```
- `WriteProcessMemory`
    ```cpp
    BOOL WriteProcessMemory(
        [in]  HANDLE  hProcess,
        [in]  LPVOID  lpBaseAddress,
        [in]  LPCVOID lpBuffer,
        [in]  SIZE_T  nSize,
        [out] SIZE_T  *lpNumberOfBytesWritten
    );
    ```

- `CreateRemoteThread`
    ```cpp
    HANDLE CreateRemoteThread(
        [in]  HANDLE                 hProcess,
        [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        [in]  SIZE_T                 dwStackSize,
        [in]  LPTHREAD_START_ROUTINE lpStartAddress,
        [in]  LPVOID                 lpParameter,
        [in]  DWORD                  dwCreationFlags,
        [out] LPDWORD                lpThreadId
    );
    ```

These are dynamically resolved at runtime using `LoadLibraryA` and `GetProcAddress` to prevent the APIs from appearing in the Import Address Table (IAT), although it seems like most who tried this challenge weren't affected by this :(

The broken part of the loader is here on line 231:
```cpp
SIZE_T shellcodeSize = sizeof(*shellcode);
```

This causes the loader to only allocate the size of the pointer to the shellcode instead of the size of the shellcode itself, this causes the loader to only copy allocate `4 bytes` of instead of `~70KB`(can't rmb exact number) of shellcode into the remote process, this causes the shellcode to be truncated and the loader to crash.

## Solution
coming soon :( but the TLDR is to use a debugger to step over the loader and patch the loader to allocate the correct amount of memory for the shellcode, or extract the shellcode from the loader and self-inject it.