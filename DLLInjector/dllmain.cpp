// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#define DLLEXPORT extern "C" __declspec(dllexport)
#define COMMITRESERVE MEM_COMMIT | MEM_RESERVE

using fnLoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using fnGetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using fnDllEntryPoint = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct DATA {
    void* LoadLibraryA;
    void* GetProcAddress;
    BYTE* BaseAddress;
};

void __stdcall RunShellCode(DATA* Data);

DLLEXPORT bool ManualMapEasy(HANDLE Targ, BYTE* bytesrc_code)
{
    if (reinterpret_cast<IMAGE_DOS_HEADER*>(bytesrc_code)->e_magic != 0x5A4D) {
        cout << "Not Founded MZ Header!!!" << endl;
        return false;
    }
    IMAGE_NT_HEADERS* ntHead = reinterpret_cast<IMAGE_NT_HEADERS*>(bytesrc_code + reinterpret_cast<IMAGE_DOS_HEADER*>(bytesrc_code)->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optionalHeader = &ntHead->OptionalHeader;
    IMAGE_FILE_HEADER* fileHeader = &ntHead->FileHeader;
    if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
        cout << "Not Founded IMAGE_FILE_MACHINE_AMD64 Machine!!!" << endl;
        return false;
    }
    BYTE* targetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(Targ, nullptr, optionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    BYTE* mappingData = reinterpret_cast<BYTE*>(VirtualAllocEx(Targ, nullptr, sizeof(DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    BYTE* shellcode = reinterpret_cast<BYTE*>(VirtualAllocEx(Targ, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    DATA mappingInfo{ 0 };
    mappingInfo.LoadLibraryA = LoadLibraryA;
    mappingInfo.GetProcAddress = GetProcAddress;
    mappingInfo.BaseAddress = targetBase;
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHead);
    for (UINT i = 0; i < fileHeader->NumberOfSections; ++i, ++fileHeader) {
        if (sectionHeader->SizeOfRawData) {
            cout << "Name: " << sectionHeader->Name << "VirtualAddress: " << sectionHeader->VirtualAddress << endl;
            WriteProcessMemory(Targ, targetBase + sectionHeader->VirtualAddress, bytesrc_code + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, nullptr);
        }
    }
    WriteProcessMemory(Targ, targetBase, bytesrc_code, optionalHeader->SizeOfHeaders, nullptr);
    WriteProcessMemory(Targ, mappingData, &mappingInfo, sizeof(DATA), nullptr);
    WriteProcessMemory(Targ, shellcode, RunShellCode, 0x1000, nullptr);
    CreateRemoteThread(Targ, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode), mappingData, 0, 0);
    cout << "Successfully Injected!!!" << endl;
    return true;
}

void __stdcall RunShellCode(DATA* Data) 
{
    BYTE* baseAddress = Data->BaseAddress;
    auto* ntHeaders = &reinterpret_cast<IMAGE_NT_HEADERS*>(baseAddress + reinterpret_cast<IMAGE_DOS_HEADER*>(baseAddress)->e_lfanew)->OptionalHeader;
    auto* entryPoint = reinterpret_cast<fnDllEntryPoint>(baseAddress + ntHeaders->AddressOfEntryPoint);
    BYTE* relocationDelta = baseAddress + ntHeaders->ImageBase;

    if (relocationDelta && ntHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(baseAddress + ntHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* relocationEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(relocation) + ntHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (relocation < relocationEnd && relocation->SizeOfBlock) {
            UINT entryCount = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relativeInfo = reinterpret_cast<WORD*>(relocation + 1);

            for (UINT i = 0; i < entryCount; ++i, ++relativeInfo) {
                if ((*relativeInfo >> 12) == IMAGE_REL_BASED_DIR64) {
                    auto* patchAddress = reinterpret_cast<UINT_PTR*>(baseAddress + relocation->VirtualAddress + (*relativeInfo & 0xFFF));
                    *patchAddress += reinterpret_cast<UINT_PTR>(relocationDelta);

                }
                relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(relocation) + relocation->SizeOfBlock);
            }
        }
    }

    if (ntHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(baseAddress + ntHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDescriptor->Name) {
            char* modName = reinterpret_cast<char*>(baseAddress + importDescriptor->Name);
            HINSTANCE moduleHandle = reinterpret_cast<fnLoadLibraryA>(Data->LoadLibraryA)(modName);

            auto* thunkRef = reinterpret_cast<ULONG_PTR*>(baseAddress + importDescriptor->OriginalFirstThunk);
            auto* funcRef = reinterpret_cast<ULONG_PTR*>(baseAddress + importDescriptor->FirstThunk);

            if (!thunkRef) {
                thunkRef = funcRef;
            }

            for (; *thunkRef; ++thunkRef, ++funcRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                    *funcRef = reinterpret_cast<ULONG_PTR>(reinterpret_cast<fnGetProcAddress>(Data->GetProcAddress)(moduleHandle, reinterpret_cast<char*>(*thunkRef)));
                }
                else {
                    auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(baseAddress + (*thunkRef));
                    *funcRef = reinterpret_cast<ULONG_PTR>(reinterpret_cast<fnGetProcAddress>(Data->GetProcAddress)(moduleHandle, importByName->Name));
                }
            }
            ++importDescriptor;
        }

        entryPoint(baseAddress, DLL_PROCESS_ATTACH, nullptr);
    }
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

