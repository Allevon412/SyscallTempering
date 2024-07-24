//
// Created by Brendan Ortiz on 7/23/2024.
//

#include "../include/PeParsing.h"

UINT32 CRC32BW(IN LPCWSTR String){

    UINT32      uMask	= 0x00,
                uHash	= 0xFFFFEFFF;
    INT         i		= 0x00;

    while (String[i] != 0) {

        uHash = uHash ^ (UINT32)String[i];

        for (int ii = 0; ii < 8; ii++) {

            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
        }

        i++;
    }

    return ~uHash;
}

UINT32 CRC32BA(IN LPCSTR String){

    UINT32      uMask	= 0x00,
                uHash	= 0xFFFFEFFF;
    INT         i		= 0x00;

    while (String[i] != 0) {

        uHash = uHash ^ (UINT32)String[i];

        for (int ii = 0; ii < 8; ii++) {

            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
        }

        i++;
    }

    return ~uHash;
}





PVOID GetExportDirectoryAddress(HMODULE hModule)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + dosHeader->e_lfanew);
    DWORD exportDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG_PTR imageExportDirectory = (ULONG_PTR)hModule + exportDirectoryRVA;

    return (PVOID)imageExportDirectory;
}

PVOID GetModuleBaseAddr(_In_ UINT32 Hash)
{
    P_INT_LDR_DATA_TABLE_ENTRY Ldr = NULL;
    PLIST_ENTRY Hdr = NULL;
    PLIST_ENTRY Ent = NULL;
    P_INT_PEB Peb = NULL;

    PTEB teb = (PTEB)__readgsqword(0x30);

    Peb = (P_INT_PEB)teb->ProcessEnvironmentBlock;
    Hdr = &Peb->Ldr->InMemoryOrderLinks;
    Ent = Hdr->Flink;

    // cycle through the doubly linked list until we reach the first link.
    for (; Hdr != Ent; Ent = Ent->Flink)
    {
        Ldr = (P_INT_LDR_DATA_TABLE_ENTRY)Ent;

        if ((HASHW(Ldr->BaseDllName.Buffer) == Hash) || Hash == 0)
            return Ldr->DllBase;

    }

    return NULL;

}