
//
// Created by Brendan Ortiz on 7/23/2024.
//

#include "../include/syscalls.h"

#include <intrin.h>

#include "../include/PeParsing.h"
#include <stdio.h>

#define Ntdll_dll_CRCW 0xf87b6f6b

pSYS_ENTRY_LIST g_SyscallList = NULL;
pBENIGN_ENTRY_LIST g_BenignSyscallList = NULL;
pTAMPERED_SYSCALL g_TamperedSyscall = NULL;

PCRITICAL_SECTION g_CriticalSection = NULL;
PVOID g_VehHandler = NULL;
LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS pExceptionInfo);
volatile unsigned short g_SYSCALL_OPCODE = 0x405D; // 0x050F ^ 0x2325

#if defined(_WIN64)
#define SEARCH_BYTES 0x8b4c
#else
#define SEARCH_BYTES 0x00b8
#endif

BOOL IsPresent(DWORD64 dw64Hash, pBENIGN_ENTRY_LIST pList) {
    for(int i = 0; i < pList->u32Count; i++) {
        if(pList->Entries[i].u32Hash == dw64Hash)
            return TRUE;
    }
    return FALSE;
}

BOOL init() {
    g_TamperedSyscall = (pTAMPERED_SYSCALL)LocalAlloc(LPTR, sizeof(TAMPERED_SYSCALL));
    g_CriticalSection = (PCRITICAL_SECTION)LocalAlloc(LPTR, sizeof(CRITICAL_SECTION));

    if(g_TamperedSyscall == NULL)
        return FALSE;
    if(!PopulateSyscallList())
        return FALSE;
    if(!PopulateBenignSyscallList())
        return FALSE;
    
    return TRUE;
}

BOOL PopulateSyscallList() {

    PIMAGE_EXPORT_DIRECTORY		pExportDirectory		        = NULL;
    PDWORD				        pdwFunctionNameArray		    = NULL;
    PDWORD				        pdwFunctionAddressArray		= NULL;
    PWORD				        pwFunctionOrdinalArray		= NULL;
    HMODULE                    hNtdll                          = NULL;

    if(g_SyscallList == NULL)
        g_SyscallList = (pSYS_ENTRY_LIST)LocalAlloc(LPTR, sizeof(SYS_ENTRY_LIST)); // we do not already have memory reserved for our list

    if(g_SyscallList->u32Count)
        return TRUE; // our list is already populated
    hNtdll = (HMODULE)GetModuleBaseAddr(Ntdll_dll_CRCW);
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)GetExportDirectoryAddress(hNtdll);

    pdwFunctionNameArray	= (PDWORD)((LPBYTE)hNtdll + pExportDirectory->AddressOfNames);
    pdwFunctionAddressArray	= (PDWORD)((LPBYTE)hNtdll + pExportDirectory->AddressOfFunctions);
    pwFunctionOrdinalArray	= (PWORD)((LPBYTE)hNtdll + pExportDirectory->AddressOfNameOrdinals);

    // Store Zw* syscalls addresses
    for (int i = 0; i < pExportDirectory->NumberOfNames; i++){

        LPSTR pFunctionName = (LPSTR)((LPBYTE)hNtdll + pdwFunctionNameArray[i]);

        if (*(unsigned short*)pFunctionName == 'wZ' && g_SyscallList->u32Count <= MAX_ENTRIES) {
            g_SyscallList->Entries[g_SyscallList->u32Count].u32Hash	= HASHA(pFunctionName);
            g_SyscallList->Entries[g_SyscallList->u32Count].uAddress	= (ULONG_PTR)((LPBYTE)hNtdll + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);
            g_SyscallList->u32Count++;
        }
    }

    // Sort Zw* syscalls addresses in ascending order
    // bubble sort addresses.
    for (int i = 0; i < g_SyscallList->u32Count - 0x01; i++){

        for (int j = 0; j < g_SyscallList->u32Count - i - 0x01; j++){

            if (g_SyscallList->Entries[j].uAddress > g_SyscallList->Entries[j + 1].uAddress) {

                SYSCALL_ENTRY TempEntry = { .u32Hash = g_SyscallList->Entries[j].u32Hash, .uAddress = g_SyscallList->Entries[j].uAddress };

                g_SyscallList->Entries[j].u32Hash = g_SyscallList->Entries[j + 1].u32Hash;
                g_SyscallList->Entries[j].uAddress = g_SyscallList->Entries[j + 1].uAddress;

                g_SyscallList->Entries[j + 1].u32Hash = TempEntry.u32Hash;
                g_SyscallList->Entries[j + 1].uAddress = TempEntry.uAddress;

            }
        }
    }

    return TRUE; // populated and sorted.
}

BOOL PopulateBenignSyscallList() {
    PIMAGE_EXPORT_DIRECTORY		pExportDirectory		        = NULL;
    PDWORD				        pdwFunctionNameArray		    = NULL;
    PDWORD				        pdwFunctionAddressArray		= NULL;
    PWORD				        pwFunctionOrdinalArray		= NULL;
    HMODULE                     hNtdll                          = NULL;

    if(g_BenignSyscallList == NULL)
        g_BenignSyscallList = (pBENIGN_ENTRY_LIST)LocalAlloc(LPTR, sizeof(BENIGN_ENTRY_LIST)); // we do not already have memory reserved for our list

    if(g_BenignSyscallList->u32Count)
        return TRUE; // our list is already populated
    hNtdll = (HMODULE)GetModuleBaseAddr(Ntdll_dll_CRCW);
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)GetExportDirectoryAddress(hNtdll);

    pdwFunctionNameArray	= (PDWORD)((LPBYTE)hNtdll + pExportDirectory->AddressOfNames);
    pdwFunctionAddressArray	= (PDWORD)((LPBYTE)hNtdll + pExportDirectory->AddressOfFunctions);
    pwFunctionOrdinalArray	= (PWORD)((LPBYTE)hNtdll + pExportDirectory->AddressOfNameOrdinals);

    //populate our list of benign syscalls.
    for(int i = 0; i < pExportDirectory->NumberOfNames; i++) {
        LPSTR pFunctionName = (LPSTR)((LPBYTE)hNtdll + pdwFunctionNameArray[i]);
        if(*(unsigned short*)pFunctionName == 'wZ') {

            ULONG_PTR uAddress = (ULONG_PTR)((LPBYTE)hNtdll + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);
            DWORD dwBytes = *(unsigned short*)uAddress;
            if((dwBytes & SEARCH_BYTES) == SEARCH_BYTES) { // we've found a benign syscall.
                for(int j = 0; j < 0x20; j++) {
                    dwBytes = *(DWORD*)(uAddress + j);
                    if((dwBytes & 0x000000B8) == 0x000000B8) { // we've found our SSN
                        g_BenignSyscallList->Entries[g_BenignSyscallList->u32Count].u32Hash	= HASHA(pFunctionName);
                        g_BenignSyscallList->Entries[g_BenignSyscallList->u32Count].uAddress	= uAddress;
                        g_BenignSyscallList->Entries[g_BenignSyscallList->u32Count].SSN = *(DWORD*)(uAddress + j + 1);
                        g_BenignSyscallList->u32Count++;
                        break;
                    }
                }
            }
        }
    }

    // sort our list of benign syscalls by SSN instead of address.
    // bubble sort SSNs. This will inherently give us the addresses in the correct order.
    // additionally, the SSN will become the index of the syscall in the list.
    // when we randomly choose a benign syscall to hook, we will use the SSN as the index.
    for (int i = 0; i < g_BenignSyscallList->u32Count - 0x01; i++){

        for (int j = 0; j < g_BenignSyscallList->u32Count - i - 0x01; j++){

            if (g_BenignSyscallList->Entries[j].SSN > g_BenignSyscallList->Entries[j + 1].SSN) {

                BENIGN_SYSCALL_ENTRY TempEntry = { .u32Hash = g_BenignSyscallList->Entries[j].u32Hash, .uAddress = g_BenignSyscallList->Entries[j].uAddress, .SSN = g_BenignSyscallList->Entries[j].SSN };

                g_BenignSyscallList->Entries[j].u32Hash = g_BenignSyscallList->Entries[j + 1].u32Hash;
                g_BenignSyscallList->Entries[j].uAddress = g_BenignSyscallList->Entries[j + 1].uAddress;
                g_BenignSyscallList->Entries[j].SSN = g_BenignSyscallList->Entries[j + 1].SSN;

                g_BenignSyscallList->Entries[j + 1].u32Hash = TempEntry.u32Hash;
                g_BenignSyscallList->Entries[j + 1].uAddress = TempEntry.uAddress;
                g_BenignSyscallList->Entries[j + 1].SSN = TempEntry.SSN;

            }
        }
    }

    return TRUE;
}

DWORD FetchSSNFromSyscallEntries(UINT32 u32Hash) {

    if(!PopulateSyscallList())
        return 0x00;

    for (int i = 0; i < g_SyscallList->u32Count; i++) {
        if (g_SyscallList->Entries[i].u32Hash == u32Hash)
            return i;
    }

    return 0x00;
}

VOID PopulateTamperedSyscall(ULONG_PTR uParam1, ULONG_PTR uParam2, ULONG_PTR uParam3, ULONG_PTR uParam4,
    ULONG_PTR uParam5, ULONG_PTR uParam6, ULONG_PTR uParam7, ULONG_PTR uParam8, ULONG_PTR uParam9, ULONG_PTR uParamA,
    ULONG_PTR uParamB, DWORD dwSyscallNumber, INT Nargs) {

    EnterCriticalSection(g_CriticalSection);
    g_TamperedSyscall->uParam1 = uParam1;
    g_TamperedSyscall->uParam2 = uParam2;
    g_TamperedSyscall->uParam3 = uParam3;
    g_TamperedSyscall->uParam4 = uParam4;
    g_TamperedSyscall->uParam5 = uParam5;
    g_TamperedSyscall->uParam6 = uParam6;
    g_TamperedSyscall->uParam7 = uParam7;
    g_TamperedSyscall->uParam8 = uParam8;
    g_TamperedSyscall->uParam9 = uParam9;
    g_TamperedSyscall->uParamA = uParamA;
    g_TamperedSyscall->uParamB = uParamB;
    g_TamperedSyscall->dwSyscallNumber = dwSyscallNumber;
    g_TamperedSyscall->Nargs = Nargs;

    LeaveCriticalSection(g_CriticalSection);

}

BOOL InitHardwareBreakpointHooking() {
    if(g_VehHandler)
        return TRUE;

    InitializeCriticalSection(g_CriticalSection);

    if(!(g_VehHandler = AddVectoredExceptionHandler(0x01, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandlerCallbackRoutine))) {
        return FALSE;
    }

    return TRUE;
}

BOOL HaltHardwareBreakpointHooking() {
    DeleteCriticalSection(g_CriticalSection);

    if(g_VehHandler) {
        if(RemoveVectoredExceptionHandler(g_VehHandler) == 0x00) {
            return FALSE;
        }

        return TRUE;
    }
    return FALSE;
}

unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
    unsigned long long mask			    = (1UL << NmbrOfBitsToModify) - 1UL;
    unsigned long long NewDr7Register	= (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);
    return NewDr7Register;
}

/*
 TODO : Implement this function in a way that uses a list of benign functions chosen at random to hook to avoid detection.
 Once the syscall is used, the hook should be removed
 and then a new syscall should be chosen at random to hook.
*/
BOOL InstallHardwareBreakpointHook(_In_ DWORD dwThreadID, _In_ ULONG_PTR uTargetFuncAddress) {
    CONTEXT Context = {.ContextFlags = CONTEXT_DEBUG_REGISTERS};
    HANDLE hThread = NULL;
    BOOL bResult = FALSE;

    //TODO : use indirect syscalls and native functions for this for uber stealth.
    if(!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID))) {
        goto _END_OF_FUNC;
    }

    if(!GetThreadContext(hThread, &Context)) {
        goto _END_OF_FUNC;
    }

    Context.Dr0 = uTargetFuncAddress;
    Context.Dr6 = 0x00;
    Context.Dr7 = SetDr7Bits(Context.Dr7, 0x10, 0x02, 0x00); // Clear the local and global exact breakpoints
    Context.Dr7 = SetDr7Bits(Context.Dr7, 0x12, 0x02, 0x00); // Clear the local and global exact breakpoints
    Context.Dr7 = SetDr7Bits(Context.Dr7, 0x00, 0x01, 0x01); // Set the local exact breakpoint

    if(!SetThreadContext(hThread, &Context))
        goto _END_OF_FUNC;

    bResult = TRUE;

    _END_OF_FUNC:
    if(hThread)
        CloseHandle(hThread);

    return bResult;
}

BOOL InitializeTamperedSyscall(_In_ ULONG_PTR uCalledSyscallAddress, _In_ UINT32 FunctionHash, _In_ INT Nargs,  _In_ ULONG_PTR uParam1, _In_ ULONG_PTR uParam2, _In_ ULONG_PTR uParam3, _In_ ULONG_PTR uParam4, ULONG_PTR uParam5, ULONG_PTR uParam6, ULONG_PTR uParam7, ULONG_PTR uParam8, ULONG_PTR uParam9, ULONG_PTR uParamA, ULONG_PTR uParamB) {

   if(!uCalledSyscallAddress || !FunctionHash)
       return FALSE;

    PVOID pDecoySyscallInstructionAdd = NULL;
    DWORD dwRealSyscallNumber = 0x00;

    for(int i = 0; i < 0x20; i++) {
        unsigned short opcodes = *(unsigned short*)(uCalledSyscallAddress + i);
        if(opcodes == (0x4552 ^ g_SYSCALL_OPCODE)) {
            pDecoySyscallInstructionAdd = (PVOID)(uCalledSyscallAddress + i);
            break;
        }
    }

    if(!pDecoySyscallInstructionAdd)
        return FALSE;

    if(!(dwRealSyscallNumber = FetchSSNFromSyscallEntries(FunctionHash)))
        return FALSE;

    PopulateTamperedSyscall(uParam1, uParam2, uParam3, uParam4, uParam5, uParam6, uParam7, uParam8, uParam9, uParamA, uParamB, dwRealSyscallNumber, Nargs);

    if(!InstallHardwareBreakpointHook(GetCurrentThreadId(), (ULONG_PTR)pDecoySyscallInstructionAdd))
        return FALSE;

    return TRUE;
}

LONG ExceptionHandlerCallbackRoutine(IN PEXCEPTION_POINTERS pExceptionInfo) {
    BOOL bResolved = FALSE;

    if(pExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        goto _EXIT_ROUTINE;

    if((ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress != pExceptionInfo->ContextRecord->Dr0)
        goto _EXIT_ROUTINE;

    EnterCriticalSection(g_CriticalSection);

    printf("[info ssn] : 0x%04X\n", g_TamperedSyscall->dwSyscallNumber);
    printf("[info param1] : 0x%llx\n", g_TamperedSyscall->uParam1);
    printf("[info param2] : 0x%llx\n", g_TamperedSyscall->uParam2);
    printf("[info param3] : 0x%llx\n", g_TamperedSyscall->uParam3);
    printf("[info param4] : 0x%llx\n", g_TamperedSyscall->uParam4);

    //Replace Decoy SSN
    pExceptionInfo->ContextRecord->Rax = (DWORD64)g_TamperedSyscall->dwSyscallNumber;
    // replace decoy parms
    pExceptionInfo->ContextRecord->R10 = g_TamperedSyscall->uParam1;
    pExceptionInfo->ContextRecord->Rdx = g_TamperedSyscall->uParam2;
    pExceptionInfo->ContextRecord->R8 = g_TamperedSyscall->uParam3;
    pExceptionInfo->ContextRecord->R9 = g_TamperedSyscall->uParam4;

    //stack content BEFORE the swap
    printf("stack content before modification\n");
    printf("[info] rsp : 0x%llx\n", pExceptionInfo->ContextRecord->Rsp);
    printf("[info] RSP+8 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x08));
    printf("[info] RSP+10 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x10));
    printf("[info] RSP+18 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x18));
    printf("[info] RSP+20 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x20));
    printf("[info] RSP+28 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x28));
    printf("[info] RSP+30 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x30));
    printf("[info] RSP+38 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x38));
    printf("[info] RSP+40 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x40));
    printf("[info] RSP+48 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x48));
    printf("[info] RSP+50 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x50));
    printf("[info] RSP+58 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x58));


    // replace decoy parms on stack if needed.
    if(g_TamperedSyscall->Nargs > 4) {
        printf("stack content after modification\n");
        *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x28) = g_TamperedSyscall->uParam5;
        *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x30) = g_TamperedSyscall->uParam6;
        *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x38) = g_TamperedSyscall->uParam7;
        *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x40) = g_TamperedSyscall->uParam8;
        *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x48) = g_TamperedSyscall->uParam9;
        *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x50) = g_TamperedSyscall->uParamA;
        *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x58) = g_TamperedSyscall->uParamB;

        printf("[info] rsp : 0x%llx\n", pExceptionInfo->ContextRecord->Rsp);
        printf("[info] RSP+8 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x08));
        printf("[info] RSP+10 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x10));
        printf("[info] RSP+18 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x18));
        printf("[info] RSP+20 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x20));
        printf("[info] RSP+28 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x28));
        printf("[info] RSP+30 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x30));
        printf("[info] RSP+38 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x38));
        printf("[info] RSP+40 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x40));
        printf("[info] RSP+48 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x48));
        printf("[info] RSP+50 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x50));
        printf("[info] RSP+58 : 0x%llx\n", *(unsigned long long*)(pExceptionInfo->ContextRecord->Rsp + 0x58));
    }


    //remove breakpoint
    pExceptionInfo->ContextRecord->Dr0 = 0ull;





    LeaveCriticalSection(g_CriticalSection);

    bResolved = TRUE;

    _EXIT_ROUTINE:
    return (bResolved ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH);
}

