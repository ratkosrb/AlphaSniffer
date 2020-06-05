// Injection code based on: https://www.codeproject.com/Articles/20240/The-Beginners-Guide-to-Codecaves

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <fcntl.h>
#include <stdio.h>
#include <io.h>
#include "opcodes.h"

// Codecave function
VOID Codecave(DWORD destAddress, VOID(*func)(VOID), BYTE nopCount);

// Writes bytes in the current process using an ASM method
VOID WriteBytesASM(DWORD destAddress, LPVOID patch, DWORD numBytes);

// Create a console
VOID CreateConsole();

#define NETCLIENT_HANDLEDATA 0x0054E560

// This variable holds the return address, it must be global!
DWORD g_returnAddress = 0;

unsigned int g_timeReceived = 0;
void* g_data = nullptr;
int g_size = 0;

void PrintIncomingPacket()
{
    printf("[ServerToClient] Time %u, Size %i\n", g_timeReceived, g_size);
    int i = 0;
    if (g_size >= 4)
    {
        char const* name = "UNKNOWN";
        unsigned int opcode = *((unsigned int*)g_data);
        auto itr = g_opcodes.find(opcode);
        if (itr != g_opcodes.end())
            name = itr->second;
        printf("Opcode: %u %s\n", opcode, name);
        i = 4;
    }
    printf("Data:\n");
    for (int j = 0; i < g_size; i++)
    {
        j++;
        unsigned int byte = *(((unsigned char*)g_data) + i);
        printf("%02x", byte);

        // bytes per line to print
        if (j == 20)
        {
            printf("\n");
            j = 0;
        }
        else
            printf(" ");
    }
    printf("\n\n");
}

int g_registerEax;

__declspec(naked) void HandleDataHook(void)
{
    __asm
    {
        pop g_returnAddress;

        mov g_registerEax, eax;

        mov eax, [esp + 4];
        mov g_timeReceived, eax;

        mov eax, [esp + 8];
        mov g_data, eax;

        mov eax, [esp + 0Ch];
        mov g_size, eax;

        mov eax, g_registerEax;

        PUSHAD;
        PUSHFD;
    }

    PrintIncomingPacket();

    __asm
    {
        POPFD;
        POPAD;

        push    ebp;
        mov     ebp, esp;
        sub     esp, 18h;

        push g_returnAddress;
        ret;
    }
}

//-----------------------------------------------------------------------------

// Define the plugins main, use a define since the code is the same for all plugins
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved)
{
    // Get rid of compiler warnings since we do not use this parameter
    UNREFERENCED_PARAMETER(lpReserved);

    // If we are attaching to a process, we do not want the dll thread messages
    if (ulReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hModule);

    // We will place a codecave at this address
    Codecave(NETCLIENT_HANDLEDATA, HandleDataHook, 1);

    // Create a console since we are in a DLL
    CreateConsole();

    // Always load/unload
    return TRUE;
}

//-----------------------------------------------------------------------------

// Writes bytes in the current process using an ASM method
VOID WriteBytesASM(DWORD destAddress, LPVOID patch, DWORD numBytes)
{
    // Store old protection of the memory page
    DWORD oldProtect = 0;

    // Store the source address
    DWORD srcAddress = PtrToUlong(patch);

    // Make sure page is writeable
    VirtualProtect((void*)(destAddress), numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Do the patch (oldschool style to avoid memcpy)
    __asm
    {
        nop						// Filler
        nop						// Filler
        nop						// Filler

        mov esi, srcAddress		// Save the address
        mov edi, destAddress	// Save the destination address
        mov ecx, numBytes		// Save the size of the patch
    Start :
        cmp ecx, 0				// Are we done yet?
        jz Exit					// If so, go to end of function

        mov al, [esi]			// Move the byte at the patch into AL
        mov[edi], al			// Move AL into the destination byte
        dec ecx					// 1 less byte to patch
        inc esi					// Next source byte
        inc edi					// Next destination byte
        jmp Start				// Repeat the process
    Exit :
        nop						// Filler
        nop						// Filler
        nop						// Filler
    }

    // Restore old page protection
    VirtualProtect((void*)(destAddress), numBytes, oldProtect, &oldProtect);
}

//-----------------------------------------------------------------------------

// Codecave function
VOID Codecave(DWORD destAddress, VOID(*func)(VOID), BYTE nopCount)
{
    // Calculate the code cave for chat interception
    DWORD offset = (PtrToUlong(func) - destAddress) - 5;

    // Buffer of NOPs, static since we limit to 'UCHAR_MAX' NOPs
    BYTE nopPatch[0xFF] = { 0 };

    // Construct the patch to the function call
    BYTE patch[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    memcpy(patch + 1, &offset, sizeof(DWORD));
    WriteBytesASM(destAddress, patch, 5);

    // We are done if we do not have NOPs
    if (nopCount == 0)
        return;

    // Fill it with nops
    memset(nopPatch, 0x90, nopCount);

    // Make the patch now
    WriteBytesASM(destAddress + 5, nopPatch, nopCount);
}

//-----------------------------------------------------------------------------

// Create a console (this code is not mine, taken from online)
VOID CreateConsole()
{
    int hConHandle = 0;
    HANDLE lStdHandle = 0;
    FILE* fp = 0;

    // Allocate a console
    AllocConsole();

    // redirect unbuffered STDOUT to the console
    lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
    fp = _fdopen(hConHandle, "w");
    *stdout = *fp;
    setvbuf(stdout, NULL, _IONBF, 0);

    // redirect unbuffered STDIN to the console
    lStdHandle = GetStdHandle(STD_INPUT_HANDLE);
    hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
    fp = _fdopen(hConHandle, "r");
    *stdin = *fp;
    setvbuf(stdin, NULL, _IONBF, 0);

    // redirect unbuffered STDERR to the console
    lStdHandle = GetStdHandle(STD_ERROR_HANDLE);
    hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
    fp = _fdopen(hConHandle, "w");
    *stderr = *fp;
    setvbuf(stderr, NULL, _IONBF, 0);
}