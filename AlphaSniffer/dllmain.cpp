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

#define CLIENT_BUILD_0_5_3 3368
#define CLIENT_BUILD_1_12_1 5875
#define CLIENT_BUILD_2_4_3 8606
#define CLIENT_BUILD_3_3_5 12340

// Alpha 0.5.3
#define NETCLIENT_HANDLEDATA_0_5_3 0x0054E560

// Vanilla 1.12.1
#define NETCLIENT_HANDLEDATA_1_12_1 0x00537C50

// TBC 2.4.3
#define NETCLIENT_HANDLEDATA_2_4_3 0x0055F9A0

// Wotlk 3.3.5
#define NETCLIENT_HANDLEDATA_3_3_5 0x00632460

unsigned int g_gameBuild = 0;
unsigned int g_patchAddress = 0;
std::map<int, const char*>* g_opcodes = nullptr;

// This variable holds the return address, it must be global!
DWORD g_returnAddress = 0;

unsigned int g_timeReceived = 0;
void* g_data = nullptr;
int g_size = 0;

char const* GetOpcodeName(unsigned int opcode)
{
    auto itr = (*g_opcodes).find(opcode);
    if (itr != (*g_opcodes).end())
        return itr->second;

    return "UNKNOWN";
}

void PrintIncomingPacket()
{
    printf("[ServerToClient] Time %u, Size %i\n", g_timeReceived, g_size);
    int i = 0;

    unsigned short opcode = *((unsigned short*)g_data);
    char const* name = GetOpcodeName(opcode);
    printf("Opcode: %u %s\n", opcode, name);

    if (g_gameBuild > CLIENT_BUILD_0_5_3)
        i = 2;
    else
        i = 4;

    if (g_size > i)
    {
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
        printf("\n");
    }
    
    printf("\n");
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

unsigned int GetGameVersion()
{
    TCHAR filename[MAX_PATH];

    GetModuleFileName(NULL, filename, MAX_PATH);

    DWORD dwHandle, sz = GetFileVersionInfoSizeA(filename, &dwHandle);
    if (0 == sz)
    {
        return 0;
    }
    char *buf = new char[sz];
    if (!GetFileVersionInfoA(filename, dwHandle, sz, &buf[0]))
    {
        delete[] buf;
        return 0;
    }
    VS_FIXEDFILEINFO * pvi;
    sz = sizeof(VS_FIXEDFILEINFO);
    if (!VerQueryValueA(&buf[0], "\\", (LPVOID*)&pvi, (unsigned int*)&sz))
    {
        delete[] buf;
        return 0;
    }
    
    return pvi->dwFileVersionLS & 0xFFFF;
}

//-----------------------------------------------------------------------------

// Define the plugins main, use a define since the code is the same for all plugins
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved)
{
    // Get rid of compiler warnings since we do not use this parameter
    UNREFERENCED_PARAMETER(lpReserved);

    if (ulReason != DLL_PROCESS_ATTACH)
        return TRUE;

    // If we are attaching to a process, we do not want the dll thread messages
    DisableThreadLibraryCalls(hModule);

    // Create a console since we are in a DLL
    CreateConsole();

    g_gameBuild = GetGameVersion();

    if (!g_gameBuild)
        g_gameBuild = CLIENT_BUILD_0_5_3;

    printf("Detected game build %u.\n", g_gameBuild);

    switch (g_gameBuild)
    {
        case CLIENT_BUILD_0_5_3:
            g_patchAddress = NETCLIENT_HANDLEDATA_0_5_3;
            g_opcodes = &g_opcodes3368;
            break;
        case CLIENT_BUILD_1_12_1:
            g_patchAddress = NETCLIENT_HANDLEDATA_1_12_1;
            g_opcodes = &g_opcodes5875;
            break;
        case CLIENT_BUILD_2_4_3:
            g_patchAddress = NETCLIENT_HANDLEDATA_2_4_3;
            g_opcodes = &g_opcodes8606;
            break;
        case CLIENT_BUILD_3_3_5:
            g_patchAddress = NETCLIENT_HANDLEDATA_3_3_5;
            g_opcodes = &g_opcodes12340;
            break;
        default:
            printf("Unsupported version!\n");
            return FALSE;
    }

    // We will place a codecave at this address
    Codecave(g_patchAddress, HandleDataHook, 1);

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