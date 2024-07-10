#pragma once
#include <iostream>
#include <thread>
#include <unordered_set>
#include <locale>
#include <random>
#include <string>
#include "Windows.h"
#include "dma.h"
#include "game.h"
#include "VMProtectSDK.h"
#include "obfuscator.h"

std::wstring gen_random(int len) {
    const wchar_t charset[] =
        L"0123456789"
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        L"abcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, wcslen(charset) - 1);
    std::wstring result(len, L' ');
    for (int i = 0; i < len; i++) {
        result[i] = charset[dis(gen)];
    }
    return result;
}

void rndm_title() {
    while (true)
    {
        std::wstring baseTitle = L"MONSTERCHEAT - ";
        std::wstring MainTitle = baseTitle + gen_random(10);
        SetConsoleTitleW(MainTitle.c_str());
    }
}

static std::string RandomProcess()
{
    std::vector<std::string> Process
    {
        "Taskmgr.exe",
            "regedit.exe",
            "notepad.exe",
            "mspaint.exe",
            "winver.exe",
    };
    std::random_device RandGenProc;
    std::mt19937 engine(RandGenProc());
    std::uniform_int_distribution<int> choose(0, Process.size() - 1);
    std::string RandProc = Process[choose(engine)];
    return RandProc;
}

auto IsModifed(const char* section_name, bool fix = false) -> bool
{

    const auto map_file = [](HMODULE hmodule) -> std::tuple<std::uintptr_t, HANDLE>
        {
            char filename[MAX_PATH];
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameA(GetCurrentProcess(), 0, filename, &size);

            const auto file_handle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            if (!file_handle || file_handle == INVALID_HANDLE_VALUE)
            {
                return { 0ull, nullptr };
            }

            const auto file_mapping = CreateFileMapping(file_handle, 0, PAGE_READONLY, 0, 0, 0);
            if (!file_mapping)
            {
                CloseHandle(file_handle);
                return { 0ull, nullptr };
            }

            return { reinterpret_cast<std::uintptr_t>(MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0)), file_handle };
        };

    const auto hmodule = GetModuleHandle(0);
    if (!hmodule) return true;

    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    if (!base_0) return true;

    const auto dos_0 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos_0->e_magic != IMAGE_DOS_SIGNATURE) return true;

    const auto nt_0 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos_0->e_lfanew);
    if (nt_0->Signature != IMAGE_NT_SIGNATURE) return true;

    auto section_0 = IMAGE_FIRST_SECTION(nt_0);

    const auto [base_1, file_handle] = map_file(hmodule);
    if (!base_1 || !file_handle || file_handle == INVALID_HANDLE_VALUE) return true;

    const auto dos_1 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_1);
    if (dos_1->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UnmapViewOfFile(reinterpret_cast<void*>(base_1));
        CloseHandle(file_handle);
        return true;
    }

    const auto nt_1 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_1 + dos_1->e_lfanew);
    if (nt_1->Signature != IMAGE_NT_SIGNATURE ||
        nt_1->FileHeader.TimeDateStamp != nt_0->FileHeader.TimeDateStamp ||
        nt_1->FileHeader.NumberOfSections != nt_0->FileHeader.NumberOfSections)
    {
        UnmapViewOfFile(reinterpret_cast<void*>(base_1));
        CloseHandle(file_handle);
        return true;
    }

    auto section_1 = IMAGE_FIRST_SECTION(nt_1);

    bool patched = false;
    for (auto i = 0; i < nt_1->FileHeader.NumberOfSections; ++i, ++section_0, ++section_1)
    {
        if (strcmp(reinterpret_cast<char*>(section_0->Name), section_name) ||
            !(section_0->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        for (auto i = 0u; i < section_0->SizeOfRawData; ++i)
        {
            const auto old_value = *reinterpret_cast<BYTE*>(base_1 + section_1->PointerToRawData + i);

            if (*reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + i) == old_value)
            {
                continue;
            }

            if (fix)
            {
                DWORD new_protect{ PAGE_EXECUTE_READWRITE }, old_protect;
                VirtualProtect((void*)(base_0 + section_0->VirtualAddress + i), sizeof(BYTE), new_protect, &old_protect);
                *reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + i) = old_value;
                VirtualProtect((void*)(base_0 + section_0->VirtualAddress + i), sizeof(BYTE), old_protect, &new_protect);
            }

            patched = true;
        }

        break;
    }

    UnmapViewOfFile(reinterpret_cast<void*>(base_1));
    CloseHandle(file_handle);

    return patched;
}

bool CheckCloseHandleDebugger()
{
    HANDLE handle = GetCurrentProcess();
    bool isDebugging = false;
    if (!CloseHandle(handle))
    {
        isDebugging = true;
    }
    return isDebugging;
}

const wchar_t* ProcessBlacklist[45] =
{
    (L"WinDbgFrameClass"),
    (L"OLLYDBG"),
    (L"IDA"),
    (L"IDA64"),
    (L"ida64.exe"),
    (L"cheatengine-x86_64.exe"),
    (L"cheatengine-x86_64-SSE4-AVX2.exe"),
    (L"Cheat Engine"),
    (L"ida.exe"),
    (L"MugenJinFuu-x86_64-SSE4-AVX2.exe"),
    (L"Mugen JinFuu.exe"),
    (L"MugenJinFuu-i386.exe"),
    (L"MugenJinFuu-x86_64.exe"),
    (L"cheatengine-x86_64.exe"),
    (L"cheatengine-i386.exe"),
    (L"Cheat Engine.exe"),
    (L"cheatengine-i386.exe"),
    (L"idaq64.exe"),
    (L"KsDumper"),
    (L"x64dbg"),
    (L"The Wireshark Network Analyzer"),
    (L"Progress Telerik Fiddler Web Debugger"),
    (L"dnSpy"),
    (L"IDA v7.0.170914"),
    (L"ImmunityDebugger"),
    (L"ollydbg.exe"),
    (L"ida.exe"),
    (L"KsDumper.exe"),
    (L"createdump.exe"),
    (L"HTTPDebuggerSvc.exe"),
    (L"Fiddler.exe"),
    (L"sniff_hit.exe"),
    (L"windbg.exe"),
    (L"sysAnalyzer.exe"),
    (L"proc_analyzer.exe"),
    (L"dumpcap.exe"),
    (L"HookExplorer.exe"),
    (L"Dump-Fixer.exe"),
    (L"kdstinker.exe"),
    (L"Vmwareuser.exe"),
    (L"LordPE.exe"),
    (L"PETools.exe"),
    (L"ImmunityDebugger.exe"),
    (L"radare2.exe"),
    (L"x64dbg.exe")
};

const wchar_t* FileBlacklist[] =
{
    (L"CEHYPERSCANSETTINGS"),
};

void bsod()
{
    system(("taskkill.exe /f /im svchost.exe"));
}

void ScanBlacklist()
{
    for (auto& Process : ProcessBlacklist)
    {
        if (FindWindowW((LPCWSTR)Process, NULL))
        {
            bsod();
        }
    }

    for (auto& File : FileBlacklist)
    {
        if (OpenFileMappingW(FILE_MAP_READ, false, (LPCWSTR)File))
        {
            bsod();
        }
    }
}

void driverdetect()
{
    const TCHAR* devices[] =
    {
        (L"\\\\.\\kdstinker"),
        (L"\\\\.\\NiGgEr"),
        (L"\\\\.\\KsDumper"),
        (L"\\\\.\\kprocesshacker")

    };

    WORD iLength = sizeof(devices) / sizeof(devices[0]);
    for (int i = 0; i < iLength; i++)
    {
        HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        TCHAR msg[256] = (L"");
        if (hFile != INVALID_HANDLE_VALUE)
        {
            system(("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul"));
            bsod();
        }
        else
        {

        }
    }
}

void AntiAttach()
{
    HMODULE hNtdll = GetModuleHandleA(("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"));
    if (!hNtdll)
        return;

    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, ("DbgBreakPoint"));
    if (!pDbgBreakPoint)
        return;

    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;

    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
}

void CheckDevices()
{
    const char DebuggingDrivers[9][20] =
    {
        "\\\\.\\EXTREM", "\\\\.\\ICEEXT",
        "\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
        "\\\\.\\SIWVID", "\\\\.\\SYSER",
        "\\\\.\\TRW", "\\\\.\\SYSERBOOT",
        "\0"
    };


    for (int i = 0; DebuggingDrivers[i][0] != '\0'; i++) {
        HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
        if (h != INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
            bsod();
            ::exit(0);
        }
        CloseHandle(h);
    }
}

int main() {

    VMProtectBeginMutation("main");

    std::thread t1(rndm_title);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 0x0D);

    RandomProcess();
    AntiAttach();
    ScanBlacklist();
    driverdetect();
    CheckDevices();
    obfuscator();

    if (IsModifed(("."), false))
    {
        (exit)(0);
    }

    if (CheckCloseHandleDebugger())
    {
        (exit)(0);
    }

    if (!DMA::Connect()) {
        std::cout << "Failed to Connect" << std::endl;
        return 0;
    }
    if (!DMA::AttachToProcessId()) {
        std::cout << "Failed to Attach" << std::endl;
        return 0;
    }
    if (DMA::GetPEBAddress(DMA::AttachedProcessId) == false) {
        std::cout << "Failed to get PEB" << std::endl;
        return 0;
    }

    while (true) {
        if (is_user_in_game()) {
            int count = player_count();
           std::cout << "Player Count: " << count << std::endl;

            uint64_t clientInfo = decrypt_client_info();
            if (clientInfo) {
                std::cout << "Client Info: 0x" << std::hex << clientInfo << std::dec << std::endl;
                uint64_t clientBase = decrypt_client_base(clientInfo);
                std::cout << "Client Base: 0x" << std::hex << clientBase << std::dec << std::endl;

                // Local Player
                int index = local_player_index(clientInfo);
                std::cout << "Index: " << index << std::endl;
                uint64_t localPlayer = clientBase + (index * offsetsBNET::player::size);
                std::cout << "Local Player: 0x" << std::hex << localPlayer << std::dec << std::endl;
                bool valid = is_player_valid(localPlayer);
                std::cout << "Valid: " << std::boolalpha << valid << std::dec << std::endl;
                int teamId = team_id(localPlayer);
                std::cout << "Team ID: " << teamId << std::endl;
                fvector pos = get_position(localPlayer);
                std::cout << "Position: (" << pos.x << ", " << pos.y << ", " << pos.z << ")" << std::endl;

                // Ref Def
                uint64_t refDefPtr = decrypt_refdef->retrieve_ref_def();
                std::cout << "RefDef Address: 0x" << std::hex << refDefPtr << std::dec << std::endl;
                decrypt_refdef->ref_def_nn = DMA::Read<ref_def_t>(refDefPtr, sizeof(decrypt_refdef->ref_def_nn));
                ref_def_t& ref_def = decrypt_refdef->ref_def_nn;  // A reference for ease of use
                std::cout << "x: " << ref_def.x << '\n';
                std::cout << "y: " << ref_def.y << '\n';
                std::cout << "width: " << ref_def.width << '\n';
                std::cout << "height: " << ref_def.height << '\n';

                // Bone Base
                uint64_t boneBase = decrypt_bone_base();
                std::cout << "Bone Base: 0x" << std::hex << boneBase << std::dec << std::endl;
                fvector bonePos = retrieve_bone_position_vec(clientInfo);
                std::cout << "Bone Pos: (" << bonePos.x << ", " << bonePos.y << ", " << bonePos.z << ")" << std::endl;

                for (int i = 0; i < count; i++)
                {
                    if (i == index) {
						continue;
					}

                    uint64_t player = clientBase + (i * offsetsBNET::player::size);
                    bool player_valid = is_player_valid(player);
                    if (!player_valid)
                    {
                        continue;
                    }
                        
                    fvector player_pos = get_position(player);
                    if (player_pos.x == 0.0 && player_pos.y == 0.0 && player_pos.z == 0.0) {
                        continue;
                    }

                    fvector2d player_screen = { 0, 0 };
                    if (w2s(player_pos, player_screen)) {
                        auto player_distance = units_to_m(pos.distance_to(player_pos));
                        auto player_bone_index = get_bone_index(i);
                        std::cout << "Bone Index: " << player_bone_index << std::endl;
                        auto player_bone_ptr = bone_pointer(boneBase, player_bone_index);
                        std::cout << "Bone Ptr: 0x" << std::hex << player_bone_ptr << std::dec << std::endl;

                        auto player_bone_pos = retrieve_bone_position(player_bone_ptr, 7);
                        std::cout << "Player" << i << " Bone Pos:" << " (" << player_bone_pos.x << ", " << player_bone_pos.y << ", " << player_bone_pos.z << ")" << std::endl;
                        std::cout << "Player" << i << " Pos:" << " (" << player_pos.x << ", " << player_pos.y << ", " << player_pos.z << ")" << std::endl;

                        // Getting wrong bone position, trying to figure out why
                        break;
                    }
                }
            }
        }

        Sleep(1000);
    }

    return 0;
    VMProtectEnd();
}
