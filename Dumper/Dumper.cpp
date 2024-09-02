#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <ctime>
#include <Windows.h>
#include <string>
#include <Windows.h>
#include "auth.hpp"
#include <string>
#include "utils.hpp"
#include "skStr.h"
#include <ctime>
#include <iomanip>
std::string tm_to_readable_time(std::tm ctx) {
    char buffer[100];

    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &ctx);

    return std::string(buffer);
}


static std::time_t string_to_timet(const std::string& timestamp) {
    struct tm tm = { 0 };

    int year, month, day, hour, minute, second;
    if (sscanf_s(timestamp.c_str(), "%4d-%2d-%2d %2d:%2d:%2d",
        &year, &month, &day, &hour, &minute, &second) != 6) {
        throw std::runtime_error("Failed to parse timestamp.");
    }

    tm.tm_year = year - 1900; // tm_year is years since 1900
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;

    std::time_t timet = mktime(&tm);
    if (timet == -1) {
        throw std::runtime_error("mktime failed.");
    }

    return timet;
}
static tm timet_to_tm(time_t timeValue) {
    tm result;
    localtime_s(&result, &timeValue); // Use localtime_s for thread safety
    return result;
}

const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);


typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadQuerySetWin32StartAddress = 9,
} THREADINFOCLASS;

typedef NTSTATUS(NTAPI* PNtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength);

DWORD GetProcessID(const wchar_t* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

void SuspendNtdllThreads(DWORD processID) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), hNtdll, &modInfo, sizeof(MODULEINFO));

    PNtQueryInformationThread NtQueryInformationThread = (PNtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

    if (!NtQueryInformationThread) {
        CloseHandle(hThreadSnap);
        return;
    }

    auto CheckAndSuspendThreads = [&]() {
        if (Thread32First(hThreadSnap, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processID) {
                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        ULONG_PTR startAddress = 0;
                        NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr);

                        if (startAddress >= (ULONG_PTR)modInfo.lpBaseOfDll &&
                            startAddress < ((ULONG_PTR)modInfo.lpBaseOfDll + modInfo.SizeOfImage)) {
                            SuspendThread(hThread);
                        }

                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnap, &te32));
        }
        };

    CheckAndSuspendThreads();

    CloseHandle(hThreadSnap);
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    CheckAndSuspendThreads();

    CloseHandle(hThreadSnap);
}


std::string GenerateRandomString(int length) {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string randomString;
    for (int i = 0; i < length; ++i) {
        randomString += chars[rand() % chars.length()];
    }
    return randomString;
}

void UpdateTitle(const std::string& prefix, std::atomic<bool>& keepUpdating) {
    while (keepUpdating) {
        std::string randomString = GenerateRandomString(16);
        std::string title = prefix + " " + randomString;
        SetConsoleTitleA(title.c_str());
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

int main() {
    std::atomic<bool> keepUpdating(true);

    std::thread newInjectTitleThread(UpdateTitle, "Zynx | Waiting for Roblox |", std::ref(keepUpdating));

    DWORD processID = 0;
    while (processID == 0) {
        processID = GetProcessID(L"RobloxPlayerBeta.exe");
        if (processID == 0) {
            system("cls");
            std::cout << "\Please reopen roblox\n";
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    keepUpdating = false;
    newInjectTitleThread.join();

    keepUpdating = true;
    std::thread injectTitleThread2(UpdateTitle, "Zynx | Injecting |", std::ref(keepUpdating));
    std::cout << "\n Suspending threads!!\n";

    SuspendNtdllThreads(processID);
    SuspendNtdllThreads(processID);

    std::cout << "\Threads suspended and Checks disabled Made by blitzedzz!.\n";
    keepUpdating = false;
    injectTitleThread2.join();
    keepUpdating = true;

    while (true) {
        std::thread injectTitleThread3(UpdateTitle, "Zynx | Injected |", std::ref(keepUpdating));
        Sleep(10);
        injectTitleThread3.join();

        DWORD processID = GetProcessID(L"RobloxPlayerBeta.exe");
        if (processID != 0) {
            HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hThreadSnap != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te32;
                te32.dwSize = sizeof(THREADENTRY32);

                if (Thread32First(hThreadSnap, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == processID) {
                            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                            if (hThread) {
                                SuspendThread(hThread);
                                ResumeThread(hThread);
                                CloseHandle(hThread);
                            }
                        }
                    } while (Thread32Next(hThreadSnap, &te32));
                }
                CloseHandle(hThreadSnap);
            }
        }
    }


    return 0;
}
