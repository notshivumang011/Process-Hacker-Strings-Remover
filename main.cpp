#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI ZwQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    int MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

extern "C" NTSTATUS NTAPI ZwReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
);

bool is_ascii_printable(char c) {
    return (c >= 32 && c <= 126);
}

bool is_wide_printable(wchar_t c) {
    return (c >= 32 && c <= 126);
}

bool iequals(const std::string& a, const std::string& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(),
        [](char a, char b) { return tolower(a) == tolower(b); });
}

std::vector<DWORD> GetPIDsByName(const std::string& procName) {
    std::vector<DWORD> pids;
    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return pids;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            char exeNameA[MAX_PATH] = {};
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, exeNameA, MAX_PATH, NULL, NULL);

            if (iequals(exeNameA, procName)) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pids;
}

int RemoveStringsFromProcess(DWORD pid, const std::vector<std::string>& keywords) {
    if (pid == 0 || pid == GetCurrentProcessId()) return 0;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return 0;

    MEMORY_BASIC_INFORMATION mbi = {};
    SIZE_T address = 0;
    int cleaned = 0;

    while (NT_SUCCESS(ZwQueryVirtualMemory(hProcess, (PVOID)address, 0, &mbi, sizeof(mbi), nullptr))) {
        if (mbi.State == MEM_COMMIT && (
            mbi.Protect == PAGE_READWRITE ||
            mbi.Protect == PAGE_WRITECOPY ||
            mbi.Protect == PAGE_EXECUTE_READWRITE ||
            mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {

            std::vector<char> buffer(mbi.RegionSize);
            if (NT_SUCCESS(ZwReadVirtualMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), nullptr))) {
                size_t i = 0;
                while (i < buffer.size()) {
                    size_t start = i;
                    while (i < buffer.size() && is_ascii_printable(buffer[i]))
                        ++i;
                    size_t len = i - start;

                    if (len > 4) {
                        std::string found(buffer.begin() + start, buffer.begin() + start + len);
                        std::string lowerFound = found;
                        std::transform(lowerFound.begin(), lowerFound.end(), lowerFound.begin(), ::tolower);

                        for (const auto& keyword : keywords) {
                            std::string lowerKeyword = keyword;
                            std::transform(lowerKeyword.begin(), lowerKeyword.end(), lowerKeyword.begin(), ::tolower);

                            if (lowerFound.find(lowerKeyword) != std::string::npos) {
                                std::vector<char> zeros(len, 0);
                                WriteProcessMemory(hProcess, (PBYTE)mbi.BaseAddress + start, zeros.data(), len, nullptr);
                                ++cleaned;
                                break;
                            }
                        }
                    }

                    while (i < buffer.size() && !is_ascii_printable(buffer[i]))
                        ++i;
                }
            }

            std::vector<wchar_t> wbuffer(mbi.RegionSize / sizeof(wchar_t));
            if (NT_SUCCESS(ZwReadVirtualMemory(hProcess, mbi.BaseAddress, wbuffer.data(), wbuffer.size() * sizeof(wchar_t), nullptr))) {
                size_t i = 0;
                while (i < wbuffer.size()) {
                    size_t start = i;
                    while (i < wbuffer.size() && is_wide_printable(wbuffer[i]))
                        ++i;
                    size_t len = i - start;

                    if (len > 4) {
                        std::wstring found(wbuffer.begin() + start, wbuffer.begin() + start + len);
                        std::wstring lowerFound = found;
                        std::transform(lowerFound.begin(), lowerFound.end(), lowerFound.begin(), ::towlower);

                        for (const auto& keyword : keywords) {
                            std::wstring wkeyword(keyword.begin(), keyword.end());
                            std::transform(wkeyword.begin(), wkeyword.end(), wkeyword.begin(), ::towlower);

                            if (lowerFound.find(wkeyword) != std::wstring::npos) {
                                std::vector<wchar_t> wzeros(len, 0);
                                WriteProcessMemory(hProcess, (PBYTE)mbi.BaseAddress + start * sizeof(wchar_t), wzeros.data(), len * sizeof(wchar_t), nullptr);
                                ++cleaned;
                                break;
                            }
                        }
                    }

                    while (i < wbuffer.size() && !is_wide_printable(wbuffer[i]))
                        ++i;
                }
            }
        }

        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    return cleaned;
}

void CleanMemoryStrings() {
    std::vector<std::string> processNames = {
        "explorer.exe"
    };

    std::vector<std::string> keywords = {
        "index.html"
    };

    std::cout << "=== ShivUmang String Cleaner v4.0 ===\n";

    for (const auto& proc : processNames) {
        std::vector<DWORD> pids = GetPIDsByName(proc);
        if (pids.empty()) {
            std::cout << "[!] Process not found: " << proc << "\n";
            continue;
        }

        for (DWORD pid : pids) {
            int result = RemoveStringsFromProcess(pid, keywords);
            std::cout << "[*] Cleaning process: " << proc << " (PID: " << pid << ") -> Cleaned: " << result << "\n";
        }
    }

    std::cout << "[+] Cleaning done.\n";
}

int main() {
    CleanMemoryStrings();
    system("pause");
    return 0;
}
