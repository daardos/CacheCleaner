/*
 * =========================================================================
 *  МЕГА-ОЧИСТЧИК КЭШЕЙ (DEVELOPER EDITION) - v13.0 SAFE_REV
 * =========================================================================
 *
 *  Утилита для безопасной очистки кэшей (npm, pip, gradle), браузеров и системы.
 *  Также умеет сжимать виртуальные диски WSL2/Docker (VHDX).
 *
 *  ОСОБЕННОСТИ:
 *  - Уровни доверия: [SAFE] (кэши браузеров), [REBUILD] (пакетные менеджеры),
 *    [DATA] (модели Ollama - требуют отдельного подтверждения).
 *  - Защита от удаления системных папок и корня профиля пользователя
 *    (пути берутся из переменных окружения, а не хардкодом под C:\).
 *  - Полная защита от reparse points (junctions/symlinks): точки соединения
 *    не обходятся и не удаляются рекурсивно - только снимается сама ссылка.
 *  - Понимает UTF-16LE и UTF-8 (включая WSL_UTF8=1).
 *  - Предупреждает, если браузер/Discord/VS Code запущены (кэш будет залочен).
 *  - Использует Job Objects и CREATE_SUSPENDED для безопасного ожидания
 *    зависших процессов (Optimize-VHD) без утечки хэндлов.
 *  - Честная статистика: освобождённое место вычисляется по факту
 *    (размер до минус размер после), включая вложенные папки.
 *
 *  ИЗМЕНЕНИЯ v13.0 относительно v12.2:
 *  1. Функция GetFreeSpace переименована в GetFreeBytesOnVolume
 *     (GetFreeSpace - макрос Windows, ломал сборку MinGW).
 *  2. FOLDERID_Desktop определён локально - флаг -luuid больше не нужен.
 *  3. IsSafePath: системные пути берутся из SystemRoot/ProgramFiles/
 *     ProgramFiles(x86)/ProgramData, а не хардкодом c:\...
 *  4. Reparse-point защита в GetSize/CleanPath (junctions под MinGW
 *     не распознаются is_symlink и раньше могли привести к удалению
 *     содержимого за пределами целевой папки).
 *  5. CleanPath корректно считает освобождённое место в подпапках.
 *  6. Удалена цель "PS Media Cache" (Adobe\Photoshop\CT) - не подтверждено,
 *     что это кэш.
 *  7. Предупреждение о запущенных браузерах/Discord/VS Code.
 *
 *  ИЗВЕСТНЫЕ ОГРАНИЧЕНИЯ (README):
 *  1. Сжатие VHDX требует Windows Pro/Enterprise (наличие Hyper-V).
 *     На Windows Home модуль Hyper-V отсутствует, программа вежливо пропустит шаг.
 *  2. Если утилита запущена внутри другого Job Object (отладчик, CI-агент),
 *     привязка может не сработать. Программа выдаст [WARN], но продолжит работу.
 *  3. Поддерживается WSL_UTF8=1. Другие значения переменной WSL_UTF8
 *     (например, TRUE) могут привести к неверному парсингу имен дистрибутивов.
 *  4. REBUILD-цели (.m2, .nuget, .gradle) перекачиваются из сети -
 *     офлайн-сборка после очистки сломается.
 *
 *  СБОРКА:
 *  MinGW: g++ -std=c++17 CacheCleaner.cpp -o cleaning.exe -lole32 -lshell32 -ladvapi32
 *  MSVC:  cl /std:c++17 /EHsc CacheCleaner.cpp   (pragma comment(lib,...) уже в коде)
 * =========================================================================
 */

#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <fstream>
#include <algorithm>
#include <cwctype>
#include <chrono>
#include <ctime>
#include <cwchar>
#include <iterator>
#include <cstring>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

namespace fs = std::filesystem;

constexpr DWORD PROCESS_LAUNCH_FAILED = 0xFFFFFFFE;
constexpr DWORD PROCESS_TIMEOUT_CODE  = 0xFFFFFFFF;

enum class Trust {
    SAFE, REBUILDABLE, DATA
};

struct CacheTarget {
    std::wstring name;
    fs::path path;
    Trust trust;
    uintmax_t size_before = 0;
    uintmax_t size_after = 0;
};

// FOLDERID_Desktop (B4BFCC3A-DB2C-424C-B029-7FE99A87C641).
// Определён локально, чтобы MinGW-сборке не требовался -luuid.
static const GUID kFolderIdDesktop =
    {0xB4BFCC3A, 0xDB2C, 0x424C, {0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41}};

// --- Утилиты ---

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    if (size_needed == 0) return "";
    std::string strTo(size_needed, 0);
    if (WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL) == 0) {
        return "";
    }
    return strTo;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    if (size_needed == 0) return L"";
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::wstring GetEnvVarW(const std::wstring& key) {
    DWORD bufferSize = GetEnvironmentVariableW(key.c_str(), NULL, 0);
    if (bufferSize == 0) return L"";
    std::wstring val(bufferSize, L'\0');
    GetEnvironmentVariableW(key.c_str(), &val[0], bufferSize);
    if (!val.empty() && val.back() == L'\0') val.pop_back();
    return val;
}

std::string FormatSize(uintmax_t bytes) {
    if (bytes == 0) return "0 B";
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    if (bytes >= 1024ULL * 1024 * 1024) oss << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
    else if (bytes >= 1024ULL * 1024) oss << (bytes / (1024.0 * 1024.0)) << " MB";
    else oss << (bytes / 1024.0) << " KB";
    return oss.str();
}

std::string TrustToString(Trust t) {
    switch (t) {
        case Trust::SAFE: return "[SAFE]";
        case Trust::REBUILDABLE: return "[REBUILD]";
        case Trust::DATA: return "[DATA]";
    }
    return "";
}

uintmax_t GetFreeBytesOnVolume(const fs::path& p) {
    wchar_t volumePath[MAX_PATH];
    if (GetVolumePathNameW(p.wstring().c_str(), volumePath, MAX_PATH)) {
        ULARGE_INTEGER freeBytesAvailable;
        if (GetDiskFreeSpaceExW(volumePath, &freeBytesAvailable, NULL, NULL)) {
            return freeBytesAvailable.QuadPart;
        }
    }
    return 0;
}

// Надёжная проверка reparse point (symlink ИЛИ junction) через WinAPI.
// std::filesystem::is_symlink под MinGW junction может не распознавать.
bool IsReparsePoint(const fs::path& p) {
    DWORD attrs = GetFileAttributesW(p.wstring().c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool IsProcessRunning(const std::wstring& exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) { found = true; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// --- Безопасность и WinAPI ---

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

DWORD RunProcess(const std::wstring& cmdLine, DWORD timeoutMs = INFINITE) {
    if (cmdLine.empty()) return PROCESS_LAUNCH_FAILED;

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    DWORD exitCode = PROCESS_LAUNCH_FAILED;

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    std::wstring cmd = cmdLine;
    if (CreateProcessW(NULL, &cmd[0], NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        if (hJob) {
            if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
                std::cout << "[WARN] Не удалось привязать процесс к Job Object.\n";
            }
        }
        ResumeThread(pi.hThread);

        DWORD waitRes = WaitForSingleObject(pi.hProcess, timeoutMs);
        if (waitRes == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            exitCode = PROCESS_TIMEOUT_CODE;
        } else {
            GetExitCodeProcess(pi.hProcess, &exitCode);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    if (hJob) CloseHandle(hJob);
    return exitCode;
}

std::string RunProcessCapture(const std::wstring& cmdLine, DWORD timeoutMs = 30000) {
    if (cmdLine.empty()) return "";

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return "";

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    std::wstring cmd = cmdLine;
    std::string output;

    if (CreateProcessW(NULL, &cmd[0], NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        if (hJob) {
            if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
                std::cout << "[WARN] Не удалось привязать процесс к Job Object (Capture).\n";
            }
        }
        ResumeThread(pi.hThread);
        CloseHandle(hWritePipe);
        hWritePipe = NULL;

        char buffer[4096];
        DWORD bytesRead;
        ULONGLONG startTime = GetTickCount64();

        while (true) {
            DWORD available = 0;
            if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &available, NULL)) break;

            if (available > 0) {
                if (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                    buffer[bytesRead] = '\0';
                    output += buffer;
                }
            } else {
                if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
                    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                        buffer[bytesRead] = '\0';
                        output += buffer;
                    }
                    break;
                }
                if (GetTickCount64() - startTime > timeoutMs) {
                    TerminateProcess(pi.hProcess, 1);
                    break;
                }
                Sleep(10);
            }
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hReadPipe);
    if (hWritePipe) CloseHandle(hWritePipe);
    if (hJob) CloseHandle(hJob);
    return output;
}

fs::path GetDesktopPath() {
    PWSTR path = NULL;
    fs::path result;
    if (SUCCEEDED(SHGetKnownFolderPath(kFolderIdDesktop, 0, NULL, &path))) {
        result = path;
        CoTaskMemFree(path);
    }
    return result;
}

bool EqPathI(const std::wstring& a, const std::wstring& b) {
    int res = CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE);
    return res == CSTR_EQUAL;
}

bool IsSafePath(const fs::path& p, const fs::path& userProfile) {
    if (p.empty() || !p.is_absolute()) return false;
    fs::path np = p.lexically_normal();
    if (np == np.root_path()) return false;
    std::wstring wpath = np.wstring();
    if (!wpath.empty() && wpath.back() == L'\\') wpath.pop_back();
    auto depth = std::distance(np.begin(), np.end());
    if (depth < 3) return false;

    // Защищаемые пути - из реальных переменных окружения (а не хардкод c:\...).
    std::vector<std::wstring> protectedPaths;
    auto pushEnv = [&](const wchar_t* name) {
        std::wstring v = GetEnvVarW(name);
        if (!v.empty()) {
            if (v.back() == L'\\') v.pop_back();
            protectedPaths.push_back(v);
        }
    };
    pushEnv(L"SystemRoot");
    pushEnv(L"ProgramFiles");
    pushEnv(L"ProgramFiles(x86)");
    pushEnv(L"ProgramData");
    pushEnv(L"ProgramW6432"); // на случай 32-битной сборки в 64-битной системе

    for (const auto& pp : protectedPaths) {
        if (EqPathI(wpath, pp)) return false;
    }
    if (!userProfile.empty()) {
        std::wstring uProf = userProfile.wstring();
        if (!uProf.empty() && uProf.back() == L'\\') uProf.pop_back();
        if (EqPathI(wpath, uProf)) return false;
    }
    return true;
}

bool AskYesNo(const std::string& prompt) {
    std::cout << prompt << " (y/N): ";
    std::string ans;
    std::getline(std::cin, ans);
    std::transform(ans.begin(), ans.end(), ans.begin(), [](unsigned char c){ return std::tolower(c); });
    return ans == "y" || ans == "yes";
}

// --- Файловые операции ---

uintmax_t GetSize(const fs::path& path) {
    uintmax_t size = 0;
    std::error_code ec;
    if (!fs::exists(path, ec)) return 0;
    try {
        if (IsReparsePoint(path)) return 0; // не считаем и не лезем внутрь
        if (fs::is_regular_file(path, ec)) return fs::file_size(path, ec);
        if (fs::is_directory(path, ec)) {
            fs::recursive_directory_iterator it(
                path, fs::directory_options::skip_permission_denied, ec);
            fs::recursive_directory_iterator end;
            while (it != end) {
                if (ec) { ec.clear(); it.increment(ec); continue; }
                const fs::path ep = it->path();
                std::error_code st_ec;
                // Junction/symlink: не считаем содержимое и не спускаемся внутрь.
                if (IsReparsePoint(ep)) {
                    if (it->is_directory(st_ec)) it.disable_recursion_pending();
                    it.increment(ec);
                    continue;
                }
                if (it->is_regular_file(st_ec)) {
                    size += it->file_size(st_ec);
                }
                it.increment(ec);
            }
        }
    } catch (...) {}
    return size;
}

uintmax_t CleanPath(const fs::path& path) {
    std::error_code ec;
    uintmax_t freed = 0;
    if (!fs::exists(path, ec)) return 0;

    if (IsReparsePoint(path)) {
        std::cout << "[WARN] Reparse point пропущен: " << WStringToString(path.wstring()) << "\n";
        return 0;
    }

    if (fs::is_regular_file(path, ec)) {
        freed = fs::file_size(path, ec);
        fs::remove(path, ec);
        return ec ? 0 : freed;
    }

    if (fs::is_directory(path, ec)) {
        for (const auto& entry : fs::directory_iterator(path, ec)) {
            if (ec) { ec.clear(); continue; }
            std::error_code rm_ec;

            // Reparse point внутри кэша: удаляем только саму ссылку,
            // содержимое за ней не трогаем.
            if (IsReparsePoint(entry.path())) {
                fs::remove(entry.path(), rm_ec);
                continue;
            }

            // Честная статистика: меряем до удаления, включая подпапки.
            uintmax_t before = GetSize(entry.path());
            fs::remove_all(entry.path(), rm_ec);
            uintmax_t after = rm_ec ? GetSize(entry.path()) : 0;
            if (after < before) freed += (before - after);
        }
    }
    return freed;
}

// --- VHDX ---

void RunFstrimAllDistros() {
    std::cout << "[*] Очистка неиспользуемых блоков (fstrim) во всех WSL-дистрибутивах...\n";

    std::string raw = RunProcessCapture(L"wsl.exe -l -q", 15000);
    if (raw.empty()) {
        std::cout << "  [!] WSL не установлен или не вернул список дистрибутивов.\n";
        return;
    }

    std::wstring wraw;
    std::wstring wslUtf8 = GetEnvVarW(L"WSL_UTF8");
    if (wslUtf8 == L"1") {
        wraw = StringToWString(raw);
    } else {
        if (raw.size() >= sizeof(wchar_t)) {
            wraw.resize(raw.size() / sizeof(wchar_t));
            memcpy(&wraw[0], raw.data(), raw.size() & ~size_t(1));
        }
    }

    std::wstringstream wss(wraw);
    std::wstring distro;
    int count = 0;

    while (std::getline(wss, distro)) {
        distro.erase(std::remove(distro.begin(), distro.end(), L'\0'), distro.end());
        distro.erase(std::remove(distro.begin(), distro.end(), L'\r'), distro.end());
        while (!distro.empty() && iswspace(distro.back())) distro.pop_back();
        while (!distro.empty() && iswspace(distro.front())) distro.erase(0, 1);

        if (distro.empty()) continue;

        std::cout << "  -> fstrim в " << WStringToString(distro) << "... ";
        std::cout.flush();

        std::wstring safeDistro = distro;
        size_t pos = 0;
        while ((pos = safeDistro.find(L'"', pos)) != std::wstring::npos) {
            safeDistro.replace(pos, 1, L"\\\"");
            pos += 2;
        }

        std::wstring cmd = L"wsl.exe -d \"" + safeDistro + L"\" -u root fstrim -av";
        DWORD code = RunProcess(cmd, 60000);

        if (code == 0) std::cout << "[OK]\n";
        else if (code == PROCESS_LAUNCH_FAILED) std::cout << "[FAIL] Процесс не запустился\n";
        else std::cout << "[FAIL/ПРОПУСК] код: " << code << "\n";

        count++;
    }

    if (count == 0) {
        std::cout << "  [!] Не найдено ни одного WSL-дистрибутива.\n";
    }
}

void CompactVHDX(bool dryRun) {
    if (!IsAdmin()) {
        std::cout << "\n[!] Сжатие VHDX требует прав Администратора. Пропуск.\n";
        return;
    }

    std::cout << "\n[*] Проверка наличия модуля Hyper-V...\n";
    DWORD code = RunProcess(L"powershell.exe -NoProfile -Command \"if (-not (Get-Module -ListAvailable Hyper-V)) { exit 1 }\"");
    if (code != 0) {
        std::cout << "[!] Модуль Hyper-V не найден. Сжатие VHDX невозможно.\n";
        return;
    }

    std::cout << "[*] Поиск виртуальных дисков...\n";
    std::vector<fs::path> vhdxFiles;
    std::error_code ec;

    fs::path packagesPath = fs::path(GetEnvVarW(L"LOCALAPPDATA")) / L"Packages";
    if (fs::exists(packagesPath, ec)) {
        for (const auto& entry : fs::directory_iterator(packagesPath, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) { ec.clear(); continue; }
            fs::path localState = entry.path() / L"LocalState";
            if (fs::exists(localState, ec)) {
                for (const auto& f : fs::directory_iterator(localState, fs::directory_options::skip_permission_denied, ec)) {
                    if (ec) { ec.clear(); continue; }
                    if (f.path().extension() == L".vhdx" && f.is_regular_file(ec)) {
                        vhdxFiles.push_back(f.path());
                    }
                }
            }
        }
    }

    fs::path dockerOldPath = fs::path(GetEnvVarW(L"LOCALAPPDATA")) / L"Docker" / L"wsl" / L"data" / L"ext4.vhdx";
    if (fs::exists(dockerOldPath, ec)) vhdxFiles.push_back(dockerOldPath);

    fs::path dockerNewPath = fs::path(GetEnvVarW(L"LOCALAPPDATA")) / L"Docker" / L"wsl" / L"disk" / L"docker_data.vhdx";
    if (fs::exists(dockerNewPath, ec)) vhdxFiles.push_back(dockerNewPath);

    if (vhdxFiles.empty()) {
        std::cout << "  [ПРОПУСК] VHDX не найдены.\n";
        return;
    }

    for (const auto& v : vhdxFiles) {
        uintmax_t sz = fs::exists(v, ec) ? fs::file_size(v, ec) : 0;
        std::cout << "  Найден: " << WStringToString(v.filename().wstring()) << " (" << FormatSize(sz) << ")\n";
    }

    if (dryRun) {
        std::cout << "  [DRY-RUN] Сжатие пропущено.\n";
        return;
    }

    if (!AskYesNo("[!] ВНИМАНИЕ: WSL и Docker Desktop будут остановлены.\n"
                  "    Незакоммиченная работа может быть потеряна.\n"
                  "    Сжатие -Mode Full требует до 2x размера VHDX свободного места\n"
                  "    и может занять 5-30 минут. Продолжить?")) {
        std::cout << "[-] Отменено.\n";
        return;
    }

    std::cout << "[*] Остановка WSL...\n";
    code = RunProcess(L"wsl.exe --shutdown", 30000);
    if (code == PROCESS_TIMEOUT_CODE) std::cout << "  [!] wsl --shutdown завис и был убит.\n";
    else if (code == PROCESS_LAUNCH_FAILED) std::cout << "  [!] wsl.exe не найден.\n";
    Sleep(3000);

    RunFstrimAllDistros();

    std::cout << "[*] Повторная остановка WSL...\n";
    code = RunProcess(L"wsl.exe --shutdown", 30000);
    if (code == PROCESS_TIMEOUT_CODE) std::cout << "  [!] wsl --shutdown завис.\n";
    Sleep(3000);

    for (const auto& v : vhdxFiles) {
        std::cout << "  -> Сжимаю: " << WStringToString(v.filename().wstring()) << "...\n";

        uintmax_t size_before = fs::exists(v, ec) ? fs::file_size(v, ec) : 0;
        uintmax_t free_space = GetFreeBytesOnVolume(v);

        if (free_space < size_before + (100ULL * 1024 * 1024)) {
            std::cout << "     [!] Мало свободного места (" << FormatSize(free_space)
                      << "). -Mode Full может упасть. Пропуск.\n";
            continue;
        }

        std::wstring wp = v.wstring();
        size_t pos = 0;
        while ((pos = wp.find(L'\'', pos)) != std::wstring::npos) {
            wp.replace(pos, 1, L"''");
            pos += 2;
        }

        std::wstring psCmd = L"powershell.exe -NoProfile -Command \"Optimize-VHD -Path '" + wp + L"' -Mode Full\"";
        DWORD exitCode = RunProcess(psCmd, 45 * 60 * 1000);

        if (exitCode == 0) {
            uintmax_t size_after = fs::exists(v, ec) ? fs::file_size(v, ec) : 0;
            if (size_before > size_after) {
                std::cout << "     [OK] Сжато на " << FormatSize(size_before - size_after) << "\n";
            } else {
                std::cout << "     [NO-OP] Размер не изменился (fstrim не сработал?)\n";
            }
        } else if (exitCode == PROCESS_LAUNCH_FAILED) {
            std::cout << "     [FAIL] Процесс не запустился (powershell.exe не найден?)\n";
        } else if (exitCode == PROCESS_TIMEOUT_CODE) {
            std::cout << "     [FAIL] Таймаут (превышено 45 минут), процесс убит.\n";
        } else {
            std::cout << "     [FAIL] Exit code: " << exitCode << "\n";
        }
    }

    std::cout << "[+] Сжатие завершено. WSL будет перезапущен при следующем вызове.\n";
}

// --- Main ---

int main(int argc, char** argv) {
    UINT oldOutCP = GetConsoleOutputCP();
    UINT oldInCP = GetConsoleCP();
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);

    bool dryRun = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dry-run") dryRun = true;
        else if (arg == "--help" || arg == "-h") {
            std::cout << "Утилита для безопасной очистки кэшей (npm, pip, gradle), браузеров и системы.\n";
            std::cout << "Также умеет сжимать виртуальные диски WSL2/Docker (VHDX).\n";
            std::cout << "(Сжатие VHDX требует Hyper-V и прав Админа).\n\n";
            std::cout << "Использование: cleaning.exe [опции]\n";
            std::cout << "  --dry-run   Показать, что будет удалено (VHDX будут перечислены, но не сжаты)\n";
            std::cout << "  --help, -h  Показать эту справку\n";
            SetConsoleOutputCP(oldOutCP);
            SetConsoleCP(oldInCP);
            return 0;
        }
    }

    try {
        bool isAdmin = IsAdmin();
        std::cout << "=== МЕГА-ОЧИСТЧИК КЭШЕЙ (v13.0 SAFE_REV) ===\n";
        std::cout << "Режим: " << (dryRun ? "DRY-RUN (только отчет)\n" : "РЕАЛЬНОЕ УДАЛЕНИЕ\n");
        std::cout << "Права администратора: " << (isAdmin ? "ДА" : "НЕТ (системные кэши пропущены)") << "\n";

        std::wstring localAppData = GetEnvVarW(L"LOCALAPPDATA");
        std::wstring appData      = GetEnvVarW(L"APPDATA");
        std::wstring userProfile  = GetEnvVarW(L"USERPROFILE");
        std::wstring tempDir      = GetEnvVarW(L"TEMP");
        std::wstring winDir       = GetEnvVarW(L"SystemRoot");

        std::vector<CacheTarget> targets = {
            {L"User Temp", fs::path(tempDir), Trust::SAFE},
            {L"SquirrelTemp", fs::path(localAppData) / L"SquirrelTemp", Trust::SAFE},
            {L"NVIDIA DXCache", fs::path(localAppData) / L"Nvidia" / L"DXCache", Trust::SAFE},
            {L"NVIDIA ComputeCache", fs::path(localAppData) / L"NVIDIA" / L"ComputeCache", Trust::SAFE},
            {L"Chrome Cache", fs::path(localAppData) / L"Google" / L"Chrome" / L"User Data" / L"Default" / L"Cache", Trust::SAFE},
            {L"Edge Cache", fs::path(localAppData) / L"Microsoft" / L"Edge" / L"User Data" / L"Default" / L"Cache", Trust::SAFE},
            {L"Yandex Cache", fs::path(localAppData) / L"Yandex" / L"YandexBrowser" / L"User Data" / L"Default" / L"Cache", Trust::SAFE},
            {L"Opera Cache", fs::path(localAppData) / L"Opera Software" / L"Opera Stable" / L"Cache", Trust::SAFE},
            {L"Discord Cache", fs::path(appData) / L"discord" / L"Cache", Trust::SAFE},
            {L"Discord Code Cache", fs::path(appData) / L"discord" / L"Code Cache", Trust::SAFE},
            {L"VS Code Cache", fs::path(appData) / L"Code" / L"Cache", Trust::SAFE},
            {L"VS Code Code Cache", fs::path(appData) / L"Code" / L"Code Cache", Trust::SAFE},
            {L"PS CameraRaw Cache", fs::path(localAppData) / L"Adobe" / L"CameraRaw" / L"Cache", Trust::SAFE},
            {L"Python (pip)", fs::path(localAppData) / L"pip" / L"Cache", Trust::REBUILDABLE},
            {L"Node.js (npm Local)", fs::path(localAppData) / L"npm-cache", Trust::REBUILDABLE},
            {L"Node.js (npm Roaming)", fs::path(appData) / L"npm-cache", Trust::REBUILDABLE},
            {L"Java (Maven)", fs::path(userProfile) / L".m2" / L"repository", Trust::REBUILDABLE},
            {L"Java (Gradle)", fs::path(userProfile) / L".gradle" / L"caches", Trust::REBUILDABLE},
            {L"C++ (NuGet)", fs::path(userProfile) / L".nuget" / L"packages", Trust::REBUILDABLE},
            {L"Ollama Models", fs::path(userProfile) / L".ollama" / L"models", Trust::DATA}
        };

        if (isAdmin) {
            targets.push_back({L"Windows Temp", fs::path(winDir) / L"Temp", Trust::SAFE});
            targets.push_back({L"Windows Prefetch (замедлит 1-й запуск)", fs::path(winDir) / L"Prefetch", Trust::SAFE});
            targets.push_back({L"Win Update Download", fs::path(winDir) / L"SoftwareDistribution" / L"Download", Trust::SAFE});
        }

        // Предупреждение о запущенных приложениях (их файлы залочены).
        {
            const std::pair<const wchar_t*, const wchar_t*> checks[] = {
                {L"chrome.exe",   L"Google Chrome"},
                {L"msedge.exe",   L"Microsoft Edge"},
                {L"browser.exe",  L"Yandex Browser"},
                {L"opera.exe",    L"Opera"},
                {L"Discord.exe",  L"Discord"},
                {L"Code.exe",     L"VS Code"},
            };
            for (const auto& c : checks) {
                if (IsProcessRunning(c.first)) {
                    std::cout << "[!] Запущен " << WStringToString(c.second)
                              << " - его кэш залочен и будет пропущен/очищен частично.\n";
                }
            }
        }

        uintmax_t total_found = 0;
        std::vector<CacheTarget> found_targets;
        size_t max_name_len = 20;

        std::cout << "\n[*] Сканирую систему...\n";
        for (auto& target : targets) {
            if (!IsSafePath(target.path, userProfile)) {
                std::cout << "  [WARN] Пропуск (небезопасный путь): " << WStringToString(target.name) << "\n";
                continue;
            }

            std::cout << "  -> Проверяю: " << WStringToString(target.name) << "...\n";

            if (fs::exists(target.path)) {
                target.size_before = GetSize(target.path);
                if (target.size_before > 20 * 1024 * 1024) {
                    found_targets.push_back(target);
                    total_found += target.size_before;
                    if (target.name.length() > max_name_len) max_name_len = target.name.length();
                }
            }
        }

        if (found_targets.empty()) {
            std::cout << "[+] Мусора больше 20 МБ не найдено!\n";
        } else {
            std::cout << "\n" << std::left << std::setw(max_name_len + 2) << "Инструмент"
                      << std::setw(12) << "Уровень" << std::setw(12) << "Размер" << "| Путь\n";
            std::cout << std::string(80 + max_name_len, '-') << "\n";

            for (const auto& t : found_targets) {
                std::cout << std::left << std::setw(max_name_len + 2) << WStringToString(t.name)
                          << std::setw(12) << TrustToString(t.trust)
                          << std::setw(12) << FormatSize(t.size_before)
                          << "| " << WStringToString(t.path.wstring()) << "\n";
            }
            std::cout << std::string(80 + max_name_len, '-') << "\n";
            std::cout << "ПОТЕНЦИАЛ: " << FormatSize(total_found) << "\n";

            if (!dryRun) {
                std::cout << "\n[?] Введите 'y' (SAFE+REBUILD), 'a' (ВСЁ, включая DATA) или 'n' (отмена): ";
                std::string answer;
                std::getline(std::cin, answer);
                std::transform(answer.begin(), answer.end(), answer.begin(), [](unsigned char c){ return std::tolower(c); });

                if (answer == "y" || answer == "a") {
                    std::cout << "\n[*] Зачистка...\n";

                    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    struct tm tstruct;
                    localtime_s(&tstruct, &now);
                    char buf[80];
                    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S_cleanup_log.txt", &tstruct);

                    fs::path desktop = GetDesktopPath();
                    if (desktop.empty()) desktop = userProfile;
                    fs::path logPath = desktop / buf;
                    std::ofstream log(logPath);
                    if (!log) {
                        std::cout << "[!] Не удалось создать лог-файл. Продолжаю без него.\n";
                    }

                    uintmax_t actually_freed = 0;
                    for (auto& t : found_targets) {
                        if (t.trust == Trust::DATA && answer != "a") {
                            std::cout << "  -> " << WStringToString(t.name) << " [ПРОПУЩЕН: DATA]\n";
                            continue;
                        }

                        std::cout << "  -> " << WStringToString(t.name) << "... ";
                        CleanPath(t.path);
                        t.size_after = GetSize(t.path);

                        uintmax_t freed = (t.size_before > t.size_after) ? (t.size_before - t.size_after) : 0;
                        actually_freed += freed;

                        if (freed == 0) std::cout << "[ЗАБЛОКИРОВАНО/0 B]\n";
                        else if (t.size_after > 0) std::cout << "[ЧАСТИЧНО] Освобождено: " << FormatSize(freed) << "\n";
                        else std::cout << "[OK] Освобождено: " << FormatSize(freed) << "\n";

                        if (log) {
                            log << WStringToString(t.name) << " | " << TrustToString(t.trust)
                                << " | " << FormatSize(freed) << "\n";
                        }
                    }

                    std::cout << "\n[+] РЕАЛЬНО ОСВОБОЖДЕНО: " << FormatSize(actually_freed) << "\n";
                    if (log) {
                        log << "=== ИТОГО: " << FormatSize(actually_freed) << " ===\n";
                        log.close();
                        std::cout << "[+] Лог сохранен: " << WStringToString(logPath.wstring()) << "\n";
                    }
                } else {
                    std::cout << "\n[-] Отменено.\n";
                }
            }
        }

        if (AskYesNo("\n[?] Проверить и сжать виртуальные диски WSL2/Docker (VHDX)?")) {
            CompactVHDX(dryRun);
        }

    } catch (const std::exception& e) {
        std::cout << "\n[!!!] КРИТИЧЕСКАЯ ОШИБКА: " << e.what() << "\n";
    }

    std::cout << "\nНажмите Enter для выхода...";
    std::cin.get();
    SetConsoleOutputCP(oldOutCP);
    SetConsoleCP(oldInCP);
    return 0;
}