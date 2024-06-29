#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

// 函数声明
void enable_device(const std::wstring& instanceId);
void disable_device(const std::wstring& instanceId);
PROCESS_INFORMATION start_external_program(const std::wstring& programPath, const std::wstring& arguments);
DWORD find_process_id(const std::wstring& processName);
void kill_process(DWORD processId);
bool is_admin();
void run_as_admin();
std::wstring get_executable_path();

// 主函数
int main() {
    if (!is_admin()) {
        run_as_admin();
        return 0;
    }

    std::wstring instanceId = L"ACPI\\NVDA0820\\NPCF";
    std::wstring exePath = get_executable_path();
    std::wstring programPath = exePath + L"\\FurMark\\FurMark.exe";
    std::wstring arguments = L"/nogui /width=1 /height=1 /run_mode=0";

    //提示正在启用设备
    std::wcout << L"Enabling device: " << instanceId << std::endl;
    // 启用设备
    enable_device(instanceId);

    //提示正在启动Furmark
    std::wcout << L"Starting FurMark..." << std::endl;
    // 启动外部程序
    PROCESS_INFORMATION pi = start_external_program(programPath, arguments);

    // 等待10秒，确保受热均匀
    std::wcout << L"Waiting for 10 seconds..." << std::endl;
    Sleep(10000);

    //提示正在禁用设备
    std::wcout << L"Disabling device: " << instanceId << std::endl;

    // 禁用设备
    disable_device(instanceId);

    // 获取进程ID并杀死进程
    DWORD processId = find_process_id(L"FurMark.exe");
    if (processId != 0) {
        kill_process(processId);
    } else {
        std::cerr << "Failed to find process: FurMark.exe" << std::endl;
    }
    //显示2秒的已完成提示
    std::wcout << L"Finished." << std::endl;
    Sleep(2000);
    return 0;
}

// 检查是否以管理员身份运行
bool is_admin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// 以管理员权限重新运行程序
void run_as_admin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath))) {
        SHELLEXECUTEINFOW sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = NULL;
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.lpParameters = NULL;
        sei.lpDirectory = NULL;
        sei.nShow = SW_NORMAL;
        sei.hInstApp = NULL;
        sei.lpIDList = NULL;
        sei.lpClass = NULL;
        sei.hkeyClass = NULL;
        sei.dwHotKey = 0;
        sei.hIcon = NULL;
        sei.hProcess = NULL;

        if (!ShellExecuteExW(&sei)) {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED) {
                std::cerr << "User refused to grant admin privileges." << std::endl;
            }
        }
    }
}

// 获取可执行文件的路径
std::wstring get_executable_path() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    return std::wstring(buffer).substr(0, pos);
}

// 启用设备的函数
void enable_device(const std::wstring& instanceId) {
    std::wstring command = L"powershell.exe -Command \"Enable-PnpDevice -InstanceId '" + instanceId + L"' -Confirm:$false\"";
    _wsystem(command.c_str());
}

// 禁用设备的函数
void disable_device(const std::wstring& instanceId) {
    std::wstring command = L"powershell.exe -Command \"Disable-PnpDevice -InstanceId '" + instanceId + L"' -Confirm:$false\"";
    _wsystem(command.c_str());
}

// 启动外部程序并返回进程句柄
PROCESS_INFORMATION start_external_program(const std::wstring& programPath, const std::wstring& arguments) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::wstring commandLine = programPath + L" " + arguments;

    // 启动外部程序
    if (!CreateProcessW(NULL, &commandLine[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to start program: " << std::endl;
        std::exit(EXIT_FAILURE);
    }

    return pi;
}

// 查找进程ID
DWORD find_process_id(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (processName == pe.szExeFile) {
                    processId = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}

// 杀死进程
void kill_process(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
}
