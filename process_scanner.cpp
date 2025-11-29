#include <iostream>
#include <windows.h>
#include <vector>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")

class MemoryScanner {
private:
    HANDLE hProcess;
    
public:
    MemoryScanner(DWORD pid = 0) {
        if (pid == 0) {
            // 默认扫描当前进程
            hProcess = GetCurrentProcess();
        } else {
            // 打开指定进程
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProcess) {
                std::cout << "无法打开进程 PID: " << pid << " 错误代码: " << GetLastError() << std::endl;
            }
        }
    }
    
    ~MemoryScanner() {
        if (hProcess && hProcess != GetCurrentProcess()) {
            CloseHandle(hProcess);
        }
    }
    
    bool IsValid() const {
        return hProcess != NULL;
    }
    
    // 获取进程句柄（公开方法）
    HANDLE GetProcessHandle() const {
        return hProcess;
    }
    
    // 搜索内存中的特定整数值
    std::vector<DWORD_PTR> SearchIntValue(int targetValue) {
        std::vector<DWORD_PTR> results;
        
        if (!hProcess) return results;
        
        MEMORY_BASIC_INFORMATION mbi;
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        
        DWORD_PTR address = (DWORD_PTR)si.lpMinimumApplicationAddress;
        DWORD_PTR maxAddress = (DWORD_PTR)si.lpMaximumApplicationAddress;
        
        std::cout << "扫描内存范围: " << (void*)address << " - " << (void*)maxAddress << std::endl;
        
        while (address < maxAddress) {
            if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // 只搜索可读可写且已提交的内存区域
                if (mbi.State == MEM_COMMIT && 
                    (mbi.Protect == PAGE_READWRITE || 
                     mbi.Protect == PAGE_EXECUTE_READWRITE ||
                     (mbi.Protect & PAGE_READWRITE))) {
                    
                    ScanMemoryRegion(mbi, targetValue, results);
                }
                
                address = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
            } else {
                break;
            }
        }
        
        return results;
    }
    
    // 替换内存中的值
    bool ReplaceValue(DWORD_PTR address, int oldValue, int newValue) {
        if (!hProcess) return false;
        
        SIZE_T bytesRead;
        int value;
        
        // 读取当前值确认
        if (ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(value), &bytesRead)) {
            if (value == oldValue) {
                // 修改内存保护为可写
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, (LPVOID)address, sizeof(value), PAGE_READWRITE, &oldProtect)) {
                    // 写入新值
                    BOOL result = WriteProcessMemory(hProcess, (LPVOID)address, &newValue, sizeof(newValue), &bytesRead);
                    // 恢复内存保护
                    VirtualProtectEx(hProcess, (LPVOID)address, sizeof(value), oldProtect, &oldProtect);
                    return result;
                }
            }
        }
        return false;
    }
    
    // 验证内存值
    bool VerifyValue(DWORD_PTR address, int expectedValue) {
        if (!hProcess) return false;
        
        int value;
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(value), &bytesRead)) {
            return value == expectedValue;
        }
        return false;
    }
    
    // 获取进程名
    std::string GetProcessName() {
        if (!hProcess) return "Unknown";
        
        char processName[MAX_PATH] = {0};
        if (GetModuleFileNameExA(hProcess, NULL, processName, MAX_PATH)) {
            return processName;
        }
        return "Unknown";
    }
    
private:
    void ScanMemoryRegion(MEMORY_BASIC_INFORMATION& mbi, int targetValue, std::vector<DWORD_PTR>& results) {
        const size_t bufferSize = mbi.RegionSize;
        if (bufferSize > 100 * 1024 * 1024) { // 限制大内存区域，避免分配过多内存
            return;
        }
        
        BYTE* buffer = new BYTE[bufferSize];
        SIZE_T bytesRead;
        
        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, bufferSize, &bytesRead)) {
            // 在缓冲区中搜索目标值
            for (size_t i = 0; i <= bytesRead - sizeof(int); i += sizeof(int)) {
                // 对齐检查，只检查4字节对齐的地址
                if ((i % sizeof(int)) == 0) {
                    int* currentValue = (int*)(buffer + i);
                    if (*currentValue == targetValue) {
                        DWORD_PTR foundAddress = (DWORD_PTR)mbi.BaseAddress + i;
                        results.push_back(foundAddress);
                    }
                }
            }
        }
        
        delete[] buffer;
    }
};

// 显示进程列表
void ShowProcessList() {
    std::cout << "\n当前运行进程列表:" << std::endl;
    std::cout << "PID\t进程名" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::cout << pe32.th32ProcessID << "\t" << pe32.szExeFile << std::endl;
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

int main() {
    std::cout << "进程内存扫描器" << std::endl;
    std::cout << "======================" << std::endl;
    
    // 显示进程列表
    ShowProcessList();
    
    DWORD targetPid;
    std::cout << "\n请输入要扫描的进程PID (输入0扫描当前进程): ";
    std::cin >> targetPid;
    
    // 创建内存扫描器
    MemoryScanner scanner(targetPid);
    
    if (!scanner.IsValid()) {
        std::cout << "无法打开指定进程，程序退出。" << std::endl;
        return 1;
    }
    
    std::cout << "成功打开进程: " << scanner.GetProcessName() << std::endl;
    
    int searchValue, replaceValue;
    std::cout << "请输入要搜索的整数值: ";
    std::cin >> searchValue;
    std::cout << "请输入要替换的整数值: ";
    std::cin >> replaceValue;
    
    std::cout << "\n正在扫描进程内存，搜索值为 " << searchValue << " 的内存地址..." << std::endl;
    std::cout << "这可能需要一些时间，请耐心等待..." << std::endl;
    
    auto addresses = scanner.SearchIntValue(searchValue);
    
    std::cout << "找到 " << addresses.size() << " 个匹配的地址" << std::endl;
    
    if (!addresses.empty()) {
        std::cout << "\n开始替换为 " << replaceValue << "..." << std::endl;
        int successCount = 0;
        
        for (size_t i = 0; i < addresses.size(); i++) {
            if (scanner.ReplaceValue(addresses[i], searchValue, replaceValue)) {
                std::cout << "[" << i + 1 << "/" << addresses.size() << "] 成功替换地址: " << (void*)addresses[i] << std::endl;
                successCount++;
            }
        }
        
        std::cout << "\n替换完成! 成功替换了 " << successCount << " 个值" << std::endl;
        
        // 可选：验证替换结果
        std::cout << "\n是否要验证替换结果？(y/n): ";
        char verify;
        std::cin >> verify;
        
        if (verify == 'y' || verify == 'Y') {
            std::cout << "验证替换结果..." << std::endl;
            int verifiedCount = 0;
            for (auto addr : addresses) {
                if (scanner.VerifyValue(addr, replaceValue)) {
                    verifiedCount++;
                }
            }
            std::cout << "验证完成: " << verifiedCount << "/" << addresses.size() << " 个值替换成功" << std::endl;
        }
    } else {
        std::cout << "没有找到值为 " << searchValue << " 的内存地址" << std::endl;
    }
    
    std::cout << "\n程序结束，按任意键退出..." << std::endl;
    std::cin.ignore();
    std::cin.get();
    
    return 0;
}