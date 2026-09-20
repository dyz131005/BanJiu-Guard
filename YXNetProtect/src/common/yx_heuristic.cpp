// BanJiu-Guard - 启发式扫描引擎实现
#include "yx_heuristic.h"
#include <windows.h>
#include <winnt.h>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <set>
#include <cstring>

namespace yx {

HeuristicEngine::HeuristicEngine() {}

// 计算数据熵值（0-8，越高越随机/加密）
double HeuristicEngine::ComputeEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;
    size_t freq[256] = { 0 };
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// 可疑导入函数列表（进程注入、代码执行、反调试等）
static const char* kSuspiciousApis[] = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "OpenProcess", "ReadProcessMemory", "SetWindowsHookEx",
    "QueueUserAPC", "NtQueueApcThread", "NtCreateThreadEx",
    "LoadLibrary", "GetProcAddress", "VirtualProtectEx",
    "TerminateProcess", "CreateProcess", "ShellExecute",
    "WinExec", "URLDownloadToFile", "InternetOpen",
    "HttpSendRequest", "CryptEncrypt", "CryptDecrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtSetInformationThread", "GetTickCount",
    "RegSetValueEx", "RegCreateKey", "CreateService",
    "StartService", "ControlService",
};

static bool IsSuspiciousApi(const char* name) {
    if (!name) return false;
    for (auto* api : kSuspiciousApis) {
        if (strcmp(name, api) == 0) return true;
    }
    return false;
}

// 检查导入表中的可疑函数
int HeuristicEngine::CheckSuspiciousImports(const void* peBase, size_t fileSize, std::string& reasons) {
    auto* dos = (PIMAGE_DOS_HEADER)peBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = (PIMAGE_NT_HEADERS)((uint8_t*)peBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRva == 0) return 0;

    // 将 RVA 转换为文件偏移（简化处理：节区对齐通常等于文件对齐）
    auto RvaToOffset = [&](DWORD rva) -> DWORD {
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize) {
                return rva - sec->VirtualAddress + sec->PointerToRawData;
            }
        }
        return 0;
    };

    DWORD importOff = RvaToOffset(importRva);
    if (importOff == 0 || importOff >= fileSize) return 0;

    std::set<std::string> suspiciousFound;
    auto* desc = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)peBase + importOff);
    while (desc->Name != 0) {
        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        DWORD thunkOff = RvaToOffset(thunkRva);
        if (thunkOff != 0 && thunkOff < fileSize) {
            if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                auto* thunk = (PIMAGE_THUNK_DATA32)((uint8_t*)peBase + thunkOff);
                while (thunk->u1.AddressOfData != 0) {
                    if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                        auto* ibn = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)peBase + RvaToOffset(thunk->u1.AddressOfData));
                        if ((uint8_t*)ibn < (uint8_t*)peBase + fileSize) {
                            const char* fn = (const char*)ibn->Name;
                            if (IsSuspiciousApi(fn)) suspiciousFound.insert(fn);
                        }
                    }
                    thunk++;
                }
            } else {
                auto* thunk = (PIMAGE_THUNK_DATA64)((uint8_t*)peBase + thunkOff);
                while (thunk->u1.AddressOfData != 0) {
                    if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                        auto* ibn = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)peBase + RvaToOffset((DWORD)thunk->u1.AddressOfData));
                        if ((uint8_t*)ibn < (uint8_t*)peBase + fileSize) {
                            const char* fn = (const char*)ibn->Name;
                            if (IsSuspiciousApi(fn)) suspiciousFound.insert(fn);
                        }
                    }
                    thunk++;
                }
            }
        }
        desc++;
        if ((uint8_t*)desc >= (uint8_t*)peBase + fileSize) break;
    }

    if (!suspiciousFound.empty()) {
        reasons += "可疑导入函数(";
        int cnt = 0;
        for (auto& s : suspiciousFound) {
            if (cnt++ > 0) reasons += ",";
            reasons += s;
            if (cnt >= 8) { reasons += "..."; break; }
        }
        reasons += ") ";
    }
    return (int)suspiciousFound.size();
}

// 检查 PE 结构异常
int HeuristicEngine::CheckPeAnomalies(const void* peBase, size_t fileSize, std::string& reasons) {
    int anomalies = 0;
    auto* dos = (PIMAGE_DOS_HEADER)peBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = (PIMAGE_NT_HEADERS)((uint8_t*)peBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    WORD numSec = nt->FileHeader.NumberOfSections;
    DWORD epRva = nt->OptionalHeader.AddressOfEntryPoint;

    auto* sec = IMAGE_FIRST_SECTION(nt);

    // 1. 检查入口点是否在 .text 之外
    bool epInText = false;
    for (WORD i = 0; i < numSec; i++, sec++) {
        if (epRva >= sec->VirtualAddress && epRva < sec->VirtualAddress + sec->Misc.VirtualSize) {
            char name[9] = { 0 };
            memcpy(name, sec->Name, 8);
            if (strcmp(name, ".text") == 0) epInText = true;
            break;
        }
    }
    if (!epInText && epRva != 0) {
        anomalies += 2;
        reasons += "入口点不在代码段 ";
    }

    // 2. 检查节区熵值（加壳检测）
    sec = IMAGE_FIRST_SECTION(nt);
    int highEntropySec = 0;
    for (WORD i = 0; i < numSec; i++, sec++) {
        if (sec->PointerToRawData == 0 || sec->SizeOfRawData == 0) continue;
        if (sec->PointerToRawData + sec->SizeOfRawData > fileSize) continue;
        // 只分析非代码节的高熵（代码节本身熵就较高）
        char name[9] = { 0 };
        memcpy(name, sec->Name, 8);
        if (strcmp(name, ".text") == 0 || strcmp(name, ".rdata") == 0) continue;

        double ent = ComputeEntropy((uint8_t*)peBase + sec->PointerToRawData, sec->SizeOfRawData);
        if (ent > 7.0) highEntropySec++;
    }
    if (highEntropySec >= 1) {
        anomalies += 3;
        reasons += "检测到加壳/加密节区(熵>7) ";
    }

    // 3. 检查节区名称异常（非标准节名）
    sec = IMAGE_FIRST_SECTION(nt);
    static const char* kStandardSecs[] = { ".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata", ".tls", ".pdata", ".CRT", ".gfids" };
    for (WORD i = 0; i < numSec; i++, sec++) {
        char name[9] = { 0 };
        memcpy(name, sec->Name, 8);
        if (name[0] == '\0') continue;
        bool standard = false;
        for (auto* s : kStandardSecs) {
            if (strcmp(name, s) == 0) { standard = true; break; }
        }
        if (!standard) {
            anomalies += 1;
            reasons += std::string("异常节名(") + name + ") ";
            break;
        }
    }

    // 4. 检查 TimeDateStamp 是否为 0（部分恶意软件会清零）
    if (nt->FileHeader.TimeDateStamp == 0) {
        anomalies += 1;
        reasons += "编译时间戳为0 ";
    }

    // 5. 检查 SizeOfImage 是否异常
    if (nt->OptionalHeader.SizeOfImage > 200 * 1024 * 1024) {
        anomalies += 1;
        reasons += "镜像大小异常 ";
    }

    return anomalies;
}

// PE 结构分析
bool HeuristicEngine::AnalyzePe(const std::wstring& filePath, HeuristicResult& result) const {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    size_t fileSize = (size_t)file.tellg();
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) return false;
    file.seekg(0, std::ios::beg);

    // 读取整个文件到内存
    std::vector<uint8_t> buffer(fileSize);
    file.read((char*)buffer.data(), fileSize);
    file.close();

    if (buffer.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) return false;

    auto* dos = (PIMAGE_DOS_HEADER)buffer.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    if (dos->e_lfanew + sizeof(DWORD) >= (LONG)buffer.size()) return false;
    auto* nt = (PIMAGE_NT_HEADERS)(buffer.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    int score = 0;
    std::string reason;

    // 1. PE 结构异常
    std::string anomalyReasons;
    int anomalies = CheckPeAnomalies(buffer.data(), buffer.size(), anomalyReasons);
    score += anomalies * 8;
    if (!anomalyReasons.empty()) reason += anomalyReasons;

    // 2. 可疑导入函数
    std::string importReasons;
    int suspiciousImports = CheckSuspiciousImports(buffer.data(), buffer.size(), importReasons);
    if (suspiciousImports > 0) {
        score += suspiciousImports * 5;
        reason += importReasons;
    }

    // 3. 组合判断：如果同时有结构异常 + 多个可疑导入，加权
    if (anomalies >= 2 && suspiciousImports >= 3) {
        score += 15;
        reason += "[多特征组合命中] ";
    }

    // 4. 检查是否有数字签名（通过安全目录）
    DWORD securityRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    if (securityRva == 0) {
        score += 5;
        reason += "无数字签名 ";
    }

    if (score > 100) score = 100;

    result.score = score;
    result.reason = reason;
    result.suspicious = (score >= 30);

    return true;
}

// 扫描单个文件
HeuristicResult HeuristicEngine::ScanFile(const std::wstring& filePath) const {
    HeuristicResult result;

    // 只扫描可执行文件
    std::wstring ext;
    size_t dot = filePath.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        ext = filePath.substr(dot);
        std::transform(ext.begin(), ext.end(), ext.begin(), towlower);
    }

    bool isExecutable = (ext == L".exe" || ext == L".dll" || ext == L".sys" ||
                         ext == L".scr" || ext == L".ocx" || ext == L".cpl" ||
                         ext == L".drv" || ext == L".efi");

    if (!isExecutable) {
        result.suspicious = false;
        result.score = 0;
        return result;
    }

    // 分析 PE 结构
    if (!AnalyzePe(filePath, result)) {
        result.suspicious = false;
        result.score = 0;
    }

    return result;
}

} // namespace yx
