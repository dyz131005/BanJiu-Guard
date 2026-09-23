// BanJiu-Guard - 机器学习检测引擎实现（LightGBM 静态库推理）
#include "yx_ml_engine.h"

#include <windows.h>
#include <winnt.h>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstring>
#include <filesystem>

#include <LightGBM/c_api.h>

namespace yx {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

// 计算数据熵值（0-8）
static double CalcEntropy(const uint8_t* data, size_t size) {
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

// RVA 转文件偏移
static DWORD RvaToOffset(PIMAGE_NT_HEADERS nt, DWORD rva) {
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD span = sec->Misc.VirtualSize > 0 ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + span) {
            return rva - sec->VirtualAddress + sec->PointerToRawData;
        }
    }
    return 0;
}

// 统计导入的 DLL 数量与函数总数
static void CountImports(const uint8_t* base, size_t fileSize, PIMAGE_NT_HEADERS nt,
                         int& numDlls, int& numFuncs) {
    numDlls = 0;
    numFuncs = 0;
    DWORD importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRva == 0) return;
    DWORD importOff = RvaToOffset(nt, importRva);
    if (importOff == 0 || importOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return;

    auto* desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + importOff);
    while (desc->Name != 0) {
        numDlls++;
        DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        DWORD thunkOff = RvaToOffset(nt, thunkRva);
        if (thunkOff != 0 && thunkOff < fileSize) {
            if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                auto* thunk = (PIMAGE_THUNK_DATA32)(base + thunkOff);
                while (thunk->u1.AddressOfData != 0 &&
                       (uintptr_t)(thunk + 1) <= (uintptr_t)base + fileSize) {
                    numFuncs++;
                    thunk++;
                }
            } else {
                auto* thunk = (PIMAGE_THUNK_DATA64)(base + thunkOff);
                while (thunk->u1.AddressOfData != 0 &&
                       (uintptr_t)(thunk + 1) <= (uintptr_t)base + fileSize) {
                    numFuncs++;
                    thunk++;
                }
            }
        }
        desc++;
        if ((uintptr_t)(desc + 1) > (uintptr_t)base + fileSize) break;
    }
}

// 统计导出函数数
static int CountExports(const uint8_t* base, size_t fileSize, PIMAGE_NT_HEADERS nt) {
    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRva == 0) return 0;
    DWORD off = RvaToOffset(nt, exportRva);
    if (off == 0 || off + sizeof(IMAGE_EXPORT_DIRECTORY) > fileSize) return 0;
    auto* expDir = (PIMAGE_EXPORT_DIRECTORY)(base + off);
    return (int)expDir->NumberOfFunctions;
}

// 递归统计资源树中的叶子数据项数量
static int CountResourceEntries(const uint8_t* base, size_t fileSize,
                                PIMAGE_RESOURCE_DIRECTORY dir, DWORD tableOff) {
    if (!dir) return 0;
    int count = 0;
    DWORD named = dir->NumberOfNamedEntries;
    DWORD total = named + dir->NumberOfIdEntries;
    auto* entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(dir + 1);
    for (DWORD i = 0; i < total; i++) {
        DWORD offToData = entry[i].OffsetToData;
        if (offToData & IMAGE_RESOURCE_DATA_IS_DIRECTORY) {
            DWORD subOff = tableOff + (offToData & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY);
            if (subOff + sizeof(IMAGE_RESOURCE_DIRECTORY) <= fileSize) {
                count += CountResourceEntries(base, fileSize,
                                              (PIMAGE_RESOURCE_DIRECTORY)(base + subOff), tableOff);
            }
        } else {
            count++;
        }
    }
    return count;
}

static int CountResources(const uint8_t* base, size_t fileSize, PIMAGE_NT_HEADERS nt) {
    DWORD rsrcRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    if (rsrcRva == 0) return 0;
    DWORD off = RvaToOffset(nt, rsrcRva);
    if (off == 0 || off + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) return 0;
    auto* root = (PIMAGE_RESOURCE_DIRECTORY)(base + off);
    return CountResourceEntries(base, fileSize, root, off);
}

// 统计调试目录条目数
static int CountDebugEntries(const uint8_t* base, size_t fileSize, PIMAGE_NT_HEADERS nt) {
    auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (dd.VirtualAddress == 0 || dd.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) return 0;
    DWORD off = RvaToOffset(nt, dd.VirtualAddress);
    if (off == 0 || off + dd.Size > fileSize) return 0;
    return (int)(dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY));
}

// 统计 RICH 头中的条目数（每条 8 字节：prodid/revision + 使用次数）
static int CountRichEntries(const uint8_t* base, size_t fileSize, LONG peOffset) {
    // RICH 头位于 DOS 头之后、PE 头之前
    if (fileSize < 0x80 || (size_t)peOffset + 4 > fileSize) return 0;
    const uint32_t kRich = 0x68636952;  // "Rich"
    const uint32_t kDanS = 0x536E6144;  // "DanS"

    uint32_t key = 0;
    LONG richPos = -1;
    for (LONG pos = 0x80; pos + 4 <= peOffset; pos += 4) {
        uint32_t v;
        memcpy(&v, base + pos, 4);
        // "Rich" 标记被 XOR，其后紧跟未加密的 key；用 key 校验标记
        if (pos + 8 <= peOffset) {
            uint32_t maybeKey;
            memcpy(&maybeKey, base + pos + 4, 4);
            if ((v ^ maybeKey) == kRich) {
                key = maybeKey;
                richPos = pos;
                break;
            }
        }
    }
    if (richPos < 0 || key == 0) return 0;

    // 找起始标记 DanS（异或后）
    LONG dansPos = -1;
    for (LONG pos = 0x80; pos + 4 <= richPos; pos += 4) {
        uint32_t v;
        memcpy(&v, base + pos, 4);
        if ((v ^ key) == kDanS) {
            dansPos = pos;
            break;
        }
    }
    if (dansPos < 0) return 0;

    // DanS 占 1 个 DWORD，其值后到 Rich 之间每 8 字节为一条
    LONG dataBytes = richPos - (dansPos + 4);
    if (dataBytes < 0) return 0;
    return dataBytes / 8;
}

// ---------------------------------------------------------------------------
// MlEngine
// ---------------------------------------------------------------------------

MlEngine::MlEngine() {}

MlEngine::~MlEngine() {
    if (m_handle) {
        LGBM_BoosterFree((BoosterHandle)m_handle);
        m_handle = nullptr;
    }
}

static std::wstring ExeDir() {
    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    return fs::path(path).parent_path().wstring();
}

bool MlEngine::Load(const std::wstring& modelPath) {
    if (m_handle) return true;

    // 候选路径：显式指定，其次 exe 目录下 models 子目录，最后 exe 目录
    std::vector<std::wstring> candidates;
    if (!modelPath.empty()) candidates.push_back(modelPath);
    std::wstring dir = ExeDir();
    candidates.push_back(dir + L"\\models\\" + kMlModelFileName);
    candidates.push_back(dir + L"\\" + kMlModelFileName);

    std::string foundPath;
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec)) {
            // wide → UTF-8
            int len = WideCharToMultiByte(CP_UTF8, 0, p.c_str(), -1, nullptr, 0, nullptr, nullptr);
            foundPath.resize(len > 0 ? len - 1 : 0);
            if (len > 0) {
                WideCharToMultiByte(CP_UTF8, 0, p.c_str(), -1, &foundPath[0], len, nullptr, nullptr);
            }
            break;
        }
    }

    if (foundPath.empty()) return false;

    BoosterHandle handle = nullptr;
    int numIter = 0;
    int ret = LGBM_BoosterCreateFromModelfile(foundPath.c_str(), &numIter, &handle);
    if (ret != 0 || !handle) return false;

    m_handle = handle;
    return true;
}

MlResult MlEngine::ScanFile(const std::wstring& filePath) const {
    MlResult result;
    if (!m_handle) return result;

    // 读取整个文件
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return result;
    size_t fileSize = (size_t)file.tellg();
    if (fileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) return result;
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(fileSize);
    file.read((char*)buf.data(), fileSize);
    file.close();

    auto* dos = (PIMAGE_DOS_HEADER)buf.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileSize) return result;
    auto* nt = (PIMAGE_NT_HEADERS)(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    WORD numSec = nt->FileHeader.NumberOfSections;
    auto* sec0 = IMAGE_FIRST_SECTION(nt);
    if ((uintptr_t)(sec0 + numSec) > (uintptr_t)(buf.data() + fileSize)) return result;

    // 特征向量（顺序必须与训练模型 feature_names 完全一致）
    double feat[22] = { 0 };

    feat[0] = (double)fileSize;                  // file_size
    feat[1] = (double)numSec;                    // num_sections

    int numDlls = 0, numFuncs = 0;
    CountImports(buf.data(), fileSize, nt, numDlls, numFuncs);
    feat[2] = (double)numFuncs;                  // num_imports
    feat[3] = (double)numDlls;                   // num_import_dlls
    feat[4] = (double)CountExports(buf.data(), fileSize, nt);   // num_exports
    feat[5] = (double)CountResources(buf.data(), fileSize, nt); // num_resources

    feat[6] = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress != 0
                  ? 1.0 : 0.0;                   // has_digital_signature

    // 全文件熵
    feat[7] = CalcEntropy(buf.data(), fileSize); // entropy_overall

    // 节区熵值统计
    DWORD epRva = nt->OptionalHeader.AddressOfEntryPoint;
    double sumEnt = 0.0, maxEnt = 0.0, minEnt = 8.0;
    int writableExec = 0, zeroName = 0, validSec = 0;
    double epEntropy = 0.0;
    int epWritable = 0, epExecutable = 0;
    DWORD maxRawEnd = 0;

    for (WORD i = 0; i < numSec; i++) {
        auto* sec = sec0 + i;

        if (sec->Name[0] == '\0') zeroName++;

        bool writable = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        bool exec = (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (writable && exec) writableExec++;

        DWORD rawEnd = sec->PointerToRawData + sec->SizeOfRawData;
        if (rawEnd > maxRawEnd && sec->SizeOfRawData > 0) maxRawEnd = rawEnd;

        if (sec->PointerToRawData != 0 && sec->SizeOfRawData > 0 &&
            rawEnd <= fileSize) {
            double ent = CalcEntropy(buf.data() + sec->PointerToRawData, sec->SizeOfRawData);
            sumEnt += ent;
            if (ent > maxEnt) maxEnt = ent;
            if (ent < minEnt) minEnt = ent;
            validSec++;

            // 入口点所在节区
            DWORD vsize = sec->Misc.VirtualSize > 0 ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            if (epRva >= sec->VirtualAddress && epRva < sec->VirtualAddress + vsize) {
                epEntropy = ent;
                epWritable = writable ? 1 : 0;
                epExecutable = exec ? 1 : 0;
            }
        }
    }
    if (validSec == 0) minEnt = 0.0;

    feat[8]  = epEntropy;                         // ep_section_entropy
    feat[9]  = (double)epWritable;                // ep_section_writable
    feat[10] = (double)epExecutable;              // ep_section_executable
    feat[11] = sumEnt;                            // sum_section_entropy
    feat[12] = maxEnt;                            // max_section_entropy
    feat[13] = minEnt;                            // min_section_entropy
    feat[14] = (double)writableExec;              // num_writable_exec_sections
    feat[15] = (double)zeroName;                  // zero_section_name_cnt
    feat[16] = (double)nt->OptionalHeader.SizeOfCode;   // size_of_code

    DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
    feat[17] = sizeOfImage > 0 ? (double)epRva / (double)sizeOfImage : 0.0;  // entrypoint_offset_ratio
    feat[18] = (double)CountDebugEntries(buf.data(), fileSize, nt);          // num_debug_entries
    feat[19] = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0
                   ? 1.0 : 0.0;                   // has_tls
    feat[20] = (double)CountRichEntries(buf.data(), fileSize, dos->e_lfanew); // num_rich_entries

    // overlay（最后一个节后的附加数据）
    if (maxRawEnd > 0 && fileSize > maxRawEnd) {
        feat[21] = (double)(fileSize - maxRawEnd) / (double)fileSize;  // overlay_size_ratio
    }

    // LightGBM 推理：row-major float64，NORMAL 预测（二分类返回 sigmoid 概率）
    int64_t outLen = 0;
    double outProb = 0.0;
    int ret = LGBM_BoosterPredictForMat((BoosterHandle)m_handle,
                                        feat,
                                        C_API_DTYPE_FLOAT64,
                                        1, m_numFeatures, 1,
                                        C_API_PREDICT_NORMAL,
                                        0, -1, "",
                                        &outLen, &outProb);
    if (ret != 0 || outLen < 1) return result;

    result.valid = true;
    result.probability = outProb;
    result.score = (int)(outProb * 100.0 + 0.5);
    if (result.score > 100) result.score = 100;
    return result;
}

// ---------------------------------------------------------------------------
// 分数融合：启发式 70% + 机器学习 30%
// ---------------------------------------------------------------------------
FusionResult FuseScores(int heurScore, const MlResult& ml) {
    FusionResult f;
    f.heurScore = heurScore;
    f.mlAvailable = ml.valid;
    f.mlScore = ml.valid ? ml.score : 0;

    double fused = ml.valid
        ? (double)heurScore * 0.7 + (double)f.mlScore * 0.3
        : (double)heurScore;
    if (fused < 0) fused = 0;
    if (fused > 100) fused = 100;
    f.score = (int)(fused + 0.5);
    f.suspicious = (f.score >= 30);
    return f;
}

} // namespace yx
