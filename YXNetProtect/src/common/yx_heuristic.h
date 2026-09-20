// BanJiu-Guard - 启发式扫描引擎
// 通过分析 PE 文件结构特征（节区熵、可疑导入函数、加壳检测、签名缺失等）
// 对未知恶意软件进行评分，不依赖特征库。
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace yx {

// 启发式扫描结果
struct HeuristicResult {
    bool        suspicious = false;     // 是否可疑
    int         score = 0;              // 威胁分数（0-100，越高越可疑）
    std::string reason;                 // 命中原因
};

// 启发式扫描引擎
class HeuristicEngine {
public:
    HeuristicEngine();

    // 扫描单个文件，返回启发式评估结果
    HeuristicResult ScanFile(const std::wstring& filePath) const;

private:
    // PE 结构分析
    bool AnalyzePe(const std::wstring& filePath, HeuristicResult& result) const;

    // 计算节区熵值（检测加壳）
    static double ComputeEntropy(const uint8_t* data, size_t size);

    // 检查导入函数是否包含可疑 API
    static int CheckSuspiciousImports(const void* peBase, size_t fileSize, std::string& reasons);

    // 检查 PE 结构异常
    static int CheckPeAnomalies(const void* peBase, size_t fileSize, std::string& reasons);
};

} // namespace yx
