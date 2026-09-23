// BanJiu-Guard - 机器学习检测引擎（LightGBM 模型推理）
// 加载预训练的 LightGBM 二分类模型，对 PE 文件提取 22 维特征并预测恶意概率。
// 与启发式引擎融合使用：最终分数 = 启发式*0.7 + ML*0.3。
#pragma once

#include <string>
#include <cstdint>

namespace yx {

// ML 推理结果
struct MlResult {
    bool   valid = false;       // 模型是否成功加载并完成推理
    double probability = 0.0;   // 恶意概率 [0,1]（sigmoid 后）
    int    score = 0;           // 归一化威胁分数 0-100
};

// 融合检测结果
struct FusionResult {
    int  score = 0;             // 融合后分数 0-100
    bool suspicious = false;    // 是否达到拦截阈值（>=30）
    bool mlAvailable = false;   // ML 模型是否参与打分
    int  heurScore = 0;         // 启发式分数
    int  mlScore = 0;           // ML 分数
};

class MlEngine {
public:
    MlEngine();
    ~MlEngine();

    MlEngine(const MlEngine&) = delete;
    MlEngine& operator=(const MlEngine&) = delete;

    // 从指定路径加载 LightGBM 模型；空路径时自动在 exe 目录下查找
    bool Load(const std::wstring& modelPath = L"");
    bool IsLoaded() const { return m_handle != nullptr; }

    // 对 PE 文件提取特征并推理，返回恶意概率分数
    MlResult ScanFile(const std::wstring& filePath) const;

private:
    void* m_handle = nullptr;    // BoosterHandle（LightGBM 预测句柄，预测线程安全）
    int   m_numFeatures = 22;    // 模型特征数
};

// 融合启发式分数与 ML 分数：启发式 70% + ML 30%
// ML 不可用时直接使用启发式分数
FusionResult FuseScores(int heurScore, const MlResult& ml);

// 默认模型文件名
constexpr const wchar_t* kMlModelFileName = L"lgbm_detector.txt";

} // namespace yx
