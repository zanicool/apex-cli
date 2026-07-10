#pragma once
#include <string>
#include <thread>
#include <fstream>
#include <algorithm>

namespace apex {

struct HardwareProfile {
    int logical_cores = 0;
    int physical_cores = 0;
    std::string cpu_model;
    int recommended_threads = 0;
    int max_safe_threads = 0;
    double system_reserve_pct = 0.25; // Reserve 25% for OS + other apps
};

inline HardwareProfile detect_hardware() {
    HardwareProfile hw;

    // Detect logical cores (threads)
    hw.logical_cores = static_cast<int>(std::thread::hardware_concurrency());
    if (hw.logical_cores == 0) hw.logical_cores = 4; // Fallback

    // Try to read CPU model and physical cores from /proc/cpuinfo (Linux)
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        
        
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos && hw.cpu_model.empty()) {
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    hw.cpu_model = line.substr(pos + 2);
                }
            }
            if (line.find("cpu cores") != std::string::npos && hw.physical_cores == 0) {
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    hw.physical_cores = std::stoi(line.substr(pos + 2));
                }
            }
        }
    }

    if (hw.physical_cores == 0) {
        // Assume hyperthreading: physical = logical / 2
        hw.physical_cores = std::max(1, hw.logical_cores / 2);
    }

    if (hw.cpu_model.empty()) {
        hw.cpu_model = "Unknown CPU";
    }

    // Calculate safe thread count
    // Rule: use up to 75% of logical cores for network I/O threads
    // Network scanning is I/O-bound, not CPU-bound, so we can go higher
    // than physical cores but shouldn't saturate everything
    int available = static_cast<int>(hw.logical_cores * (1.0 - hw.system_reserve_pct));
    available = std::max(2, available); // Minimum 2 threads

    // For network I/O we can multiply by 4-8x since threads mostly wait
    // But cap it so we don't run out of file descriptors or memory
    hw.max_safe_threads = std::min(available * 8, 500);
    hw.recommended_threads = std::min(available * 4, 200);

    return hw;
}

/// Auto-tune thread count based on hardware. Returns optimal thread count.
inline int auto_threads(int user_requested = 0) {
    auto hw = detect_hardware();

    if (user_requested > 0) {
        // User specified — respect it but warn if too high
        if (user_requested > hw.max_safe_threads) {
            return hw.max_safe_threads;
        }
        return user_requested;
    }

    // Auto-detect optimal
    return hw.recommended_threads;
}

} // namespace apex
