#define _GNU_SOURCE
#include "mem_scanner.hpp"
#include <sys/uio.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <future>
#include <algorithm>

MemScanner::MemScanner() : m_isScanning(false), m_progress(0.0f) {}

MemScanner::~MemScanner() {
    detach();
}

bool MemScanner::attach(pid_t pid) {
    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
    if (!maps_file.is_open()) return false;

    m_pid = pid;
    return true;
}

void MemScanner::detach() {
    m_pid = -1;
    clearResults();
}

void MemScanner::clearResults() {
    std::lock_guard<std::mutex> lock(m_resultsMutex);
    m_results.clear();
}

struct Settings {
    int alignment = 4;
    bool darkMode = true;
    bool scanRead = true;
    bool scanWrite = false;
    bool scanExec = false;
    bool excludeKernel = true;
    int maxResults = 10000;
};
extern Settings g_settings;

std::vector<MemoryRegion> MemScanner::getRegions() {
    std::vector<MemoryRegion> regions;
    if (m_pid == -1) return regions;

    std::ifstream maps_file("/proc/" + std::to_string(m_pid) + "/maps");
    std::string line;

    while (std::getline(maps_file, line)) {
        std::istringstream iss(line);
        std::string range, perms, offset, dev, inode, pathname;
        iss >> range >> perms >> offset >> dev >> inode;

        size_t dash = range.find('-');
        uintptr_t start = std::stoull(range.substr(0, dash), nullptr, 16);
        uintptr_t end = std::stoull(range.substr(dash + 1), nullptr, 16);

        bool permMatch = (g_settings.scanRead && perms.find('r') != std::string::npos) ||
        (g_settings.scanWrite && perms.find('w') != std::string::npos) ||
        (g_settings.scanExec && perms.find('x') != std::string::npos);

        if (permMatch &&
            !(g_settings.excludeKernel && start >= 0xffffffff80000000) &&
            pathname.find("[vvar]") == std::string::npos &&
            pathname.find("[vdso]") == std::string::npos) {
            regions.push_back({start, end, perms, pathname});
            }
    }
    return regions;
}

ssize_t MemScanner::readRaw(uintptr_t address, void* buffer, size_t size) {
    if (m_pid == -1) return -1;
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = (void*)address;
    remote[0].iov_len = size;
    return process_vm_readv(m_pid, local, 1, remote, 1, 0);
}

ssize_t MemScanner::writeRaw(uintptr_t address, const void* buffer, size_t size) {
    if (m_pid == -1) return -1;
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = (void*)buffer;
    local[0].iov_len = size;
    remote[0].iov_base = (void*)address;
    remote[0].iov_len = size;
    return process_vm_writev(m_pid, local, 1, remote, 1, 0);
}

template<typename T>
T MemScanner::readMemory(uintptr_t address) {
    T buffer;
    if (readRaw(address, &buffer, sizeof(T)) != sizeof(T)) {
        std::memset(&buffer, 0, sizeof(T));
    }
    return buffer;
}

template<typename T>
bool MemScanner::writeMemory(uintptr_t address, T value) {
    return writeRaw(address, &value, sizeof(T)) == sizeof(T);
}

template uint8_t MemScanner::readMemory<uint8_t>(uintptr_t);
template uint16_t MemScanner::readMemory<uint16_t>(uintptr_t);
template uint32_t MemScanner::readMemory<uint32_t>(uintptr_t);
template uint64_t MemScanner::readMemory<uint64_t>(uintptr_t);
template float MemScanner::readMemory<float>(uintptr_t);
template double MemScanner::readMemory<double>(uintptr_t);

template bool MemScanner::writeMemory<uint8_t>(uintptr_t, uint8_t);
template bool MemScanner::writeMemory<uint16_t>(uintptr_t, uint16_t);
template bool MemScanner::writeMemory<uint32_t>(uintptr_t, uint32_t);
template bool MemScanner::writeMemory<uint64_t>(uintptr_t, uint64_t);
template bool MemScanner::writeMemory<float>(uintptr_t, float);
template bool MemScanner::writeMemory<double>(uintptr_t, double);


const size_t CHUNK_SIZE = 1024 * 1024; // 1MB

void MemScanner::scanRegionChunked(const MemoryRegion& region, ValueType type, uint32_t targetVal, float targetFloat, const std::string& targetStr, std::vector<ScanResult>& localResults) {
    size_t regionSize = region.end - region.start;
    
    // Determine number of threads to use for parallel chunk processing within this region
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) {
        numThreads = 4; // Default to 4 if hardware_concurrency() is not available
    }
    
    // Calculate total number of 1MB chunks in the region
    size_t totalChunks = (regionSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    
    // If the region is too small, or we don't have enough chunks/threads to make parallelization worthwhile, scan sequentially.
    if (numThreads <= 1 || totalChunks < numThreads * 2) { // Heuristic: only parallelize if at least 2 chunks per thread
        std::vector<uint8_t> buffer(CHUNK_SIZE + 8); // Buffer for reading chunks
        for (size_t offset = 0; offset < regionSize; offset += CHUNK_SIZE) {
            size_t bytesToRead = std::min(CHUNK_SIZE, regionSize - offset);
            // Read one extra byte so we can check the null terminator for strings
            size_t readSize = std::min(bytesToRead + 1, regionSize - offset);
            if (readRaw(region.start + offset, buffer.data(), readSize) > 0) {
                // Determine the size of the value we are searching for
                size_t valSize = (type == ValueType::String) ? targetStr.length() : 4;
                if (bytesToRead < valSize) continue; // Not enough bytes in this chunk to contain the value

                for (size_t i = 0; i <= bytesToRead - valSize; ++i) {
                    bool match = false;
                    if (type == ValueType::FourBytes) {
                        uint32_t val;
                        std::memcpy(&val, &buffer[i], 4);
                        if (val == targetVal) match = true;
                    } else if (type == ValueType::Float) {
                        float val;
                        std::memcpy(&val, &buffer.data()[i], 4);
                        if (val == targetFloat) match = true;
                    } else if (type == ValueType::String) {
                        if (std::memcmp(&buffer[i], targetStr.c_str(), targetStr.length()) == 0) {
                            // Exact match only: the byte immediately after must be a null terminator.
                            // This prevents "[FeedbackTool]" matching "[FeedbackTool](Clone)".
                            size_t afterIdx = i + targetStr.length();
                            if (afterIdx >= readSize || buffer[afterIdx] == '\0') { // Fixed multi-character literal
                                match = true;
                            }
                        }
                    }

                    if (match) {
                        localResults.push_back({region.start + offset + i});
                    }
                }
            }
        }
        return; // Sequential scan done
    }

    // Parallel processing for large regions
    std::vector<std::future<std::vector<ScanResult>>> futures;
    size_t subChunkSize = totalChunks / numThreads;
    size_t remainder = totalChunks % numThreads;
    size_t currentOffset = 0;

    for (unsigned int i = 0; i < numThreads; ++i) {
        size_t chunksForThisThread = subChunkSize + (i < remainder ? 1 : 0);
        size_t startOffset = currentOffset;
        size_t endOffset = startOffset + chunksForThisThread * CHUNK_SIZE;
        // Ensure endOffset does not exceed regionSize
        endOffset = std::min(endOffset, regionSize); 
        
        if (startOffset >= endOffset) continue; // Skip if no work for this thread

        // Capture regionSize explicitly
        futures.push_back(std::async(std::launch::async, [this, region, regionSize, type, targetVal, targetFloat, targetStr, startOffset, endOffset]() {
            std::vector<ScanResult> threadLocalResults;
            size_t currentOffsetInThread = startOffset;
            // Buffer size for reading chunks. Add CHUNK_SIZE for the actual chunk, and 8 for safety/string null check.
            std::vector<uint8_t> buffer(CHUNK_SIZE + 8); 

            while(currentOffsetInThread < endOffset) {
                // Determine the size of data to read for the current chunk, ensuring we don't read past the region's end.
                // Add 1 for potential string null terminator check.
                size_t bytesToRead = std::min(CHUNK_SIZE, endOffset - currentOffsetInThread);
                // Use captured regionSize here.
                size_t readSize = std::min(bytesToRead + 1, regionSize - currentOffsetInThread); 

                if (readRaw(region.start + currentOffsetInThread, buffer.data(), readSize) > 0) {
                    // Determine the size of the value we are searching for
                    size_t valSize = (type == ValueType::String) ? targetStr.length() : 4;
                    if (bytesToRead < valSize) continue; // Not enough bytes in this chunk to contain the value

                    for (size_t i = 0; i <= bytesToRead - valSize; ++i) {
                        bool match = false;
                        if (type == ValueType::FourBytes) {
                            uint32_t val;
                            std::memcpy(&val, &buffer[i], 4);
                            if (val == targetVal) match = true;
                        } else if (type == ValueType::Float) {
                            float val;
                            std::memcpy(&val, &buffer.data()[i], 4);
                            if (val == targetFloat) match = true;
                        } else if (type == ValueType::String) {
                            if (std::memcmp(&buffer[i], targetStr.c_str(), targetStr.length()) == 0) {
                                // Exact match only: the byte immediately after must be a null terminator.
                                size_t afterIdx = i + targetStr.length();
                                // Fixed multi-character literal, use '\0'
                                if (afterIdx >= readSize || buffer[afterIdx] == '\0') { 
                                    match = true;
                                }
                            }
                        }

                        if (match) {
                            threadLocalResults.push_back({region.start + currentOffsetInThread + i});
                        }
                    }
                }
                currentOffsetInThread += CHUNK_SIZE; // Move to the next chunk
            }
            return threadLocalResults;
        }));
        currentOffset = endOffset; // Update offset for the next thread
    }

    // Collect results from all threads
    for (auto& future : futures) {
        auto results = future.get();
        localResults.insert(localResults.end(), results.begin(), results.end());
    }
}

std::string MemScanner::readString(uintptr_t address, size_t maxLength) {
    std::vector<char> buffer(maxLength + 1);
    ssize_t n = readRaw(address, buffer.data(), maxLength);
    if (n <= 0) return "";
    buffer[n] = '\0';
    return std::string(buffer.data());
}

bool MemScanner::writeString(uintptr_t address, const std::string& value) {
    return writeRaw(address, value.c_str(), value.length()) == (ssize_t)value.length();
}

void MemScanner::firstScan(ValueType type, const std::string& valueStr) {
    if (m_isScanning) return;
    m_isScanning = true;
    m_progress = 0.0f;

    std::thread([this, type, valueStr]() {
        clearResults();
        auto regions = getRegions();

        uint32_t targetVal = 0;
        float targetFloat = 0.0f;
        try {
            if (type == ValueType::FourBytes) targetVal = (uint32_t)std::stoul(valueStr);
            if (type == ValueType::Float) targetFloat = std::stof(valueStr);
        } catch (...) {
            m_isScanning = false;
            return;
        }

        std::vector<std::future<std::vector<ScanResult>>> futures;
        for (const auto& region : regions) {
            futures.push_back(std::async(std::launch::async, [this, region, type, targetVal, targetFloat, valueStr]() {
                std::vector<ScanResult> local;
                scanRegionChunked(region, type, targetVal, targetFloat, valueStr, local);
                return local;
            }));
        }

        std::vector<ScanResult> allResults;
        for (size_t i = 0; i < futures.size(); ++i) {
            auto results = futures[i].get();
            allResults.insert(allResults.end(), results.begin(), results.end());
            m_progress = (float)(i + 1) / futures.size();
        }

        {
            std::lock_guard<std::mutex> lock(m_resultsMutex);
            m_results = std::move(allResults);
        }

        m_isScanning = false;
        m_progress = 1.0f;
    }).detach();
}

void MemScanner::nextScan(ValueType type, const std::string& valueStr) {
    if (m_isScanning) return;
    m_isScanning = true;
    m_progress = 0.0f; // Reset progress

    std::thread([this, type, valueStr]() {
        uint32_t targetVal = 0;
        float targetFloat = 0.0f;
        try {
            if (type == ValueType::FourBytes) targetVal = (uint32_t)std::stoul(valueStr);
            if (type == ValueType::Float) targetFloat = std::stof(valueStr);
        } catch (...) {
            m_isScanning = false;
            return;
        }

        std::vector<ScanResult> currentResults;
        {
            std::lock_guard<std::mutex> lock(m_resultsMutex);
            currentResults = m_results; // Make a copy to iterate over
        }

        if (currentResults.empty()) {
            m_isScanning = false;
            m_progress = 1.0f;
            return;
        }

        std::vector<ScanResult> newResults;
        std::vector<std::future<std::vector<ScanResult>>> futures;

        // Determine number of threads
        unsigned int numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) {
            numThreads = 4; // Default to 4 if hardware_concurrency() is not available
        }
        // Ensure we don't use more threads than results to check
        numThreads = std::min(numThreads, (unsigned int)currentResults.size());
        
        size_t chunkSize = currentResults.size() / numThreads;
        size_t remainder = currentResults.size() % numThreads;
        size_t startIndex = 0;

        for (unsigned int i = 0; i < numThreads; ++i) {
            size_t currentChunkSize = chunkSize + (i < remainder ? 1 : 0);
            size_t endIndex = startIndex + currentChunkSize;

            if (currentChunkSize == 0) continue; // Skip if no work for this thread

            futures.push_back(std::async(std::launch::async, [this, &currentResults, type, targetVal, targetFloat, valueStr, startIndex, endIndex]() {
                std::vector<ScanResult> localResults;
                for (size_t j = startIndex; j < endIndex; ++j) {
                    const auto& res = currentResults[j];
                    bool match = false;
                    if (type == ValueType::FourBytes) {
                        uint32_t val = readMemory<uint32_t>(res.address);
                        if (val == targetVal) match = true;
                    } else if (type == ValueType::Float) {
                        float val = readMemory<float>(res.address);
                        if (val == targetFloat) match = true;
                    } else if (type == ValueType::String) {
                        // Read one extra byte so we can check the null terminator after the match.
                        std::string val = readString(res.address, valueStr.length() + 1);
                        if (val.length() >= valueStr.length() &&
                            val.substr(0, valueStr.length()) == valueStr &&
                            (val.length() == valueStr.length() || val[valueStr.length()] == '\\0')) { // Escaped null terminator for string literal
                            match = true;
                        }
                    }
                    if (match) {
                        localResults.push_back(res);
                    }
                }
                return localResults;
            }));
            startIndex = endIndex;
        }

        // Collect results and update progress
        for (size_t i = 0; i < futures.size(); ++i) {
            auto results = futures[i].get();
            newResults.insert(newResults.end(), results.begin(), results.end());
            // Update progress based on how many futures have completed. This is a rough approximation.
            m_progress = (float)(i + 1) / futures.size(); 
        }

        {
            std::lock_guard<std::mutex> lock(m_resultsMutex);
            m_results = std::move(newResults);
        }

        m_isScanning = false;
        m_progress = 1.0f; // Ensure progress is 100% upon completion
    }).detach();
}
