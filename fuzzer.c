#include <iostream>
#include <windows.h>
#include <ole2.h>
#include <objbase.h>
#include <fstream>

// Helper to log results
void LogResult(const std::string& message) {
    std::ofstream logFile("fuzz_log.txt", std::ios::app);
    logFile << message << std::endl;
    logFile.close();
}

// Fuzzing entry function
void FuzzStgOpenStorage(const std::wstring& filePath) {
    IStorage* pStorage = nullptr;

    // Attempt to open the file with StgOpenStorageEx
    HRESULT hr = StgOpenStorageEx(
        filePath.c_str(),           // File path
        STGM_READ | STGM_SHARE_DENY_WRITE,  // Read-only mode
        STGFMT_STORAGE,             // Open compound document format
        0,                          // Reserved
        nullptr,                    // Optional performance buffer
        nullptr,                    // Optional security descriptor
        IID_IStorage,               // Interface ID to retrieve
        (void**)&pStorage           // Output storage object
    );

    if (SUCCEEDED(hr)) {
        std::wcout << L"[INFO] Successfully opened: " << filePath << std::endl;
        LogResult("[SUCCESS] Opened: " + std::string(filePath.begin(), filePath.end()));
        pStorage->Release();
    } else {
        std::wcout << L"[ERROR] Failed to open: " << filePath << L" HRESULT=" << std::hex << hr << std::endl;
        LogResult("[ERROR] HRESULT=" + std::to_string(hr) + " while opening: " + std::string(filePath.begin(), filePath.end()));
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: fuzz_harness.exe <path to input file>" << std::endl;
        return 1;
    }

    // Convert the input file path to a wide string
    std::string inputFile = argv[1];
    std::wstring wideInputFile(inputFile.begin(), inputFile.end());

    // Try to fuzz StgOpenStorageEx
    try {
        FuzzStgOpenStorage(wideInputFile);
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        LogResult("[EXCEPTION] " + std::string(e.what()));
    }

    return 0;
}