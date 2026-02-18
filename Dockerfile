# Use Ubuntu 22.04 LTS as base
FROM ubuntu:22.04

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Update and install base dependencies
RUN apt-get update && apt-get install -y \
    # Essential build tools
    build-essential \
    cmake \
    make \
    pkg-config \
    autoconf \
    automake \
    libtool \
    wget \
    curl \
    git \
    unzip \
    zip \
    tar \
    # MinGW compiler and tools
    mingw-w64 \
    g++-mingw-w64-x86-64 \
    mingw-w64-tools \
    mingw-w64-x86-64-dev \
    # Python for web server
    python3 \
    python3-pip \
    # Additional utilities
    nano \
    vim \
    tree \
    file \
    binutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create symlinks for MinGW (sometimes needed)
RUN ln -sf /usr/bin/x86_64-w64-mingw32-g++ /usr/bin/mingw32-g++ 2>/dev/null || true

# Download and install additional Windows libraries from LLVM-MinGW
RUN wget https://github.com/mstorsjo/llvm-mingw/releases/download/20250114/llvm-mingw-20250114-ucrt-ubuntu-20.04-x86_64.tar.xz && \
    tar -xf llvm-mingw-20250114-ucrt-ubuntu-20.04-x86_64.tar.xz && \
    # Copy additional headers
    cp -r llvm-mingw-20250114-ucrt-ubuntu-20.04-x86_64/x86_64-w64-mingw32/include/* /usr/x86_64-w64-mingw32/include/ 2>/dev/null || true && \
    # Copy additional libraries
    cp -r llvm-mingw-20250114-ucrt-ubuntu-20.04-x86_64/x86_64-w64-mingw32/lib/* /usr/x86_64-w64-mingw32/lib/ 2>/dev/null || true && \
    # Clean up
    rm -rf llvm-mingw-20250114-ucrt-ubuntu-20.04-x86_64*

# Install nlohmann/json library (required for your code)
RUN git clone https://github.com/nlohmann/json.git && \
    mkdir -p /usr/x86_64-w64-mingw32/include/nlohmann && \
    cp json/single_include/nlohmann/json.hpp /usr/x86_64-w64-mingw32/include/nlohmann/ && \
    rm -rf json

# Create directory structure for Windows headers if missing
RUN mkdir -p /usr/x86_64-w64-mingw32/include && \
    mkdir -p /usr/x86_64-w64-mingw32/lib

# Download and install Windows SDK headers (partial)
RUN git clone https://github.com/Alexpux/mingw-w64.git /tmp/mingw-w64 && \
    cd /tmp/mingw-w64/mingw-w64-headers && \
    ./configure --prefix=/usr/x86_64-w64-mingw32 --host=x86_64-w64-mingw32 && \
    make install && \
    cd / && rm -rf /tmp/mingw-w64

# Create a script to verify installation
RUN echo '#!/bin/bash' > /usr/local/bin/verify-mingw.sh && \
    echo 'echo "🔍 Verifying MinGW installation:"' >> /usr/local/bin/verify-mingw.sh && \
    echo 'x86_64-w64-mingw32-g++ --version' >> /usr/local/bin/verify-mingw.sh && \
    echo 'echo ""' >> /usr/local/bin/verify-mingw.sh && \
    echo 'echo "📚 Checking critical headers:"' >> /usr/local/bin/verify-mingw.sh && \
    echo 'for header in windows.h winsock2.h wininet.h shlobj.h iphlpapi.h wlanapi.h winternl.h tlhelp32.h gdiplus.h winhttp.h winreg.h wincrypt.h nb30.h; do' >> /usr/local/bin/verify-mingw.sh && \
    echo '    if [ -f "/usr/x86_64-w64-mingw32/include/$header" ]; then' >> /usr/local/bin/verify-mingw.sh && \
    echo '        echo "✅ $header found"' >> /usr/local/bin/verify-mingw.sh && \
    echo '    else' >> /usr/local/bin/verify-mingw.sh && \
    echo '        echo "❌ $header MISSING"' >> /usr/local/bin/verify-mingw.sh && \
    echo '    fi' >> /usr/local/bin/verify-mingw.sh && \
    echo 'done' >> /usr/local/bin/verify-mingw.sh && \
    chmod +x /usr/local/bin/verify-mingw.sh

# Run verification
RUN /usr/local/bin/verify-mingw.sh

# Set working directory
WORKDIR /build

# Copy the serve.sh script (will be added via GitHub)
COPY serve.sh .

# Make sure serve.sh is executable
RUN chmod +x serve.sh

# Copy the source file (will be added via GitHub)
COPY lab_practice_v3.cpp .

# Create a simple test file to verify compilation works
RUN echo '#include <iostream>' > test.cpp && \
    echo 'int main() { std::cout << "Hello from Windows!" << std::endl; return 0; }' >> test.cpp && \
    x86_64-w64-mingw32-g++ -static -o test.exe test.cpp && \
    echo "✅ Test compilation successful" || echo "❌ Test compilation failed"

# Create a Windows API test file
RUN echo '#include <windows.h>' > test_win.cpp && \
    echo 'int WINAPI WinMain(HINSTANCE h1, HINSTANCE h2, LPSTR lp, int nShow) {' >> test_win.cpp && \
    echo '    MessageBoxA(NULL, "Windows API Test", "Success", MB_OK);' >> test_win.cpp && \
    echo '    return 0;' >> test_win.cpp && \
    echo '}' >> test_win.cpp && \
    x86_64-w64-mingw32-g++ -static -o test_win.exe test_win.cpp -lgdi32 -luser32 && \
    echo "✅ Windows API test successful" || echo "❌ Windows API test failed"

# Create a GDI+ test file (since your code uses it)
RUN echo '#include <windows.h>' > test_gdi.cpp && \
    echo '#include <gdiplus.h>' >> test_gdi.cpp && \
    echo 'using namespace Gdiplus;' >> test_gdi.cpp && \
    echo 'int main() {' >> test_gdi.cpp && \
    echo '    GdiplusStartupInput gdiplusStartupInput;' >> test_gdi.cpp && \
    echo '    ULONG_PTR gdiplusToken;' >> test_gdi.cpp && \
    echo '    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);' >> test_gdi.cpp && \
    echo '    GdiplusShutdown(gdiplusToken);' >> test_gdi.cpp && \
    echo '    return 0;' >> test_gdi.cpp && \
    echo '}' >> test_gdi.cpp && \
    x86_64-w64-mingw32-g++ -static -o test_gdi.exe test_gdi.cpp -lgdiplus && \
    echo "✅ GDI+ test successful" || echo "❌ GDI+ test failed"

# Create a WLAN API test file
RUN echo '#include <windows.h>' > test_wlan.cpp && \
    echo '#include <wlanapi.h>' >> test_wlan.cpp && \
    echo 'int main() {' >> test_wlan.cpp && \
    echo '    HANDLE hClient = NULL;' >> test_wlan.cpp && \
    echo '    DWORD dwVersion = 0;' >> test_wlan.cpp && \
    echo '    WlanOpenHandle(2, NULL, &dwVersion, &hClient);' >> test_wlan.cpp && \
    echo '    if (hClient) WlanCloseHandle(hClient, NULL);' >> test_wlan.cpp && \
    echo '    return 0;' >> test_wlan.cpp && \
    echo '}' >> test_wlan.cpp && \
    x86_64-w64-mingw32-g++ -static -o test_wlan.exe test_wlan.cpp -lwlanapi && \
    echo "✅ WLAN API test successful" || echo "❌ WLAN API test failed"

# Display all test results
RUN echo "=========================================" && \
    echo "Test Compilation Results:" && \
    echo "=========================================" && \
    ls -la test*.exe 2>/dev/null || echo "No test executables found"

# Create a helper script to list available libraries
RUN echo '#!/bin/bash' > /usr/local/bin/list-libs.sh && \
    echo 'echo "📚 Available Windows libraries:"' >> /usr/local/bin/list-libs.sh && \
    echo 'find /usr/x86_64-w64-mingw32/lib -name "*.a" | sort | while read lib; do' >> /usr/local/bin/list-libs.sh && \
    echo '    echo "   $(basename $lib)"' >> /usr/local/bin/list-libs.sh && \
    echo 'done' >> /usr/local/bin/list-libs.sh && \
    chmod +x /usr/local/bin/list-libs.sh

# Create a helper script to list available headers
RUN echo '#!/bin/bash' > /usr/local/bin/list-headers.sh && \
    echo 'echo "📚 Available Windows headers:"' >> /usr/local/bin/list-headers.sh && \
    echo 'find /usr/x86_64-w64-mingw32/include -name "*.h" | sort | head -50 | while read header; do' >> /usr/local/bin/list-headers.sh && \
    echo '    echo "   $(basename $header)"' >> /usr/local/bin/list-headers.sh && \
    echo 'done' >> /usr/local/bin/list-headers.sh && \
    chmod +x /usr/local/bin/list-headers.sh

# Create a README file with instructions
RUN echo "Windows Executable Builder" > /README.txt && \
    echo "=========================" >> /README.txt && \
    echo "" >> /README.txt && \
    echo "This container compiles Windows executables using MinGW-w64." >> /README.txt && \
    echo "" >> /README.txt && \
    echo "Files:" >> /README.txt && \
    echo "  /build/lab_practice_v3.cpp - Your source code" >> /README.txt && \
    echo "  /build/serve.sh - Web server script" >> /README.txt && \
    echo "" >> /README.txt && \
    echo "Compilation commands used:" >> /README.txt && \
    echo "  x86_64-w64-mingw32-g++ -static -O2 -s -o output.exe input.cpp \\" >> /README.txt && \
    echo "    -lws2_32 -lwininet -liphlpapi -lwlanapi -ladvapi32 -lgdiplus \\" >> /README.txt && \
    echo "    -lshell32 -lwinhttp -lcrypt32 -lnetapi32 -static-libgcc -static-libstdc++" >> /README.txt && \
    echo "" >> /README.txt && \
    echo "Helper scripts:" >> /README.txt && \
    echo "  verify-mingw.sh - Check MinGW installation" >> /README.txt && \
    echo "  list-libs.sh - List available libraries" >> /README.txt && \
    echo "  list-headers.sh - List available headers" >> /README.txt

# Expose port for web server
EXPOSE 8080

# Set the default command to run serve.sh
CMD ["/build/serve.sh"]

# Health check to ensure the service is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/ || exit 1
