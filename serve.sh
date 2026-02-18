#!/bin/bash

echo "========================================="
echo "🚀 Starting diagnostic and compilation"
echo "========================================="
echo ""

# =========================================
# DIAGNOSTIC INFORMATION
# =========================================
echo "📋 System Information:"
echo "Current directory: $(pwd)"
echo "Current user: $(whoami)"
echo "Operating System: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo ""

echo "📂 Directory contents:"
ls -la
echo ""

# =========================================
# CHECK FOR SOURCE FILE
# =========================================
echo "📄 Checking for source file:"
if [ -f "lab_practice_v3.cpp" ]; then
    echo "✅ Source file found: lab_practice_v3.cpp"
    echo "File size: $(wc -l < lab_practice_v3.cpp) lines"
    echo "First 10 lines of source:"
    echo "----------------------------------------"
    head -10 lab_practice_v3.cpp
    echo "----------------------------------------"
else
    echo "❌ Source file NOT found!"
    echo "Files in current directory:"
    ls -la
    exit 1
fi
echo ""

# =========================================
# CHECK COMPILER
# =========================================
echo "🔧 Checking compiler:"
if command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "✅ Compiler found: $(which x86_64-w64-mingw32-g++)"
    echo "Compiler version:"
    x86_64-w64-mingw32-g++ --version | head -1
else
    echo "❌ Compiler NOT found!"
    exit 1
fi
echo ""

# =========================================
# CHECK HEADERS AND LIBRARIES
# =========================================
echo "📚 Checking available headers and libraries:"

# Check include directories
echo ""
echo "Include directories:"
for dir in /usr/x86_64-w64-mingw32/include /usr/include /usr/local/include; do
    if [ -d "$dir" ]; then
        echo "✅ $dir exists"
        echo "   Files in $dir (first 20):"
        ls -la "$dir" 2>/dev/null | head -20 | sed 's/^/   /'
    else
        echo "❌ $dir not found"
    fi
done

# Check specific Windows headers
echo ""
echo "Windows-specific headers:"
headers=(
    "windows.h"
    "winsock2.h"
    "wininet.h"
    "shlobj.h"
    "psapi.h"
    "iphlpapi.h"
    "wlanapi.h"
    "winternl.h"
    "tlhelp32.h"
    "userenv.h"
    "commdlg.h"
    "gdiplus.h"
    "winhttp.h"
    "winreg.h"
    "wincrypt.h"
    "nb30.h"
)

for header in "${headers[@]}"; do
    found=0
    for dir in /usr/x86_64-w64-mingw32/include /usr/include; do
        if [ -f "$dir/$header" ]; then
            echo "✅ $header found in $dir"
            found=1
            break
        fi
    done
    if [ $found -eq 0 ]; then
        echo "❌ $header MISSING"
    fi
done

# Check library directories
echo ""
echo "Library directories:"
for dir in /usr/x86_64-w64-mingw32/lib /usr/lib/gcc/x86_64-w64-mingw32/*; do
    if [ -d "$dir" ]; then
        echo "✅ $dir exists"
        echo "   Libraries in $dir (first 20):"
        ls -la "$dir"/*.a 2>/dev/null | head -20 | sed 's/^/   /' || echo "   No .a files found"
    fi
done

# Check specific libraries
echo ""
echo "Windows-specific libraries:"
libraries=(
    "libws2_32.a"
    "libwininet.a"
    "libiphlpapi.a"
    "libwlanapi.a"
    "libadvapi32.a"
    "libgdiplus.a"
    "libshell32.a"
    "libwinhttp.a"
    "libcrypt32.a"
    "libnetapi32.a"
)

for lib in "${libraries[@]}"; do
    found=0
    for dir in /usr/x86_64-w64-mingw32/lib /usr/lib/gcc/x86_64-w64-mingw32/*; do
        if [ -f "$dir/$lib" ] || [ -f "$dir/${lib%.a}.dll.a" ]; then
            echo "✅ $lib found in $dir"
            found=1
            break
        fi
    done
    if [ $found -eq 0 ]; then
        echo "❌ $lib MISSING"
    fi
done
echo ""

# =========================================
# TEST MINIMAL COMPILATION
# =========================================
echo "🧪 Testing minimal compilation..."
echo '#include <iostream>' > test_minimal.cpp
echo 'int main() { std::cout << "Hello from Windows!" << std::endl; return 0; }' >> test_minimal.cpp

x86_64-w64-mingw32-g++ -static -o test_minimal.exe test_minimal.cpp -v 2>&1 | tee test_minimal_log.txt

if [ -f "test_minimal.exe" ]; then
    echo "✅ Minimal test compilation successful!"
    file test_minimal.exe
    ls -lh test_minimal.exe
else
    echo "❌ Minimal test compilation failed!"
    echo "Last 20 lines of compilation log:"
    tail -20 test_minimal_log.txt
fi
echo ""

# =========================================
# TEST WINDOWS API COMPILATION
# =========================================
echo "🧪 Testing Windows API compilation..."
echo '#include <windows.h>' > test_win.cpp
echo 'int WINAPI WinMain(HINSTANCE h1, HINSTANCE h2, LPSTR lp, int nShow) {' >> test_win.cpp
echo '    MessageBoxA(NULL, "Test from Windows API", "Test", MB_OK);' >> test_win.cpp
echo '    return 0;' >> test_win.cpp
echo '}' >> test_win.cpp

x86_64-w64-mingw32-g++ -static -o test_win.exe test_win.cpp -lgdi32 -luser32 -v 2>&1 | tee test_win_log.txt

if [ -f "test_win.exe" ]; then
    echo "✅ Windows API test compilation successful!"
else
    echo "❌ Windows API test compilation failed!"
    echo "Last 20 lines of compilation log:"
    tail -20 test_win_log.txt
fi
echo ""

# =========================================
# MAIN COMPILATION ATTEMPT
# =========================================
echo "========================================="
echo "🔨 Attempting main compilation"
echo "========================================="
echo ""

# Try multiple compilation methods
COMPILE_SUCCESS=0

# Method 1: Full compilation with all libraries
echo "Method 1: Full compilation with all libraries..."
x86_64-w64-mingw32-g++ -static -O2 -s -o lab_practice_v3.exe lab_practice_v3.cpp \
    -lws2_32 \
    -lwininet \
    -liphlpapi \
    -lwlanapi \
    -ladvapi32 \
    -lgdiplus \
    -lshell32 \
    -lwinhttp \
    -lcrypt32 \
    -lnetapi32 \
    -lole32 \
    -loleaut32 \
    -luuid \
    -lcomctl32 \
    -lcomdlg32 \
    -static-libgcc \
    -static-libstdc++ \
    -std=c++17 \
    -D_WIN32_WINNT=0x0601 \
    -DWINVER=0x0601 \
    -I/usr/x86_64-w64-mingw32/include \
    -L/usr/x86_64-w64-mingw32/lib \
    -v 2>&1 | tee compilation_log.txt

if [ $? -eq 0 ] && [ -f "lab_practice_v3.exe" ]; then
    echo "✅ Method 1 succeeded!"
    COMPILE_SUCCESS=1
else
    echo "❌ Method 1 failed"
    
    # Method 2: Try with essential libraries only
    echo ""
    echo "Method 2: Compilation with essential libraries..."
    x86_64-w64-mingw32-g++ -static -O2 -s -o lab_practice_v3.exe lab_practice_v3.cpp \
        -lws2_32 \
        -lwininet \
        -liphlpapi \
        -ladvapi32 \
        -lgdiplus \
        -lshell32 \
        -lwinhttp \
        -lcrypt32 \
        -static-libgcc \
        -static-libstdc++ \
        -std=c++17 \
        -D_WIN32_WINNT=0x0601 \
        -DWINVER=0x0601 \
        -v 2>&1 | tee -a compilation_log.txt
    
    if [ $? -eq 0 ] && [ -f "lab_practice_v3.exe" ]; then
        echo "✅ Method 2 succeeded!"
        COMPILE_SUCCESS=1
    else
        echo "❌ Method 2 failed"
        
        # Method 3: Try with even fewer libraries
        echo ""
        echo "Method 3: Minimal library compilation..."
        x86_64-w64-mingw32-g++ -static -O2 -s -o lab_practice_v3.exe lab_practice_v3.cpp \
            -lws2_32 \
            -ladvapi32 \
            -lgdi32 \
            -luser32 \
            -lkernel32 \
            -static-libgcc \
            -static-libstdc++ \
            -std=c++17 \
            -v 2>&1 | tee -a compilation_log.txt
        
        if [ $? -eq 0 ] && [ -f "lab_practice_v3.exe" ]; then
            echo "✅ Method 3 succeeded!"
            COMPILE_SUCCESS=1
        else
            echo "❌ Method 3 failed"
            COMPILE_SUCCESS=0
        fi
    fi
fi

echo ""

# =========================================
# COMPILATION RESULT
# =========================================
echo "========================================="
echo "📊 Compilation Result"
echo "========================================="

if [ $COMPILE_SUCCESS -eq 1 ] && [ -f "lab_practice_v3.exe" ]; then
    echo "✅ COMPILATION SUCCESSFUL!"
    echo ""
    echo "Executable details:"
    file lab_practice_v3.exe
    ls -lh lab_practice_v3.exe
    
    # Copy to output directory
    mkdir -p /output
    cp lab_practice_v3.exe /output/
    cp compilation_log.txt /output/ 2>/dev/null
    echo ""
    echo "✅ Executable copied to /output/"
else
    echo "❌ COMPILATION FAILED"
    echo ""
    echo "Last 50 lines of compilation log:"
    echo "----------------------------------------"
    tail -50 compilation_log.txt
    echo "----------------------------------------"
    echo ""
    echo "Common issues and solutions:"
    echo "1. Missing Windows headers - Install mingw-w64-headers"
    echo "2. Missing libraries - Check if -l flags are correct"
    echo "3. Source code errors - Check for syntax errors in your code"
    echo "4. GDI+ issues - Ensure gdiplus is properly installed"
    echo "5. WLAN API issues - May need additional headers"
fi

# =========================================
# CREATE WEB INTERFACE
# =========================================
echo ""
echo "========================================="
echo "🌐 Creating web interface"
echo "========================================="

# Create output directory if it doesn't exist
mkdir -p /output

# Create index.html with status
cat > /output/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Windows Executable Builder</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #333;
            margin-bottom: 30px;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 15px;
        }
        .success {
            background: #d4edda;
            color: #155724;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 5px solid #28a745;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 5px solid #dc3545;
        }
        .info-box {
            background: #e9ecef;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .download-btn {
            display: inline-block;
            background: #0078d7;
            color: white;
            padding: 15px 40px;
            text-decoration: none;
            border-radius: 50px;
            font-size: 18px;
            font-weight: bold;
            margin: 20px 0;
            transition: background 0.3s;
            border: none;
            cursor: pointer;
        }
        .download-btn:hover {
            background: #005a9e;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .log-box {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            max-height: 500px;
            overflow-y: auto;
            margin: 20px 0;
            border: 1px solid #333;
        }
        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 5px solid #ffc107;
        }
        .file-info {
            font-size: 16px;
            margin: 10px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .file-info strong {
            color: #0078d7;
            width: 120px;
            display: inline-block;
        }
        .button-container {
            text-align: center;
            margin: 30px 0;
        }
        .timestamp {
            color: #666;
            font-size: 14px;
            margin-top: 20px;
            text-align: right;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ Windows Executable Builder</h1>
EOF

if [ -f "lab_practice_v3.exe" ]; then
    # Success case
    FILESIZE=$(ls -lh lab_practice_v3.exe | awk '{print $5}')
    FILETYPE=$(file lab_practice_v3.exe | cut -d':' -f2-)
    
    cat >> /output/index.html << EOF
        <div class="success">
            <strong>✅ BUILD SUCCESSFUL!</strong><br>
            Your Windows executable has been successfully compiled.
        </div>
        
        <div class="info-box">
            <h3>📊 File Information</h3>
            <div class="file-info"><strong>Filename:</strong> lab_practice_v3.exe</div>
            <div class="file-info"><strong>Size:</strong> $FILESIZE</div>
            <div class="file-info"><strong>Type:</strong> $FILETYPE</div>
            <div class="file-info"><strong>Build Time:</strong> $(date)</div>
        </div>
        
        <div class="button-container">
            <a href="/lab_practice_v3.exe" class="download-btn" download>📥 DOWNLOAD EXECUTABLE</a>
        </div>
EOF
else
    # Failure case
    cat >> /output/index.html << EOF
        <div class="error">
            <strong>❌ BUILD FAILED</strong><br>
            Compilation was not successful. Check the log below for errors.
        </div>
        
        <div class="info-box">
            <h3>🔧 Troubleshooting Tips</h3>
            <ul>
                <li>Check if all required Windows headers are installed</li>
                <li>Verify that all library flags (-l) are correct</li>
                <li>Look for syntax errors in the source code</li>
                <li>Ensure GDI+ and WLAN libraries are available</li>
                <li>Check the compilation log for specific error messages</li>
            </ul>
        </div>
EOF
fi

# Add compilation log section
cat >> /output/index.html << 'EOF'
        <h3>📋 Compilation Log</h3>
        <div class="log-box">
            <pre>
EOF

if [ -f compilation_log.txt ]; then
    cat compilation_log.txt >> /output/index.html
else
    echo "No compilation log available" >> /output/index.html
fi

# Add test logs if they exist
if [ -f test_minimal_log.txt ]; then
    echo "" >> /output/index.html
    echo "=== MINIMAL TEST LOG ===" >> /output/index.html
    cat test_minimal_log.txt >> /output/index.html
fi

if [ -f test_win_log.txt ]; then
    echo "" >> /output/index.html
    echo "=== WINDOWS API TEST LOG ===" >> /output/index.html
    cat test_win_log.txt >> /output/index.html
fi

# Close HTML
cat >> /output/index.html << 'EOF'
            </pre>
        </div>
        
        <div class="warning">
            <strong>⚠️ IMPORTANT SECURITY NOTICE:</strong><br>
            This executable is for authorized lab use only. Always:
            <ul>
                <li>Run in isolated virtual machines</li>
                <li>Scan with multiple antivirus engines</li>
                <li>Monitor network traffic during testing</li>
                <li>Have snapshot/restore capability ready</li>
                <li>Never run on production or personal systems</li>
            </ul>
        </div>
        
        <div class="timestamp">
            Last updated: $(date)
        </div>
    </div>
</body>
</html>
EOF

# Copy executable and logs to output
if [ -f "lab_practice_v3.exe" ]; then
    cp lab_practice_v3.exe /output/
fi
cp *.txt /output/ 2>/dev/null || true

# =========================================
# START WEB SERVER
# =========================================
echo ""
echo "========================================="
echo "🌐 Starting web server"
echo "========================================="

# Get the port Render assigns
PORT=${PORT:-10000}

# Show what's being served
echo "📁 Serving files from: /output"
echo "📋 Directory contents:"
ls -la /output/

echo ""
echo "🚀 Server starting on port $PORT"
echo "📎 Main URL: http://localhost:$PORT"
echo "📎 Download URL: http://localhost:$PORT/lab_practice_v3.exe"
echo "📎 Status page: http://localhost:$PORT/index.html"
echo ""

# Start the web server
cd /output
exec python3 -m http.server $PORT --bind 0.0.0.0
