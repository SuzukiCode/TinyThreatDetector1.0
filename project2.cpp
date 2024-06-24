//============================================================================
// Name        : Simple_Malware_Scanner.cpp
// Author      : Susan Verdin
// Version     : Simple Malware scanner that reads hashes from a .txt file
// Description : Hello World in C++, Ansi-style
//============================================================================

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <tchar.h>

bool findYara32(wchar_t* yara32FilePath) {
    // Construct the full path to yara32.exe in Windows\System32
    wchar_t system32Path[MAX_PATH];
    if (!GetSystemDirectoryW(system32Path, MAX_PATH)) {
        wprintf(L"Failed to retrieve System32 directory.\n");
        return false;
    }

    wchar_t searchPath[MAX_PATH];
    _snwprintf_s(searchPath, MAX_PATH, _TRUNCATE, L"%s\\yara32.exe", system32Path);

    // Check if the file exists
    if (GetFileAttributes(searchPath) != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(yara32FilePath, MAX_PATH, searchPath);
        return true;
    }

    wprintf(L"yara32.exe not found in Windows\\System32 directory.\n");
    return false;
}

bool browseForFile(wchar_t* filePath, LPCWSTR filter) {
    OPENFILENAMEW ofn;
    wchar_t szFile[MAX_PATH];

    // Initialize OPENFILENAMEW
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = L'\0';
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    // Display the Open dialog box
    if (GetOpenFileNameW(&ofn) == TRUE) {
        wcscpy_s(filePath, MAX_PATH, szFile);
        return true;
    }
    else {
        return false;
    }
}

bool runYara(wchar_t* yaraFilePath, wchar_t* yaraRulesFilePath, wchar_t* sampleFilePath) {
    wchar_t command[MAX_PATH * 2];
    swprintf_s(command, MAX_PATH * 2, L"\"%s\" %s %s", yaraFilePath, yaraRulesFilePath, sampleFilePath);

    // Print the command to debug
    wprintf(L"Command: %s\n\n", command); // Print command with newline after

    // Execute the command
    int result = _wsystem(command);
    if (result == 0) {
        wprintf(L"YARA scan completed successfully.\n");
        return true;
    }
    else {
        wprintf(L"YARA scan failed with error code: %d\n", result);
        return false;
    }
}

int main() {
    wchar_t yaraFilePath[MAX_PATH];
    wchar_t yaraRulesFilePath[MAX_PATH];
    wchar_t sampleFilePath[MAX_PATH];
    wchar_t yara32FilePath[MAX_PATH];

    // Find yara32.exe in Windows\System32
    if (!findYara32(yara32FilePath)) {
        wprintf(L"Failed to find yara32.exe in Windows\\System32 directory.\n");
        return 1;
    }

    wprintf(L"Found yara32.exe: %s\n", yara32FilePath); // Debug output

    // Select the YARA rules file (.yar)
    wprintf(L"Please select the YARA rules file (.yar):\n");
    if (!browseForFile(yaraRulesFilePath, L"YARA Rules Files (*.yar)\0*.yar\0All Files\0*.*\0")) {
        wprintf(L"Failed to select YARA rules file.\n");
        return 1;
    }

    wprintf(L"Selected YARA rules file: %s\n", yaraRulesFilePath); // Debug output

    // Select the sample file to scan
    wprintf(L"Please select the sample file to scan:\n");
    if (!browseForFile(sampleFilePath, L"All Files\0*.*\0")) {
        wprintf(L"Failed to select sample file.\n");
        return 1;
    }

    wprintf(L"Selected sample file: %s\n", sampleFilePath); // Debug output

    // Running YARA scan
    wprintf(L"Running YARA scan...\n");
    if (!runYara(yara32FilePath, yaraRulesFilePath, sampleFilePath)) {
        wprintf(L"YARA scan failed.\n");
        return 1;
    }

    return 0;
}
