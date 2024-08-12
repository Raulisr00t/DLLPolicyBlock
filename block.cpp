#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <string.h>
#include <Psapi.h>

#define LOCAL_BLOCKDLLPOLICY

#ifdef LOCAL_BLOCKDLLPOLICY
#define STOP_ARG "Raulisr00t"
#endif

using namespace std;

bool CreateProcessWithDllPolicy(IN LPCSTR lpProcessPath, OUT HANDLE* hProcess, OUT HANDLE* hThread, OUT DWORD* dwProcessID) {
    STARTUPINFOEXA SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    SIZE_T sAttrSize = 0;
    PVOID pAttrBuff = NULL;

    if (lpProcessPath == NULL) {
        cerr << "[!] Please Include Process Path [!]" << endl;
        return FALSE;
    }

    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // Determine the size of the attribute list
    InitializeProcThreadAttributeList(NULL, 1, 0, &sAttrSize);
    pAttrBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);

    if (pAttrBuff == NULL) {
        cerr << "[!] HeapAlloc failed for pAttrBuff [!]" << endl;
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuff, 1, 0, &sAttrSize)) {
        cerr << "[!] InitializeProcThreadAttributeList Failed With Error: " << GetLastError() << endl;
        HeapFree(GetProcessHeap(), 0, pAttrBuff);
        return FALSE;
    }

    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    if (!UpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(DWORD64), NULL, NULL)) {
        cerr << "[!] UpdateProcThreadAttribute Failed With Error: " << GetLastError() << endl;
        DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuff);
        HeapFree(GetProcessHeap(), 0, pAttrBuff);
        return FALSE;
    }

    SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuff;

    if (!CreateProcessA(
        lpProcessPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &SiEx.StartupInfo,
        &Pi)) {

        cerr << "[!] CreateProcessA Failed With Error: " << GetLastError() << endl;
        DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuff);
        HeapFree(GetProcessHeap(), 0, pAttrBuff);
        return FALSE;
    }

    *dwProcessID = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    // Clean up
    DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuff);
    HeapFree(GetProcessHeap(), 0, pAttrBuff);

    return TRUE;
}

int main(int argc, char* argv[]) {
    DWORD pid = 0;
    HANDLE hProcess = NULL, hThread = NULL;

#ifdef LOCAL_BLOCKDLLPOLICY
    if (argc == 2 && strcmp(argv[1], STOP_ARG) == 0) {
        // REAL IMPLEMENTATION CODE ...
        cout << "[+] Process Now Created with The Block DLL Policy" << endl;
        return 0;
    }

    else {
        cerr << "[i] Local Process Is Not Protected With The Block Dll Policy" << endl;

        CHAR pcFilename[MAX_PATH * 2] = { 0 };

        if (!GetModuleFileNameA(NULL, pcFilename, MAX_PATH * 2)) {
            cerr << "[!] GetModuleFileNameA Failed With Error: " << GetLastError() << endl;
            return -1;
        }

        DWORD dwBufferSize = (DWORD)(lstrlenA(pcFilename) + lstrlenA(STOP_ARG) + 0xFF);
        CHAR* pcBuffer = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

        if (!pcBuffer) {
            cerr << "[!] HeapAlloc Failed [!]" << endl;
            return -1;
        }

        sprintf_s(pcBuffer, dwBufferSize, "%s %s", pcFilename, STOP_ARG);

        // Fork with block DLL policy
        if (!CreateProcessWithDllPolicy(pcBuffer, &hProcess, &hThread, &pid)) {
            HeapFree(GetProcessHeap(), 0, pcBuffer);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, pcBuffer);

        cout << "[i] Process Created With PID: " << pid << endl;
    }

#endif // LOCAL_BLOCKDLLPOLICY

#ifndef LOCAL_BLOCKDLLPOLICY
    // If LOCAL_BLOCKDLLPOLICY is not defined
    CHAR pPath[MAX_PATH] = "C:\\Windows\\System32\\RuntimeBroker.exe";

    if (!CreateProcessWithDllPolicy(pPath,hProcess,hThread,&pid)){
        return -1;
    }
    cout << "[i] Process Created With PID: " << pid << endl;
#endif // !LOCAL_BLOCKDLLPOLICY

    return 0;
}
