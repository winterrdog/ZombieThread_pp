# ZombieThread_pp🧟
Another Meterpreter code injection technique using C++ that attempts to bypass Win-Def. This repo is a C++ adaptation of @Bl4ckM1rror 's C# version.

# Introduction 📚
The idea behind this project was to try to figure out how inject shellcode into a remote process and go under the Windows Defender's radar.

The program's algorithm is quite simple( and maybe clear :) ):

- Open a remote process using `OpenProcess`.
- Decrypt the meterpreter payload in memory.
- Allocate some memory in the remote process using `VirtualAllocEx`, ensuring we assign the correct permissions to write to the memory of course.
- Write the payload into the allocated memory using `WriteProcessMemory`.
- Protect the memory using `VirtualProtectEx`, setting the protection to `PAGE_NOACCESS`.
- Create a new suspended thread using `CreateRemoteThread`.
- Sleep for 30 seconds while Defender scans the remote process memory for malicious code.
- Change the protection on the memory using `VirtualProtectEx`, setting the protection to `PAGE_EXECUTE_READ_WRITE`.
- Resuming the remote thread using `ResumeThread`

It would appear that protecting the page with `PAGE_NOACCESS` containing our meterpreter shellcode is not scanned by Defender and is not detected. By suspending the thread upon creation we are able to 'hold' the shellcode in memory until Windows Defender has done it's scan then execute the shellcode when Defender has finished( Remember Windows Defender is good at runtime analysis but this trick is also good at runtime evasion ).

# VERY-VERY Important 📝✍️
- Remember, the code looks for an instance of explorer.exe( not Internet Explorer for Christ's sake ) to inject into, if you want to inject into another process, you MUST change it in the `danger.cpp` code.
- Also remember to provide the `sh_code` variable with your meterpreter shellcode. That line( line 54 ) looks something like this:
```cpp
  unsigned char sh_code[]{/* paste your shellcode here */};
```
- You can use `mingw` or `Visual Studio` to compile this program's code( Can't illustrate on how to do that )

# AV Scan Results 🚨🚨

The binary was scanned using [antiscan.me](https://antiscan.me/scan/new/result?id=JkbJGQBeJIw6) on 20/06/2022.

![AV Scan](https://github.com/Bl4ckM1rror/ZombieThread/blob/main/antiscan.png?raw=true)

# Credits 🫡
A huge thanks to @Bl4ckM1rror.
