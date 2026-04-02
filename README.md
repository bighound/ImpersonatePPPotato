# ImpersonatePPPotato
A C++ implementation of the famous [GodPotato](https://github.com/BeichenDream/GodPotato) tool for privilege escalation in Windows environments.
This project is a complete C++ port of the original GodPotato tool. The main motivation behind this version is to eliminate the dependency on the .NET framework (.NET 2.0/3.5/4.x) required by the original C# version. It also includes some improvements regarding OPSEC, bypassing some of the most commonly used EDRs. Being a native C++ binary provides greater control over the management of DCOM objects.

This tool take adventeage about some defects in RPCSS when deserializing a DCOM object, allowing the SYSTEM user to connect to a pipe created by the attacker and impersonate its token, enabling code execution as SYSTEM.
To do this, the SeImpersonatePrivilege privilege must be enabled, which is generally present in all service accounts for Web/SQL.

# Affected Version
Windows Server 2012 - Windows Server 2022 Windows8 - Windows 11
## About this version
- Completely rewritten in C++
- No .NET dependency
- Adapted for learning about DCOM objects and research, as well as the need to use a version undetectable by EDRs
- Additional changes: Stealthier token search for evasion, removal of .NET metadata, etc.
# Compilation
You can compile the .sln project as you usually do, but i strongly recommend you to compile it with cl.exe as follows (With this way you'll bypass somes EDRs):
```
cl.exe /O1 /GL /Gy /GF /MD /DNDEBUG /std:c++17 /GR- /EHsc- /W4 ImpersonatePPPotato.cpp ImpersonatePPPotatoContext.cpp ImpersonatePPPotatoUnmarshalTrigger.cpp /link /LTCG /OPT:REF /OPT:ICF /DEBUG:NONE ole32.lib oleaut32.lib advapi32.lib kernel32.lib rpcrt4.lib shlwapi.lib
```
# PoC
``` 
  ImpersonatePPPotato - Token Stealing Exploit
  COM-based privilege escalation via RPC Hooking

Usage: C:\Poc\ImpersonatePPPotato.exe -c <command> [options]

Options:
  -c <cmd>    Command to execute with SYSTEM privileges
  -p <name>   Pipe name (default: ImpersonatePPPotato)
  -h          Show this help message

Example:
  C:\Poc\ImpersonatePPPotato.exe -c "cmd /c whoami"
```
![](images/1.png)

```
ImpersonatePPPotato.exe -c "cmd /c whoami"
```
![](images/2.png)

# Credits
This project is a C++ port of the original C# project created by BeichenDream.

Original repository:
[https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

All credit for the original idea and implementation belongs to its author.
# Disclaimer
**For educational and authorized auditing purposes only.** This tool has been created strictly for use by security professionals in environments where they have explicit permission from the system owner. The author is not responsible for the misuse of this tool.
# Acknowledgments
Thanks to BeichenDream for the original C# project that served as a basis and inspiration.
