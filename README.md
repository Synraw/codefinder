# Codefinder
Codefinder is a small experimental project of mine aimed at the detection of injected code in windows processes. It is more of a testing grounds than anything at the moment but is designed for use in malware analysis and reverse engineering software which makes use of DLL Injection, remote shellcode injection and a few other techniques.

This is obviously aimed at windows systems, and some structures might be a little off on older systems. All my development work is done on Windows 10 but please let me know if there is any issues with other systems.

### Features:
 - Process Module List
 - Process Memory Map
 - Scanning allocated pages for PE headers and other common structures
 - Determining module name by PDB debug path
 - Determining module name from file mappings
 - Dumping raw memory pages to file
 - Dumping raw modules to file
 - Tracing threads back to injected code blocks

### Planned:
- Scanning for common windows hooks
- Scanning for target specific hooks
- Pattern scanning for common code (such as CRT implementations)

### Building:
For the easiest time building this project, use Visual Studio 2017 to open the folder as a cmake project. Older versions of visual studio by default do not support cmake and this project makes use of a few C++17 features so most older compilers will not build it.

### Thanks:
Thanks to [Timboy67678](https://github.com/Timboy67678) and Daax for letting me bounce ideas off them now and then :heart_eyes:
