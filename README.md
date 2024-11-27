# IAT-Hooking
Project goal: Hijack the CreateFileA function to run MessageBoxA.

In this project you can find an implementation of the IAT-Hooking technique in order to cause the CreateFileA function to run a Message Box function that will display a message on the screen: "CreateFileA hooked successfully!".

The repo contains two main files: main.cpp and hook.cpp.
In the main file you can find the general functionality for running the program for reading content from a file using WinApi functions.

In the hook file you can find the algorithm of the function that executes the hook and the hook function.
## Acknowledgements

 - [MessageBoxA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)
 - [CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
 - [IAT-Hooking](ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking)

## Demo
[![Demo](https://github.com/AI-fergan/IAT-Hooking/blob/main/demo-files/demo.png)](https://github.com/AI-fergan/IAT-Hooking/blob/main/demo-files/demo.mp4)
