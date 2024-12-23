# Shellcode Injector
This Shellcode Injector is a Windows-based program that injects shellcode into a target process using only NTAPI functions. The shellcode is provided as a binary file and is injected into the target process by creating a remote thread in the target's memory. The program accepts two command-line arguments:
- Process Name: The name of the target process to inject the shellcode into. The injector will locate the process by its name, retrieve its Process ID (PID), and use it for the injection.
- Binary File: The path to a binary file containing the raw shellcode. This shellcode will be injected into the target process memory.

Key Features:
- NTAPI-based: Uses low-level NTAPI functions to interact directly with the Windows kernel for process manipulation and thread creation, avoiding high-level Windows API calls such as CreateRemoteThread.
- PID Retrieval: The injector automatically retrieves the PID of the target process based on the provided process name.
- Binary Shellcode Injection: Reads shellcode from a specified binary file (.bin) and injects it into the target process’s memory.
- Remote Thread Creation: Once the shellcode is loaded into the target process's memory, the injector creates a remote thread within the process to execute the shellcode.
- Flexible Input: Accepts the name of the target process and the binary shellcode file via command-line arguments.
