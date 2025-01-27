# SHELLCODE Opcode Generator and executor
```
+================================================+
|/ _\  /\  /\/__\/ /   / /   / __\ /___\/   \/__\|
|\ \  / /_/ /_\ / /   / /   / /   //  // /\ /_\  |
|_\ \/ __  //__/ /___/ /___/ /___/ \_// /_///__  |
|\__/\/ /_/\__/\____/\____/\____/\___/___,'\__/  |
|  /___\_ __   ___ ___   __| | ___               |
| //  // '_ \ / __/ _ \ / _` |/ _ \              |
|/ \_//| |_) | (_| (_) | (_| |  __/              |
|\___/ | .__/ \___\___/ \__,_|\___|              |
|   ___|_|                                       |
|  / _ \___ _ __   ___ _ __ __ _| |_ ___  _ __   |
| / /_\/ _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|  |
|/ /_\\  __/ | | |  __/ | | (_| | || (_) | |     |
|\____/\___|_| |_|\___|_|  \__,_|\__\___/|_|     |
+================================================+
```
# Idea
Idea was to create a shelcode generator that produces array of shellcode bytes that you can save to memory and execute. That way it is harder for RE to understand the code, because function is decrypted on-the-fly and allocated to virtual memory.

# Building
Run Makefile with Make. Requires C++17 standard to compile.

# Current limitations
* Opcode must be self relient because links broke after you move assembly to different location. That means that you can't simply call API functions before getting it's function address. 
* Return type of function must be manually specified in code.
* Accepts only 1 input argument.

## Example usage
* Write Hello wordl example
  ```c++
  int test_return_int(){
	return 1;
  }
  ```
  * Paste dumped code
  ```asm
  0000000000000000 <_Z15test_return_intv>:
   0:   55                      push   %rbp
   1:   48 89 e5                mov    %rsp,%rbp
   4:   b8 01 00 00 00          mov    $0x1,%eax
   9:   5d                      pop    %rbp
   a:   c3                      ret
  ```
  * Get function bytes in return
  ```c++
  const unsigned char function_bytes[] =        "\x55\x48\x89\xE5\xB8\x01\x00\x00\x00\x5D\xC3";
  const unsigned char function_bytes_cipher[] = "\x66\x66\xB8\xD1\x89\x34\x39\x33\x33\x73\xF2";
  ```
  * Get return from function
  ```
  ════════════════════════════════════════
  Dynamically executed function returned: 1
  ════════════════════════════════════════
  ```

## Functionality
* Extract hex opcode from the pasted dump
  ```c++
  std::string function_hex_string;
  extract_hex_opcode_from_objdump(dumped_assembly_code.str(), function_hex_string);
  ```
* Convert hex string to actual bytes
  ```c++
  unsigned char* function_bytes = new unsigned char[function_bytes_size];
  hex_string_to_bytes(function_hex_string, function_bytes);
  ```
* xor shellcode array with key
  ```c++
  unsigned char* function_bytes_cipher = new unsigned char[function_bytes_size];
  xor_array(function_bytes, xor_key.c_str(), function_bytes_size, function_bytes_cipher);
  ```
* un-xor shellcode array with same key
  ```c++
  unsigned char* function_bytes_de_ciphered = new unsigned char[function_bytes_size];
  xor_array(function_bytes_cipher, xor_key.c_str(), function_bytes_size, function_bytes_de_ciphered);
  ```
* Allocate virtual memory with shellcode
  ```c++
  LPVOID executableMemory = VirtualAlloc(NULL, function_bytes_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  ```
* Execute shellcode with arguments
  ```c++
  ReturnType result = func_ptr(std::forward<Args>(args)...);
  ```
* Get executed function return results
  ```c++
  std::cout << "Dynamically executed function returned: " << result << std::endl;
  ```
  
