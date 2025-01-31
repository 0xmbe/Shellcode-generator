# SHELLCODE Opcode Generator and executor
```
+================================================+
|/"_\  /\  /\/__\/"/   /"/   /"__\ /"""\/"""\/__\|
|\ \  / /_/ /_\ / /   / /   / /   //  // /\ /_\  |
|_\ \/ __  //__/ /___/ /___/ /___/ \_// /_///__  |
|\__/\/ /_/\__/\____/\____/\____/\___/___,'\__/  |
|  /___\_ __   ___ ___   __|"| ___               |
| //  // "_ \ / __/ _ \ / _` |/ _ \              |
|/ \_//| |_) | (_| (_) | (_| |  __/              |
|\___/_| .__/ \___\___/ \__,_|\___|              |
|  /"_"\_|_ _ __   ___ _ __ __ _|"|_ ___  _ __   |
| / /_\/ _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|  |
|/ /_\\  __/ | | |  __/ | | (_| | || (_) | |     |
|\____/\___|_| |_|\___|_|  \__,_|\__\___/|_|     |
+================================================+
```
# Idea
Idea was to create a shelcode generator that produces array of shellcode bytes that you can save to memory and execute. That way it is harder for RE to understand the code, because function is decrypted on-the-fly and allocated to virtual memory.
# Features
* ✔️  Generation of shellcode assembly opcodes from C++ code.
* ✔️  Multi input argument execution of virtual methods created from generated shellcode buffer.
* ✔️  Shellcode encryption.
* ✔️  Fun

# Current limitations
* Opcode must be self relient because links broke after you move assembly to different location. That means that you can't simply call API functions before getting it's function address.
* It is very easy to get no memory access because of broken links.
* Return type of function must be manually specified in code.
* 🔥~~Accepts only 1 input argument.~~
* All input arguments must be of the same type.

# Building
Run Makefile with Make. Requires C++17 standard to compile.

## Example usage
* Write Hello world example
  ```c++
  int test_return_int(){
	return 1;
  }
  ```
* Set input and output function type
  ```c++
  /////////////////////////////////
  // Define INPUT arguments type
  /////////////////////////////////	
  //using I_type = int;		
  using I_type = const char*;	
  //using I_type = char;		

  /////////////////////////////////
  // Define OUTPUT return type
  /////////////////////////////////
  using O_type = int;	
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
* Execute virtual function
  ```c++
  result = execute_virtual_function_bytes
        <O_type>(                                       // Virtual function return type
                function_bytes_de_ciphered,             // Buffer with opcodes
                static_cast<I_type>(args[0])            // Input arguments
         );
  ```
* Get return from function
  ```
  ════════════════════════════════════════
  Dynamically executed function returned: 1
  ════════════════════════════════════════
  ```
## Example 2 usage
* Write Hello world example
  ```c++
  int test_check_password2(const char* str1) {
	const char str2[] = "var45ssfxkgoofrx";
	size_t c = 0;
	for (c = 0; str1[c] != '\0'; ++c){}		// count string length
	if (c != 16){
		return 1;
	}
	for (size_t i = 0; i < 16; ++i) {
		if (str1[i] != str2[i]) {
			return 1;
		}
	}
	return 0;
  }
  ```
* Paste dumped code
  ```asm
  000000000000000b <_Z20test_check_password2PKc>:
   b:   55                      push   %rbp
   c:   48 89 e5                mov    %rsp,%rbp
   f:   48 83 ec 30             sub    $0x30,%rsp
  13:   48 89 4d 10             mov    %rcx,0x10(%rbp)
  17:   48 b8 76 61 72 34 35    movabs $0x6673733534726176,%rax
  ... ommmited ...
  9f:   48 83 45 f0 01          addq   $0x1,-0x10(%rbp)
  a4:   48 83 7d f0 0f          cmpq   $0xf,-0x10(%rbp)
  a9:   76 cd                   jbe    78 <_Z20test_check_password2PKc+0x6d>
  ab:   b8 00 00 00 00          mov    $0x0,%eax
  b0:   48 83 c4 30             add    $0x30,%rsp
  b4:   5d                      pop    %rbp
  b5:   c3                      ret
  ```
* Get function bytes in return
  ```c++
  const unsigned char function_bytes[] =        "\x55\x48\x89\xE5\x48\x83\xEC\x30\x13\x48\x89\x4D\x10\x17\x48\xB8\x76\x61\x72\x34\x35\x1E\x73\x73\x66\x21\x48\xBA\x78\x6B\x67\x6F\x6F\x28\x66\x72\x78\x2B\x48\x89\x45\xD0\x2F\x48\x89\x55\xD8\x33\xC6\x45\xE0\x00\x37\x48\xC7\x45\xF8\x00\x00\x00\x3E\x00\x3F\x48\xC7\x45\xF8\x00\x00\x00\x46\x00\x47\xEB\x05\x4E\x49\x48\x83\x45\xF8\x01\x4E\x48\x8B\x55\x10\x52\x48\x8B\x45\xF8\x56\x48\x01\xD0\x59\x0F\xB6\x00\x5C\x84\xC0\x5E\x75\xE9\x49\x60\x48\x83\x7D\xF8\x10\x65\x74\x07\x6E\x67\xB8\x01\x00\x00\x00\x6C\xEB\x42\xB0\x6E\x48\xC7\x45\xF0\x00\x00\x00\x75\x00\x76\xEB\x2C\xA4\x78\x48\x8B\x55\x10\x7C\x48\x8B\x45\xF0\x80\x48\x01\xD0\x83\x0F\xB6\x10\x86\x48\x8D\x4D\xD0\x8A\x48\x8B\x45\xF0\x8E\x48\x01\xC8\x91\x0F\xB6\x00\x94\x38\xC2\x96\x74\x07\x9F\x98\xB8\x01\x00\x00\x00\x9D\xEB\x11\xB0\x9F\x48\x83\x45\xF0\x01\xA4\x48\x83\x7D\xF0\x0F\xA9\x76\xCD\x78\xAB\xB8\x00\x00\x00\x00\xB0\x48\x83\xC4\x30\xB4\x5D\xB5\xC3";

  const unsigned char function_bytes_cipher[] = "\x66\x66\xB8\xD1\x79\xB6\xD5\x03\x20\x66\xB8\x79\x21\x22\x71\x8B\x45\x4F\x43\x00\x04\x2B\x4A\x40\x55\x0F\x79\x8E\x49\x5E\x5E\x5C\x5C\x06\x57\x46\x49\x1E\x71\xBA\x76\xFE\x1E\x7C\xB8\x60\xE1\x00\xF5\x6B\xD1\x34\x06\x7D\xFE\x76\xCB\x2E\x31\x34\x0F\x35\x06\x7B\xF4\x6B\xC9\x34\x31\x35\x7F\x33\x74\xC5\x34\x7A\x78\x7D\xBA\x76\xCB\x2F\x7F\x7C\xBA\x60\x29\x61\x7B\xA5\x74\xCC\x67\x7D\x38\xE3\x6A\x21\x87\x34\x6D\xB1\xF9\x6D\x46\xC7\x78\x54\x79\xB6\x44\xCB\x23\x4B\x45\x33\x5F\x52\x81\x32\x33\x2E\x31\x58\xDA\x77\x89\x5D\x7B\xE9\x74\xC4\x31\x35\x39\x46\x33\x58\xDA\x18\x95\x4D\x71\xB8\x66\x3E\x4D\x7C\xBA\x70\xC9\xB3\x7B\x2F\xE1\xB7\x3E\x83\x29\xB5\x7B\xA3\x7C\xE4\xBB\x7D\xB2\x76\xC3\xA0\x79\x35\xF9\xA4\x36\x85\x33\xBA\x09\xF6\xA7\x41\x3E\xAC\xAB\x96\x30\x34\x31\x35\xA4\xD8\x22\x9E\xAE\x7C\xB2\x70\xC9\x32\x97\x66\xB2\x49\xC1\x3A\x90\x45\xFE\x56\x9A\x8C\x31\x35\x39\x33\x83\x66\xB2\xF0\x01\x81\x64\x86\xF0";
* Execute virtual function
  ```c++
  result = execute_virtual_function_bytes
        <O_type>(                                       // Virtual function return type
                function_bytes_de_ciphered,             // Buffer with opcodes
                static_cast<I_type>(args[0])            // Input arguments
         );
  ```
* Get return from function
  ```
  ════════════════════════════════════════
  Dynamically executed function returned: 0
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
  
