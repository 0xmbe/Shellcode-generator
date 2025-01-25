# Shellcode-generator
Dirty implementation of shellcode generator and executor. Required C++17

# Idea
Idea was to create a shelcode generator that produces array of shellcode bytes that you can save to memory and execute.
## Functionality
* Generate shellcode
  ```c++
  generate_opcode_from_assembly_instructions();
  ```
* xor shellcode array with key
  ```c++
  unsigned char out_for_functionBytes_cipher[CONST_FUNC_SIZE];
  xor_array(functionBytes, key.c_str(), CONST_FUNC_SIZE, out_for_functionBytes_cipher);
  ```
* un-xor shellcode array with same key
  ```c++
  unsigned char out2[CONST_FUNC_SIZE];
  xor_array(functionBytes_cipher, key.c_str(), CONST_FUNC_SIZE, out2);
  ```
* Allocate virtual memory with shellcode
* Execute shellcode with arguments
* Get return results
  ```c++
  auto res = execute_function_bytes(out2, input.c_str());
  ```
  
