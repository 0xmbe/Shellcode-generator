
#define _USE_MATH_DEFINES
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <memoryapi.h>
#include <errhandlingapi.h>
#include <cstdio>
#include <ios>
#include <iosfwd>
#include <cstdlib>
#include <regex>
#include <optional>
#include <type_traits>
#include "gtest/gtest.h"
#include <cmath>

// Switch unit testing run automatically at the start
bool enable_unit_testing = true;

/////////////////////////////////
// Define INPUT arguments type
/////////////////////////////////
/////////using I_type = char const [5];		//"The C++ Standard forbids containers of const elements because allocator<const T> is ill-formed.";	
// using I_type_ = void*;					// OK
//using I_type = int;						// OK
using I_type = const char*;				// OK
//using I_type = char;						// OK
//using I_type = std::string;				// ?


/////////////////////////////////
// Define OUTPUT return type
/////////////////////////////////
using O_type = int;						// OK
//using O_type = const char*;				// CRASH



//
//// Global definition for creating new arrays of same size
size_t function_bytes_size = 0;
//
//// Default key for XOR-ing operation
const std::string default_xor_key = std::to_string(M_PI);

// Error checking
void check(bool expr, const char* exprStr) {
	if (!expr) {
		std::cerr << "Expression: " << exprStr << std::endl;
		std::cerr << "GetLastError: " << GetLastError() << std::endl;
		std::cout << "Press key to exit\n";
		std::cin.get();
		exit(-1);
	}
}

// Macro to call the function with the expression as string
#define CHECK(expr) check((expr), #expr) 

// Simplify multi character print
void print_char(char char_code, size_t times, bool endline = true) {
	for (size_t i = 0; i < times; ++i) {
		std::cout << char_code;
	}
	if (endline == true) {
		std::cout << std::endl;
	}
}

// Read multi line input to stream
void read_multi_line_input(std::stringstream& output) {
	std::cout << "\nDump complete\nCopy 1 complete dumped function for which you want to make the opcode.\nPaste dumped code here, confirm with double ENTER:" << std::endl;
	std::string line;
	// Read lines until we get empty line. -Suitable for single functions only
	while (std::getline(std::cin, line)) {
		if (line.empty()) {
			break;
		}
		output << line << '\n';
	}
}

void set_xor_key(std::string& xor_key) {
	std::getline(std::cin, xor_key);

	// Use default key if no input
	if (xor_key.size() == 0) {
		std::cout << "Using default xor key: " << default_xor_key << std::endl;
		xor_key = default_xor_key;
	}
}

// Converts string text hex values to actual hex values in memory
void hex_string_to_bytes(const std::string& input, unsigned char* output) {
	size_t length = input.length() / 2; // 1 byte == 2 digits
	for (size_t i = 0; i < length; ++i) {
		std::string byteString = input.substr(i * 2, 2);
		output[i] = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
	}
}

/// <summary>
/// Parser for Objdump.exe output
/// </summary>
/// <param name="input">: Multi line input from console stream</param>
/// <param name="output">: Raw bytes in string format</param>
void extract_hex_opcode_from_objdump(const std::string& input, std::string& output) {
	// Prepare the regex pattern for matching hexadecimal bytes
	std::regex hex_pattern(R"(\b[0-9a-fA-F]{2}\b)");
	std::stringstream input_stream(input);
	std::string line;
	std::vector<std::string> hexParts;

	while (std::getline(input_stream, line)) {

		// Find position of the colon
		size_t colon_pos = line.find(':');

		// If the colon is found, strip everything before including the colon
		if (colon_pos != std::string::npos) {
			line = line.substr(colon_pos + 1);
		}

		// Find position of the 4 spaces (not the best solution)
		size_t space4x_pos = line.find("    ");
		// If 4 spaces are found, strip everything before
		if (space4x_pos != std::string::npos) {
			line.resize(space4x_pos);
		}

		// Apply the regex to the line after the colon
		std::sregex_iterator sregex_iterator(line.begin(), line.end(), hex_pattern);
		std::sregex_iterator end;

		while (sregex_iterator != end) {
			hexParts.push_back(sregex_iterator->str());
			++sregex_iterator;
		}
	}

	// Assemble output byte by byte
	for (const auto& piece : hexParts) {
		output += piece;
	}
}

// Classic xor algorithm
void xor_array(const unsigned char* input, const char* key, size_t length, unsigned char* output) {
	for (size_t i = 0; i < length; ++i) {
		output[i] = input[i] ^ key[i % strlen((const char*)key)];
	}
}

// Print single argument of any time
template<typename T>
void printArgument(T&& arg) {
	std::cout << "Value: " << std::forward<T>(arg) << std::setw(15) << " | Type: " << typeid(arg).name() << "\n";
}

// Variadic template function to print all forwarded arguments
template<typename... Args>
void printAllArguments(Args&&... args) {
	(printArgument(std::forward<Args>(args)), ...);
}

/// <summary>
/// Allocates memory with input bytes, casts (*) to allocated function, calls function with received arguments
/// </summary>
/// <typeparam name="...Args"></typeparam>
/// <param name="bytes">: byte array with function opcode</param>
/// <param name="...args">: variadic argumets</param>
/// <returns></returns>
template<typename O_type, typename... Args>
std::optional<O_type> execute_virtual_function_bytes(const unsigned char* bytes, Args&&... args) {

	std::cout << "\nExecuting virtual function bytes\n";

	// Allocate executable memory
	LPVOID executableMemory = VirtualAlloc(
		NULL,
		function_bytes_size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (executableMemory == NULL) {
		std::cerr << "Memory allocation failed: " << GetLastError() << std::endl;
		return {};
	}

	// Print all arguments before executing the function
	std::cout << "Arguments:\n";
	printAllArguments(std::forward<Args>(args)...);
	std::cout << std::endl;

	// Copy function bytes to executable memory
	memcpy(executableMemory, bytes, function_bytes_size);

	// Prepare object for results
	O_type result = {};

	// Cast executable memory to function pointer
	auto func_ptr = reinterpret_cast<O_type(*)(Args...)>(executableMemory);

	// Execute function
	result = func_ptr(std::forward<Args>(args)...);

	// Display return results
	print_char('\xcd', 40);
	std::cout << "Dynamically executed function returned: " << result << std::endl;
	print_char('\xcd', 40);

	//std::cerr << GetLastError() << std::endl;

	// Free allocated memory
	VirtualFree(executableMemory, 0, MEM_RELEASE);

	return result;
}

// Wrapper that calls execute_virtual_function_bytes based on how many input arguments we have
template<typename Out, typename In>
void call_virtual_function_wrapper(std::vector<In>& args, unsigned char* function_bytes_de_ciphered, std::optional<Out>& result) {
	if (args.size() == 0) {
		result = execute_virtual_function_bytes<Out>(function_bytes_de_ciphered);
	}
	else if (args.size() == 1) {
		result = execute_virtual_function_bytes<Out>(function_bytes_de_ciphered, static_cast<In>(args[0]));
	}
	else if (args.size() == 2) {
		result = execute_virtual_function_bytes<Out>(function_bytes_de_ciphered, static_cast<In>(args[0]), static_cast<In>(args[1]));
	}
	else if (args.size() == 3) {
		result = execute_virtual_function_bytes<Out>(function_bytes_de_ciphered, static_cast<In>(args[0]), static_cast<In>(args[1]), static_cast<In>(args[2]));
	}
}

template <typename I_type>
std::vector<I_type> processInput() {
	std::vector<I_type> args;
	std::string input;
	while (true) {

		std::cout << "Enter argument " << args.size() << ":" << std::endl;

		std::getline(std::cin, input);
		if (input.empty()) {
			break;
		}

		std::istringstream iss(input);
		std::string str_value;

		if (iss >> str_value) {
			if constexpr (std::is_same_v<I_type, const char*>) {

				// Create a new copy so it doesn't get lost on the way out
				char* str_PKc = new char[strlen(str_value.c_str()) + 1];
				strcpy_s(str_PKc, strlen(str_value.c_str()) + 1, str_value.c_str());

				// Add it to vector
				args.emplace_back(str_PKc);
				//args.push_back(str_PKc);

				// cleanup
			//	delete[] str_PKc;
			}
			else if constexpr (std::is_same_v<I_type, std::string>) {
				I_type value = str_value;
				args.push_back(value);
			}
			else if constexpr (std::is_same_v<I_type, int>) {
				I_type value = std::stoi(str_value);
				args.push_back(value);
			}
			// OTER TYPES													-> NOT TESTED
			else {
				I_type value = {};
				std::istringstream iss2(input);
				if (iss2 >> value) {
					args.push_back(value);
					//std::cout << value << std::endl;
				}
				else {
					std::cerr << "Invalid input. Please enter a valid type." << std::endl;
				}
			}
		}
		else {
			std::cerr << "Invalid input. Please enter a valid type." << std::endl;
		}
	}
	return args;
}

/// UNIT TESTS
#pragma region Unit_tests

TEST(extract_hex_opcode_from_objdump, _Z23test_02_out_INT_in_CHARc) {

	// Dumped (copied) result
	std::string dumped_assembly_code = R"(
0000000000000014 <_Z23test_02_out_INT_in_CHARc>:
  14:   55                      push   rbp
  15:   48 89 e5                mov    rbp,rsp
  18:   48 83 ec 10             sub    rsp,0x10
  1c:   89 c8                   mov    eax,ecx
  1e:   88 45 10                mov    BYTE PTR [rbp+0x10],al
  21:   c6 45 ff 63             mov    BYTE PTR [rbp-0x1],0x63
  25:   80 7d 10 63             cmp    BYTE PTR [rbp+0x10],0x63
  29:   75 07                   jne    32 <_Z23test_02_out_INT_in_CHARc+0x1e>
  2b:   b8 01 00 00 00          mov    eax,0x1
  30:   eb 05                   jmp    37 <_Z23test_02_out_INT_in_CHARc+0x23>
  32:   b8 00 00 00 00          mov    eax,0x0
  37:   48 83 c4 10             add    rsp,0x10
  3b:   5d                      pop    rbp
  3c:   c3                      ret
)";

	// Checked and confirmed STANDARD etalone
	const unsigned char function_bytes_STANDARD[] =
		"\x55\x48\x89\xE5\x48\x83\xEC\x10\x89\xC8\x88\x45\x10\xC6\x45\xFF\x63\x80\x7D\x10\x63\x75\x07\xB8\x01\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x10\x5D\xC3";

	// Extract hex opcode from the pasted dump
	std::string function_hex_string_;
	extract_hex_opcode_from_objdump(dumped_assembly_code.c_str(), function_hex_string_);

	// Set function size
	size_t function_bytes_size_ = function_hex_string_.size() / 2;

	// Convert hex string to actual bytes
	unsigned char* function_bytes_ = new unsigned char[function_bytes_size_];
	hex_string_to_bytes(function_hex_string_, function_bytes_);

	// Compare memory of both arrays
	int result_memcmp_function_bytes = memcmp(function_bytes_, function_bytes_STANDARD, function_bytes_size_);

	// Cleanup
	delete[]function_bytes_;

	// Test
	EXPECT_EQ(result_memcmp_function_bytes, 0);
}

TEST(extract_hex_opcode_from_objdump, _Z20test_xx_big_functionPKcii) {

	// Dumped (copied) result
	std::string dumped_assembly_code = R"(
0000000000000284 <_Z20test_xx_big_functionPKcii>:
 284:   55                      push   rbp
 285:   48 89 e5                mov    rbp,rsp
 288:   48 83 ec 20             sub    rsp,0x20
 28c:   48 89 4d 10             mov    QWORD PTR [rbp+0x10],rcx
 290:   89 55 18                mov    DWORD PTR [rbp+0x18],edx
 293:   44 89 45 20             mov    DWORD PTR [rbp+0x20],r8d
 297:   c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
 29e:   c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
 2a5:   eb 04                   jmp    2ab <_Z20test_xx_big_functionPKcii+0x27>
 2a7:   83 45 fc 01             add    DWORD PTR [rbp-0x4],0x1
 2ab:   8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
 2ae:   48 63 d0                movsxd rdx,eax
 2b1:   48 8b 45 10             mov    rax,QWORD PTR [rbp+0x10]
 2b5:   48 01 d0                add    rax,rdx
 2b8:   0f b6 00                movzx  eax,BYTE PTR [rax]
 2bb:   84 c0                   test   al,al
 2bd:   75 e8                   jne    2a7 <_Z20test_xx_big_functionPKcii+0x23>
 2bf:   c7 45 f8 00 00 00 00    mov    DWORD PTR [rbp-0x8],0x0
 2c6:   48 b8 76 61 72 34 35    movabs rax,0x6673733534726176
 2cd:   73 73 66
 2d0:   48 89 45 e1             mov    QWORD PTR [rbp-0x1f],rax
 2d4:   48 b8 66 78 6b 67 6f    movabs rax,0x666f6f676b7866
 2db:   6f 66 00
 2de:   48 89 45 e8             mov    QWORD PTR [rbp-0x18],rax
 2e2:   c7 45 f4 00 00 00 00    mov    DWORD PTR [rbp-0xc],0x0
 2e9:   eb 28                   jmp    313 <_Z20test_xx_big_functionPKcii+0x8f>
 2eb:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
 2ee:   48 63 d0                movsxd rdx,eax
 2f1:   48 8b 45 10             mov    rax,QWORD PTR [rbp+0x10]
 2f5:   48 01 d0                add    rax,rdx
 2f8:   0f b6 10                movzx  edx,BYTE PTR [rax]
 2fb:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
 2fe:   48 98                   cdqe
 300:   0f b6 44 05 e1          movzx  eax,BYTE PTR [rbp+rax*1-0x1f]
 305:   38 c2                   cmp    dl,al
 307:   74 06                   je     30f <_Z20test_xx_big_functionPKcii+0x8b>
 309:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
 30c:   89 45 f8                mov    DWORD PTR [rbp-0x8],eax
 30f:   83 45 f4 01             add    DWORD PTR [rbp-0xc],0x1
 313:   8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
 316:   3b 45 fc                cmp    eax,DWORD PTR [rbp-0x4]
 319:   7c d0                   jl     2eb <_Z20test_xx_big_functionPKcii+0x67>
 31b:   8b 55 18                mov    edx,DWORD PTR [rbp+0x18]
 31e:   8b 45 20                mov    eax,DWORD PTR [rbp+0x20]
 321:   01 c2                   add    edx,eax
 323:   8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
 326:   01 d0                   add    eax,edx
 328:   89 45 f0                mov    DWORD PTR [rbp-0x10],eax
 32b:   8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
 32e:   48 83 c4 20             add    rsp,0x20
 332:   5d                      pop    rbp
 333:   c3                      ret
)";

	// Checked and confirmed STANDARD etalone
	const unsigned char function_bytes_STANDARD[] =
		"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x89\x4d\x10\x89\x55\x18\x44\x89\x45\x20\xc7\x45\xfc\x00\x00\x00\x00\xc7\x45\xfc\x00\x00\x00\x00\xeb\x04\x83\x45\xfc\x01\x8b\x45\xfc\x48\x63\xd0\x48\x8b\x45\x10\x48\x01\xd0\x0f\xb6\x00\x84\xc0\x75\xe8\xc7\x45\xf8\x00\x00\x00\x00\x48\xb8\x76\x61\x72\x34\x35\x73\x73\x66\x48\x89\x45\xe1\x48\xb8\x66\x78\x6b\x67\x6f\x6f\x66\x00\x48\x89\x45\xe8\xc7\x45\xf4\x00\x00\x00\x00\xeb\x28\x8b\x45\xf4\x48\x63\xd0\x48\x8b\x45\x10\x48\x01\xd0\x0f\xb6\x10\x8b\x45\xf4\x48\x98\x0f\xb6\x44\x05\xe1\x38\xc2\x74\x06\x8b\x45\xf4\x89\x45\xf8\x83\x45\xf4\x01\x8b\x45\xf4\x3b\x45\xfc\x7c\xd0\x8b\x55\x18\x8b\x45\x20\x01\xc2\x8b\x45\xf8\x01\xd0\x89\x45\xf0\x8b\x45\xf0\x48\x83\xc4\x20\x5d\xc3";

	// Extract hex opcode from the pasted dump
	std::string function_hex_string_;
	extract_hex_opcode_from_objdump(dumped_assembly_code.c_str(), function_hex_string_);

	// Set function size
	size_t function_bytes_size_ = function_hex_string_.size() / 2;

	// Convert hex string to actual bytes
	unsigned char* function_bytes_ = new unsigned char[function_bytes_size_];
	hex_string_to_bytes(function_hex_string_, function_bytes_);

	// Compare memory of both arrays
	int result_memcmp_function_bytes = memcmp(function_bytes_, function_bytes_STANDARD, function_bytes_size_);

	// Test extract_hex_opcode_from_objdump conversion
	EXPECT_EQ(result_memcmp_function_bytes, 0);
	//////////////////////////////////////////////////


	// Set xor key
	std::string xor_key_ = default_xor_key;

	// XOR functionBytes to cipher
	unsigned char* function_bytes_cipher_ = new unsigned char[function_bytes_size_];
	xor_array(function_bytes_, xor_key_.c_str(), function_bytes_size_, function_bytes_cipher_);

	// XOR again
	unsigned char* function_bytes_de_ciphered_ = new unsigned char[function_bytes_size_];
	xor_array(function_bytes_cipher_, xor_key_.c_str(), function_bytes_size_, function_bytes_de_ciphered_);

	// Compare memory of both arrays
	int result_function_bytes_de_ciphered_ = memcmp(function_bytes_de_ciphered_, function_bytes_STANDARD, function_bytes_size_);

	// Test xor_array function
	EXPECT_EQ(result_function_bytes_de_ciphered_, 0);
	//////////////////////////////////////////////////

	// Cleanup
	delete[]function_bytes_;
	delete[]function_bytes_cipher_;
}
TEST(call_virtual_function_wrapper, test_01_out_INT_in_2xINT) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x89\x4D\x10\x89\x55\x18\x8B\x55\x10\x8B\x45\x18\x01\xD0\x5D\xC3";

	// Set buffer size
	function_bytes_size = 21;

	// Set input and output types
	using I_type_ = int;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { 345, 543 };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<I_type_, O_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 888);
}
TEST(call_virtual_function_wrapper, test_02_out_INT_in_CHAR) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x48\x83\xEC\x10\x89\xC8\x88\x45\x10\xC6\x45\xFF\x63\x80\x7D\x10\x63\x75\x07\xB8\x01\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x10\x5D\xC3";

	// Set buffer size
	function_bytes_size = 42;

	// Set input and output types
	using I_type_ = char;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { 'a' };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 0);
}
TEST(call_virtual_function_wrapper, test_03_out_INT_in_PKc) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x48\x89\x4D\x10\xB8\x01\x00\x00\x00\x5D\xC3";

	// Set buffer size
	function_bytes_size = 16;

	// Set input and output types
	using I_type_ = const char*;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { "some random text" };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 1);
}
TEST(call_virtual_function_wrapper, test_04_out_INT_in_PKc) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x48\x89\x4D\x10\x48\x8B\x45\x10\x0F\xB6\x00\x3C\x61\x75\x07\xB8\x00\x00\x00\x00\xEB\x05\xB8\x01\x00\x00\x00\x5D\xC3";

	// Set buffer size
	function_bytes_size = 34;

	// Set input and output types
	using I_type_ = const char*;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { "a <-- is it?" };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 0);
}
TEST(call_virtual_function_wrapper, test_05_out_INT_in_PKc) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x48\x83\xEC\x10\x48\x89\x4D\x10\xC7\x45\xFC\x00\x00\x00\x00\xC7\x45\xFC\x00\x00\x00\x00\xEB\x04\x83\x45\xFC\x01\x8B\x45\xFC\x48\x63\xD0\x48\x8B\x45\x10\x48\x01\xD0\x0F\xB6\x00\x84\xC0\x75\xE8\x8B\x45\xFC\x48\x83\xC4\x10\x5D\xC3";

	// Set buffer size
	function_bytes_size = 62;

	// Set input and output types
	using I_type_ = const char*;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { "The length of this random text 43 is bytes + null terminator" };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 60);
}
TEST(call_virtual_function_wrapper, test_06_out_INT_in_PKc) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x48\x83\xEC\x10\x48\x89\x4D\x10\xC7\x45\xFC\x0A\x00\x00\x00\xC7\x45\xF8\x14\x00\x00\x00\x8B\x45\xFC\x3B\x45\xF8\x7E\x05\x8B\x45\xFC\xEB\x12\x8B\x45\xF8\x3B\x45\xFC\x7E\x05\x8B\x45\xF8\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x10\x5D\xC3";

	// Set buffer size
	function_bytes_size = 64;

	// Set input and output types
	using I_type_ = const char*;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { "Whatever ..." };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 20);
}
TEST(call_virtual_function_wrapper, test_07_out_INT_in_VOID) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\xB8\x01\x00\x00\x00\x5D\xC3";

	// Set buffer size
	function_bytes_size = 12;

	// Set input and output types
	using I_type_ = void*;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = {  };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 1);
}
TEST(call_virtual_function_wrapper, test_08_out_INT_in_INT) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x89\x4D\x10\x8B\x45\x10\x5D\xC3";

	// Set buffer size
	function_bytes_size = 13;

	// Set input and output types
	using I_type_ = int;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { 1337 };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 1337);
}
TEST(call_virtual_function_wrapper, test_09_out_INT_in_PKc) {

	// Define function bytes
	unsigned char function_bytes[] =
		"\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x89\x4D\x10\x48\xB8\x76\x61\x72\x34\x35\x73\x73\x66\x48\xBA\x78\x6B\x67\x6F\x6F\x66\x72\x78\x48\x89\x45\xE0\x48\x89\x55\xE8\xC6\x45\xF0\x00\xC7\x45\xFC\x00\x00\x00\x00\xC7\x45\xFC\x00\x00\x00\x00\xEB\x04\x83\x45\xFC\x01\x8B\x45\xFC\x48\x63\xD0\x48\x8B\x45\x10\x48\x01\xD0\x0F\xB6\x00\x84\xC0\x75\xE8\x83\x7D\xFC\x10\x74\x07\xB8\x01\x00\x00\x00\xEB\x3D\xC7\x45\xF8\x00\x00\x00\x00\xEB\x29\x8B\x45\xF8\x48\x63\xD0\x48\x8B\x45\x10\x48\x01\xD0\x0F\xB6\x10\x8B\x45\xF8\x48\x98\x0F\xB6\x44\x05\xE0\x38\xC2\x74\x07\xB8\x01\x00\x00\x00\xEB\x0F\x83\x45\xF8\x01\x83\x7D\xF8\x0F\x7E\xD1\xB8\x00\x00\x00\x00\x48\x83\xC4\x20\x5D\xC3";

	// Set buffer size
	function_bytes_size = 165;

	// Set input and output types
	using I_type_ = const char*;
	using O_type_ = int;

	// Set user input arguments
	std::vector<I_type_> args_ = { "var45ssfxkgoofrx" };

	// Call virtual function based on how many input arguments we have
	std::optional<O_type_> result_;
	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);

	// Test
	EXPECT_EQ(result_.value(), 0);
}
//TEST(call_virtual_function_wrapper, test_10_out_INT_in_2xPKc_1xINT) {
//
//	// Define function bytes
//	unsigned char function_bytes[] =
//		"\x55\x48\x89\xE5\x48\x83\xEC\x10\x48\x89\x4D\x10\x48\x89\x55\x18\x44\x89\x45\x20\xC7\x45\xFC\x00\x00\x00\x00\xEB\x2F\x8B\x45\xFC\x48\x63\xD0\x48\x8B\x45\x10\x48\x01\xD0\x0F\xB6\x10\x8B\x45\xFC\x48\x63\xC8\x48\x8B\x45\x18\x48\x01\xC8\x0F\xB6\x00\x38\xC2\x74\x07\xB8\x01\x00\x00\x00\xEB\x11\x83\x45\xFC\x01\x8B\x45\xFC\x3B\x45\x20\x7C\xC9\xB8\x00\x00\x00\x00\x48\x83\xC4\x10\x5D\xC3";
//
//	// Set buffer size
//	function_bytes_size = 165;
//
//	// Set input and output types
//	using I_type_ = const char*;
//	using O_type_ = int;
//
//	// Set user input arguments
//	std::vector<I_type_> args_ = { "abcde", "abcde", "5" };
//
//	// Call virtual function based on how many input arguments we have
//	std::optional<O_type_> result_;
//	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);
//
//	// Test
//	EXPECT_EQ(result_.value(), 0);
//}
//TEST(call_virtual_function_wrapper, test_10_out_INT_in_2xPKc_1xINT) {
//
//	// Define function bytes
//	unsigned char function_bytes[] =
//		"\x55\x48\x89\xE5\x48\x83\xEC\x20\x48\x89\x4D\x10\x89\x55\x18\x48\xB8\x76\x61\x72\x34\x35\x73\x73\x66\x48\x89\x45\xED\x48\xB8\x66\x78\x6B\x67\x6F\x6F\x66\x00\x48\x89\x45\xF4\xC7\x45\xFC\x00\x00\x00\x00\xEB\x29\x8B\x45\xFC\x48\x63\xD0\x48\x8B\x45\x10\x48\x01\xD0\x0F\xB6\x10\x8B\x45\xFC\x48\x98\x0F\xB6\x44\x05\xED\x38\xC2\x74\x07\xB8\x01\x00\x00\x00\xEB\x11\x83\x45\xFC\x01\x8B\x45\xFC\x3B\x45\x18\x7C\xCF\xB8\x00\x00\x00\x00\x48\x83\xC4\x20\x5D\xC3";
//
//	// Set buffer size
//	function_bytes_size = 113;
//
//	// Set input and output types
//	using I_type_ = const char*;
//	using O_type_ = int;
//
//	// Set user input arguments
//	std::vector<I_type_> args_ = { "abcde", "abcde", "5" };
//
//	// Call virtual function based on how many input arguments we have
//	std::optional<O_type_> result_;
//	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);
//
//	// Test
//	EXPECT_EQ(result_.value(), 0);
//}
//TEST(call_virtual_function_wrapper, test_12_out_PKc_in_PKc) {
//
//	// Define function bytes
//	unsigned char function_bytes[] =
//		"\x55\x48\x89\xE5\x48\x89\x4D\x10\x48\x8D\x05\x00\x00\x00\x00\x5D\xC3";
//
//	// Set buffer size
//	function_bytes_size = 18;
//
//	// Set input and output types
//	using I_type_ = const char*;
//	using O_type_ = const char*;
//
//	// Set user input arguments
//	std::vector<I_type_> args_ = { "Something" };
//
//	// Call virtual function based on how many input arguments we have
//	std::optional<O_type_> result_ = {};
//	call_virtual_function_wrapper<O_type_, I_type_>(args_, function_bytes, result_);
//
//	// Test
//	EXPECT_EQ(result_.value(), 0);
//}

#pragma endregion Unit_tests

void InitGoogleTest_wrapper(int argc, char* argv[]) {

	testing::InitGoogleTest(&argc, argv);

	RUN_ALL_TESTS();

	std::cout << "Unit test completed. Press key to continue." << std::endl;
}

int main(int argc, char* argv[]) {
start:
	std::cout << R"(
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
2025-02-02
Coded by: Matija Bensa
)" << '\n';
	// ASCII generated from: https://www.asciiart.eu/text-to-ascii-art

	// Run unit tests
	if (enable_unit_testing) {
		InitGoogleTest_wrapper(argc, argv);
		std::cin.get();
	}

	std::cout << "File cFunction.cpp should already contain code.\nIf it doesn't first write a code and then come back.\nPress Enter to continue.\n";
	//	std::cin.get();

	// Check if g++ exists
	CHECK(!system("g++ --version > NUL 2>&1"));

	// Compile to .o file
	std::cout << "Compiling cFunction.cpp to cFunction.o" << std::endl;
	system("g++ -c -o cFunction.o cFunction.cpp");

	// Check if Objdump exists
	CHECK(!system("objdump --version > NUL 2>&1"));

	// Dump .o file
	std::cout << "Dumping cFunction.o" << std::endl;
	system("objdump -d cFunction.o -M intel");

	// Get pasted opcode
	std::stringstream dumped_assembly_code;
	read_multi_line_input(dumped_assembly_code);

	// Return to start if no input was made
	if (dumped_assembly_code.str().size() < 1) {
		std::cout << "Nothing entered..." << std::endl;
		goto start;
	}

	// Extract hex opcode from the pasted dump
	std::string function_hex_string;
	extract_hex_opcode_from_objdump(dumped_assembly_code.str(), function_hex_string);

	// Set function size
	function_bytes_size = function_hex_string.size() / 2;
	std::cout << "function_bytes_size: " << std::dec << function_bytes_size << std::endl << std::endl;

	// Convert hex string to actual bytes
	unsigned char* function_bytes = new unsigned char[function_bytes_size];
	hex_string_to_bytes(function_hex_string, function_bytes);

	// Print byte array
	std::cout << "const unsigned char function_bytes[] = \n\"";
	for (size_t i = 0; i < function_bytes_size; ++i) {
		printf("\\x%02X", function_bytes[i]);
	}
	std::cout << std::dec << "\";" << std::endl;

	//goto start;		// FOR DEBUG

	// Set XOR key
	std::cout << "\nSet XOR key to cipher the opcode, or just press ENTER to use default key\nPress Enter to continue.\n";
	std::string xor_key;
	set_xor_key(xor_key);

	// XOR functionBytes to cipher
	unsigned char* function_bytes_cipher = new unsigned char[function_bytes_size];
	xor_array(function_bytes, xor_key.c_str(), function_bytes_size, function_bytes_cipher);

	// Print XOR-ed function
	std::cout << "\nconst unsigned char function_bytes_cipher[] = \n\"";
	for (size_t i = 0; i < function_bytes_size; ++i) {
		printf("\\x%02X", function_bytes_cipher[i]);
	}
	std::cout << "\";" << std::endl;

	// XOR again
	unsigned char* function_bytes_de_ciphered = new unsigned char[function_bytes_size];
	xor_array(function_bytes_cipher, xor_key.c_str(), function_bytes_size, function_bytes_de_ciphered);

	// And check memory if bytes after xoring are the same as at beginning
	if (memcmp(function_bytes, function_bytes_de_ciphered, function_bytes_size)) {
		std::cout << "XOR-in error!\n";
		return 1;
	}

	// Cleanup
	delete[]function_bytes;
	delete[]function_bytes_cipher;

	// Input and output types are defined in the "header" of this file
	std::cout << "\nPredefined INPUT arguments type: <" << typeid(I_type).name() << ">" << std::endl;
	std::cout << "Predefined OUTPUT result type:   <" << typeid(O_type).name() << ">" << std::endl;

	// Test calling method, set input argument(s)
	std::cout << "\nCall opcode function with arguments:\n";

	// Get user input arguments into a vector of Input types
	std::vector<I_type> args = processInput<I_type>();

	// Call virtual function based on how many input arguments we have
	std::optional<O_type> result;
	call_virtual_function_wrapper<O_type, I_type>(args, function_bytes_de_ciphered, result);

	// Again print the return result
	if (result.has_value()) {
		std::cout << "result: " << result.value() << std::endl;
	}

	std::cout << "Press key to exit\n";
	std::cin.get();
	return 0;
}

