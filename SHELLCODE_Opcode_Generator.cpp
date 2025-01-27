
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
#pragma comment(lib, "iphlpapi.lib")
#include <cmath>
#include <cstdio>
#include <ios>
#include <iosfwd>
#include <cstdlib>
#include <regex>


// Global definition for creating new arrays of same size
size_t function_bytes_size = 0;

// Default key for XOR-ing operation
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
	char aa = '\x55';
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
	std::regex hex_pattern(R"(\b[0-9a-fA-F]{2}\b)");
	std::sregex_iterator sregex_iterator(input.begin(), input.end(), hex_pattern);
	std::sregex_iterator end;
	std::vector<std::string> hexParts;

	while (sregex_iterator != end) {
		hexParts.push_back(sregex_iterator->str());
		++sregex_iterator;
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
template<typename ReturnType, typename... Args>
ReturnType execute_virtual_function_bytes(
	const unsigned char* bytes,
	Args&&... args) {

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
		return ERROR;
	}

	// Print all arguments before executing the function
	std::cout << "Arguments:\n";
	printAllArguments(std::forward<Args>(args)...);
	std::cout << std::endl;

	// Copy function bytes to executable memory
	memcpy(executableMemory, bytes, function_bytes_size);

	// Cast executable memory to function pointer
	auto func_ptr = reinterpret_cast<ReturnType(*)(Args...)>(executableMemory);

	// Execute function
	//ReturnType result = func_ptr(std::forward<Args&&>(args)...);
	ReturnType result = func_ptr(std::forward<Args>(args)...);

	// Display return results
	print_char('\xcd', 40);
	std::cout << "Dynamically executed function returned: " << result << std::endl;
	print_char('\xcd', 40);




	std::cerr << GetLastError() << std::endl;


	// Free allocated memory
	VirtualFree(executableMemory, 0, MEM_RELEASE);

	return {};
}



int main() {
start:
	std::cout << R"(
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
Coded by: Matija Bensa
)" << '\n';
	// ASCII generated from: https://www.asciiart.eu/text-to-ascii-art

	std::cout << "File cFunction.cpp should already contain code.\nIf it doesn't first write a code and then come back.\nPress Enter to continue.\n";
	std::cin.get();

	// Check if g++ exists
	CHECK(!system("g++ --version > NUL 2>&1"));

	// Compile to .o file
	std::cout << "Compiling cFunction.cpp to cFunction.o" << std::endl;
	system("g++ -c -o cFunction.o cFunction.cpp");

	// Check if Objdump exists
	CHECK(!system("objdump --version > NUL 2>&1"));

	// Dump .o file
	std::cout << "Dumping cFunction.o" << std::endl;
	system("objdump -d cFunction.o");

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

	// And check if bytes are equal
	if (memcmp(function_bytes, function_bytes_de_ciphered, function_bytes_size)) {
		std::cout << "XOR-in error!\n";
		return 1;
	}

	// Delete function_bytes
	delete[]function_bytes;

	// Delete function_bytes_cipher
	delete[]function_bytes_cipher;

	// Test calling method, set input argument(s)
	std::cout << "\nCall opcode function with arguments:\n";
	std::string input;
	std::getline(std::cin, input);

	// Run decrypted function bytes
	auto result = execute_virtual_function_bytes<int>(function_bytes_de_ciphered, input.c_str());

	//std::cout << "result: " << result << std::endl;

	std::cout << "Press key to exit\n";
	std::cin.get();
	return 0;
}




