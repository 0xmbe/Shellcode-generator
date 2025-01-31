
#include <iostream>
#include <windows.h>
#include <iostream>
#include <cstring>

//##################
// TEST OUTPUT: INT
//##################

//
// TEST INPUT: INT
//
int test_01_out_INT_in_2xINT(int num1, int num2){					// OK
	return num1 + num2;
}

//
// TEST INPUT: CHAR
//
int test_02_out_INT_in_CHAR(char c){								// OK
	const char p = 'c';
	if (p == c)
		return 1; 
	return 0;
}

//
// TEST INPUT: CONST CHAR*
//
int test_03_out_INT_in_PKc(const char* str1) {						// OK
	return 1;
}
int test_04_out_INT_in_PKc(const char* str1) {						// OK
	if (str1[0] == 'a'){
		return 0;
	}
	return 1;
}
int test_05_out_INT_in_PKc(const char* str1) {						// OK
	int c = 0;
	for (c = 0; str1[c] != '\0'; ++c){}
	return c;
}
int test_06_out_INT_in_PKc(const char* str1) {						// OK
	int a = 10;
	int b = 20;
	if (a > b){
		return a;
	}
	if (b > a){
		return b;
	}
	return 0;
}
int test_07_out_INT_in_VOID(){										// OK
	return 1;
}
int test_08_out_INT_in_INT(int in){									// OK
	return in;
}
int test_09_out_INT_in_PKc(const char* str1) {						// OK
	const char str2[] = "var45ssfxkgoofrx";
	int c = 0;
	for (c = 0; str1[c] != '\0'; ++c){}		// count string length
	if (c != 16){
		return 1;
	}
	for (int i = 0; i < 16; ++i) {
		if (str1[i] != str2[i]) {
			return 1;
		}
	}
	return 0;
}

//
// TEST INPUT: CONST CHAR* & INT		----> Currently not supported different input types
//
int test_10_out_INT_in_2xPKc_1xINT(const char* str1, const char* str2, int length) {		// CRASH
	for (int i = 0; i < length; ++i) {
		if (str1[i] != str2[i]) {
			return 1;
		}
	}
	return 0;
}
int test_11_out_INT_in_1xPKc_1xINT(const char* str1, int length) {							// CRASH
	const char str2[] = "var45ssfxkgoof";
	for (int i = 0; i < length; ++i) {
		if (str1[i] != str2[i]) {
			return 1;
		}
	}
	return 0;
}

//##################
// TEST OUTPUT: INT
//##################

//
// TEST INPUT: CONST CHAR*
//
const char* test_12_out_PKc_in_PKc(const char* str1){										// CRASH
	return "OK";
}

// int test_1_out_INT_in_string(std::string str1) {
	// std::string str2 = "var45ssfxkgoofrx";
	// if (str1.size() != 16) {
		// return 1;
	// }
	// for (int i = 0; i < 16; ++i) {
		// if (str1.c_str()[i] != str2.c_str()[i]) {
			// return 1;
		// }
	// }
	// return 0;
// }
// int test_1_out_INT_in_2xPKc(const char* str1, const char* str2) {			// ?
	// for (int i = 0; str1[i] != '\0' || str2[i] != '\0'; ++i) {
		// if (str1[i] > str2[i]) {
			// return 1;
		// }
		// if (str2[i] > str1[i]) {
			// return -1;
		// }
	// }
	// return 0;
// }
// int test_1_out_INT_in_PKc(const char str1[32], const char str2[32]) {		// ?
	// for (int i = 0; str1[i] != '\0' || str2[i] != '\0'; ++i) {
		// if (str1[i] > str2[i]) {
			// return 1;
		// }
		// if (str2[i] > str1[i]) {
			// return -1;
		// }
	// }
	// return 0;
// }





int main(){
	return 0;
}

