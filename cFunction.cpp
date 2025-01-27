
#include <windows.h>
#include <iostream>


//
// TEST INT
//
int test_return_int(){
	return 1;
}
// int test_return_int_argument(int in){			// CRASH
	// return in;
// }
// int test_check_char(char c){						// CRASH
	// const char p = 'c';
	// if (p != c)
		// return 1; 
	// return 0;
// }
// int test_check_string_equal(const char* str1, const char* str2, size_t length) {			// CRASH
	// for (size_t i = 0; i < length; ++i) {
		// if (str1[i] != str2[i]) {
			// return 1;
		// }
	// }
	// return 0;
// }
// int test_check_password1(const char* str1, size_t length) {			// CRASH
	// const char str2[] = "var45ssfxkgoof";
	// for (size_t i = 0; i < length; ++i) {
		// if (str1[i] != str2[i]) {
			// return 1;
		// }
	// }
	// return 0;
// }
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
int test_return_biggest(const char* str1, const char* str2) {			// Always returns -1
	for (size_t i = 0; str1[i] != '\0' || str2[i] != '\0'; ++i) {
		if (str1[i] > str2[i]) {
			return 1;
		}
		if (str2[i] > str1[i]) {
			return -1;
		}
	}
	return 0;
}
int test_return_biggest2(const char str1[32], const char str2[32]) {	// Always returns -1
	for (size_t i = 0; str1[i] != '\0' || str2[i] != '\0'; ++i) {
		if (str1[i] > str2[i]) {
			return 1;
		}
		if (str2[i] > str1[i]) {
			return -1;
		}
	}
	return 0;
}

int main(){
	test_check_password2("aaaaaaaa");
	return 0;
}

