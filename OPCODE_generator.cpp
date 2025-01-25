
#include <windows.h>
#include <iostream>

int func(){
	return 42;
}
int func2(int in){
	return in;
}
int check_password(const char* pass){
	const char* p = "Password1";
	for (int i = 0; i < strlen(pass); ++i){
		if (pass[i] != p[i])
			return 1;
	}
	return 0;
}
int check_password2(char c){
	const char p = 'c';
	if (p != c)
		return 1; 
	return 0;
}
int check_string_equal(const char* str1, const char* str2, size_t length) {
	for (size_t i = 0; i < length; ++i) {
		if (str1[i] != str2[i]) {
			return 1;
		}
	}
	return 0;
}
int check_password4(const char* str1, size_t length) {
	const char str2[] = "var45ssfxkgoof";
	for (size_t i = 0; i < length; ++i) {
		if (str1[i] != str2[i]) {
			return 1;
		}
	}
	return 0;
}
int check_password5(const char* str1) {
	const char str2[] = "var45ssfxkgoofrx";
	if (strlen(str1) != 16){
		return 1;
	}
	for (size_t i = 0; i < 16; ++i) {
		if (str1[i] != str2[i]) {
			return 1;
		}
	}
	return 0;
}
int check_password6(const char* str1) {
	const char str2[] = "var45ssfxkgoofrx";
	size_t c = 0;
	for (c = 0; str1[c] != '\0'; ++c){}
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

int main(){
	func();
	func2(5);
	check_password("Mat");
	return 0;
}