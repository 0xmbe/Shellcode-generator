
@echo ===============================
@echo SHELLCODE Opcode Generator MAKE
@echo ===============================

::echo Compile .o file
g++ -c -o OPCODE_generator.o OPCODE_generator.cpp

::echo Link to executable
:: Don't need for this process
::g++ OPCODE_generator.o -o OPCODE_generator.exe

:: Dump .o file
objdump -d OPCODE_generator.o

pause