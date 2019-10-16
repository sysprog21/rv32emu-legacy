/*
 riscv64-unknown-elf-gcc -march=rv32i -mabi=ilp32 -O3 -nostdlib test1.c -o test1
*/
void _start()
{
    volatile char* tx = (volatile char*) 0x40002000;
    const char* hello = "Hello RISC-V!\n";
    while (*hello) {
        *tx = *hello;
        hello++;
    }
}
