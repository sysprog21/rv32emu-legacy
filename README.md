# RISC-V RV32I[MA] emulator with ELF support

This is a RISC-V emulator for the RV32I architecture, based on [TinyEMU](https://bellard.org/tinyemu/)
and stripped down for RV32I only.

Requires libelf-dev:
```shell
$ sudo apt-get install libelf-dev
```

How to compile it:
```shell
$ gcc -O3 -Wall emu-rv32i.c -o emu-rv32i -lelf
```
or
```shell
$ make emu-rv32i
```

Passed RV32I compliance tests from https://github.com/riscv/riscv-compliance
- Must install the [risc-v toolchain](https://xpack.github.io/riscv-none-embed-gcc/)
```shell
$ git clone https://github.com/riscv/riscv-compliance
$ cd riscv-compliance
$ make RISCV_PREFIX=riscv-none-embed- RISCV_DEVICE=rv32i TARGET_SIM=/abs/to/emu-rv32i RISCV_TARGET=rv32emu TARGETDIR=/abs/to/riscv-target variant
```
- Run RV32IMC compliance tests.
Assume `emu-rv32i` in `$PATH` environment variable.
```shell
$ git clone https://github.com/riscv/riscv-compliance
$ cd riscv-compliance
$ make RISCV_PREFIX=riscv-none-embed- RISCV_DEVICE=rv32imc TARGET_SIM=/abs/to/rv32emu/emu-rv32i RISCV_TARGET=rv32emu TARGETDIR=/abs/to/riscv-target variant
```

Compiling and running simple code:
```shell
$ make test1
```

then
```shell
$ ./emu-rv32i test1
Hello RISC-V!
```

- RV32M and RV32A instructions may be enabled by commenting `#define STRICT_RV32I`.


Passed RV32C compliance tests from https://github.com/riscv/riscv-compliance
```shell
make C-ADDI.log
```
If there is no accident, it will output the `TEST PASSED`


- RV32C instructions can be enabled by commenting `#define RV32C`
## How to build RISC-V toolchain from scratch

https://github.com/riscv/riscv-gnu-toolchain

64-bit universal version (riscv64-unknown-elf-* that can build 32-bit code too):
```shell
$ ./configure --prefix=/opt/riscv
$ make
```

32-bit version (riscv32-unknown-elf-*):
```shell
$ ./configure --prefix=/opt/riscv32 --with-arch=rv32i --with-abi=ilp32
$ make
```
