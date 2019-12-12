/* Modified by Nober <s0913768710@gmail.com>
    13-DEC-2019 - Define all CSR macro
*/

/*
RISCV emulator for the RV32I architecture
based on TinyEMU by Fabrice Bellard, see https://bellard.org/tinyemu/
stripped down for RV32I only, all "gotos" removed, and fixed some bugs for the compliance test
by Frank Buss, 2018

Requires libelf-dev:

sudo apt-get install libelf-dev


Compile it like this:

gcc -O3 -Wall -lelf emu-rv32i.c -o emu-rv32i


It is compatible to Spike for the command line arguments, which means you can run
the compliance test from https://github.com/riscv/riscv-compliance like this:

make RISCV_TARGET=spike RISCV_DEVICE=rv32i TARGET_SIM=/full/path/emulator variant

It is also compatible with qemu32, as it is used for Zephyr. You can compile the
Zephyr examples for qemu like this:

cd zephyr
source zephyr-env.sh
cd samples/synchronization
mkdir build && cd build
cmake -GNinja -DBOARD=qemu_riscv32 ..
ninja

After this you can run it with the emulator like this:

emu-rv32i zephyr/zephyr.elf


original copyright:
*/



/*
 * RISCV emulator
 *
 * Copyright (c) 2016 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>


// ====================================================== //
// =================== User Trap Setup ================== //
// ====================================================== //
uint32_t ustatus;           /* User status register  */
uint32_t uie;               /* User interrupt-enable register */
uint32_t utvec;             /* User trap handler base address */
// ====================================================== //
// ================= User Trap Handling ================= //
// ====================================================== //
uint32_t uscratch;           /* Scratch register for user trap handlers*/
uint32_t uepc;               /* User exception program counter */
uint32_t ucause;             /* User trap cause*/
uint32_t ubadaddr;           /* User bad address */
uint32_t uip;                /* User interrupt pending */
// ====================================================== //
// ============== User Floating-Point CSRs ============== //
// ====================================================== //
uint32_t fflags;             /* Floating-Point Accrued Exceptions*/
uint32_t frm;                /* Floating-Point Dynamic Rounding Mode*/
