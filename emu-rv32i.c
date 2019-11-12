/*
 * A minimalist RISC-V emulator for the RV32I architecture.
 *
 * rv32emu is freely redistributable under the MIT License. See the file
 * "LICENSE" for information on usage and redistribution of this file.
 */

#define XLEN 32

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* uncomment this for an instruction trace and other debug outputs */
// #define DEBUG_OUTPUT
// #define DEBUG_EXTRA

#define STRICT_RV32I
#define FALSE (0)
#define TRUE (-1)

#ifdef DEBUG_EXTRA

uint32_t minmemr, maxmemr, minmemw, maxmemw;

#define STATS_NUM 64

unsigned int stats[STATS_NUM], top[5], itop[5];

char statnames[64][16] = {
    "LUI",   "AUIPC",  "JAL",    "JALR",    "BEQ",    "BNE",    "BLT",
    "BGE",   "BLTU",   "BGEU",   "LB",      "LH",     "LW",     "LBU",
    "LHU",   "SB",     "SH",     "SW",      "ADDI",   "SLTI",   "SLTIU",
    "XORI",  "ORI",    "ANDI",   "SLLI",    "SRLI",   "SRAI",   "ADD",
    "SUB",   "SLL",    "SLT",    "SLTU",    "XOR",    "SRL",    "SRA",
    "OR",    "AND",    "FENCE",  "FENCE.I", "ECALL",  "EBREAK", "CSRRW",
    "CSRRS", "CSRRC",  "CSRRWI", "CSRRSI",  "CSRRCI", "LI*",    "MUL",
    "MULH",  "MULHSU", "MULHU",  "DIV",     "DIVU",   "REM",    "REMU",
    "LR.W",  "SC.W",   "URET",   "SRET",    "MRET",   "WFI",    "SFENCE.VMA",
    ""};

void init_stats(void)
{
    for (int i = 0; i < STATS_NUM; i++)
        stats[i] = 0;
    minmemr = minmemw = ~0;
    maxmemr = maxmemw = 0;
}

void print_stats(uint64_t total)
{
    printf("\nInstructions Stat:\n");
    top[0] = top[1] = top[2] = top[3] = top[4] = stats[0];
    itop[0] = itop[1] = itop[2] = itop[3] = itop[4] = 0;
    for (int i = 0; i < STATS_NUM; i++) {
        if (stats[i] > top[0]) {
            top[4] = top[3];
            itop[4] = itop[3];
            top[3] = top[2];
            itop[3] = itop[2];
            top[2] = top[1];
            itop[2] = itop[1];
            top[1] = top[0];
            itop[1] = itop[0];
            top[0] = stats[i];
            itop[0] = i;
        } else if (stats[i] > top[1]) {
            top[4] = top[3];
            itop[4] = itop[3];
            top[3] = top[2];
            itop[3] = itop[2];
            top[2] = top[1];
            itop[2] = itop[1];
            top[1] = stats[i];
            itop[1] = i;
        } else if (stats[i] > top[2]) {
            top[4] = top[3];
            itop[4] = itop[3];
            top[3] = top[2];
            itop[3] = itop[2];
            top[2] = stats[i];
            itop[2] = i;
        } else if (stats[i] > top[3]) {
            top[4] = top[3];
            itop[4] = itop[3];
            top[3] = stats[i];
            itop[3] = i;
        } else if (stats[i] > top[4]) {
            top[4] = stats[i];
            itop[4] = i;
        }
        if (stats[i]) {
            if (i < 63)
                printf("%s\t= %u\n", statnames[i], stats[i]);
            else
                printf("[%i] = %u\n", i, stats[i]);
        }
    }
    printf("\nFive Most Frequent:\n");
    for (int j = 0; j < 5; j++) {
        printf("%i) %s\t= %u (%2.2lf%%)\n", j + 1, statnames[itop[j]], top[j],
               top[j] * 100.0 / (double) total);
    }
    printf("\nMemory Reading Area %x...%x\n", minmemr, maxmemr);
    if (minmemw + 1)
        printf("Memory Writing Area %x...%x\n", minmemw, maxmemw);
    else
        printf("Memory Writing Area NONE\n");
}

#endif

#ifdef DEBUG_OUTPUT
#define debug_out(...) printf(__VA_ARGS__)
#else
#define debug_out(...)
#endif

/* memory mapped registers */
#define MTIME_ADDR 0x40000000
#define MTIMECMP_ADDR 0x40000008
#define UART_TX_ADDR 0x40002000

/* emulate RAM */
#define RAM_SIZE 0x10000
uint8_t ram[RAM_SIZE];

/* special memory mapped registers */
uint64_t mtime;
uint64_t mtimecmp;

/* virtual start address for index 0 in the ram array */
uint32_t ram_start;

/* program entry point */
uint32_t start;

/* last byte of the memory initialized and temporary value */
uint32_t ram_last = 0;
uint32_t ram_curr = 0;

/* used when called from the compliance tests */
uint32_t begin_signature = 0;
uint32_t end_signature = 0;

/* is set to false to exit the emulator */
int machine_running = TRUE;

/* privilege levels */
#define PRV_U 0
#define PRV_S 1
#define PRV_H 2
#define PRV_M 3

/* CPU state */
uint32_t pc;
uint32_t next_pc;
uint32_t insn;
uint32_t reg[32];

uint8_t priv = PRV_M; /* see PRV_x */
uint8_t fs;           /* MSTATUS_FS value */
uint8_t mxl;          /* MXL field in MISA register */

uint64_t jump_counter = 0, backward_counter = 0, forward_counter = 0,
         true_counter = 0, false_counter = 0;

uint64_t insn_counter = 0;
int pending_exception; /* used during MMU exception handling */
uint32_t pending_tval;

/* CSRs */
uint32_t mstatus;
uint32_t mtvec;
uint32_t mscratch;
uint32_t mepc;
uint32_t mcause;
uint32_t mtval;
uint32_t mhartid; /* ro */
uint32_t misa;
uint32_t mie;
uint32_t mip;
uint32_t medeleg;
uint32_t mideleg;
uint32_t mcounteren;

uint32_t stvec;
uint32_t sscratch;
uint32_t sepc;
uint32_t scause;
uint32_t stval;
uint32_t satp;
uint32_t scounteren;
uint32_t load_res; /* for atomic LR/SC */

/* exception causes */
#define CAUSE_MISALIGNED_FETCH 0x0
#define CAUSE_FAULT_FETCH 0x1
#define CAUSE_ILLEGAL_INSTRUCTION 0x2
#define CAUSE_BREAKPOINT 0x3
#define CAUSE_MISALIGNED_LOAD 0x4
#define CAUSE_FAULT_LOAD 0x5
#define CAUSE_MISALIGNED_STORE 0x6
#define CAUSE_FAULT_STORE 0x7
#define CAUSE_USER_ECALL 0x8
#define CAUSE_SUPERVISOR_ECALL 0x9
#define CAUSE_HYPERVISOR_ECALL 0xa
#define CAUSE_MACHINE_ECALL 0xb
#define CAUSE_FETCH_PAGE_FAULT 0xc
#define CAUSE_LOAD_PAGE_FAULT 0xd
#define CAUSE_STORE_PAGE_FAULT 0xf
#define CAUSE_INTERRUPT ((uint32_t) 1 << 31)

/* misa CSR */
#define MCPUID_SUPER (1 << ('S' - 'A'))
#define MCPUID_USER (1 << ('U' - 'A'))
#define MCPUID_I (1 << ('I' - 'A'))
#define MCPUID_M (1 << ('M' - 'A'))
#define MCPUID_A (1 << ('A' - 'A'))
#define MCPUID_F (1 << ('F' - 'A'))
#define MCPUID_D (1 << ('D' - 'A'))
#define MCPUID_Q (1 << ('Q' - 'A'))
#define MCPUID_C (1 << ('C' - 'A'))

#define MIP_USIP (1 << 0)
#define MIP_SSIP (1 << 1)
#define MIP_HSIP (1 << 2)
#define MIP_MSIP (1 << 3)
#define MIP_UTIP (1 << 4)
#define MIP_STIP (1 << 5)
#define MIP_HTIP (1 << 6)
#define MIP_MTIP (1 << 7)
#define MIP_UEIP (1 << 8)
#define MIP_SEIP (1 << 9)
#define MIP_HEIP (1 << 10)
#define MIP_MEIP (1 << 11)

/* mstatus CSR */
#define MSTATUS_SPIE_SHIFT 5
#define MSTATUS_MPIE_SHIFT 7
#define MSTATUS_SPP_SHIFT 8
#define MSTATUS_MPP_SHIFT 11
#define MSTATUS_FS_SHIFT 13
#define MSTATUS_UXL_SHIFT 32
#define MSTATUS_SXL_SHIFT 34

#define MSTATUS_UIE (1 << 0)
#define MSTATUS_SIE (1 << 1)
#define MSTATUS_HIE (1 << 2)
#define MSTATUS_MIE (1 << 3)
#define MSTATUS_UPIE (1 << 4)
#define MSTATUS_SPIE (1 << MSTATUS_SPIE_SHIFT)
#define MSTATUS_HPIE (1 << 6)
#define MSTATUS_MPIE (1 << MSTATUS_MPIE_SHIFT)
#define MSTATUS_SPP (1 << MSTATUS_SPP_SHIFT)
#define MSTATUS_HPP (3 << 9)
#define MSTATUS_MPP (3 << MSTATUS_MPP_SHIFT)
#define MSTATUS_FS (3 << MSTATUS_FS_SHIFT)
#define MSTATUS_XS (3 << 15)
#define MSTATUS_MPRV (1 << 17)
#define MSTATUS_SUM (1 << 18)
#define MSTATUS_MXR (1 << 19)
#define MSTATUS_UXL_MASK ((uint64_t) 3 << MSTATUS_UXL_SHIFT)
#define MSTATUS_SXL_MASK ((uint64_t) 3 << MSTATUS_SXL_SHIFT)

static inline int ctz32(uint32_t val)
{
#if defined(__GNUC__) && __GNUC__ >= 4
    return val ? __builtin_ctz(val) : 32;
#else
    /* Binary search for the trailing one bit.  */
    int cnt;
    cnt = 0;
    if (!(val & 0x0000FFFFUL)) {
        cnt += 16;
        val >>= 16;
    }
    if (!(val & 0x000000FFUL)) {
        cnt += 8;
        val >>= 8;
    }
    if (!(val & 0x0000000FUL)) {
        cnt += 4;
        val >>= 4;
    }
    if (!(val & 0x00000003UL)) {
        cnt += 2;
        val >>= 2;
    }
    if (!(val & 0x00000001UL)) {
        cnt++;
        val >>= 1;
    }
    if (!(val & 0x00000001UL)) {
        cnt++;
    }
    return cnt;
#endif
}

#define SSTATUS_MASK0                                                        \
    (MSTATUS_UIE | MSTATUS_SIE | MSTATUS_UPIE | MSTATUS_SPIE | MSTATUS_SPP | \
     MSTATUS_FS | MSTATUS_XS | MSTATUS_SUM | MSTATUS_MXR)
#define SSTATUS_MASK SSTATUS_MASK0


#define MSTATUS_MASK                                                         \
    (MSTATUS_UIE | MSTATUS_SIE | MSTATUS_MIE | MSTATUS_UPIE | MSTATUS_SPIE | \
     MSTATUS_MPIE | MSTATUS_SPP | MSTATUS_MPP | MSTATUS_FS | MSTATUS_MPRV |  \
     MSTATUS_SUM | MSTATUS_MXR)

/* cycle and insn counters */
#define COUNTEREN_MASK ((1 << 0) | (1 << 2))

/* return the complete mstatus with the SD bit */
uint32_t get_mstatus(uint32_t mask)
{
    uint32_t val;
    int sd;
    val = mstatus | (fs << MSTATUS_FS_SHIFT);
    val &= mask;
    sd =
        ((val & MSTATUS_FS) == MSTATUS_FS) | ((val & MSTATUS_XS) == MSTATUS_XS);
    if (sd)
        val |= (uint32_t) 1 << (XLEN - 1);
    return val;
}

void set_mstatus(uint32_t val)
{
    fs = (val >> MSTATUS_FS_SHIFT) & 3;

    uint32_t mask = MSTATUS_MASK & ~MSTATUS_FS;
    mstatus = (mstatus & ~mask) | (val & mask);
}

void invalid_csr(uint32_t *pval, uint32_t csr)
{
    /* the 'time' counter is usually emulated */
    if (csr != 0xc01 && csr != 0xc81) {
        debug_out("csr_read: invalid CSR=0x%x\n", csr);
    }
    *pval = 0;
}

/* return -1 if invalid CSR. 0 if OK. 'will_write' indicate that the
   csr will be written after (used for CSR access check) */
int csr_read(uint32_t *pval, uint32_t csr, int will_write)
{
    uint32_t val;

#ifdef DEBUG_EXTRA
    printf("csr_read: csr=0x%03x %i\n", csr, will_write);
#endif

    if (((csr & 0xc00) == 0xc00) && will_write)
        return -1; /* read-only CSR */
    if (priv < ((csr >> 8) & 3))
        return -1; /* not enough priviledge */

    switch (csr) {
    case 0xc00: /* cycle */
    case 0xc02: /* instret */
    {
        uint32_t counteren;
        if (priv < PRV_M) {
            if (priv < PRV_S)
                counteren = scounteren;
            else
                counteren = mcounteren;
            if (((counteren >> (csr & 0x1f)) & 1) == 0) {
                invalid_csr(pval, csr);
                return -1;
            }
        }
    }
        val = (int64_t) insn_counter;
        break;
    case 0xc80: /* cycleh */
    case 0xc82: /* instreth */
    {
        uint32_t counteren;
        if (priv < PRV_M) {
            if (priv < PRV_S)
                counteren = scounteren;
            else
                counteren = mcounteren;
            if (((counteren >> (csr & 0x1f)) & 1) == 0) {
                invalid_csr(pval, csr);
                return -1;
            }
        }
    }
        val = insn_counter >> 32;
        break;

    case 0x100:
        val = get_mstatus(SSTATUS_MASK);
        break;
    case 0x104: /* sie */
        val = mie & mideleg;
        break;
    case 0x105:
        val = stvec;
        break;
    case 0x106:
        val = scounteren;
        break;
    case 0x140:
        val = sscratch;
        break;
    case 0x141:
        val = sepc;
        break;
    case 0x142:
        val = scause;
        break;
    case 0x143:
        val = stval;
        break;
    case 0x144: /* sip */
        val = mip & mideleg;
        break;
    case 0x180:
        val = satp;
        break;
    case 0x300:
        val = get_mstatus((uint32_t) -1);
        break;
    case 0x301:
        val = misa;
        val |= (uint32_t) mxl << (XLEN - 2);
        break;
    case 0x302:
        val = medeleg;
        break;
    case 0x303:
        val = mideleg;
        break;
    case 0x304:
        val = mie;
        break;
    case 0x305:
        val = mtvec;
        break;
    case 0x306:
        val = mcounteren;
        break;
    case 0x340:
        val = mscratch;
        break;
    case 0x341:
        val = mepc;
        break;
    case 0x342:
        val = mcause;
        break;
    case 0x343:
        val = mtval;
        break;
    case 0x344:
        val = mip;
        break;
    case 0xb00: /* mcycle */
    case 0xb02: /* minstret */
        val = (int64_t) insn_counter;
        break;
    case 0xb80: /* mcycleh */
    case 0xb82: /* minstreth */
        val = insn_counter >> 32;
        break;
    case 0xf14:
        val = mhartid;
        break;
    default:
        invalid_csr(pval, csr);
        /* return -1; */
        return 0;
    }

#ifdef DEBUG_EXTRA
    printf("csr_read: csr=0x%03x --> 0x%08x\n", csr, val);
#endif

    *pval = val;
    return 0;
}

/* return -1 if invalid CSR, 0 if OK, 1 if the interpreter loop must be
   exited (e.g. XLEN was modified), 2 if TLBs have been flushed. */
int csr_write(uint32_t csr, uint32_t val)
{
    uint32_t mask;
#ifdef DEBUG_EXTRA
    printf("csr_write: csr=0x%03x val=0x%08x\n", csr, val);
#endif
    switch (csr) {
    case 0x100: /* sstatus */
        set_mstatus((mstatus & ~SSTATUS_MASK) | (val & SSTATUS_MASK));
        break;
    case 0x104: /* sie */
        mask = mideleg;
        mie = (mie & ~mask) | (val & mask);
        break;
    case 0x105:
        stvec = val & ~3;
        break;
    case 0x106:
        scounteren = val & COUNTEREN_MASK;
        break;
    case 0x140:
        sscratch = val;
        break;
    case 0x141:
        sepc = val & ~1;
        break;
    case 0x142:
        scause = val;
        break;
    case 0x143:
        stval = val;
        break;
    case 0x144: /* sip */
        mask = mideleg;
        mip = (mip & ~mask) | (val & mask);
        break;
    case 0x180: /* no ASID implemented */
    {
        int new_mode;
        new_mode = (val >> 31) & 1;
        satp = (val & (((uint32_t) 1 << 22) - 1)) | (new_mode << 31);
    }
        return 2;

    case 0x300:
        set_mstatus(val);
        break;
    case 0x301: /* misa */
        break;
    case 0x302:
        mask = (1 << (CAUSE_STORE_PAGE_FAULT + 1)) - 1;
        medeleg = (medeleg & ~mask) | (val & mask);
        break;
    case 0x303:
        mask = MIP_SSIP | MIP_STIP | MIP_SEIP;
        mideleg = (mideleg & ~mask) | (val & mask);
        break;
    case 0x304:
        mask = MIP_MSIP | MIP_MTIP | MIP_SSIP | MIP_STIP | MIP_SEIP;
        mie = (mie & ~mask) | (val & mask);
        break;
    case 0x305:
        mtvec = val & ~3;
        break;
    case 0x306:
        mcounteren = val & COUNTEREN_MASK;
        break;
    case 0x340:
        mscratch = val;
        break;
    case 0x341:
        mepc = val & ~1;
        break;
    case 0x342:
        mcause = val;
        break;
    case 0x343:
        mtval = val;
        break;
    case 0x344:
        mask = MIP_SSIP | MIP_STIP;
        mip = (mip & ~mask) | (val & mask);
        break;
    default:
        return 0;
        /* return -1; */
    }
    return 0;
}

void handle_sret()
{
    int spp, spie;
    spp = (mstatus >> MSTATUS_SPP_SHIFT) & 1;
    /* set the IE state to previous IE state */
    spie = (mstatus >> MSTATUS_SPIE_SHIFT) & 1;
    mstatus = (mstatus & ~(1 << spp)) | (spie << spp);
    /* set SPIE to 1 */
    mstatus |= MSTATUS_SPIE;
    /* set SPP to U */
    mstatus &= ~MSTATUS_SPP;
    priv = spp;
    next_pc = sepc;
}

void handle_mret()
{
    int mpp, mpie;
    mpp = (mstatus >> MSTATUS_MPP_SHIFT) & 3;
    /* set the IE state to previous IE state */
    mpie = (mstatus >> MSTATUS_MPIE_SHIFT) & 1;
    mstatus = (mstatus & ~(1 << mpp)) | (mpie << mpp);
    /* set MPIE to 1 */
    mstatus |= MSTATUS_MPIE;
    /* set MPP to U */
    mstatus &= ~MSTATUS_MPP;
    priv = mpp;
    next_pc = mepc;
}

void raise_exception(uint32_t cause, uint32_t tval)
{
    int deleg;

    /* exit for Zephyr applications */
    if (cause == CAUSE_ILLEGAL_INSTRUCTION) {
        debug_out("raise_exception: illegal instruction 0x%x 0x%x\n", cause,
                  tval);
        machine_running = FALSE;
        return;
    }

    if (priv <= PRV_S) {
        /* delegate the exception to the supervisor priviledge */
        if (cause & CAUSE_INTERRUPT)
            deleg = (mideleg >> (cause & (XLEN - 1))) & 1;
        else
            deleg = (medeleg >> cause) & 1;
    } else {
        deleg = 0;
    }

    if (deleg) {
        scause = cause;
        sepc = pc;
        stval = tval;
        mstatus = (mstatus & ~MSTATUS_SPIE) |
                  (((mstatus >> priv) & 1) << MSTATUS_SPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_SPP) | (priv << MSTATUS_SPP_SHIFT);
        mstatus &= ~MSTATUS_SIE;
        priv = PRV_S;
        next_pc = stvec;
    } else {
        mcause = cause;
        mepc = pc;
        mtval = tval;
        mstatus = (mstatus & ~MSTATUS_MPIE) |
                  (((mstatus >> priv) & 1) << MSTATUS_MPIE_SHIFT);
        mstatus = (mstatus & ~MSTATUS_MPP) | (priv << MSTATUS_MPP_SHIFT);
        mstatus &= ~MSTATUS_MIE;
        priv = PRV_M;
        next_pc = mtvec;
    }
}

uint32_t get_pending_irq_mask()
{
    uint32_t pending_ints, enabled_ints;

    pending_ints = mip & mie;
    if (pending_ints == 0)
        return 0;

    enabled_ints = 0;
    switch (priv) {
    case PRV_M:
        if (mstatus & MSTATUS_MIE)
            enabled_ints = ~mideleg;
        break;
    case PRV_S:
        enabled_ints = ~mideleg;
        if (mstatus & MSTATUS_SIE)
            enabled_ints |= mideleg;
        break;
    default:
    case PRV_U:
        enabled_ints = -1;
        break;
    }
    return pending_ints & enabled_ints;
}

int raise_interrupt()
{
    uint32_t mask;
    int irq_num;

    mask = get_pending_irq_mask();
    if (mask == 0)
        return 0;
    irq_num = ctz32(mask);
    raise_exception(irq_num | CAUSE_INTERRUPT, 0);
    return -1;
}

/* read 32-bit instruction from memory by PC */

uint32_t get_insn32(uint32_t pc)
{
#ifdef DEBUG_EXTRA
    if (pc && pc < minmemr)
        minmemr = pc;
    if (pc + 3 > maxmemr)
        maxmemr = pc + 3;
#endif
    uint32_t ptr = pc - ram_start;
    if (ptr > RAM_SIZE)
        return 1;
    uint8_t *p = ram + ptr;
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

/* read 8-bit data from memory */

int target_read_u8(uint8_t *pval, uint32_t addr)
{
#ifdef DEBUG_EXTRA
    if ((addr >> 28) != 4 && addr < minmemr)
        minmemr = addr;
    if (addr > maxmemr)
        maxmemr = addr;
#endif
    addr -= ram_start;
    if (addr > RAM_SIZE) {
        *pval = 0;
        printf("illegal read 8, PC: 0x%08x, address: 0x%08x\n", pc,
               addr + ram_start);
        return 1;
    } else {
        uint8_t *p = ram + addr;
        *pval = p[0];
    }
    return 0;
}

/* read 16-bit data from memory */

int target_read_u16(uint16_t *pval, uint32_t addr)
{
#ifdef DEBUG_EXTRA
    if ((addr >> 28) != 4 && addr < minmemr)
        minmemr = addr;
    if (addr + 1 > maxmemr)
        maxmemr = addr + 1;
#endif
    if (addr & 1) {
        pending_exception = CAUSE_MISALIGNED_LOAD;
        pending_tval = addr;
        return 1;
    }
    addr -= ram_start;
    if (addr > RAM_SIZE) {
        *pval = 0;
        printf("illegal read 16, PC: 0x%08x, address: 0x%08x\n", pc,
               addr + ram_start);
        return 1;
    } else {
        uint8_t *p = ram + addr;
        *pval = p[0] | (p[1] << 8);
    }
    return 0;
}

/* read 32-bit data from memory */

int target_read_u32(uint32_t *pval, uint32_t addr)
{
#ifdef DEBUG_EXTRA
    if ((addr >> 28) != 4 && addr < minmemr)
        minmemr = addr;
    if (addr + 3 > maxmemr)
        maxmemr = addr + 3;
#endif
    if (addr & 3) {
        pending_exception = CAUSE_MISALIGNED_LOAD;
        pending_tval = addr;
        return 1;
    }
    if (addr == MTIMECMP_ADDR) {
        *pval = (uint32_t) mtimecmp;
    } else if (addr == MTIMECMP_ADDR + 4) {
        *pval = (uint32_t)(mtimecmp >> 32);
    } else if (addr == MTIME_ADDR) {
        *pval = (uint32_t) mtime;
    } else if (addr == MTIME_ADDR + 4) {
        *pval = (uint32_t)(mtime >> 32);
    } else {
        addr -= ram_start;
        if (addr > RAM_SIZE) {
            *pval = 0;
            printf("illegal read 32, PC: 0x%08x, address: 0x%08x\n", pc,
                   addr + ram_start);
            return 1;
        } else {
            uint8_t *p = ram + addr;
            *pval = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
        }
    }
    return 0;
}

/* write 8-bit data to memory */

int target_write_u8(uint32_t addr, uint8_t val)
{
#ifdef DEBUG_EXTRA
    if ((addr >> 28) != 4 && addr < minmemw)
        minmemw = addr;
    if (addr > maxmemw)
        maxmemw = addr;
#endif
    if (addr == UART_TX_ADDR) {
        /* test for UART output, compatible with QEMU */
        printf("%c", val);
    } else {
        addr -= ram_start;
        if (addr > RAM_SIZE - 1) {
            printf("illegal write 8, PC: 0x%08x, address: 0x%08x\n", pc,
                   addr + ram_start);
            return 1;
        } else {
            uint8_t *p = ram + addr;
            p[0] = val & 0xff;
        }
    }
    return 0;
}

/* write 16-bit data to memory */

int target_write_u16(uint32_t addr, uint16_t val)
{
#ifdef DEBUG_EXTRA
    if ((addr >> 28) != 4 && addr < minmemw)
        minmemw = addr;
    if (addr + 1 > maxmemw)
        maxmemw = addr + 1;
#endif
    if (addr & 1) {
        pending_exception = CAUSE_MISALIGNED_STORE;
        pending_tval = addr;
        return 1;
    }
    addr -= ram_start;
    if (addr > RAM_SIZE - 2) {
        printf("illegal write 16, PC: 0x%08x, address: 0x%08x\n", pc,
               addr + ram_start);
        return 1;
    } else {
        uint8_t *p = ram + addr;
        p[0] = val & 0xff;
        p[1] = (val >> 8) & 0xff;
    }
    return 0;
}

/* write 32-bit data to memory */

int target_write_u32(uint32_t addr, uint32_t val)
{
#ifdef DEBUG_EXTRA
    if ((addr >> 28) != 4 && addr < minmemw)
        minmemw = addr;
    if (addr + 3 > maxmemw)
        maxmemw = addr + 3;
#endif
    if (addr & 3) {
        pending_exception = CAUSE_MISALIGNED_STORE;
        pending_tval = addr;
        return 1;
    }
    if (addr == MTIMECMP_ADDR) {
        mtimecmp = (mtimecmp & 0xffffffff00000000ll) | val;
        mip &= ~MIP_MTIP;
    } else if (addr == MTIMECMP_ADDR + 4) {
        mtimecmp = (mtimecmp & 0xffffffffll) | (((uint64_t) val) << 32);
        mip &= ~MIP_MTIP;
    } else {
        addr -= ram_start;
        if (addr > RAM_SIZE - 4) {
            printf("illegal write 32, PC: 0x%08x, address: 0x%08x\n", pc,
                   addr + ram_start);
            return 1;
        } else {
            uint8_t *p = ram + addr;
            p[0] = val & 0xff;
            p[1] = (val >> 8) & 0xff;
            p[2] = (val >> 16) & 0xff;
            p[3] = (val >> 24) & 0xff;
        }
    }
    return 0;
}

#ifndef STRICT_RV32I

int32_t div32(int32_t a, int32_t b)
{
    if (b == 0) {
        return -1;
    } else if (a == ((int32_t) 1 << (XLEN - 1)) && b == -1) {
        return a;
    } else {
        return a / b;
    }
}

uint32_t divu32(uint32_t a, uint32_t b)
{
    if (b == 0) {
        return -1;
    }
    return a / b;
}

int32_t rem32(int32_t a, int32_t b)
{
    if (b == 0) {
        return a;
    } else if (a == ((int32_t) 1 << (XLEN - 1)) && b == -1) {
        return 0;
    }
    return a % b;
}

uint32_t remu32(uint32_t a, uint32_t b)
{
    if (b == 0) {
        return a;
    }
    return a % b;
}

static uint32_t mulh32(int32_t a, int32_t b)
{
    return ((int64_t) a * (int64_t) b) >> 32;
}

static uint32_t mulhsu32(int32_t a, uint32_t b)
{
    return ((int64_t) a * (int64_t) b) >> 32;
}

static uint32_t mulhu32(uint32_t a, uint32_t b)
{
    return ((int64_t) a * (int64_t) b) >> 32;
}

#endif

#ifdef DEBUG_EXTRA

/* dumps all registers, useful for in-depth debugging */

static void dump_regs()
{
    printf("\nRegisters:\n");
    printf("x0 zero: %08x\n", reg[0]);
    printf("x1 ra:   %08x\n", reg[1]);
    printf("x2 sp:   %08x\n", reg[2]);
    printf("x3 gp:   %08x\n", reg[3]);
    printf("x4 tp:   %08x\n", reg[4]);
    printf("x5 t0:   %08x\n", reg[5]);
    printf("x6 t1:   %08x\n", reg[6]);
    printf("x7 t2:   %08x\n", reg[7]);
    printf("x8 s0:   %08x\n", reg[8]);
    printf("x9 s1:   %08x\n", reg[9]);
    printf("x10 a0:  %08x\n", reg[10]);
    printf("x11 a1:  %08x\n", reg[11]);
    printf("x12 a2:  %08x\n", reg[12]);
    printf("x13 a3:  %08x\n", reg[13]);
    printf("x14 a4:  %08x\n", reg[14]);
    printf("x15 a5:  %08x\n", reg[15]);
    printf("x16 a6:  %08x\n", reg[16]);
    printf("x17 a7:  %08x\n", reg[17]);
    printf("x18 s2:  %08x\n", reg[18]);
    printf("x19 s3:  %08x\n", reg[19]);
    printf("x20 s4:  %08x\n", reg[20]);
    printf("x21 s5:  %08x\n", reg[21]);
    printf("x22 s6:  %08x\n", reg[22]);
    printf("x23 s7:  %08x\n", reg[23]);
    printf("x24 s8:  %08x\n", reg[24]);
    printf("x25 s9:  %08x\n", reg[25]);
    printf("x26 s10: %08x\n", reg[26]);
    printf("x27 s11: %08x\n", reg[27]);
    printf("x28 t3:  %08x\n", reg[28]);
    printf("x29 t4:  %08x\n", reg[29]);
    printf("x30 t5:  %08x\n", reg[30]);
    printf("x31 t6:  %08x\n", reg[31]);
}

#endif

void execute_instruction()
{
    uint32_t opcode, rd, rs1, rs2, funct3;
    int32_t imm, cond, err;
    uint32_t addr, val = 0, val2;

    opcode = insn & 0x7f;
    rd = (insn >> 7) & 0x1f;
    rs1 = (insn >> 15) & 0x1f;
    rs2 = (insn >> 20) & 0x1f;

    switch (opcode) {
    case 0x37: /* lui */

#ifdef DEBUG_EXTRA
        debug_out(">>> LUI\n");
        stats[0]++;
#endif
        if (rd != 0)
            reg[rd] = (int32_t)(insn & 0xfffff000);
        break;

    case 0x17: /* auipc */

#ifdef DEBUG_EXTRA
        debug_out(">>> AUIPC\n");
        stats[1]++;
#endif
        if (rd != 0)
            reg[rd] = (int32_t)(pc + (int32_t)(insn & 0xfffff000));
        break;

    case 0x6f: /* jal */

#ifdef DEBUG_EXTRA
        debug_out(">>> JAL\n");
        stats[2]++;
#endif
        imm = ((insn >> (31 - 20)) & (1 << 20)) | ((insn >> (21 - 1)) & 0x7fe) |
              ((insn >> (20 - 11)) & (1 << 11)) | (insn & 0xff000);
        imm = (imm << 11) >> 11;
        if (rd != 0)
            reg[rd] = pc + 4;
        next_pc = (int32_t)(pc + imm);
        if (next_pc > pc)
            forward_counter++;
        else
            backward_counter++;
        jump_counter++;
        break;

    case 0x67: /* jalr */

#ifdef DEBUG_EXTRA
        debug_out(">>> JALR\n");
        stats[3]++;
#endif
        imm = (int32_t) insn >> 20;
        val = pc + 4;
        next_pc = (int32_t)(reg[rs1] + imm) & ~1;
        if (rd != 0)
            reg[rd] = val;
        if (next_pc > pc)
            forward_counter++;
        else
            backward_counter++;
        jump_counter++;
        break;

    case 0x63: /* BRANCH */

        funct3 = (insn >> 12) & 7;
        switch (funct3 >> 1) {
        case 0: /* beq/bne */
#ifdef DEBUG_EXTRA
            if (!(funct3 & 1)) {
                debug_out(">>> BEQ\n");
                stats[4]++;
            } else {
                debug_out(">>> BNE\n");
                stats[5]++;
            }
#endif
            cond = (reg[rs1] == reg[rs2]);
            break;
        case 2: /* blt/bge */
#ifdef DEBUG_EXTRA
            if (!(funct3 & 1)) {
                debug_out(">>> BLT\n");
                stats[6]++;
            } else {
                debug_out(">>> BGE\n");
                stats[7]++;
            }
#endif
            cond = ((int32_t) reg[rs1] < (int32_t) reg[rs2]);
            break;
        case 3: /* bltu/bgeu */
#ifdef DEBUG_EXTRA
            if (!(funct3 & 1)) {
                debug_out(">>> BLTU\n");
                stats[8]++;
            } else {
                debug_out(">>> BGEU\n");
                stats[9]++;
            }
#endif
            cond = (reg[rs1] < reg[rs2]);
            break;
        default:
            raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
            return;
        }
        cond ^= (funct3 & 1);
        if (cond) {
            imm = ((insn >> (31 - 12)) & (1 << 12)) |
                  ((insn >> (25 - 5)) & 0x7e0) | ((insn >> (8 - 1)) & 0x1e) |
                  ((insn << (11 - 7)) & (1 << 11));
            imm = (imm << 19) >> 19;
            next_pc = (int32_t)(pc + imm);
            if (next_pc > pc)
                forward_counter++;
            else
                backward_counter++;
            jump_counter++;
            true_counter++;
            break;
        } else
            false_counter++;
        break;

    case 0x03: /* LOAD */

        funct3 = (insn >> 12) & 7;
        imm = (int32_t) insn >> 20;
        addr = reg[rs1] + imm;
        switch (funct3) {
        case 0: /* lb */
        {
#ifdef DEBUG_EXTRA
            debug_out(">>> LB\n");
            stats[10]++;
#endif
            uint8_t rval;
            if (target_read_u8(&rval, addr)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            val = (int8_t) rval;
        } break;

        case 1: /* lh */
        {
#ifdef DEBUG_EXTRA
            debug_out(">>> LH\n");
            stats[11]++;
#endif
            uint16_t rval;
            if (target_read_u16(&rval, addr)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            val = (int16_t) rval;
        } break;

        case 2: /* lw */
        {
#ifdef DEBUG_EXTRA
            debug_out(">>> LW\n");
            stats[12]++;
#endif
            uint32_t rval;
            if (target_read_u32(&rval, addr)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            val = (int32_t) rval;
        } break;

        case 4: /* lbu */
        {
#ifdef DEBUG_EXTRA
            debug_out(">>> LBU\n");
            stats[13]++;
#endif
            uint8_t rval;
            if (target_read_u8(&rval, addr)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            val = rval;
        } break;

        case 5: /* lhu */
        {
#ifdef DEBUG_EXTRA
            debug_out(">>> LHU\n");
            stats[14]++;
#endif
            uint16_t rval;
            if (target_read_u16(&rval, addr)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            val = rval;
        } break;

        default:
            raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
            return;
        }
        if (rd != 0)
            reg[rd] = val;
        break;

    case 0x23: /* STORE */

        funct3 = (insn >> 12) & 7;
        imm = rd | ((insn >> (25 - 5)) & 0xfe0);
        imm = (imm << 20) >> 20;
        addr = reg[rs1] + imm;
        val = reg[rs2];
        switch (funct3) {
        case 0: /* sb */
#ifdef DEBUG_EXTRA
            debug_out(">>> SB\n");
            stats[15]++;
#endif
            if (target_write_u8(addr, val)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            break;

        case 1: /* sh */
#ifdef DEBUG_EXTRA
            debug_out(">>> SH\n");
            stats[16]++;
#endif
            if (target_write_u16(addr, val)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            break;

        case 2: /* sw */
#ifdef DEBUG_EXTRA
            debug_out(">>> SW\n");
            stats[17]++;
#endif
            if (target_write_u32(addr, val)) {
                raise_exception(pending_exception, pending_tval);
                return;
            }
            break;

        default:
            raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
            return;
        }
        break;

    case 0x13: /* OP-IMM */

        funct3 = (insn >> 12) & 7;
        imm = (int32_t) insn >> 20;
        switch (funct3) {
        case 0: /* addi */
#ifdef DEBUG_EXTRA
            debug_out(">>> ADDI\n");
            stats[18]++;
            if (rs1 == 0)
                stats[47]++; /* li */
#endif
            val = (int32_t)(reg[rs1] + imm);
            break;
        case 1: /* slli */
#ifdef DEBUG_EXTRA
            debug_out(">>> SLLI\n");
            stats[24]++;
#endif
            if ((imm & ~(XLEN - 1)) != 0) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            val = (int32_t)(reg[rs1] << (imm & (XLEN - 1)));
            break;
        case 2: /* slti */
#ifdef DEBUG_EXTRA
            debug_out(">>> SLTI\n");
            stats[19]++;
#endif
            val = (int32_t) reg[rs1] < (int32_t) imm;
            break;
        case 3: /* sltiu */
#ifdef DEBUG_EXTRA
            debug_out(">>> SLTIU\n");
            stats[20]++;
#endif
            val = reg[rs1] < (uint32_t) imm;
            break;
        case 4: /* xori */
#ifdef DEBUG_EXTRA
            debug_out(">>> XORI\n");
            stats[21]++;
#endif
            val = reg[rs1] ^ imm;
            break;
        case 5: /* srli/srai */
            if ((imm & ~((XLEN - 1) | 0x400)) != 0) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            if (imm & 0x400) {
#ifdef DEBUG_EXTRA
                debug_out(">>> SRAI\n");
                stats[26]++;
#endif
                val = (int32_t) reg[rs1] >> (imm & (XLEN - 1));
            } else {
#ifdef DEBUG_EXTRA
                debug_out(">>> SRLI\n");
                stats[25]++;
#endif
                val = (int32_t)((uint32_t) reg[rs1] >> (imm & (XLEN - 1)));
            }
            break;
        case 6: /* ori */
#ifdef DEBUG_EXTRA
            debug_out(">>> ORI\n");
            stats[22]++;
#endif
            val = reg[rs1] | imm;
            break;
        case 7: /* andi */
#ifdef DEBUG_EXTRA
            debug_out(">>> ANDI\n");
            stats[23]++;
#endif
            val = reg[rs1] & imm;
            break;
        }
        if (rd != 0)
            reg[rd] = val;
        break;

    case 0x33: /* OP */

        imm = insn >> 25;
        val = reg[rs1];
        val2 = reg[rs2];
#ifndef STRICT_RV32I
        if (imm == 1) {
            funct3 = (insn >> 12) & 7;
            switch (funct3) {
            case 0: /* mul */
#ifdef DEBUG_EXTRA
                debug_out(">>> MUL\n");
                stats[48]++;
#endif
                val = (int32_t)((int32_t) val * (int32_t) val2);
                break;
            case 1: /* mulh */
#ifdef DEBUG_EXTRA
                debug_out(">>> MULH\n");
                stats[49]++;
#endif
                val = (int32_t) mulh32(val, val2);
                break;
            case 2: /* mulhsu */
#ifdef DEBUG_EXTRA
                debug_out(">>> MULHSU\n");
                stats[50]++;
#endif
                val = (int32_t) mulhsu32(val, val2);
                break;
            case 3: /* mulhu */
#ifdef DEBUG_EXTRA
                debug_out(">>> MULHU\n");
                stats[51]++;
#endif
                val = (int32_t) mulhu32(val, val2);
                break;
            case 4: /* div */
#ifdef DEBUG_EXTRA
                debug_out(">>> DIV\n");
                stats[52]++;
#endif
                val = div32(val, val2);
                break;
            case 5: /* divu */
#ifdef DEBUG_EXTRA
                debug_out(">>> DIVU\n");
                stats[53]++;
#endif
                val = (int32_t) divu32(val, val2);
                break;
            case 6: /* rem */
#ifdef DEBUG_EXTRA
                debug_out(">>> REM\n");
                stats[54]++;
#endif
                val = rem32(val, val2);
                break;
            case 7: /* remu */
#ifdef DEBUG_EXTRA
                debug_out(">>> REMU\n");
                stats[55]++;
#endif
                val = (int32_t) remu32(val, val2);
                break;
            default:
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
        } else
#endif
        {
            if (imm & ~0x20) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
            switch (funct3) {
            case 0: /* add */
#ifdef DEBUG_EXTRA
                debug_out(">>> ADD\n");
                stats[27]++;
#endif
                val = (int32_t)(val + val2);
                break;
            case 0 | 8: /* sub */
#ifdef DEBUG_EXTRA
                debug_out(">>> SUB\n");
                stats[28]++;
#endif
                val = (int32_t)(val - val2);
                break;
            case 1: /* sll */
#ifdef DEBUG_EXTRA
                debug_out(">>> SLL\n");
                stats[29]++;
#endif
                val = (int32_t)(val << (val2 & (XLEN - 1)));
                break;
            case 2: /* slt */
#ifdef DEBUG_EXTRA
                debug_out(">>> SLT\n");
                stats[30]++;
#endif
                val = (int32_t) val < (int32_t) val2;
                break;
            case 3: /* sltu */
#ifdef DEBUG_EXTRA
                debug_out(">>> SLTU\n");
                stats[31]++;
#endif
                val = val < val2;
                break;
            case 4: /* xor */
#ifdef DEBUG_EXTRA
                debug_out(">>> XOR\n");
                stats[32]++;
#endif
                val = val ^ val2;
                break;
            case 5: /* srl */
#ifdef DEBUG_EXTRA
                debug_out(">>> SRL\n");
                stats[33]++;
#endif
                val = (int32_t)((uint32_t) val >> (val2 & (XLEN - 1)));
                break;
            case 5 | 8: /* sra */
#ifdef DEBUG_EXTRA
                debug_out(">>> SRA\n");
                stats[34]++;
#endif
                val = (int32_t) val >> (val2 & (XLEN - 1));
                break;
            case 6: /* or */
#ifdef DEBUG_EXTRA
                debug_out(">>> OR\n");
                stats[35]++;
#endif
                val = val | val2;
                break;
            case 7: /* and */
#ifdef DEBUG_EXTRA
                debug_out(">>> AND\n");
                stats[36]++;
#endif
                val = val & val2;
                break;
            default:
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
        }
        if (rd != 0)
            reg[rd] = val;
        break;

    case 0x73: /* SYSTEM */

        funct3 = (insn >> 12) & 7;
        imm = insn >> 20;
        if (funct3 & 4)
            val = rs1;
        else
            val = reg[rs1];
        funct3 &= 3;
        switch (funct3) {
        case 1: /* csrrw & csrrwi */
#ifdef DEBUG_EXTRA
            if ((insn >> 12) & 4) {
                debug_out(">>> CSRRWI\n");
                stats[44]++;
            } else {
                debug_out(">>> CSRRW\n");
                stats[41]++;
            }
#endif
            if (csr_read(&val2, imm, TRUE)) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            val2 = (int32_t) val2;
            err = csr_write(imm, val);
            if (err < 0) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            if (rd != 0)
                reg[rd] = val2;
            if (err > 0) {
                /* pc = pc + 4; */
            }
            break;

        case 2: /* csrrs & csrrsi */
        case 3: /* csrrc & csrrci */
            if (csr_read(&val2, imm, (rs1 != 0))) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            val2 = (int32_t) val2;
#ifdef DEBUG_EXTRA
            switch ((insn >> 12) & 7) {
            case 2:
                debug_out(">>> CSRRS\n");
                stats[42]++;
                break;
            case 3:
                debug_out(">>> CSRRC\n");
                stats[43]++;
                break;
            case 6:
                debug_out(">>> CSRRSI\n");
                stats[45]++;
                break;
            case 7:
                debug_out(">>> CSRRCI\n");
                stats[46]++;
                break;
            }
#endif
            if (rs1 != 0) {
                if (funct3 == 2) {
                    val = val2 | val;
                } else {
                    val = val2 & ~val;
                }
                err = csr_write(imm, val);
                if (err < 0) {
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
            } else {
                err = 0;
            }
            if (rd != 0)
                reg[rd] = val2;
            break;

        case 0:
            switch (imm) {
            case 0x000: /* ecall */
#ifdef DEBUG_EXTRA
                debug_out(">>> ECALL\n");
                stats[39]++;
#endif
                if (insn & 0x000fff80) {
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
                /*
                 * compliance test specific: if bit 0 of gp (x3) is 0, it is a
                 * syscall, otherwise it is the program end, with the exit code
                 * in the bits 31:1
                 */
                if (begin_signature) {
                    if (reg[3] & 1) {
                        debug_out("program end, result: %04x\n", reg[3] >> 1);
                        machine_running = FALSE;
                        return;

                    } else {
                        debug_out("syscall: %04x\n", reg[3]);
                        raise_exception(CAUSE_USER_ECALL + priv, 0);
                    }
                } else {
                    /* on real hardware, an exception is raised, the I-ECALL-01
                     * compliance test tests this as well */
                    raise_exception(CAUSE_USER_ECALL + priv, 0);
                    return;
                }
                break;

            case 0x001: /* ebreak */
#ifdef DEBUG_EXTRA
                debug_out(">>> EBREAK\n");
                stats[40]++;
#endif
                if (insn & 0x000fff80) {
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
                raise_exception(CAUSE_BREAKPOINT, 0);
                return;

            case 0x102: /* sret */
            {
#ifdef DEBUG_EXTRA
                debug_out(">>> SRET\n");
                stats[59]++;
#endif
                if ((insn & 0x000fff80) || (priv < PRV_S)) {
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
                handle_sret();
                return;
            } break;

            case 0x105: /* wfi */
#ifdef DEBUG_EXTRA
                debug_out(">>> WFI\n");
                stats[61]++;
#endif
                /* wait for interrupt: it is allowed to execute it as nop */
                break;

            case 0x302: /* mret */
            {
#ifdef DEBUG_EXTRA
                debug_out(">>> MRET\n");
                stats[60]++;
#endif
                if ((insn & 0x000fff80) || (priv < PRV_M)) {
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
                handle_mret();
                return;
            } break;

            default:
                if ((imm >> 5) == 0x09) {
#ifdef DEBUG_EXTRA
                    debug_out(">>> SFENCE.VMA\n");
                    stats[62]++;
#endif
                    /* sfence.vma */
                    if ((insn & 0x00007f80) || (priv == PRV_U)) {
                        raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                        return;
                    }
                } else {
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
                break;
            }
            break;

        default:
            raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
            return;
        }
        break;

    case 0x0f: /* MISC-MEM */

        funct3 = (insn >> 12) & 7;
        switch (funct3) {
        case 0: /* fence */
#ifdef DEBUG_EXTRA
            debug_out(">>> FENCE\n");
            stats[37]++;
#endif
            if (insn & 0xf00fff80) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            break;

        case 1: /* fence.i */
#ifdef DEBUG_EXTRA
            debug_out(">>> FENCE.I\n");
            stats[38]++;
#endif
            if (insn != 0x0000100f) {
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
            break;

        default:
            raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
            return;
        }
        break;

#ifndef STRICT_RV32I

    case 0x2f: /* AMO */

        funct3 = (insn >> 12) & 7;
        switch (funct3) {
        case 2: {
            uint32_t rval;

            addr = reg[rs1];
            funct3 = insn >> 27;
            switch (funct3) {
            case 2: /* lr.w */
#ifdef DEBUG_EXTRA
                debug_out(">>> LR.W\n");
                stats[56]++;
#endif
                if (rs2 != 0) {
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
                if (target_read_u32(&rval, addr)) {
                    raise_exception(pending_exception, pending_tval);
                    return;
                }
                val = (int32_t) rval;
                load_res = addr;
                break;

            case 3: /* sc.w */
#ifdef DEBUG_EXTRA
                debug_out(">>> SC.W\n");
                stats[57]++;
#endif
                if (load_res == addr) {
                    if (target_write_u32(addr, reg[rs2])) {
                        raise_exception(pending_exception, pending_tval);
                        return;
                    }
                    val = 0;
                } else {
                    val = 1;
                }
                break;

            case 1:    /* amiswap.w */
            case 0:    /* amoadd.w */
            case 4:    /* amoxor.w */
            case 0xc:  /* amoand.w */
            case 0x8:  /* amoor.w */
            case 0x10: /* amomin.w */
            case 0x14: /* amomax.w */
            case 0x18: /* amominu.w */
            case 0x1c: /* amomaxu.w */

#ifdef DEBUG_EXTRA
                debug_out(">>> AM...\n");
                stats[63]++;
#endif
                if (target_read_u32(&rval, addr)) {
                    raise_exception(pending_exception, pending_tval);
                    return;
                }
                val = (int32_t) rval;
                val2 = reg[rs2];
                switch (funct3) {
                case 1: /* amiswap.w */
                    break;
                case 0: /* amoadd.w */
                    val2 = (int32_t)(val + val2);
                    break;
                case 4: /* amoxor.w */
                    val2 = (int32_t)(val ^ val2);
                    break;
                case 0xc: /* amoand.w */
                    val2 = (int32_t)(val & val2);
                    break;
                case 0x8: /* amoor.w */
                    val2 = (int32_t)(val | val2);
                    break;
                case 0x10: /* amomin.w */
                    if ((int32_t) val < (int32_t) val2)
                        val2 = (int32_t) val;
                    break;
                case 0x14: /* amomax.w */
                    if ((int32_t) val > (int32_t) val2)
                        val2 = (int32_t) val;
                    break;
                case 0x18: /* amominu.w */
                    if ((uint32_t) val < (uint32_t) val2)
                        val2 = (int32_t) val;
                    break;
                case 0x1c: /* amomaxu.w */
                    if ((uint32_t) val > (uint32_t) val2)
                        val2 = (int32_t) val;
                    break;
                default:
                    raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                    return;
                }
                if (target_write_u32(addr, val2)) {
                    raise_exception(pending_exception, pending_tval);
                    return;
                }
                break;
            default:
                raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
                return;
            }
        } break;
        default:
            raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
            return;
        }
        if (rd != 0)
            reg[rd] = val;
        break;

#endif

    default:
        raise_exception(CAUSE_ILLEGAL_INSTRUCTION, insn);
        return;
    }
}

/* returns realtime in nanoseconds */
int64_t get_clock()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}


void riscv_cpu_interp_x32()
{
    /* we use a single execution loop to keep a simple control flow for
     * emscripten */
    while (machine_running) {
#if 1
        /* update timer, assuming 10 MHz clock (100 ns period) for the mtime
         * counter */
        mtime = get_clock() / 100ll;

        /* for reproducible debug runs, you can use a fixed fixed increment per
         * instruction */
#else
        mtime += 10;
#endif
        /* default value for next PC is next instruction, can be changed by
         * branches or exceptions */
        next_pc = pc + 4;

        /* test for timer interrupt */
        if (mtimecmp <= mtime) {
            mip |= MIP_MTIP;
        }
        if ((mip & mie) != 0 && (mstatus & MSTATUS_MIE)) {
            raise_interrupt();
        } else {
            /* normal instruction execution */
            insn = get_insn32(pc);
            insn_counter++;

            debug_out("[%08x]=%08x, mtime: %lx, mtimecmp: %lx\n", pc, insn,
                      mtime, mtimecmp);
            execute_instruction();
        }

        /* test for misaligned fetches */
        if (next_pc & 3) {
            raise_exception(CAUSE_MISALIGNED_FETCH, next_pc);
        }

        /* update current PC */
        pc = next_pc;
    }

    debug_out("done interp %lx int=%x mstatus=%lx prv=%d\n",
              (uint64_t) insn_counter, mip & mie, (uint64_t) mstatus, priv);
}

int main(int argc, char **argv)
{
#ifdef DEBUG_OUTPUT
    FILE *fo;
    char *po, hex_file[100];
#endif

    /* automatic STDOUT flushing, no fflush needed */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* parse command line */
    const char *elf_file = NULL;
    const char *signature_file = NULL;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (arg == strstr(arg, "+signature=")) {
            signature_file = arg + 11;
        } else if (arg[0] != '-') {
            elf_file = arg;
        }
    }
    if (elf_file == NULL) {
        printf("missing ELF file\n");
        return 1;
    }

    for (uint32_t u = 0; u < RAM_SIZE; u++)
        ram[u] = 0;


#ifdef DEBUG_EXTRA
    init_stats();
#endif


    /* open ELF file */
    elf_version(EV_CURRENT);
    int fd = open(elf_file, O_RDONLY);
    if (fd == -1) {
        printf("can't open file %s\n", elf_file);
        return 1;
    }
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);

    /* scan for symbol table */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == SHT_SYMTAB) {
            Elf_Data *data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < count; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (strcmp(name, "begin_signature") == 0) {
                    begin_signature = sym.st_value;
                }
                if (strcmp(name, "end_signature") == 0) {
                    end_signature = sym.st_value;
                }

                /* for compliance test */
                if (strcmp(name, "_start") == 0) {
                    start = sym.st_value;
                }

                /* for zephyr */
                if (strcmp(name, "__reset") == 0) {
                    start = sym.st_value;
                }
                if (strcmp(name, "__irq_wrapper") == 0) {
                    mtvec = sym.st_value;
                }
            }
        }
    }

    /* set .text section as the base address */
    scn = NULL;
    size_t shstrndx;
    elf_getshdrstrndx(elf, &shstrndx);
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);

        if (shdr.sh_type == SHT_PROGBITS) {
            if (strcmp(name, ".text") == 0) {
                ram_start = shdr.sh_addr;
                break;
            }
        }
    }

    debug_out("begin_signature: 0x%08x\n", begin_signature);
    debug_out("end_signature: 0x%08x\n", end_signature);
    debug_out("ram_start: 0x%08x\n", ram_start);
    debug_out("entry point: 0x%08x\n", start);

    /* scan for program */
    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);

        /* filter NULL address sections and .bss */
        if (shdr.sh_addr && shdr.sh_type != SHT_NOBITS) {
            Elf_Data *data = elf_getdata(scn, NULL);
            if (shdr.sh_addr >= ram_start) {
                for (size_t i = 0; i < shdr.sh_size; i++) {
                    ram_curr = shdr.sh_addr + i - ram_start;
                    if (ram_curr >= RAM_SIZE) {
                        debug_out(
                            "memory pointer outside of range 0x%08x (section "
                            "at address 0x%08x)\n",
                            ram_curr, (uint32_t) shdr.sh_addr);
                        /* break; */
                    } else {
                        ram[ram_curr] = ((uint8_t *) data->d_buf)[i];
                        if (ram_curr > ram_last)
                            ram_last = ram_curr;
                    }
                }
            } else {
                debug_out("ignoring section at address 0x%08x\n",
                          (uint32_t) shdr.sh_addr);
            }
        }
    }

    /* close ELF file */
    elf_end(elf);
    close(fd);

#ifdef DEBUG_OUTPUT
    printf("codesize: 0x%08x (%i)\n", ram_last + 1, ram_last + 1);
    strcpy(hex_file, elf_file);
    po = strrchr(hex_file, '.');
    if (po != NULL)
        *po = 0;
    strcat(hex_file, ".mem");
    fo = fopen(hex_file, "wt");
    if (fo != NULL) {
        for (uint32_t u = 0; u <= ram_last; u++) {
            fprintf(fo, "%02X ", ram[u]);
            if ((u & 15) == 15)
                fprintf(fo, "\n");
        }
        fprintf(fo, "\n");
        fclose(fo);
    }
#if 1
    fo = fopen("rom.v", "wt");
    if (fo != NULL) {
        fprintf(fo, "module rom(addr,data);\n");
        uint32_t romsz = (ram_start & 0xFFFF) + ram_last + 1;
        printf("codesize with offset: %i\n", romsz);
        if (romsz >= 32768)
            fprintf(fo, "input [15:0] addr;\n");
        else if (romsz >= 16384)
            fprintf(fo, "input [14:0] addr;\n");
        else if (romsz >= 8192)
            fprintf(fo, "input [13:0] addr;\n");
        else if (romsz >= 4096)
            fprintf(fo, "input [12:0] addr;\n");
        else if (romsz >= 2048)
            fprintf(fo, "input [11:0] addr;\n");
        else if (romsz >= 1024)
            fprintf(fo, "input [10:0] addr;\n");
        else if (romsz >= 512)
            fprintf(fo, "input [9:0] addr;\n");
        else if (romsz >= 256)
            fprintf(fo, "input [8:0] addr;\n");
        else
            fprintf(fo, "input [7:0] addr;\n");
        fprintf(fo,
                "output reg [7:0] data;\nalways @(addr) begin\n case(addr)\n");
        for (uint32_t u = 0; u <= ram_last; u++) {
            fprintf(fo, " %i : data = 8'h%02X;\n", (ram_start & 0xFFFF) + u,
                    ram[u]);
        }
        fprintf(fo,
                " default: data = 8'h01; // invalid instruction\n "
                "endcase\nend\nendmodule\n");
        fclose(fo);
    }
#endif
#endif

    uint64_t ns1 = get_clock();

    /* run program in emulator */
    pc = start;
    reg[2] = ram_start + RAM_SIZE;
    riscv_cpu_interp_x32();

    uint64_t ns2 = get_clock();

    /* write signature */
    if (signature_file) {
        FILE *sf = fopen(signature_file, "w");
        int size = end_signature - begin_signature;
        for (int i = 0; i < size / 16; i++) {
            for (int j = 0; j < 16; j++) {
                fprintf(sf, "%02x", ram[begin_signature + 15 - j - ram_start]);
            }
            begin_signature += 16;
            fprintf(sf, "\n");
        }
        fclose(sf);
    }

#ifdef DEBUG_EXTRA
    dump_regs();
    print_stats(insn_counter);
#endif

#if 1
    printf("\n");
    printf(">>> Execution time: %llu ns\n", (long long unsigned) ns2 - ns1);
    printf(">>> Instruction count: %llu (IPS=%llu)\n",
           (long long unsigned) insn_counter,
           (long long) insn_counter * 1000000000LL / (ns2 - ns1));
    printf(">>> Jumps: %llu (%2.2lf%%) - %llu forwards, %llu backwards\n",
           (long long unsigned) jump_counter,
           jump_counter * 100.0 / insn_counter,
           (long long unsigned) forward_counter,
           (long long unsigned) backward_counter);
    printf(">>> Branching T=%llu (%2.2lf%%) F=%llu (%2.2lf%%)\n",
           (long long unsigned) true_counter,
           true_counter * 100.0 / (true_counter + false_counter),
           (long long unsigned) false_counter,
           false_counter * 100.0 / (true_counter + false_counter));
    printf("\n");
#endif
    return 0;
}
