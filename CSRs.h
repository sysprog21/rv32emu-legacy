#include <stdint.h>


// ====================================================== //
// =================== User Trap Setup ================== //
// ====================================================== //
uint32_t ustatus; /* User status register  */
uint32_t uie;     /* User interrupt-enable register */
uint32_t utvec;   /* User trap handler base address */
// ====================================================== //
// ================= User Trap Handling ================= //
// ====================================================== //
uint32_t uscratch; /* Scratch register for user trap handlers*/
uint32_t uepc;     /* User exception program counter */
uint32_t ucause;   /* User trap cause*/
uint32_t ubadaddr; /* User bad address */
uint32_t uip;      /* User interrupt pending */
// ====================================================== //
// ============== User Floating-Point CSRs ============== //
// ====================================================== //
uint32_t fflags; /* Floating-Point Accrued Exceptions*/
uint32_t frm;    /* Floating-Point Dynamic Rounding Mode*/
