#include <stdio.h>
#include <cstring>
#include "cpu.h"
#include "memory.h"
#include "common.h"

core_t cores[NUM_CORES];
uint64_t ACTIVE_CORE;
uint8_t pm[PHYSICAL_MEMORY_SPACE];

/*==================================*/
/*          registers               */
/*==================================*/

// data structures
typedef enum INST_OPERATOR {
    INST_MOV,
    INST_PUSH,
    INST_POP,
    INST_LEAVE,
    INST_CALL,
    INST_RET,
    INST_ADD,
    INST_SUB,
    INST_CMP,
    INST_JNE,
    INST_JMP,
} op_t;

typedef enum OPERAND_TYPE {
    EMPTY,
    IMM,
    REG,
    MEM_IMM,
    MEM_REG1,
    MEM_IMM_REG1,
    MEM_REG1_REG2,
    MEM_IMM_REG1_REG2,
    MEM_REG2_SCAL,
    MEM_IMM_REG2_SCAL,
    MEM_REG1_REG2_SCAL,
    MEM_IMM_REG1_REG2_SCAL,
} od_type_t;

typedef struct OPERAND_STRUCT {
    od_type_t   type;   // IMM, REG, MEM
    int64_t     imm;    // immediate number
    uint64_t    scal;   // scale number to register 2
    uint64_t    reg1;   // main register
    uint64_t    reg2;   // minor register
} od_t;

typedef struct INST_STRUCT {
    op_t    op;
    od_t    src;
    od_t    dst;
} inst_t;

/*==================================*/
/*    parse assembly instruction    */
/*==================================*/

// functions to map the string assembly code to inst_t instance
static void parse_instruction(const char *str, inst_t *inst, core_t *cr);
static void parse_operand(const char *str, od_t *od, core_t *cr);
static uint64_t decode_operand(od_t *od);

// interpret the operand
static uint64_t decode_operand(od_t *od) {
    // access memory: return the virtual address
    uint64_t vaddr = 0;

    switch (od->type) {
    case IMM:
        // immediate signed number can be negative: convert to bitmap
        vaddr = (uint64_t)&od->imm;
        break;
    case REG:
        // default main register
        vaddr = (uint64_t)&od->reg1;
        break;
    case EMPTY:
        break;
    case MEM_IMM:
        vaddr = od->imm;
        break;
    case MEM_REG1:
        vaddr = *(uint64_t *)od->reg1;
        break;
    case MEM_IMM_REG1:
        vaddr = od->imm + *(uint64_t *)od->reg1;
        break;
    case MEM_REG1_REG2:
        vaddr = *(uint64_t *)od->reg1 + *(uint64_t *)od->reg2;
        break;
    case MEM_IMM_REG1_REG2:
        vaddr = od->imm + *(uint64_t *)od->reg1 + *(uint64_t *)od->reg2;
        break;
    case MEM_REG2_SCAL:
        vaddr = *(uint64_t *)od->reg2 * od->scal;
        break;
    case MEM_IMM_REG2_SCAL:
        vaddr = od->imm + *(uint64_t *)od->reg2 * od->scal;
    case MEM_REG1_REG2_SCAL:
        vaddr = *(uint64_t *)od->reg1 + *(uint64_t *)od->reg2 * od->scal;
        break;
    case MEM_IMM_REG1_REG2_SCAL:
        vaddr = od->imm + *(uint64_t *)od->reg1 + *(uint64_t *)od->reg2 * od->scal;
        break;
    default:
        break;
    }

    return vaddr;
}

static void parse_instruction(const char *str, inst_t *inst, core_t *cr) {

}

static void parse_operand(const char *str, od_t *od, core_t *cr) {
    // str: assembly code string, e.g. mov %rsp,%rbp
    // od: pointer to the address to store the parsed operand
    // cr: active core the processor
    od->type = EMPTY;
    od->imm = 0;
    od->reg1 = 0;
    od->reg2 = 0;
    od->scal = 0;

    int str_len = strlen(str);
    if (str_len == 0) {
        return;
    }

    if (str[0] == '$') {
        // immediate operand
        od->type = IMM;
        // try to parse the immediate number
        od->imm = string2uint(str, 1, -1);
    } else if (str[0] == '%') {
        // register

    } else {
        // memory access
    }

}

/*==================================*/
/*      instruction handlers        */
/*==================================*/

// insturction (sub)set
// In this simulator, the instructions have been decoded and fetched
// so there will be no page fault during fetching
// otherwise the instructions must handle the page fault (swap in from disk) first
// and then re-fetch the instruction and do decoding
// and finally re-run the instruction

static void mov_handler         (od_t *src_od, od_t *dst_od, core_t *cr);
static void push_handler        (od_t *src_od, od_t *dst_od, core_t *cr);
static void pop_handler         (od_t *src_od, od_t *dst_od, core_t *cr);
static void leave_handler       (od_t *src_od, od_t *dst_od, core_t *cr);
static void call_handler        (od_t *src_od, od_t *dst_od, core_t *cr);
static void ret_handler         (od_t *src_od, od_t *dst_od, core_t *cr);
static void add_handler         (od_t *src_od, od_t *dst_od, core_t *cr);
static void sub_handler         (od_t *src_od, od_t *dst_od, core_t *cr);
static void cmp_handler         (od_t *src_od, od_t *dst_od, core_t *cr);
static void jne_handler         (od_t *src_od, od_t *dst_od, core_t *cr);
static void jmp_handler         (od_t *src_od, od_t *dst_od, core_t *cr);

// handler table storing the handlers to different instruction types
// pointer to function
typedef void (*handler_t)(od_t *, od_t *, core_t *);
static handler_t handler_table[] = {
    mov_handler,
    push_handler,
    pop_handler,
    leave_handler,
    call_handler,
    ret_handler,
    add_handler,
    sub_handler,
    cmp_handler,
    jne_handler,
    jmp_handler,
};

// reset the condition flags
// inline to reduce cost
static inline void reset_cflags(core_t *cr) {
    cr->CF = 0;
    cr->ZF = 0;
    cr->SF = 0;
    cr->OF = 0;
}

// update the rip pointer to the next instruction sequentially
static inline void next_rip(core_t *cr) {
    // we are handling the fixed-length of assembly string here
    // but their size can be variable as true X86 instructions
    // that's because the operands' sizes follow the specific encoding rule
    // the risc-v is a fixed length ISA
    cr->rip = cr->rip + sizeof(char) * MAX_INSTRUCTION_CHAR;
}

// instruction handlers
static void mov_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);
    uint64_t dst = decode_operand(dst_od);

    if (src_od->type == REG && dst_od->type == REG) {
        // src: register
        // dst: register
        *(uint64_t *)dst = *(uint64_t *)src;
    } else if (src_od->type == REG && dst_od->type >= MEM_IMM) {
        // src: register
        // dst: virtual address
        write64bits_dram(va2pa(dst, cr), *(uint64_t *)src, cr);
    } else if (src_od->type >= MEM_IMM && dst_od->type == REG) {
        // src: virtual address
        // dst: register
        *(uint64_t *)dst = read64bits_dram(va2pa(src, cr), cr);
    } else if (src_od->type == IMM && dst_od->type == REG) {
        // src: immediate number (uint64_t bit map)
        // dst: register
        *(uint64_t *)dst = *(uint64_t *)src;
    }

    next_rip(cr);
    reset_cflags(cr);
}

static void push_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    if (src_od->type == REG) {
        // src: register
        // dst: empty
        (cr->reg).rsp -= 8;
        write64bits_dram(va2pa((cr->reg).rsp, cr), *(uint64_t *)src, cr);
        next_rip(cr);
        reset_cflags(cr);
    }
}

static void pop_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    if (src_od->type == REG) {
        // src: register
        // dst: empty
        *(uint64_t *)src = read64bits_dram(va2pa((cr->reg).rsp, cr), cr);
        next_rip(cr);
        reset_cflags(cr);
    }
}

static void leave_handler(od_t *src_od, od_t *dst_od, core_t *cr) {

}

static void call_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    // src: immediate number: virtual address of target function starting
    // dst: empty
    next_rip(cr);
    (cr->reg).rsp -= 8;
    write64bits_dram(va2pa((cr->reg).rsp, cr), cr->rip, cr);
    cr->rip = *(uint64_t *)src;
    reset_cflags(cr);
}

static void ret_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    // src: empty
    // dst: empty
    cr->rip = read64bits_dram(va2pa((cr->reg).rsp, cr), cr);
    (cr->reg).rsp += 8;
    reset_cflags(cr);
}

static void add_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);
    uint64_t dst = decode_operand(dst_od);

    if (src_od->type == REG && dst_od->type == REG) {
        // src: register
        // dst: register
        *(uint64_t *)src += *(uint64_t *)dst;

        // set condition flags

        next_rip(cr);
    }
}

static void sub_handler(od_t *src_od, od_t *dst_od, core_t *cr) {

}

static void cmp_handler(od_t *src_od, od_t *dst_od, core_t *cr) {

}

static void jne_handler(od_t *src_od, od_t *dst_od, core_t *cr) {

}

static void jmp_handler(od_t *src_od, od_t *dst_od, core_t *cr) {

}


// instruction cycle is implemented in CPU
void instruction_cycle(core_t *cr) {
    const char *inst_str = (const char *)cr->rip;

    // DECODE: decode the run-time instruction operands
    inst_t inst;
    printf("\t%s\n", inst_str);
    parse_instruction(inst_str, &inst, cr);

    // EXECUTE: get the function pointer or handler by the operator
    handler_t handler = handler_table[inst.op];
    // update CPU and memory according the instruction
    handler(&(inst.src), &(inst.dst), cr);
}

void print_register(core_t *cr) {
    printf("rax = %16lx\trbx = %16lx\nrcx = %16lx\trdx = %16lx\n",
        (cr->reg).rax, (cr->reg).rbx, (cr->reg).rcx, (cr->reg).rdx);
    printf("rsi = %16lx\trdi = %16lx\nrbp = %16lx\trsp = %16lx\n",
        (cr->reg).rsi, (cr->reg).rdi, (cr->reg).rbp, (cr->reg).rsp);
    printf("rip = %16lx\n", cr->rip);
}

void print_stack(core_t *cr) {
    int n = 10;

    uint64_t *low = (uint64_t *)&pm[va2pa((cr->reg).rsp, cr)];
    uint64_t *high = (uint64_t *)&pm[va2pa((cr->reg).rbp, cr)];
    uint64_t *origHigh = high, *origLow = low;

    uint64_t rspStart = (cr->reg).rbp;

    while (low <= high) {
        printf("0x%016lx : %16lx", rspStart, (uint64_t)*high);

        if (high == origHigh) {
            printf(" <=== rbp");
        } else if (high == origLow) {
            printf (" <=== rsp");
        }
        --high;
        rspStart -= 8;

        printf("\n");
    }
}