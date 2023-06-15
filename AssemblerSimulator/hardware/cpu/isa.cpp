#include <stdio.h>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include "cpu.h"
#include "memory.h"
#include "common.h"

#define MAX_INSTRUCTION_EXE 64

core_t cores[NUM_CORES];
uint64_t ACTIVE_CORE;
uint8_t pm[PHYSICAL_MEMORY_SPACE];

/*==================================*/
/*           instruction            */
/*==================================*/

// data structures
enum op_t {
    INST_MOV,           // 0
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
};

enum od_type_t {
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
};

struct od_t {
    od_type_t   type;   // IMM, REG, MEM
    uint64_t     imm;   // immediate number
    uint64_t    scal;   // scale number to register 2
    // reg1, reg2 is the address of cr.reg.xxx
    uint64_t    reg1;   // main register
    uint64_t    reg2;   // minor register
};

struct inst_t {
    op_t    op;
    od_t    src;
    od_t    dst;
};

/*==================================*/
/*    parse assembly instruction    */
/*==================================*/

// functions to map the string assembly code to inst_t instance
static void parse_instruction(const char *str, inst_t *inst, core_t *cr);
static void parse_operand(const char *str, od_t *od, core_t *cr);
static uint64_t decode_operand(od_t *od);

// interpret the operand
static uint64_t decode_operand(od_t *od) {
    if (od->type == EMPTY) {
        return 0;
    } else if (od->type == IMM) {
        // immediate signed number can be negative: convert to bitmap
        return od->imm;
    } else if (od->type == REG) {
        // default main register
        return od->reg1;
    } else {
        // access memory: return the virtual address
        uint64_t vaddr = 0;

        switch (od->type) {
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
}

// Key-value pair mapping template
template<typename T1, typename T2>
struct map_t {
    T1 key;
    T2 value;
};

static uint64_t reflect_register(const char *str, core_t *cr) {
    reg_t *reg = &cr->reg;
    // lookup map for the address of register
    map_t<const char *, uint64_t> reg_addr[] = {
        {"%rax", (uint64_t)&reg->rax},
        {"%eax", (uint64_t)&reg->eax},
        {"%ax",  (uint64_t)&reg->ax},
        {"%ah",  (uint64_t)&reg->ah},
        {"%al",  (uint64_t)&reg->al},

        {"%rbx", (uint64_t)&reg->rbx},
        {"%ebx", (uint64_t)&reg->ebx},
        {"%bx",  (uint64_t)&reg->bx},
        {"%bh",  (uint64_t)&reg->bh},
        {"%bl",  (uint64_t)&reg->bl},

        {"%rcx", (uint64_t)&reg->rcx},
        {"%ecx", (uint64_t)&reg->ecx},
        {"%cx",  (uint64_t)&reg->cx},
        {"%ch",  (uint64_t)&reg->ch},
        {"%cl",  (uint64_t)&reg->cl},

        {"%rdx", (uint64_t)&reg->rdx},
        {"%edx", (uint64_t)&reg->edx},
        {"%dx",  (uint64_t)&reg->dx},
        {"%dh",  (uint64_t)&reg->dh},
        {"%dl",  (uint64_t)&reg->dl},

        {"%rsi", (uint64_t)&reg->rsi},
        {"%esi", (uint64_t)&reg->esi},
        {"%si",  (uint64_t)&reg->si},
        {"%sih", (uint64_t)&reg->sih},
        {"%sil", (uint64_t)&reg->sil},

        {"%rdi", (uint64_t)&reg->rdi},
        {"%edi", (uint64_t)&reg->edi},
        {"%di",  (uint64_t)&reg->di},
        {"%dih", (uint64_t)&reg->dih},
        {"%dil", (uint64_t)&reg->dil},
        
        {"%rbp", (uint64_t)&reg->rbp},
        {"%ebp", (uint64_t)&reg->ebp},
        {"%bp",  (uint64_t)&reg->bp},
        {"%bph", (uint64_t)&reg->bph},
        {"%bpl", (uint64_t)&reg->bpl},

        {"%rsp", (uint64_t)&reg->rsp},
        {"%esp", (uint64_t)&reg->esp},
        {"%sp",  (uint64_t)&reg->sp},
        {"%sph", (uint64_t)&reg->sph},
        {"%spl", (uint64_t)&reg->spl},

        {"%r8",  (uint64_t)&reg->r8},
        {"%r8d", (uint64_t)&reg->r8d},
        {"%r8w", (uint64_t)&reg->r8w},
        {"%r8b", (uint64_t)&reg->r8b},

        {"%r9",  (uint64_t)&reg->r9},
        {"%r9d", (uint64_t)&reg->r9d},
        {"%r9w", (uint64_t)&reg->r9w},
        {"%r9b", (uint64_t)&reg->r9b},

        {"%r10",  (uint64_t)&reg->r10},
        {"%r10d", (uint64_t)&reg->r10d},
        {"%r10w", (uint64_t)&reg->r10w},
        {"%r10b", (uint64_t)&reg->r10b},
        
        {"%r11",  (uint64_t)&reg->r11},
        {"%r11d", (uint64_t)&reg->r11d},
        {"%r11w", (uint64_t)&reg->r11w},
        {"%r11b", (uint64_t)&reg->r11b},
        
        {"%r12",  (uint64_t)&reg->r12},
        {"%r12d", (uint64_t)&reg->r12d},
        {"%r12w", (uint64_t)&reg->r12w},
        {"%r12b", (uint64_t)&reg->r12b},
        
        {"%r13",  (uint64_t)&reg->r13},
        {"%r13d", (uint64_t)&reg->r13d},
        {"%r13w", (uint64_t)&reg->r13w},
        {"%r13b", (uint64_t)&reg->r13b},
        
        {"%r14",  (uint64_t)&reg->r14},
        {"%r14d", (uint64_t)&reg->r14d},
        {"%r14w", (uint64_t)&reg->r14w},
        {"%r14b", (uint64_t)&reg->r14b},

        {"%r15",  (uint64_t)&reg->r15},
        {"%r15d", (uint64_t)&reg->r15d},
        {"%r15w", (uint64_t)&reg->r15w},
        {"%r15b", (uint64_t)&reg->r15b},
    };

    for (int i = 0; i < sizeof(reg_addr) / sizeof(reg_addr[0]); ++i) {
        if (!strcmp(str, reg_addr[i].key)) {
            return reg_addr[i].value;
        }
    }
    printf("reflect register: %s register does not exist", str);
    exit(1);
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
        od->type = REG;
        od->reg1 = reflect_register(str, cr);
    } else {
        // memory access
        char imm[MAX_INSTRUCTION_CHAR] = {'\0'};
        int imm_len = 0;
        char reg1[MAX_INSTRUCTION_CHAR] = {'\0'};
        int reg1_len = 0;
        char reg2[MAX_INSTRUCTION_CHAR] = {'\0'};
        int reg2_len = 0;
        char scal[MAX_INSTRUCTION_CHAR] = {'\0'};
        int scal_len = 0;

        int count_b = 0;        // brackets
        int count_c = 0;        // comma

        for (int i = 0; i < str_len; ++i) {
            char c = str[i];

            if (c == '(' || c == ')') {
                ++count_b;
            } else if (c == ',') {
                ++count_c;
            } else {
                // parse imm(reg1, reg2, scal)
                if (count_b == 0) {
                    imm[imm_len++] = c;
                } else if (count_b == 1) {
                    if (count_c == 0) {
                        reg1[reg1_len++] = c;
                    } else if (count_c == 1) {
                        reg2[reg2_len++] = c;
                    } else if (count_c == 2) {
                        scal[scal_len++] = c;
                    } else {
                        printf("parse operand: %s inner operand error\n", str);
                        exit(1);
                    }
                }
            }
        }

        // set operand
        if (imm_len > 0) {
            od->imm = string2uint(imm, 0, imm_len);
        }
        if (reg1_len > 0) {
            od->reg1 = reflect_register(reg1, cr);
        }
        if (reg2_len > 0) {
            od->reg2 = reflect_register(reg2, cr);
        }
        if (scal_len > 0) {
            od->scal = string2uint(scal, 0, scal_len);
            if (od->scal != 1 && od->scal != 2 && od->scal != 4 && od->scal != 8) {
                printf("%s is not a legal scaler\n", scal);
                exit(1);
            }
        }

        // set operand type
        if (imm_len > 0) {
            if (count_b == 0) {
                od->type = MEM_IMM;
            } else if (count_c == 0) {
                od->type = MEM_IMM_REG1;
            } else if (count_c == 1) {
                od->type = MEM_IMM_REG1_REG2;
            } else if (count_c == 2) {
                if (reg1_len == 0) {
                    od->type = MEM_IMM_REG2_SCAL;
                } else {
                    od->type = MEM_IMM_REG1_REG2_SCAL;
                }
            }
        } else {
            if (reg1_len != 0 && reg2_len == 0) {
                od->type = MEM_REG1;
            } else if (reg1_len != 0 && reg2_len != 0) {
                if (scal_len == 0) {
                    od->type = MEM_REG1_REG2;
                } else {
                    od->type = MEM_REG1_REG2_SCAL;
                }
            } else if (reg1_len == 0 && reg2_len != 0) {
                od->type = MEM_REG2_SCAL;
            } else {
                printf("parse operand: %s memory operand error\n", str);
                exit(1);
            }
        }
    }
}

// lookup table for the type of instruction
map_t<const char *, op_t> op_type[] = {
    {"mov",     INST_MOV},
    {"movq",    INST_MOV},
    {"push",    INST_PUSH},
    {"pop",     INST_POP},
    {"leave",   INST_LEAVE},
    {"leaveq",  INST_LEAVE},
    {"call",    INST_CALL},
    {"callq",   INST_CALL},
    {"ret",     INST_RET},
    {"retq",    INST_RET},
    {"add",     INST_ADD},
    {"sub",     INST_SUB},
    {"cmp",     INST_CMP},
    {"cmpq",    INST_CMP},
    {"jne",     INST_JNE},
    {"jmp",     INST_JMP},
};

static void parse_instruction(const char *str, inst_t *inst, core_t *cr) {
    // str: assembly code string, e.g. mov %rsp,%rbp
    // inst: pointer to the address to store the parsed instruction
    // cr: active core the processor
    char op[MAX_INSTRUCTION_CHAR] = {'\0'};
    int op_len = 0;
    char src[MAX_INSTRUCTION_CHAR] = {'\0'};
    int src_len = 0;
    char dst[MAX_INSTRUCTION_CHAR] = {'\0'};
    int dst_len = 0;

    int count_b = 0;        // brackets

    // DFA: `Deterministic Finite Automaton` to scan string and get value
    int state = 0;
    for (int i = 0; i < strlen(str); ++i) {
        char c = tolower(str[i]);
        if ('(' == c || ')' == c) {
            ++count_b;
        }

        if (state == 0 && c != ' ') {
            state = 1;
            op[op_len++] = c;
        } else if (state == 1) {
            if (c == ' ') {
                state = 2;
            } else {
                op[op_len++] = c;
            }
        } else if (state == 2 && c != ' ') {
            state = 3;
            src[src_len++] = c;
        } else if (state == 3) {
            if (c == ',' && (count_b == 0 || count_b == 2)) {
                state = 4;
            } else {
                src[src_len++] = c;
            }
        } else if (state == 4 && c != ' ') {
            state = 5;
            dst[dst_len++] = c;
        } else if (state == 5) {
            if (c == ' ' && (count_b == 0 || count_b == 2)) {
                state = 6;
            } else {
                dst[dst_len++] = c;
            }
        } else {
            continue;
        }
    }

    parse_operand(src, &inst->src, cr);
    parse_operand(dst, &inst->dst, cr);
    for (int i = 0; i < sizeof(op_type) / sizeof(op_type[0]); ++i) {
        if (!strcmp(op, op_type[i].key)) {
            inst->op = op_type[i].value;
            debug_printf(DEBUG_PARSEINST, "[%s (%d)] [%s (%d)] [%s (%d)]\n",
                op, inst->op, src, inst->src.type, dst, inst->dst.type);
            return;
        }
    }
    printf("parse instruction: %s is a not legal operator", op);
    exit(1);
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
        // src: immediate number (uint64_t bitmap)
        // dst: register
        *(uint64_t *)dst = src;
    }

    next_rip(cr);
    cr->flag.__cpu_flag_value = 0;
}

static void push_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    if (src_od->type == REG) {
        // src: register
        // dst: empty
        cr->reg.rsp -= 8;
        write64bits_dram(va2pa(cr->reg.rsp, cr), *(uint64_t *)src, cr);
        next_rip(cr);
        cr->flag.__cpu_flag_value = 0;
    }
}

static void pop_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    if (src_od->type == REG) {
        // src: register
        // dst: empty
        *(uint64_t *)src = read64bits_dram(va2pa(cr->reg.rsp, cr), cr);
        cr->reg.rsp += 8;
        next_rip(cr);
        cr->flag.__cpu_flag_value = 0;
    }
}

static void leave_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    // movq %rbp,%rsp
    cr->reg.rsp = cr->reg.rbp;
    // popq %rbp
    cr->reg.rbp = read64bits_dram(va2pa(cr->reg.rsp, cr), cr);
    cr->reg.rsp += 8;
    next_rip(cr);
    cr->flag.__cpu_flag_value = 0;
}

static void call_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    // src: immediate number: virtual address of target function starting
    // dst: empty
    next_rip(cr);
    cr->reg.rsp -= 8;
    write64bits_dram(va2pa(cr->reg.rsp, cr), cr->rip, cr);
    cr->rip = src;
    cr->flag.__cpu_flag_value = 0;
}

static void ret_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    // src: empty
    // dst: empty
    cr->rip = read64bits_dram(va2pa(cr->reg.rsp, cr), cr);
    cr->reg.rsp += 8;
    cr->flag.__cpu_flag_value = 0;
}

static void add_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);
    uint64_t dst = decode_operand(dst_od);

    if (src_od->type == REG && dst_od->type == REG) {
        // src: register
        // dst: register
        uint64_t val = *(uint64_t *)src + *(uint64_t *)dst;

        // set condition flags
        cr->flag.CF = val < *(uint64_t *)src;
        cr->flag.ZF = val == 0;
        cr->flag.SF = val >> 63 & 0x1;
        cr->flag.OF = ((int64_t)*(uint64_t *)src < 0 && (int64_t)*(uint64_t *)dst < 0) && 
            ((int64_t)val < 0 ^ (int64_t)*(uint64_t *)src < 0);

        // update register
        *(uint64_t *)dst = val;
        next_rip(cr);
    } else if (src_od->type == IMM && dst_od->type == REG) {
        // src: immediate number
        // dst: register
        uint64_t val = *(uint64_t *)dst + src;

        // set condition flags
        cr->flag.CF = val < src;
        cr->flag.ZF = val == 0;
        cr->flag.SF = val >> 63 & 0x1;
        cr->flag.OF = ((int64_t)src < 0 && (int64_t)*(uint64_t *)dst < 0) && 
            ((int64_t)val < 0 ^ (int64_t)src < 0);
        
        // update register
        *(uint64_t *)dst = val;
        next_rip(cr);
    }
}

static void sub_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);
    uint64_t dst = decode_operand(dst_od);

    if (src_od->type == REG && dst_od->type == REG) {
        // src: register
        // dst: register
        uint64_t val = *(uint64_t *)dst + ~(*(uint64_t *)src) + 1;

        cr->flag.CF = val > *(uint64_t *)src;
        cr->flag.ZF = val == 0;
        cr->flag.SF = val >> 63 & 0x1;
        cr->flag.OF = ((int64_t)*(uint64_t *)src > 0 && (int64_t)*(uint64_t *)dst < 0) && 
            ((int64_t)val < 0 && (int64_t)*(uint64_t *)dst < 0);
        
        *(uint64_t *)dst = val;
        next_rip(cr);
        
    } else if (src_od->type == IMM && dst_od->type == REG) {
        // src: immediate number
        // dst: register
        uint64_t val = *(uint64_t *)dst + ~src + 1;

        cr->flag.CF = val > src;
        cr->flag.ZF = val == 0;
        cr->flag.SF = val >> 63 & 0x1;
        cr->flag.OF = ((int64_t)src > 0 && (int64_t)*(uint64_t *)dst < 0) && 
            ((int64_t)val < 0 && (int64_t)dst < 0);

        *(uint64_t *)dst = val;
        next_rip(cr);
    }
}

static void cmp_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);
    uint64_t dst = decode_operand(dst_od);

    if (src_od->type == REG && dst_od->type == REG) {
        // src: register
        // dst: register
        uint64_t val = *(uint64_t *)dst + ~(*(uint64_t *)src) + 1;

        cr->flag.CF = val > *(uint64_t *)src;
        cr->flag.ZF = val == 0;
        cr->flag.SF = val >> 63 & 0x1;
        cr->flag.OF = ((int64_t)*(uint64_t *)src > 0 && (int64_t)*(uint64_t *)dst < 0) && 
            ((int64_t)val < 0 && (int64_t)*(uint64_t *)dst < 0);
        
        next_rip(cr);
        
    } else if (src_od->type == IMM && dst_od->type == REG) {
        // src: immediate number
        // dst: register
        uint64_t val = *(uint64_t *)dst + ~src + 1;

        cr->flag.CF = val > src;
        cr->flag.ZF = val == 0;
        cr->flag.SF = val >> 63 & 0x1;
        cr->flag.OF = ((int64_t)src > 0 && (int64_t)*(uint64_t *)dst < 0) && 
            ((int64_t)val < 0 && (int64_t)dst < 0);

        next_rip(cr);
    } else if (src_od->type == IMM && dst_od->type >= MEM_IMM) {
        // src: immediate number
        // dst: memory access
        dst = read64bits_dram(va2pa(dst, cr), cr);
        uint64_t val = dst + ~src + 1;

        cr->flag.CF = val > src;
        cr->flag.ZF = val == 0;
        cr->flag.SF = val >> 63 & 0x1;
        cr->flag.OF = ((int64_t)src > 0 && (int64_t)dst < 0) && 
            ((int64_t)val < 0 && (int64_t)dst < 0);

        next_rip(cr);
    }
}

static void jne_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    if (src_od->type == MEM_IMM) {
        if (!cr->flag.ZF) {
            cr->rip = src;
        } else {
            next_rip(cr);
        }
    }
    cr->flag.__cpu_flag_value = 0;
}

static void jmp_handler(od_t *src_od, od_t *dst_od, core_t *cr) {
    uint64_t src = decode_operand(src_od);

    if (src_od->type == MEM_IMM) {
        cr->rip = src;
    }
    cr->flag.__cpu_flag_value = 0;
}


// instruction cycle is implemented in CPU
void instruction_cycle(core_t *cr) {
    // [FETCH]: get the instruction string by program counter
    char inst_str[MAX_INSTRUCTION_CHAR];
    readinst_dram(va2pa(cr->rip, cr), inst_str, cr);
    debug_printf(DEBUG_INSTRUCTIONCYCLE, "0x%08lx\t%s\n", cr->rip, inst_str);

    // [DECODE]: decode the run-time instruction operands
    inst_t inst;
    parse_instruction(inst_str, &inst, cr);

    // [EXECUTE]: get the function pointer or handler by the operator
    handler_t handler = handler_table[inst.op];
    // update CPU and memory according the instruction
    handler(&(inst.src), &(inst.dst), cr);
}

void print_register(core_t *cr) {
    printf("rax = %16lx\trbx = %16lx\nrcx = %16lx\trdx = %16lx\n",
        cr->reg.rax, cr->reg.rbx, cr->reg.rcx, cr->reg.rdx);
    printf("rsi = %16lx\trdi = %16lx\nrbp = %16lx\trsp = %16lx\n",
        cr->reg.rsi, cr->reg.rdi, cr->reg.rbp, cr->reg.rsp);
    printf("rip = %16lx\n", cr->rip);
    printf("CF = %u\tZF = %u\tSF = %u\tOF = %u\n",
        cr->flag.CF, cr->flag.ZF, cr->flag.SF, cr->flag.OF);
}

void print_stack(core_t *cr) {
    int n = 10;

    uint64_t *low = (uint64_t *)&pm[va2pa(cr->reg.rsp, cr)];
    uint64_t *high = (uint64_t *)&pm[va2pa(cr->reg.rbp, cr)];
    uint64_t *origHigh = high, *origLow = low;

    uint64_t rspStart = cr->reg.rbp;

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

void TestString2Uint() {
    const char *nums[12] = {
        "0",
        "-0",
        "0x0",
        "1234",
        "0x1234",
        "0xabcd",
        "-0xabcd",
        "-1234",
        "2147483647",
        "-2147483648",
        "0x8000000000000000",
        "0xffffffffffffffff",
    };

    for (int i = 0; i < 12; ++i) {
        printf("%s => %lx\n", nums[i], string2uint(nums[i], 0, -1));
    }
}

void TestParsingOperand() {
    ACTIVE_CORE = 0x0;
    core_t *ac = &cores[ACTIVE_CORE];

    const char *strs[11] = {
        "$0x1234",
        "%rax",
        "0xabcd",
        "(%rsp)",
        "0xabcd(%rsp)",
        "(%rsp,%rbx)",
        "0xabcd(%rsp,%rbx)",
        "(,%rbx,8)",
        "0xabcd(,%rbx,8)",
        "(%rsp,%rbx,8)",
        "0xabcd(%rsp,%rbx,8)"
    };

    printf("rax %p\n", &ac->reg.rax);
    printf("rsp %p\n", &ac->reg.rsp);
    printf("rbx %p\n", &ac->reg.rbx);

    for (int i = 0; i < 11; ++i) {
        od_t od;
        parse_operand(strs[i], &od, ac);

        printf("type = %d\timm = %16lx\treg1 = %16lx\treg2 = %16lx\tscal = %16lx\n",
            od.type, od.imm, od.reg1, od.reg2, od.scal);
    }
}

void TestParsingInstruction() {
    ACTIVE_CORE = 0x0;
    core_t *ac = &cores[ACTIVE_CORE];

    char assembly[15][MAX_INSTRUCTION_CHAR] = {
        "push   %rbp",
        "mov    %rsp,%rbp",
        "mov    %rdi,-0x18(%rbp)",
        "mov    %rsi,-0x20(%rbp)",
        "mov    -0x18(%rbp),%rdx",
        "mov    -0x20(%rbp),%rax",
        "add    %rdx,%rax",
        "mov    %rax,-0x8(%rbp)",
        "mov    -0x8(%rbp),%rax",
        "pop    %rbp",
        "retq",
        "mov    %rdx,%rsi",
        "mov    %rax,%rdi",
        "callq  0",
        "mov    %rax,-0x8(%rbp)",
    };

    inst_t inst;
    for (int i = 0; i < 15; ++i) {
        parse_instruction(assembly[i], &inst, ac);
    }
}

void TestAddFunctionCallAndComputation() {
    ACTIVE_CORE = 0x0;
    core_t *ac = (core_t *)&cores[ACTIVE_CORE];

    // init state
    ac->reg.rax = 0x12340000;
    ac->reg.rbx = 0x0;
    ac->reg.rcx = 0x555555557da0;
    ac->reg.rdx = 0xabcd;
    ac->reg.rsi = 0x7fffffffda48;
    ac->reg.rdi = 0x1;
    ac->reg.rbp = 0x7fffffffd930;
    ac->reg.rsp = 0x7fffffffd910;

    ac->flag.__cpu_flag_value = 0;

    write64bits_dram(va2pa(0x7fffffffd930, ac), 0x1, ac);               // rbp
    write64bits_dram(va2pa(0x7fffffffd928, ac), 0x7ffff7e93754, ac);
    write64bits_dram(va2pa(0x7fffffffd920, ac), 0xabcd, ac);
    write64bits_dram(va2pa(0x7fffffffd918, ac), 0x12340000, ac);
    write64bits_dram(va2pa(0x7fffffffd910, ac), 0xf7f9c0c8, ac);        // rsp

    char assembly[15][MAX_INSTRUCTION_CHAR] = {
        "push   %rbp",                      // 0
        "mov    %rsp,%rbp",                 // 1
        "mov    %rdi,-0x18(%rbp)",          // 2
        "mov    %rsi,-0x20(%rbp)",          // 3
        "mov    -0x18(%rbp),%rdx",          // 4
        "mov    -0x20(%rbp),%rax",          // 5
        "add    %rdx,%rax",                 // 6
        "mov    %rax,-0x8(%rbp)",           // 7
        "mov    -0x8(%rbp),%rax",           // 8
        "pop    %rbp",                      // 9
        "retq",                             // 10
        "mov    %rdx,%rsi",                 // 11
        "mov    %rax,%rdi",                 // 12
        "callq  0x400000",                         // 13
        "mov    %rax,-0x8(%rbp)",           // 14
    };

    for (int i = 0; i < 15; ++i) {
        writeinst_darm(va2pa(0x400000 + 0x40 * i, ac), assembly[i], ac);
    }
    ac->rip = 0x400000 + 0x40 * 11;
    printf("%lx\n", ac->rip);
    printf("%lx\n", MAX_INSTRUCTION_CHAR * sizeof(char) * 11 + 0x400000);

    for (int i = 0; i < 15; ++i) {
        instruction_cycle(ac);
        print_register(ac);
        print_stack(ac);
        printf("\n");
    }

    int match = 1;
    match = match && (ac->reg.rax == 0x1234abcd);
    match = match && (ac->reg.rbx == 0x0);
    match = match && (ac->reg.rcx == 0x555555557da0);
    match = match && (ac->reg.rdx == 0x12340000);
    match = match && (ac->reg.rsi == 0xabcd);
    match = match && (ac->reg.rdi == 0x12340000);
    match = match && (ac->reg.rbp == 0x7fffffffd930);
    match = match && (ac->reg.rsp == 0x7fffffffd910);

    if (match) {
        printf("register match\n");
    } else {
        printf("register mismatch\n");
    }

    match = match && (read64bits_dram(va2pa(0x7fffffffd930, ac), ac) == 0x1);
    match = match && (read64bits_dram(va2pa(0x7fffffffd928, ac), ac) == 0x1234abcd);
    match = match && (read64bits_dram(va2pa(0x7fffffffd920, ac), ac) == 0xabcd);
    match = match && (read64bits_dram(va2pa(0x7fffffffd918, ac), ac) == 0x12340000);
    match = match && (read64bits_dram(va2pa(0x7fffffffd910, ac), ac) == 0xf7f9c0c8);

    if (match) {
        printf("memory match\n");
    } else {
        printf("memory mismatch\n");
    }
}

void TestSumRecursiveCondition() {
    ACTIVE_CORE = 0x0;
    core_t *ac = &cores[ACTIVE_CORE];

    /*
    `rbp` (high address) represents the beginning related to the function, 
    and `rsp` (low address) represents the end related to the function.

    $(gdb) b main
    $(gdb) run
    $(gdb) disas
        0x0000555555555160 <+0>:     endbr64
        0x0000555555555164 <+4>:     push   %rbp
        0x0000555555555165 <+5>:     mov    %rsp,%rbp
        0x0000555555555168 <+8>:     sub    $0x10,%rsp
    =>  0x000055555555516c <+12>:    mov    $0x3,%edi
        0x0000555555555171 <+17>:    call   0x555555555129 <_Z3summ>
        0x0000555555555176 <+22>:    mov    %rax,-0x8(%rbp)
    $(gdb) info r
        rax            0x555555555160      93824992235872
        rbx            0x0                 0
        rcx            0x555555557df8      93824992247288
        rdx            0x7fffffffdee8      140737488346856
        rsi            0x7fffffffded8      140737488346840
        rdi            0x1                 1
        rbp            0x7fffffffddc0      0x7fffffffddc0
        rsp            0x7fffffffddb0      0x7fffffffddb0
        ...
    $(gdb) x/10 0x7fffffffddb0
        0x7fffffffddb0: 0x00001000      0x00000000      0x55555040     0x00005555
        0x7fffffffddc0: 0x00000001      0x00000000      0xf7d9fd90     0x00007fff
        0x7fffffffddd0: 0x00000000      0x00000000
    $(gdb) si 2
    $(gdb) disas
    =>  0x0000555555555129 <+0>:     endbr64
        0x000055555555512d <+4>:     push   %rbp
        0x000055555555512e <+5>:     mov    %rsp,%rbp
        0x0000555555555131 <+8>:     sub    $0x10,%rsp
        0x0000555555555135 <+12>:    mov    %rdi,-0x8(%rbp)
        0x0000555555555139 <+16>:    cmpq   $0x0,-0x8(%rbp)
        0x000055555555513e <+21>:    jne    0x555555555147 <_Z3summ+30>
        0x0000555555555140 <+23>:    mov    $0x0,%eax
        0x0000555555555145 <+28>:    jmp    0x55555555515e <_Z3summ+53>
        0x0000555555555147 <+30>:    mov    -0x8(%rbp),%rax
        0x000055555555514b <+34>:    sub    $0x1,%rax
        0x000055555555514f <+38>:    mov    %rax,%rdi
        0x0000555555555152 <+41>:    call   0x555555555129 <_Z3summ>
        0x0000555555555157 <+46>:    mov    -0x8(%rbp),%rdx
        0x000055555555515b <+50>:    add    %rdx,%rax
        0x000055555555515e <+53>:    leave
        0x000055555555515f <+54>:    ret
    $(gdb) fin
    $(gdb) disas
        0x0000555555555171 <+17>:    call   0x555555555129 <_Z3summ>
    =>  0x0000555555555176 <+22>:    mov    %rax,-0x8(%rbp)
        0x000055555555517a <+26>:    mov    $0x0,%eax
        0x000055555555517f <+31>:    leave
        0x0000555555555180 <+32>:    ret
    $(gdb) info r
        rax            0x6                 6
        rbx            0x0                 0
        rcx            0x555555557df8      93824992247288
        rdx            0x3                 3
        rsi            0x7fffffffded8      140737488346840
        rdi            0x0                 0
        rbp            0x7fffffffddc0      0x7fffffffddc0
        rsp            0x7fffffffddb0      0x7fffffffddb0
        ...
    $(gdb) x/6 $rsp
        0x7fffffffddb0: 0x00001000      0x00000000      0x55555040     0x00005555
        0x7fffffffddc0: 0x00000001      0x00000000
    */

    char assembly[19][MAX_INSTRUCTION_CHAR] = {
        "push   %rbp",                  // 0
        "mov    %rsp,%rbp",             // 1
        "sub    $0x10,%rsp",            // 2
        "mov    %rdi,-0x8(%rbp)",       // 3
        "cmpq   $0x0,-0x8(%rbp)",       // 4
        "jne    0x400200",              // 5: jump to 8
        "mov    $0x0,%eax",             // 6
        "jmp    0x400380",              // 7: jump to 14
        "mov    -0x8(%rbp),%rax",       // 8
        "sub    $0x1,%rax",             // 9
        "mov    %rax,%rdi",             // 10
        "call   0x400000",              // 11
        "mov    -0x8(%rbp),%rdx",       // 12
        "add    %rdx,%rax",             // 13
        "leave",                        // 14
        "ret",                          // 15
        "mov    $0x3,%edi",             // 16
        "call   0x400000",              // 17
        "mov    %rax,-0x8(%rbp)",       // 18
    };

    // copy code to physical memory
    for (int i = 0; i < 19; ++i) {
        writeinst_darm(va2pa(i * 0x40 + 0x400000, ac), assembly[i], ac);
    }

    // initialize register and memory
    ac->reg.rax = 0x555555555160;
    ac->reg.rbx = 0x0;
    ac->reg.rcx = 0x555555557df8;
    ac->reg.rdx = 0x7fffffffdee8;
    ac->reg.rsi = 0x7fffffffded8;
    ac->reg.rdi = 0x1;
    ac->reg.rbp = 0x7fffffffddc0;
    ac->reg.rsp = 0x7fffffffddb0;
    ac->rip = MAX_INSTRUCTION_CHAR * sizeof(char) * 16 + 0x400000;
    ac->flag.__cpu_flag_value = 0;

    write64bits_dram(va2pa(0x7fffffffddc0, ac), 0x00000001, ac);            // rbp
    write64bits_dram(va2pa(0x7fffffffddb8, ac), 0x555555555040, ac);
    write64bits_dram(va2pa(0x7fffffffddb0, ac), 0x00001000, ac);            // rsp

    for (int i = 0; i < MAX_INSTRUCTION_EXE && ac->rip <= 18 * 0x40 + 0x400000; ++i) {
        instruction_cycle(ac);
        print_register(ac);
        print_stack(ac);
        printf("\n");
    }

    bool match = true;

    match = match && ac->reg.rax == 0x6;
    match = match && ac->reg.rbx == 0x0;
    match = match && ac->reg.rcx == 0x555555557df8;
    match = match && ac->reg.rdx == 0x3;
    match = match && ac->reg.rsi == 0x7fffffffded8;
    match = match && ac->reg.rdi == 0x0;
    match = match && ac->reg.rbp == 0x7fffffffddc0;
    match = match && ac->reg.rsp == 0x7fffffffddb0;
    
    if (match) {
        printf("register match\n");
    } else {
        printf("register mismatch\n");
    }

    match = match && read64bits_dram(va2pa(0x7fffffffddc0, ac), ac) == 0x00000001;
    match = match && read64bits_dram(va2pa(0x7fffffffddb8, ac), ac) == 0x00000006;
    match = match && read64bits_dram(va2pa(0x7fffffffddb0, ac), ac) == 0x00001000;

    if (match) {
        printf("memory match\n");
    } else {
        printf("memory mismatch\n");
    }
}