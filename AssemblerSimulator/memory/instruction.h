#ifndef INSTRUCTION_H
#define INSTRUCTION_H

#include <stdint.h>
#include "register.h"

// operator type
typedef enum OP {
    PUSH_REG,
    POP_REG,
    MOV_REG_REG,
    MOV_REG_MEM,
    MOV_MEM_REG,
    ADD_REG_REG,
    CALL,
    RET,
} op_t;

// operand type
typedef enum OD_TYPE {
    IMM, REG, MM_IMM, MM_REG, MM_IMM_REG, MM_REG1_REG2, MM_IMM_REG1_REG2,
    MM_REG2_S, MM_IMM_REG2_S, MM_REG1_REG2_S, MM_IMM_REG1_REG2_S, EMPTY
} od_type_t;

// operand
typedef struct OD {
    od_type_t type;
    int64_t imm;
    int64_t scal;
    uint64_t *reg1;
    uint64_t *reg2;
} od_t;

// instruction
typedef struct INSTRUCT_STRUCT {
    op_t op;    // mov, add, push
    od_t src;
    od_t dst;
    char code[50];
} inst_t;

void push_reg_handler(uint64_t src, uint64_t dst);
void pop_reg_handler(uint64_t src, uint64_t dst);
void mov_reg_reg_handler(uint64_t src, uint64_t dst);
void add_reg_reg_handler(uint64_t src, uint64_t dst);

// pointer pointing to the function
#define NUM_INSTRTYPE 30
typedef void (*handler_t)(uint64_t, uint64_t);
extern handler_t handler_table[NUM_INSTRTYPE];

void instruction_cycle();

#endif