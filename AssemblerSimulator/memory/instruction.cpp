#include <stdio.h>
#include "instruction.h"
#include "mmu.h"
#include "dram.h"

handler_t handler_table[NUM_INSTRTYPE] = {
    push_reg_handler,
    pop_reg_handler,
    mov_reg_reg_handler,
    mov_reg_mem_handler,
    mov_mem_reg_handler,
    add_reg_reg_handler,
    call_handler,
    ret_handler,
};

static uint64_t decode_od(od_t od) {
    if (od.type == IMM) {
        return (uint64_t)od.imm;
    } else if (od.type == REG) {
        return (uint64_t)od.reg1;
    } else if (od.type == EMPTY) {
        return (uint64_t)0;
    } else {
        // mm
        uint64_t vaddr;

        switch (od.type) {
            case MM_IMM:
                vaddr = od.imm;
                break;
            case MM_REG:
                vaddr = *od.reg1;
                break;
            case MM_IMM_REG:
                vaddr = od.imm + *od.reg1;
                break;
            case MM_REG1_REG2:
                vaddr = *od.reg1 + *od.reg2;
                break;
            case MM_IMM_REG1_REG2:
                vaddr = od.imm + *od.reg1 + *od.reg2;
                break;
            case MM_REG2_S:
                vaddr = *od.reg2 * od.scal;
                break;
            case MM_IMM_REG2_S:
                vaddr = od.imm + *od.reg2 * od.scal;
                break;
            case MM_REG1_REG2_S:
                vaddr = *od.reg1 + *od.reg2 * od.scal;
                break;
            case MM_IMM_REG1_REG2_S:
                vaddr = od.imm + *od.reg1 + *od.reg2 * od.scal;
                break;
        }

        return vaddr;
    }
}

void push_reg_handler(uint64_t src, uint64_t dst){
    reg.rsp -= 8;
    write64bits_dram(va2pa(reg.rsp), *(uint64_t *)src);
    reg.rip += sizeof(inst_t);
}

void pop_reg_handler(uint64_t src, uint64_t dst) {
    *(uint64_t *)src = read64bits_dram(va2pa(reg.rsp));
    reg.rsp += 8;
    reg.rip += sizeof(inst_t);
}

void mov_reg_reg_handler(uint64_t src, uint64_t dst) {
    *(uint64_t *)dst = *(uint64_t *)src;
    reg.rip += sizeof(inst_t);
}

void mov_reg_mem_handler(uint64_t src, uint64_t dst) {
    write64bits_dram(va2pa(dst), *(uint64_t *)src);
    reg.rip += sizeof(inst_t);
}

void mov_mem_reg_handler(uint64_t src, uint64_t dst) {
    *(uint64_t *)dst = read64bits_dram(va2pa(src));
    reg.rip += sizeof(inst_t);
}

void add_reg_reg_handler(uint64_t src, uint64_t dst) {
    *(uint64_t *)dst = *(uint64_t *)src + *(uint64_t *)dst;
    reg.rip += sizeof(inst_t);
}

void call_handler(uint64_t src, uint64_t dst) {
    push_reg_handler((uint64_t)&reg.rip, 0);
    reg.rip = src;
}

void ret_handler(uint64_t src, uint64_t dst) {
    pop_reg_handler((uint64_t)&reg.rip, 0);
}

void instruction_cycle() {
    inst_t *instr = (inst_t *)reg.rip;


    uint64_t src = decode_od(instr->src);
    uint64_t dst = decode_od(instr->dst);

    handler_t handler = handler_table[instr->op];
    handler(src, dst);

    printf("    %s\n", instr->code);
}