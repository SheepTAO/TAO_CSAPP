#include "elf.h"

inst_t program[15] = {
     // uint64_t add(uint64_t, uint64_t)
    {
        PUSH_REG,
        { REG, 0, 0, (uint64_t *)&reg.rbp, nullptr },
        { EMPTY, 0, 0, nullptr, nullptr },
        "push %rbp"
    },
    {
        MOV_REG_REG,
        { REG, 0, 0, (uint64_t *)&reg.rsp, nullptr },
        { REG, 0, 0, (uint64_t *)&reg.rbp, nullptr },
        "mov %rsp, %rbp"
    },
    {
        MOV_REG_MEM,
        { REG, 0, 0, (uint64_t *)&reg.rdi, nullptr },
        { MM_IMM_REG, -0x18, 0, (uint64_t *)&reg.rbp, nullptr },
        "mov %rdi, -0x18(%rbp)"
    },
    {
        MOV_REG_MEM,
        { REG, 0, 0, (uint64_t *)&reg.rsi, nullptr },
        { MM_IMM_REG, -0x20, 0, (uint64_t *)&reg.rbp, nullptr },
        "mov %rsi, -0x20(%rbp)"
    },
    {
        MOV_MEM_REG,
        { MM_IMM_REG, -0x18, 0, (uint64_t *)&reg.rbp, nullptr },
        { REG, 0, 0, (uint64_t *)&reg.rdx, nullptr },
        "mov -0x18(%rbp), %rdx"
    },
    {
        MOV_MEM_REG,
        { MM_IMM_REG, -0x20, 0, (uint64_t *)&reg.rbp, nullptr },
        { REG, 0, 0, (uint64_t *)&reg.rax, nullptr },
        "mov -0x20(%rbp), %rax"
    },
    {
        ADD_REG_REG,
        { REG, 0, 0, (uint64_t *)&reg.rdx, nullptr },
        { REG, 0, 0, (uint64_t *)&reg.rax, nullptr },
        "add %rdx, %rax"
    },
    {
        MOV_REG_MEM,
        { REG, 0, 0, (uint64_t *)&reg.rax, nullptr },
        { MM_IMM_REG, -0x8, 0, (uint64_t *)&reg.rbp, nullptr },
        "mov %rax, -0x8(%rbp)"
    },
    {
        MOV_MEM_REG,
        { MM_IMM_REG, -0x8, 0, (uint64_t *)&reg.rbp, nullptr },
        { REG, 0, 0, (uint64_t *)&reg.rax, nullptr },
        "mov -0x8(%rbp), %rax"
    },
    {
        POP_REG,
        { REG, 0, 0, (uint64_t *)&reg.rbp, nullptr },
        { EMPTY, 0, 0, nullptr, nullptr },
        "pop %rbp"
    },
    {
        RET,
        { REG, 0, 0, nullptr, nullptr },
        { REG, 0, 0, nullptr, nullptr },
        "retq"
    },
    // main entry point
    {
        MOV_REG_REG,
        { REG, 0, 0, (uint64_t *)&reg.rdx, nullptr },
        { REG, 0, 0, (uint64_t *)&reg.rsi, nullptr },
        "mov %rdx, %rsi"
    },
    {
        MOV_REG_REG,
        { REG, 0, 0, (uint64_t *)&reg.rax, nullptr },
        { REG, 0, 0, (uint64_t *)&reg.rdi, nullptr },
        "mov %rax, %rdi"
    },
    {
        CALL,
        { IMM, (int64_t)&program[0], 0, nullptr, nullptr},
        { EMPTY, 0, 0, nullptr, nullptr},
        "call <add>"
    },
    {
        MOV_REG_MEM,
        { REG, 0, 0, (uint64_t *)&reg.rax, nullptr },
        { MM_IMM_REG, -0x8, 0, (uint64_t *)&reg.rbp, nullptr },
        "mov %rax, -0x8(%rbp)"
    }
};