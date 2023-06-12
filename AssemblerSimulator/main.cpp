#include <iostream>
#include "cpu.h"
#include "memory.h"
#include "common.h"

static void TestAddFunctionCallAndComputation();
static void TestString2Uint();

int main()
{
    TestString2Uint();

    return 0;
}

static void TestAddFunctionCallAndComputation() {
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

    ac->CF = 0;
    ac->ZF = 0;
    ac->SF = 0;
    ac->OF = 0;

    write64bits_dram(va2pa(0x7fffffffd930, ac), 0x1, ac);               // rbp
    write64bits_dram(va2pa(0x7fffffffd928, ac), 0x7ffff7e93754, ac);
    write64bits_dram(va2pa(0x7fffffffd920, ac), 0xabcd, ac);
    write64bits_dram(va2pa(0x7fffffffd918, ac), 0x12340000, ac);
    write64bits_dram(va2pa(0x7fffffffd910, ac), 0xf7f9c0c8, ac);        // rsp

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
    ac->rip = (uint64_t)&assembly[11];
    sprintf(assembly[13], "callq  $%p", &assembly[0]);

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
        std::cout << "register match" << std::endl;
    } else {
        std::cout << "register mismatch" << std::endl;
    }

    match = match && (read64bits_dram(va2pa(0x7fffffffd930, ac), ac) == 0x1);
    match = match && (read64bits_dram(va2pa(0x7fffffffd928, ac), ac) == 0x7ffff7e93754);
    match = match && (read64bits_dram(va2pa(0x7fffffffd920, ac), ac) == 0xabcd);
    match = match && (read64bits_dram(va2pa(0x7fffffffd918, ac), ac) == 0x12340000);
    match = match && (read64bits_dram(va2pa(0x7fffffffd910, ac), ac) == 0xf7f9c0c8);

    if (match) {
        std::cout << "memory match" << std::endl;
    } else {
        std::cout << "memory mismatch" << std::endl;
    }
}

static void TestString2Uint() {
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
        printf("%s => %lx\n", nums[i], string2uint(nums[i]));
    }
}