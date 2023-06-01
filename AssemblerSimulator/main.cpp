#include <iostream>
#include "cpu/register.h"
#include "memory/dram.h"
#include "disk/elf.h"
#include "memory/instruction.h"

int main()
{
    //init
    reg.rax = 0x12340000;
    reg.rbx = 0x0;
    reg.rcx = 0x555555557da0;
    reg.rdx = 0xabcd;
    reg.rsi = 0x7fffffffda48;
    reg.rdi = 0x1;
    reg.rbp = 0x7fffffffd930;
    reg.rsp = 0x7fffffffd910;
    reg.rip = (uint64_t)&program[11];

    /* 
    `rbp` (high) represents the beginning related to the function, 
    and `rsp` (low) represents the end related to the function.
    .eg.
    0x0000555555555192 <+4>:     push   %rbp
    0x0000555555555193 <+5>:     mov    %rsp,%rbp
    0x0000555555555196 <+8>:     sub    $0x20,%rsp
    0x000055555555519a <+12>:    movq   $0x12340000,-0x18(%rbp)
    0x00005555555551a2 <+20>:    movq   $0xabcd,-0x10(%rbp)
    0x00005555555551aa <+28>:    mov    -0x10(%rbp),%rdx
    0x00005555555551ae <+32>:    mov    -0x18(%rbp),%rax
=>  0x00005555555551b2 <+36>:    mov    %rdx,%rsi
    0x00005555555551b5 <+39>:    mov    %rax,%rdi
    0x00005555555551b8 <+42>:    call   0x555555555169 <_Z3addmm>
    0x00005555555551bd <+47>:    mov    %rax,-0x8(%rbp)
    while $info r
    rax            0x12340000          305397760
    rbx            0x0                 0
    rcx            0x555555557da0      93824992247200
    rdx            0xabcd              43981
    rsi            0x7fffffffda48      140737488345672
    rdi            0x1                 1
    rbp            0x7fffffffd930      0x7fffffffd930
    rsp            0x7fffffffd910      0x7fffffffd910
    */
    mm[va2pa(0x7fffffffd930)] = 0x1;                // rbp
    mm[va2pa(0x7fffffffd928)] = 0x7ffff7e93754;
    mm[va2pa(0x7fffffffd920)] = 0xabcd;
    mm[va2pa(0x7fffffffd918)] = 0x12340000;
    mm[va2pa(0x7fffffffd910)] = 0xf7f9c0c8;         // rsp

    // run inst
    for (uint i = 0; i < 15; ++i) {
        instruction_cycle();
    }

    // verify
    bool match = 1;
    match = match && (reg.rax == 0x1234abcd);
    match = match && (reg.rbx == 0x0);
    match = match && (reg.rcx == 0x555555557da0);
    match = match && (reg.rdx == 0x12340000);
    match = match && (reg.rsi == 0xabcd);
    match = match && (reg.rdi == 0x12340000);
    match = match && (reg.rbp == 0x7fffffffd930);
    match = match && (reg.rsp == 0x7fffffffd910);

    if (match) {
        std::cout << "register match" << std::endl;
    } else {
        std::cout << "register mismatch" << std::endl;
    }

    match = match && (mm[va2pa(0x7fffffffd930)] == 0x1);                // rbp
    match = match && (mm[va2pa(0x7fffffffd928)] == 0x1234abcd);
    match = match && (mm[va2pa(0x7fffffffd920)] == 0xabcd);
    match = match && (mm[va2pa(0x7fffffffd918)] == 0x12340000);
    match = match && (mm[va2pa(0x7fffffffd910)] == 0xf7f9c0c8);         // rsp

    if (match) {
        std::cout << "memory match" << std::endl;
    } else {
        std::cout << "memory mismatch" << std::endl;
    }

    return 0;
}