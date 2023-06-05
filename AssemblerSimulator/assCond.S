
assCond:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000318 <.interp>:
 318:	2f                   	(bad)  
 319:	6c                   	insb   (%dx),%es:(%rdi)
 31a:	69 62 36 34 2f 6c 64 	imul   $0x646c2f34,0x36(%rdx),%esp
 321:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
 326:	78 2d                	js     355 <__abi_tag-0x37>
 328:	78 38                	js     362 <__abi_tag-0x2a>
 32a:	36 2d 36 34 2e 73    	ss sub $0x732e3436,%eax
 330:	6f                   	outsl  %ds:(%rsi),(%dx)
 331:	2e 32 00             	cs xor (%rax),%al

Disassembly of section .note.gnu.property:

0000000000000338 <.note.gnu.property>:
 338:	04 00                	add    $0x0,%al
 33a:	00 00                	add    %al,(%rax)
 33c:	20 00                	and    %al,(%rax)
 33e:	00 00                	add    %al,(%rax)
 340:	05 00 00 00 47       	add    $0x47000000,%eax
 345:	4e 55                	rex.WRX push %rbp
 347:	00 02                	add    %al,(%rdx)
 349:	00 00                	add    %al,(%rax)
 34b:	c0 04 00 00          	rolb   $0x0,(%rax,%rax,1)
 34f:	00 03                	add    %al,(%rbx)
 351:	00 00                	add    %al,(%rax)
 353:	00 00                	add    %al,(%rax)
 355:	00 00                	add    %al,(%rax)
 357:	00 02                	add    %al,(%rdx)
 359:	80 00 c0             	addb   $0xc0,(%rax)
 35c:	04 00                	add    $0x0,%al
 35e:	00 00                	add    %al,(%rax)
 360:	01 00                	add    %eax,(%rax)
 362:	00 00                	add    %al,(%rax)
 364:	00 00                	add    %al,(%rax)
	...

Disassembly of section .note.gnu.build-id:

0000000000000368 <.note.gnu.build-id>:
 368:	04 00                	add    $0x0,%al
 36a:	00 00                	add    %al,(%rax)
 36c:	14 00                	adc    $0x0,%al
 36e:	00 00                	add    %al,(%rax)
 370:	03 00                	add    (%rax),%eax
 372:	00 00                	add    %al,(%rax)
 374:	47                   	rex.RXB
 375:	4e 55                	rex.WRX push %rbp
 377:	00 81 d8 f9 a1 9f    	add    %al,-0x605e0628(%rcx)
 37d:	45 24 33             	rex.RB and $0x33,%al
 380:	35 a0 15 38 90       	xor    $0x903815a0,%eax
 385:	b0 4c                	mov    $0x4c,%al
 387:	0b 2f                	or     (%rdi),%ebp
 389:	a2                   	.byte 0xa2
 38a:	26                   	es
 38b:	7c                   	.byte 0x7c

Disassembly of section .note.ABI-tag:

000000000000038c <__abi_tag>:
 38c:	04 00                	add    $0x0,%al
 38e:	00 00                	add    %al,(%rax)
 390:	10 00                	adc    %al,(%rax)
 392:	00 00                	add    %al,(%rax)
 394:	01 00                	add    %eax,(%rax)
 396:	00 00                	add    %al,(%rax)
 398:	47                   	rex.RXB
 399:	4e 55                	rex.WRX push %rbp
 39b:	00 00                	add    %al,(%rax)
 39d:	00 00                	add    %al,(%rax)
 39f:	00 03                	add    %al,(%rbx)
 3a1:	00 00                	add    %al,(%rax)
 3a3:	00 02                	add    %al,(%rdx)
 3a5:	00 00                	add    %al,(%rax)
 3a7:	00 00                	add    %al,(%rax)
 3a9:	00 00                	add    %al,(%rax)
	...

Disassembly of section .gnu.hash:

00000000000003b0 <.gnu.hash>:
 3b0:	02 00                	add    (%rax),%al
 3b2:	00 00                	add    %al,(%rax)
 3b4:	05 00 00 00 01       	add    $0x1000000,%eax
 3b9:	00 00                	add    %al,(%rax)
 3bb:	00 06                	add    %al,(%rsi)
 3bd:	00 00                	add    %al,(%rax)
 3bf:	00 00                	add    %al,(%rax)
 3c1:	00 81 00 00 00 00    	add    %al,0x0(%rcx)
 3c7:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 3cd <__abi_tag+0x41>
 3cd:	00 00                	add    %al,(%rax)
 3cf:	00 d1                	add    %dl,%cl
 3d1:	65 ce                	gs (bad) 
 3d3:	6d                   	insl   (%dx),%es:(%rdi)

Disassembly of section .dynsym:

00000000000003d8 <.dynsym>:
	...
 3f0:	10 00                	adc    %al,(%rax)
 3f2:	00 00                	add    %al,(%rax)
 3f4:	12 00                	adc    (%rax),%al
	...
 406:	00 00                	add    %al,(%rax)
 408:	43 00 00             	rex.XB add %al,(%r8)
 40b:	00 20                	add    %ah,(%rax)
	...
 41d:	00 00                	add    %al,(%rax)
 41f:	00 5f 00             	add    %bl,0x0(%rdi)
 422:	00 00                	add    %al,(%rax)
 424:	20 00                	and    %al,(%rax)
	...
 436:	00 00                	add    %al,(%rax)
 438:	6e                   	outsb  %ds:(%rsi),(%dx)
 439:	00 00                	add    %al,(%rax)
 43b:	00 20                	add    %ah,(%rax)
	...
 44d:	00 00                	add    %al,(%rax)
 44f:	00 01                	add    %al,(%rcx)
 451:	00 00                	add    %al,(%rax)
 453:	00 22                	add    %ah,(%rdx)
	...

Disassembly of section .dynstr:

0000000000000468 <.dynstr>:
 468:	00 5f 5f             	add    %bl,0x5f(%rdi)
 46b:	63 78 61             	movsxd 0x61(%rax),%edi
 46e:	5f                   	pop    %rdi
 46f:	66 69 6e 61 6c 69    	imul   $0x696c,0x61(%rsi),%bp
 475:	7a 65                	jp     4dc <__abi_tag+0x150>
 477:	00 5f 5f             	add    %bl,0x5f(%rdi)
 47a:	6c                   	insb   (%dx),%es:(%rdi)
 47b:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%rdx),%esp
 482:	72 74                	jb     4f8 <__abi_tag+0x16c>
 484:	5f                   	pop    %rdi
 485:	6d                   	insl   (%dx),%es:(%rdi)
 486:	61                   	(bad)  
 487:	69 6e 00 6c 69 62 63 	imul   $0x6362696c,0x0(%rsi),%ebp
 48e:	2e 73 6f             	jae,pn 500 <__abi_tag+0x174>
 491:	2e 36 00 47 4c       	cs ss add %al,0x4c(%rdi)
 496:	49                   	rex.WB
 497:	42                   	rex.X
 498:	43 5f                	rex.XB pop %r15
 49a:	32 2e                	xor    (%rsi),%ch
 49c:	32 2e                	xor    (%rsi),%ch
 49e:	35 00 47 4c 49       	xor    $0x494c4700,%eax
 4a3:	42                   	rex.X
 4a4:	43 5f                	rex.XB pop %r15
 4a6:	32 2e                	xor    (%rsi),%ch
 4a8:	33 34 00             	xor    (%rax,%rax,1),%esi
 4ab:	5f                   	pop    %rdi
 4ac:	49 54                	rex.WB push %r12
 4ae:	4d 5f                	rex.WRB pop %r15
 4b0:	64 65 72 65          	fs gs jb 519 <__abi_tag+0x18d>
 4b4:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 4bb:	4d 
 4bc:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 4be:	6f                   	outsl  %ds:(%rsi),(%dx)
 4bf:	6e                   	outsb  %ds:(%rsi),(%dx)
 4c0:	65 54                	gs push %rsp
 4c2:	61                   	(bad)  
 4c3:	62                   	(bad)  
 4c4:	6c                   	insb   (%dx),%es:(%rdi)
 4c5:	65 00 5f 5f          	add    %bl,%gs:0x5f(%rdi)
 4c9:	67 6d                	insl   (%dx),%es:(%edi)
 4cb:	6f                   	outsl  %ds:(%rsi),(%dx)
 4cc:	6e                   	outsb  %ds:(%rsi),(%dx)
 4cd:	5f                   	pop    %rdi
 4ce:	73 74                	jae    544 <__abi_tag+0x1b8>
 4d0:	61                   	(bad)  
 4d1:	72 74                	jb     547 <__abi_tag+0x1bb>
 4d3:	5f                   	pop    %rdi
 4d4:	5f                   	pop    %rdi
 4d5:	00 5f 49             	add    %bl,0x49(%rdi)
 4d8:	54                   	push   %rsp
 4d9:	4d 5f                	rex.WRB pop %r15
 4db:	72 65                	jb     542 <__abi_tag+0x1b6>
 4dd:	67 69 73 74 65 72 54 	imul   $0x4d547265,0x74(%ebx),%esi
 4e4:	4d 
 4e5:	43 6c                	rex.XB insb (%dx),%es:(%rdi)
 4e7:	6f                   	outsl  %ds:(%rsi),(%dx)
 4e8:	6e                   	outsb  %ds:(%rsi),(%dx)
 4e9:	65 54                	gs push %rsp
 4eb:	61                   	(bad)  
 4ec:	62                   	.byte 0x62
 4ed:	6c                   	insb   (%dx),%es:(%rdi)
 4ee:	65                   	gs
	...

Disassembly of section .gnu.version:

00000000000004f0 <.gnu.version>:
 4f0:	00 00                	add    %al,(%rax)
 4f2:	02 00                	add    (%rax),%al
 4f4:	01 00                	add    %eax,(%rax)
 4f6:	01 00                	add    %eax,(%rax)
 4f8:	01 00                	add    %eax,(%rax)
 4fa:	03 00                	add    (%rax),%eax

Disassembly of section .gnu.version_r:

0000000000000500 <.gnu.version_r>:
 500:	01 00                	add    %eax,(%rax)
 502:	02 00                	add    (%rax),%al
 504:	22 00                	and    (%rax),%al
 506:	00 00                	add    %al,(%rax)
 508:	10 00                	adc    %al,(%rax)
 50a:	00 00                	add    %al,(%rax)
 50c:	00 00                	add    %al,(%rax)
 50e:	00 00                	add    %al,(%rax)
 510:	75 1a                	jne    52c <__abi_tag+0x1a0>
 512:	69 09 00 00 03 00    	imul   $0x30000,(%rcx),%ecx
 518:	2c 00                	sub    $0x0,%al
 51a:	00 00                	add    %al,(%rax)
 51c:	10 00                	adc    %al,(%rax)
 51e:	00 00                	add    %al,(%rax)
 520:	b4 91                	mov    $0x91,%ah
 522:	96                   	xchg   %eax,%esi
 523:	06                   	(bad)  
 524:	00 00                	add    %al,(%rax)
 526:	02 00                	add    (%rax),%al
 528:	38 00                	cmp    %al,(%rax)
 52a:	00 00                	add    %al,(%rax)
 52c:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

0000000000000530 <.rela.dyn>:
 530:	f0 3d 00 00 00 00    	lock cmp $0x0,%eax
 536:	00 00                	add    %al,(%rax)
 538:	08 00                	or     %al,(%rax)
 53a:	00 00                	add    %al,(%rax)
 53c:	00 00                	add    %al,(%rax)
 53e:	00 00                	add    %al,(%rax)
 540:	20 11                	and    %dl,(%rcx)
 542:	00 00                	add    %al,(%rax)
 544:	00 00                	add    %al,(%rax)
 546:	00 00                	add    %al,(%rax)
 548:	f8                   	clc    
 549:	3d 00 00 00 00       	cmp    $0x0,%eax
 54e:	00 00                	add    %al,(%rax)
 550:	08 00                	or     %al,(%rax)
 552:	00 00                	add    %al,(%rax)
 554:	00 00                	add    %al,(%rax)
 556:	00 00                	add    %al,(%rax)
 558:	e0 10                	loopne 56a <__abi_tag+0x1de>
 55a:	00 00                	add    %al,(%rax)
 55c:	00 00                	add    %al,(%rax)
 55e:	00 00                	add    %al,(%rax)
 560:	08 40 00             	or     %al,0x0(%rax)
 563:	00 00                	add    %al,(%rax)
 565:	00 00                	add    %al,(%rax)
 567:	00 08                	add    %cl,(%rax)
 569:	00 00                	add    %al,(%rax)
 56b:	00 00                	add    %al,(%rax)
 56d:	00 00                	add    %al,(%rax)
 56f:	00 08                	add    %cl,(%rax)
 571:	40 00 00             	rex add %al,(%rax)
 574:	00 00                	add    %al,(%rax)
 576:	00 00                	add    %al,(%rax)
 578:	d8 3f                	fdivrs (%rdi)
 57a:	00 00                	add    %al,(%rax)
 57c:	00 00                	add    %al,(%rax)
 57e:	00 00                	add    %al,(%rax)
 580:	06                   	(bad)  
 581:	00 00                	add    %al,(%rax)
 583:	00 01                	add    %al,(%rcx)
	...
 58d:	00 00                	add    %al,(%rax)
 58f:	00 e0                	add    %ah,%al
 591:	3f                   	(bad)  
 592:	00 00                	add    %al,(%rax)
 594:	00 00                	add    %al,(%rax)
 596:	00 00                	add    %al,(%rax)
 598:	06                   	(bad)  
 599:	00 00                	add    %al,(%rax)
 59b:	00 02                	add    %al,(%rdx)
	...
 5a5:	00 00                	add    %al,(%rax)
 5a7:	00 e8                	add    %ch,%al
 5a9:	3f                   	(bad)  
 5aa:	00 00                	add    %al,(%rax)
 5ac:	00 00                	add    %al,(%rax)
 5ae:	00 00                	add    %al,(%rax)
 5b0:	06                   	(bad)  
 5b1:	00 00                	add    %al,(%rax)
 5b3:	00 03                	add    %al,(%rbx)
	...
 5bd:	00 00                	add    %al,(%rax)
 5bf:	00 f0                	add    %dh,%al
 5c1:	3f                   	(bad)  
 5c2:	00 00                	add    %al,(%rax)
 5c4:	00 00                	add    %al,(%rax)
 5c6:	00 00                	add    %al,(%rax)
 5c8:	06                   	(bad)  
 5c9:	00 00                	add    %al,(%rax)
 5cb:	00 04 00             	add    %al,(%rax,%rax,1)
	...
 5d6:	00 00                	add    %al,(%rax)
 5d8:	f8                   	clc    
 5d9:	3f                   	(bad)  
 5da:	00 00                	add    %al,(%rax)
 5dc:	00 00                	add    %al,(%rax)
 5de:	00 00                	add    %al,(%rax)
 5e0:	06                   	(bad)  
 5e1:	00 00                	add    %al,(%rax)
 5e3:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 5e9 <__abi_tag+0x25d>
 5e9:	00 00                	add    %al,(%rax)
 5eb:	00 00                	add    %al,(%rax)
 5ed:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 a2 2f 00 00    	push   0x2fa2(%rip)        # 3fc8 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 a3 2f 00 00 	bnd jmp *0x2fa3(%rip)        # 3fd0 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)

Disassembly of section .plt.got:

0000000000001030 <__cxa_finalize@plt>:
    1030:	f3 0f 1e fa          	endbr64 
    1034:	f2 ff 25 bd 2f 00 00 	bnd jmp *0x2fbd(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    103b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001040 <_start>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	31 ed                	xor    %ebp,%ebp
    1046:	49 89 d1             	mov    %rdx,%r9
    1049:	5e                   	pop    %rsi
    104a:	48 89 e2             	mov    %rsp,%rdx
    104d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1051:	50                   	push   %rax
    1052:	54                   	push   %rsp
    1053:	45 31 c0             	xor    %r8d,%r8d
    1056:	31 c9                	xor    %ecx,%ecx
    1058:	48 8d 3d 01 01 00 00 	lea    0x101(%rip),%rdi        # 1160 <main>
    105f:	ff 15 73 2f 00 00    	call   *0x2f73(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1065:	f4                   	hlt    
    1066:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    106d:	00 00 00 

0000000000001070 <deregister_tm_clones>:
    1070:	48 8d 3d 99 2f 00 00 	lea    0x2f99(%rip),%rdi        # 4010 <__TMC_END__>
    1077:	48 8d 05 92 2f 00 00 	lea    0x2f92(%rip),%rax        # 4010 <__TMC_END__>
    107e:	48 39 f8             	cmp    %rdi,%rax
    1081:	74 15                	je     1098 <deregister_tm_clones+0x28>
    1083:	48 8b 05 56 2f 00 00 	mov    0x2f56(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    108a:	48 85 c0             	test   %rax,%rax
    108d:	74 09                	je     1098 <deregister_tm_clones+0x28>
    108f:	ff e0                	jmp    *%rax
    1091:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1098:	c3                   	ret    
    1099:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010a0 <register_tm_clones>:
    10a0:	48 8d 3d 69 2f 00 00 	lea    0x2f69(%rip),%rdi        # 4010 <__TMC_END__>
    10a7:	48 8d 35 62 2f 00 00 	lea    0x2f62(%rip),%rsi        # 4010 <__TMC_END__>
    10ae:	48 29 fe             	sub    %rdi,%rsi
    10b1:	48 89 f0             	mov    %rsi,%rax
    10b4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10b8:	48 c1 f8 03          	sar    $0x3,%rax
    10bc:	48 01 c6             	add    %rax,%rsi
    10bf:	48 d1 fe             	sar    %rsi
    10c2:	74 14                	je     10d8 <register_tm_clones+0x38>
    10c4:	48 8b 05 25 2f 00 00 	mov    0x2f25(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    10cb:	48 85 c0             	test   %rax,%rax
    10ce:	74 08                	je     10d8 <register_tm_clones+0x38>
    10d0:	ff e0                	jmp    *%rax
    10d2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    10d8:	c3                   	ret    
    10d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010e0 <__do_global_dtors_aux>:
    10e0:	f3 0f 1e fa          	endbr64 
    10e4:	80 3d 25 2f 00 00 00 	cmpb   $0x0,0x2f25(%rip)        # 4010 <__TMC_END__>
    10eb:	75 2b                	jne    1118 <__do_global_dtors_aux+0x38>
    10ed:	55                   	push   %rbp
    10ee:	48 83 3d 02 2f 00 00 	cmpq   $0x0,0x2f02(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    10f5:	00 
    10f6:	48 89 e5             	mov    %rsp,%rbp
    10f9:	74 0c                	je     1107 <__do_global_dtors_aux+0x27>
    10fb:	48 8b 3d 06 2f 00 00 	mov    0x2f06(%rip),%rdi        # 4008 <__dso_handle>
    1102:	e8 29 ff ff ff       	call   1030 <__cxa_finalize@plt>
    1107:	e8 64 ff ff ff       	call   1070 <deregister_tm_clones>
    110c:	c6 05 fd 2e 00 00 01 	movb   $0x1,0x2efd(%rip)        # 4010 <__TMC_END__>
    1113:	5d                   	pop    %rbp
    1114:	c3                   	ret    
    1115:	0f 1f 00             	nopl   (%rax)
    1118:	c3                   	ret    
    1119:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001120 <frame_dummy>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	e9 77 ff ff ff       	jmp    10a0 <register_tm_clones>

0000000000001129 <_Z3summ>:
    1129:	f3 0f 1e fa          	endbr64 
    112d:	55                   	push   %rbp
    112e:	48 89 e5             	mov    %rsp,%rbp
    1131:	48 83 ec 10          	sub    $0x10,%rsp
    1135:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    1139:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    113e:	75 07                	jne    1147 <_Z3summ+0x1e>
    1140:	b8 00 00 00 00       	mov    $0x0,%eax
    1145:	eb 17                	jmp    115e <_Z3summ+0x35>
    1147:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    114b:	48 83 e8 01          	sub    $0x1,%rax
    114f:	48 89 c7             	mov    %rax,%rdi
    1152:	e8 d2 ff ff ff       	call   1129 <_Z3summ>
    1157:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    115b:	48 01 d0             	add    %rdx,%rax
    115e:	c9                   	leave  
    115f:	c3                   	ret    

0000000000001160 <main>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	55                   	push   %rbp
    1165:	48 89 e5             	mov    %rsp,%rbp
    1168:	48 83 ec 10          	sub    $0x10,%rsp
    116c:	bf 03 00 00 00       	mov    $0x3,%edi
    1171:	e8 b3 ff ff ff       	call   1129 <_Z3summ>
    1176:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    117a:	b8 00 00 00 00       	mov    $0x0,%eax
    117f:	c9                   	leave  
    1180:	c3                   	ret    

Disassembly of section .fini:

0000000000001184 <_fini>:
    1184:	f3 0f 1e fa          	endbr64 
    1188:	48 83 ec 08          	sub    $0x8,%rsp
    118c:	48 83 c4 08          	add    $0x8,%rsp
    1190:	c3                   	ret    

Disassembly of section .rodata:

0000000000002000 <_IO_stdin_used>:
    2000:	01 00                	add    %eax,(%rax)
    2002:	02 00                	add    (%rax),%al

Disassembly of section .eh_frame_hdr:

0000000000002004 <__GNU_EH_FRAME_HDR>:
    2004:	01 1b                	add    %ebx,(%rbx)
    2006:	03 3b                	add    (%rbx),%edi
    2008:	30 00                	xor    %al,(%rax)
    200a:	00 00                	add    %al,(%rax)
    200c:	05 00 00 00 1c       	add    $0x1c000000,%eax
    2011:	f0 ff                	lock (bad) 
    2013:	ff 64 00 00          	jmp    *0x0(%rax,%rax,1)
    2017:	00 2c f0             	add    %ch,(%rax,%rsi,8)
    201a:	ff                   	(bad)  
    201b:	ff 8c 00 00 00 3c f0 	decl   -0xfc40000(%rax,%rax,1)
    2022:	ff                   	(bad)  
    2023:	ff 4c 00 00          	decl   0x0(%rax,%rax,1)
    2027:	00 25 f1 ff ff a4    	add    %ah,-0x5b00000f(%rip)        # ffffffffa500201e <_end+0xffffffffa4ffe006>
    202d:	00 00                	add    %al,(%rax)
    202f:	00 5c f1 ff          	add    %bl,-0x1(%rcx,%rsi,8)
    2033:	ff c4                	inc    %esp
    2035:	00 00                	add    %al,(%rax)
	...

Disassembly of section .eh_frame:

0000000000002038 <__FRAME_END__-0xb0>:
    2038:	14 00                	adc    $0x0,%al
    203a:	00 00                	add    %al,(%rax)
    203c:	00 00                	add    %al,(%rax)
    203e:	00 00                	add    %al,(%rax)
    2040:	01 7a 52             	add    %edi,0x52(%rdx)
    2043:	00 01                	add    %al,(%rcx)
    2045:	78 10                	js     2057 <__GNU_EH_FRAME_HDR+0x53>
    2047:	01 1b                	add    %ebx,(%rbx)
    2049:	0c 07                	or     $0x7,%al
    204b:	08 90 01 00 00 14    	or     %dl,0x14000001(%rax)
    2051:	00 00                	add    %al,(%rax)
    2053:	00 1c 00             	add    %bl,(%rax,%rax,1)
    2056:	00 00                	add    %al,(%rax)
    2058:	e8 ef ff ff 26       	call   2700204c <_end+0x26ffe034>
    205d:	00 00                	add    %al,(%rax)
    205f:	00 00                	add    %al,(%rax)
    2061:	44 07                	rex.R (bad) 
    2063:	10 00                	adc    %al,(%rax)
    2065:	00 00                	add    %al,(%rax)
    2067:	00 24 00             	add    %ah,(%rax,%rax,1)
    206a:	00 00                	add    %al,(%rax)
    206c:	34 00                	xor    $0x0,%al
    206e:	00 00                	add    %al,(%rax)
    2070:	b0 ef                	mov    $0xef,%al
    2072:	ff                   	(bad)  
    2073:	ff 10                	call   *(%rax)
    2075:	00 00                	add    %al,(%rax)
    2077:	00 00                	add    %al,(%rax)
    2079:	0e                   	(bad)  
    207a:	10 46 0e             	adc    %al,0xe(%rsi)
    207d:	18 4a 0f             	sbb    %cl,0xf(%rdx)
    2080:	0b 77 08             	or     0x8(%rdi),%esi
    2083:	80 00 3f             	addb   $0x3f,(%rax)
    2086:	1a 3a                	sbb    (%rdx),%bh
    2088:	2a 33                	sub    (%rbx),%dh
    208a:	24 22                	and    $0x22,%al
    208c:	00 00                	add    %al,(%rax)
    208e:	00 00                	add    %al,(%rax)
    2090:	14 00                	adc    $0x0,%al
    2092:	00 00                	add    %al,(%rax)
    2094:	5c                   	pop    %rsp
    2095:	00 00                	add    %al,(%rax)
    2097:	00 98 ef ff ff 10    	add    %bl,0x10ffffef(%rax)
	...
    20a5:	00 00                	add    %al,(%rax)
    20a7:	00 1c 00             	add    %bl,(%rax,%rax,1)
    20aa:	00 00                	add    %al,(%rax)
    20ac:	74 00                	je     20ae <__GNU_EH_FRAME_HDR+0xaa>
    20ae:	00 00                	add    %al,(%rax)
    20b0:	79 f0                	jns    20a2 <__GNU_EH_FRAME_HDR+0x9e>
    20b2:	ff                   	(bad)  
    20b3:	ff 37                	push   (%rdi)
    20b5:	00 00                	add    %al,(%rax)
    20b7:	00 00                	add    %al,(%rax)
    20b9:	45 0e                	rex.RB (bad) 
    20bb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    20c1:	6e                   	outsb  %ds:(%rsi),(%dx)
    20c2:	0c 07                	or     $0x7,%al
    20c4:	08 00                	or     %al,(%rax)
    20c6:	00 00                	add    %al,(%rax)
    20c8:	1c 00                	sbb    $0x0,%al
    20ca:	00 00                	add    %al,(%rax)
    20cc:	94                   	xchg   %eax,%esp
    20cd:	00 00                	add    %al,(%rax)
    20cf:	00 90 f0 ff ff 21    	add    %dl,0x21fffff0(%rax)
    20d5:	00 00                	add    %al,(%rax)
    20d7:	00 00                	add    %al,(%rax)
    20d9:	45 0e                	rex.RB (bad) 
    20db:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
    20e1:	58                   	pop    %rax
    20e2:	0c 07                	or     $0x7,%al
    20e4:	08 00                	or     %al,(%rax)
	...

00000000000020e8 <__FRAME_END__>:
    20e8:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000003df0 <__frame_dummy_init_array_entry>:
    3df0:	20 11                	and    %dl,(%rcx)
    3df2:	00 00                	add    %al,(%rax)
    3df4:	00 00                	add    %al,(%rax)
	...

Disassembly of section .fini_array:

0000000000003df8 <__do_global_dtors_aux_fini_array_entry>:
    3df8:	e0 10                	loopne 3e0a <_DYNAMIC+0xa>
    3dfa:	00 00                	add    %al,(%rax)
    3dfc:	00 00                	add    %al,(%rax)
	...

Disassembly of section .dynamic:

0000000000003e00 <_DYNAMIC>:
    3e00:	01 00                	add    %eax,(%rax)
    3e02:	00 00                	add    %al,(%rax)
    3e04:	00 00                	add    %al,(%rax)
    3e06:	00 00                	add    %al,(%rax)
    3e08:	22 00                	and    (%rax),%al
    3e0a:	00 00                	add    %al,(%rax)
    3e0c:	00 00                	add    %al,(%rax)
    3e0e:	00 00                	add    %al,(%rax)
    3e10:	0c 00                	or     $0x0,%al
    3e12:	00 00                	add    %al,(%rax)
    3e14:	00 00                	add    %al,(%rax)
    3e16:	00 00                	add    %al,(%rax)
    3e18:	00 10                	add    %dl,(%rax)
    3e1a:	00 00                	add    %al,(%rax)
    3e1c:	00 00                	add    %al,(%rax)
    3e1e:	00 00                	add    %al,(%rax)
    3e20:	0d 00 00 00 00       	or     $0x0,%eax
    3e25:	00 00                	add    %al,(%rax)
    3e27:	00 84 11 00 00 00 00 	add    %al,0x0(%rcx,%rdx,1)
    3e2e:	00 00                	add    %al,(%rax)
    3e30:	19 00                	sbb    %eax,(%rax)
    3e32:	00 00                	add    %al,(%rax)
    3e34:	00 00                	add    %al,(%rax)
    3e36:	00 00                	add    %al,(%rax)
    3e38:	f0 3d 00 00 00 00    	lock cmp $0x0,%eax
    3e3e:	00 00                	add    %al,(%rax)
    3e40:	1b 00                	sbb    (%rax),%eax
    3e42:	00 00                	add    %al,(%rax)
    3e44:	00 00                	add    %al,(%rax)
    3e46:	00 00                	add    %al,(%rax)
    3e48:	08 00                	or     %al,(%rax)
    3e4a:	00 00                	add    %al,(%rax)
    3e4c:	00 00                	add    %al,(%rax)
    3e4e:	00 00                	add    %al,(%rax)
    3e50:	1a 00                	sbb    (%rax),%al
    3e52:	00 00                	add    %al,(%rax)
    3e54:	00 00                	add    %al,(%rax)
    3e56:	00 00                	add    %al,(%rax)
    3e58:	f8                   	clc    
    3e59:	3d 00 00 00 00       	cmp    $0x0,%eax
    3e5e:	00 00                	add    %al,(%rax)
    3e60:	1c 00                	sbb    $0x0,%al
    3e62:	00 00                	add    %al,(%rax)
    3e64:	00 00                	add    %al,(%rax)
    3e66:	00 00                	add    %al,(%rax)
    3e68:	08 00                	or     %al,(%rax)
    3e6a:	00 00                	add    %al,(%rax)
    3e6c:	00 00                	add    %al,(%rax)
    3e6e:	00 00                	add    %al,(%rax)
    3e70:	f5                   	cmc    
    3e71:	fe                   	(bad)  
    3e72:	ff 6f 00             	ljmp   *0x0(%rdi)
    3e75:	00 00                	add    %al,(%rax)
    3e77:	00 b0 03 00 00 00    	add    %dh,0x3(%rax)
    3e7d:	00 00                	add    %al,(%rax)
    3e7f:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 3e85 <_DYNAMIC+0x85>
    3e85:	00 00                	add    %al,(%rax)
    3e87:	00 68 04             	add    %ch,0x4(%rax)
    3e8a:	00 00                	add    %al,(%rax)
    3e8c:	00 00                	add    %al,(%rax)
    3e8e:	00 00                	add    %al,(%rax)
    3e90:	06                   	(bad)  
    3e91:	00 00                	add    %al,(%rax)
    3e93:	00 00                	add    %al,(%rax)
    3e95:	00 00                	add    %al,(%rax)
    3e97:	00 d8                	add    %bl,%al
    3e99:	03 00                	add    (%rax),%eax
    3e9b:	00 00                	add    %al,(%rax)
    3e9d:	00 00                	add    %al,(%rax)
    3e9f:	00 0a                	add    %cl,(%rdx)
    3ea1:	00 00                	add    %al,(%rax)
    3ea3:	00 00                	add    %al,(%rax)
    3ea5:	00 00                	add    %al,(%rax)
    3ea7:	00 88 00 00 00 00    	add    %cl,0x0(%rax)
    3ead:	00 00                	add    %al,(%rax)
    3eaf:	00 0b                	add    %cl,(%rbx)
    3eb1:	00 00                	add    %al,(%rax)
    3eb3:	00 00                	add    %al,(%rax)
    3eb5:	00 00                	add    %al,(%rax)
    3eb7:	00 18                	add    %bl,(%rax)
    3eb9:	00 00                	add    %al,(%rax)
    3ebb:	00 00                	add    %al,(%rax)
    3ebd:	00 00                	add    %al,(%rax)
    3ebf:	00 15 00 00 00 00    	add    %dl,0x0(%rip)        # 3ec5 <_DYNAMIC+0xc5>
	...
    3ecd:	00 00                	add    %al,(%rax)
    3ecf:	00 03                	add    %al,(%rbx)
    3ed1:	00 00                	add    %al,(%rax)
    3ed3:	00 00                	add    %al,(%rax)
    3ed5:	00 00                	add    %al,(%rax)
    3ed7:	00 c0                	add    %al,%al
    3ed9:	3f                   	(bad)  
    3eda:	00 00                	add    %al,(%rax)
    3edc:	00 00                	add    %al,(%rax)
    3ede:	00 00                	add    %al,(%rax)
    3ee0:	07                   	(bad)  
    3ee1:	00 00                	add    %al,(%rax)
    3ee3:	00 00                	add    %al,(%rax)
    3ee5:	00 00                	add    %al,(%rax)
    3ee7:	00 30                	add    %dh,(%rax)
    3ee9:	05 00 00 00 00       	add    $0x0,%eax
    3eee:	00 00                	add    %al,(%rax)
    3ef0:	08 00                	or     %al,(%rax)
    3ef2:	00 00                	add    %al,(%rax)
    3ef4:	00 00                	add    %al,(%rax)
    3ef6:	00 00                	add    %al,(%rax)
    3ef8:	c0 00 00             	rolb   $0x0,(%rax)
    3efb:	00 00                	add    %al,(%rax)
    3efd:	00 00                	add    %al,(%rax)
    3eff:	00 09                	add    %cl,(%rcx)
    3f01:	00 00                	add    %al,(%rax)
    3f03:	00 00                	add    %al,(%rax)
    3f05:	00 00                	add    %al,(%rax)
    3f07:	00 18                	add    %bl,(%rax)
    3f09:	00 00                	add    %al,(%rax)
    3f0b:	00 00                	add    %al,(%rax)
    3f0d:	00 00                	add    %al,(%rax)
    3f0f:	00 1e                	add    %bl,(%rsi)
    3f11:	00 00                	add    %al,(%rax)
    3f13:	00 00                	add    %al,(%rax)
    3f15:	00 00                	add    %al,(%rax)
    3f17:	00 08                	add    %cl,(%rax)
    3f19:	00 00                	add    %al,(%rax)
    3f1b:	00 00                	add    %al,(%rax)
    3f1d:	00 00                	add    %al,(%rax)
    3f1f:	00 fb                	add    %bh,%bl
    3f21:	ff                   	(bad)  
    3f22:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f25:	00 00                	add    %al,(%rax)
    3f27:	00 01                	add    %al,(%rcx)
    3f29:	00 00                	add    %al,(%rax)
    3f2b:	08 00                	or     %al,(%rax)
    3f2d:	00 00                	add    %al,(%rax)
    3f2f:	00 fe                	add    %bh,%dh
    3f31:	ff                   	(bad)  
    3f32:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f35:	00 00                	add    %al,(%rax)
    3f37:	00 00                	add    %al,(%rax)
    3f39:	05 00 00 00 00       	add    $0x0,%eax
    3f3e:	00 00                	add    %al,(%rax)
    3f40:	ff                   	(bad)  
    3f41:	ff                   	(bad)  
    3f42:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f45:	00 00                	add    %al,(%rax)
    3f47:	00 01                	add    %al,(%rcx)
    3f49:	00 00                	add    %al,(%rax)
    3f4b:	00 00                	add    %al,(%rax)
    3f4d:	00 00                	add    %al,(%rax)
    3f4f:	00 f0                	add    %dh,%al
    3f51:	ff                   	(bad)  
    3f52:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f55:	00 00                	add    %al,(%rax)
    3f57:	00 f0                	add    %dh,%al
    3f59:	04 00                	add    $0x0,%al
    3f5b:	00 00                	add    %al,(%rax)
    3f5d:	00 00                	add    %al,(%rax)
    3f5f:	00 f9                	add    %bh,%cl
    3f61:	ff                   	(bad)  
    3f62:	ff 6f 00             	ljmp   *0x0(%rdi)
    3f65:	00 00                	add    %al,(%rax)
    3f67:	00 03                	add    %al,(%rbx)
	...

Disassembly of section .got:

0000000000003fc0 <_GLOBAL_OFFSET_TABLE_>:
    3fc0:	00 3e                	add    %bh,(%rsi)
	...

Disassembly of section .data:

0000000000004000 <__data_start>:
	...

0000000000004008 <__dso_handle>:
    4008:	08 40 00             	or     %al,0x0(%rax)
    400b:	00 00                	add    %al,(%rax)
    400d:	00 00                	add    %al,(%rax)
	...

Disassembly of section .bss:

0000000000004010 <completed.0>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp (%r8),%spl
   5:	28 55 62             	sub    %dl,0x62(%rbp)
   8:	75 6e                	jne    78 <__abi_tag-0x314>
   a:	74 75                	je     81 <__abi_tag-0x30b>
   c:	20 31                	and    %dh,(%rcx)
   e:	31 2e                	xor    %ebp,(%rsi)
  10:	33 2e                	xor    (%rsi),%ebp
  12:	30 2d 31 75 62 75    	xor    %ch,0x75627531(%rip)        # 75627549 <_end+0x75623531>
  18:	6e                   	outsb  %ds:(%rsi),(%dx)
  19:	74 75                	je     90 <__abi_tag-0x2fc>
  1b:	31 7e 32             	xor    %edi,0x32(%rsi)
  1e:	32 2e                	xor    (%rsi),%ch
  20:	30 34 2e             	xor    %dh,(%rsi,%rbp,1)
  23:	31 29                	xor    %ebp,(%rcx)
  25:	20 31                	and    %dh,(%rcx)
  27:	31 2e                	xor    %ebp,(%rsi)
  29:	33 2e                	xor    (%rsi),%ebp
  2b:	30 00                	xor    %al,(%rax)

Disassembly of section .debug_aranges:

0000000000000000 <.debug_aranges>:
   0:	2c 00                	sub    $0x0,%al
   2:	00 00                	add    %al,(%rax)
   4:	02 00                	add    (%rax),%al
   6:	00 00                	add    %al,(%rax)
   8:	00 00                	add    %al,(%rax)
   a:	08 00                	or     %al,(%rax)
   c:	00 00                	add    %al,(%rax)
   e:	00 00                	add    %al,(%rax)
  10:	29 11                	sub    %edx,(%rcx)
  12:	00 00                	add    %al,(%rax)
  14:	00 00                	add    %al,(%rax)
  16:	00 00                	add    %al,(%rax)
  18:	58                   	pop    %rax
	...

Disassembly of section .debug_info:

0000000000000000 <.debug_info>:
   0:	e2 00                	loop   2 <__abi_tag-0x38a>
   2:	00 00                	add    %al,(%rax)
   4:	05 00 01 08 00       	add    $0x80100,%eax
   9:	00 00                	add    %al,(%rax)
   b:	00 03                	add    %al,(%rbx)
   d:	08 00                	or     %al,(%rax)
   f:	00 00                	add    %al,(%rax)
  11:	21 00                	and    %eax,(%rax)
  13:	00 00                	add    %al,(%rax)
  15:	00 2a                	add    %ch,(%rdx)
  17:	00 00                	add    %al,(%rax)
  19:	00 29                	add    %ch,(%rcx)
  1b:	11 00                	adc    %eax,(%rax)
  1d:	00 00                	add    %al,(%rax)
  1f:	00 00                	add    %al,(%rax)
  21:	00 58 00             	add    %bl,0x0(%rax)
	...
  2c:	00 00                	add    %al,(%rax)
  2e:	01 01                	add    %eax,(%rcx)
  30:	08 aa 00 00 00 01    	or     %ch,0x1000000(%rdx)
  36:	02 07                	add    (%rdi),%al
  38:	d1 00                	roll   (%rax)
  3a:	00 00                	add    %al,(%rax)
  3c:	01 04 07             	add    %eax,(%rdi,%rax,1)
  3f:	9d                   	popf   
  40:	00 00                	add    %al,(%rax)
  42:	00 01                	add    %al,(%rcx)
  44:	08 07                	or     %al,(%rdi)
  46:	98                   	cwtl   
  47:	00 00                	add    %al,(%rax)
  49:	00 01                	add    %al,(%rcx)
  4b:	01 06                	add    %eax,(%rsi)
  4d:	ac                   	lods   %ds:(%rsi),%al
  4e:	00 00                	add    %al,(%rax)
  50:	00 01                	add    %al,(%rcx)
  52:	02 05 e4 00 00 00    	add    0xe4(%rip),%al        # 13c <__abi_tag-0x250>
  58:	04 04                	add    $0x4,%al
  5a:	05 69 6e 74 00       	add    $0x746e69,%eax
  5f:	01 08                	add    %ecx,(%rax)
  61:	05 bd 00 00 00       	add    $0xbd,%eax
  66:	02 c6                	add    %dh,%al
  68:	00 00                	add    %al,(%rax)
  6a:	00 02                	add    %al,(%rdx)
  6c:	2d 1b 43 00 00       	sub    $0x431b,%eax
  71:	00 01                	add    %al,(%rcx)
  73:	01 06                	add    %eax,(%rsi)
  75:	b3 00                	mov    $0x0,%bl
  77:	00 00                	add    %al,(%rax)
  79:	02 c8                	add    %al,%cl
  7b:	00 00                	add    %al,(%rax)
  7d:	00 03                	add    %al,(%rbx)
  7f:	1b 14 66             	sbb    (%rsi,%riz,2),%edx
  82:	00 00                	add    %al,(%rax)
  84:	00 05 b8 00 00 00    	add    %al,0xb8(%rip)        # 142 <__abi_tag-0x24a>
  8a:	01 0c 05 58 00 00 00 	add    %ecx,0x58(,%rax,1)
  91:	60                   	(bad)  
  92:	11 00                	adc    %eax,(%rax)
  94:	00 00                	add    %al,(%rax)
  96:	00 00                	add    %al,(%rax)
  98:	00 21                	add    %ah,(%rcx)
  9a:	00 00                	add    %al,(%rax)
  9c:	00 00                	add    %al,(%rax)
  9e:	00 00                	add    %al,(%rax)
  a0:	00 01                	add    %al,(%rcx)
  a2:	9c                   	pushf  
  a3:	b5 00                	mov    $0x0,%ch
  a5:	00 00                	add    %al,(%rax)
  a7:	06                   	(bad)  
  a8:	61                   	(bad)  
  a9:	00 01                	add    %al,(%rcx)
  ab:	0e                   	(bad)  
  ac:	0e                   	(bad)  
  ad:	79 00                	jns    af <__abi_tag-0x2dd>
  af:	00 00                	add    %al,(%rax)
  b1:	02 91 68 00 07 73    	add    0x73070068(%rcx),%dl
  b7:	75 6d                	jne    126 <__abi_tag-0x266>
  b9:	00 01                	add    %al,(%rcx)
  bb:	03 0a                	add    (%rdx),%ecx
  bd:	00 00                	add    %al,(%rax)
  bf:	00 00                	add    %al,(%rax)
  c1:	79 00                	jns    c3 <__abi_tag-0x2c9>
  c3:	00 00                	add    %al,(%rax)
  c5:	29 11                	sub    %edx,(%rcx)
  c7:	00 00                	add    %al,(%rax)
  c9:	00 00                	add    %al,(%rax)
  cb:	00 00                	add    %al,(%rax)
  cd:	37                   	(bad)  
  ce:	00 00                	add    %al,(%rax)
  d0:	00 00                	add    %al,(%rax)
  d2:	00 00                	add    %al,(%rax)
  d4:	00 01                	add    %al,(%rcx)
  d6:	9c                   	pushf  
  d7:	08 6e 00             	or     %ch,0x0(%rsi)
  da:	01 03                	add    %eax,(%rbx)
  dc:	17                   	(bad)  
  dd:	79 00                	jns    df <__abi_tag-0x2ad>
  df:	00 00                	add    %al,(%rax)
  e1:	02                   	.byte 0x2
  e2:	91                   	xchg   %eax,%ecx
  e3:	68                   	.byte 0x68
	...

Disassembly of section .debug_abbrev:

0000000000000000 <.debug_abbrev>:
   0:	01 24 00             	add    %esp,(%rax,%rax,1)
   3:	0b 0b                	or     (%rbx),%ecx
   5:	3e 0b 03             	ds or  (%rbx),%eax
   8:	0e                   	(bad)  
   9:	00 00                	add    %al,(%rax)
   b:	02 16                	add    (%rsi),%dl
   d:	00 03                	add    %al,(%rbx)
   f:	0e                   	(bad)  
  10:	3a 0b                	cmp    (%rbx),%cl
  12:	3b 0b                	cmp    (%rbx),%ecx
  14:	39 0b                	cmp    %ecx,(%rbx)
  16:	49 13 00             	adc    (%r8),%rax
  19:	00 03                	add    %al,(%rbx)
  1b:	11 01                	adc    %eax,(%rcx)
  1d:	25 0e 13 0b 03       	and    $0x30b130e,%eax
  22:	1f                   	(bad)  
  23:	1b 1f                	sbb    (%rdi),%ebx
  25:	11 01                	adc    %eax,(%rcx)
  27:	12 07                	adc    (%rdi),%al
  29:	10 17                	adc    %dl,(%rdi)
  2b:	00 00                	add    %al,(%rax)
  2d:	04 24                	add    $0x24,%al
  2f:	00 0b                	add    %cl,(%rbx)
  31:	0b 3e                	or     (%rsi),%edi
  33:	0b 03                	or     (%rbx),%eax
  35:	08 00                	or     %al,(%rax)
  37:	00 05 2e 01 3f 19    	add    %al,0x193f012e(%rip)        # 193f016b <_end+0x193ec153>
  3d:	03 0e                	add    (%rsi),%ecx
  3f:	3a 0b                	cmp    (%rbx),%cl
  41:	3b 0b                	cmp    (%rbx),%ecx
  43:	39 0b                	cmp    %ecx,(%rbx)
  45:	49 13 11             	adc    (%r9),%rdx
  48:	01 12                	add    %edx,(%rdx)
  4a:	07                   	(bad)  
  4b:	40 18 7c 19 01       	sbb    %dil,0x1(%rcx,%rbx,1)
  50:	13 00                	adc    (%rax),%eax
  52:	00 06                	add    %al,(%rsi)
  54:	34 00                	xor    $0x0,%al
  56:	03 08                	add    (%rax),%ecx
  58:	3a 0b                	cmp    (%rbx),%cl
  5a:	3b 0b                	cmp    (%rbx),%ecx
  5c:	39 0b                	cmp    %ecx,(%rbx)
  5e:	49 13 02             	adc    (%r10),%rax
  61:	18 00                	sbb    %al,(%rax)
  63:	00 07                	add    %al,(%rdi)
  65:	2e 01 3f             	cs add %edi,(%rdi)
  68:	19 03                	sbb    %eax,(%rbx)
  6a:	08 3a                	or     %bh,(%rdx)
  6c:	0b 3b                	or     (%rbx),%edi
  6e:	0b 39                	or     (%rcx),%edi
  70:	0b 6e 0e             	or     0xe(%rsi),%ebp
  73:	49 13 11             	adc    (%r9),%rdx
  76:	01 12                	add    %edx,(%rdx)
  78:	07                   	(bad)  
  79:	40 18 7c 19 00       	sbb    %dil,0x0(%rcx,%rbx,1)
  7e:	00 08                	add    %cl,(%rax)
  80:	05 00 03 08 3a       	add    $0x3a080300,%eax
  85:	0b 3b                	or     (%rbx),%edi
  87:	0b 39                	or     (%rcx),%edi
  89:	0b 49 13             	or     0x13(%rcx),%ecx
  8c:	02 18                	add    (%rax),%bl
  8e:	00 00                	add    %al,(%rax)
	...

Disassembly of section .debug_line:

0000000000000000 <.debug_line>:
   0:	70 00                	jo     2 <__abi_tag-0x38a>
   2:	00 00                	add    %al,(%rax)
   4:	05 00 08 00 3c       	add    $0x3c000800,%eax
   9:	00 00                	add    %al,(%rax)
   b:	00 01                	add    %al,(%rcx)
   d:	01 01                	add    %eax,(%rcx)
   f:	fb                   	sti    
  10:	0e                   	(bad)  
  11:	0d 00 01 01 01       	or     $0x1010100,%eax
  16:	01 00                	add    %eax,(%rax)
  18:	00 00                	add    %al,(%rax)
  1a:	01 00                	add    %eax,(%rax)
  1c:	00 01                	add    %al,(%rcx)
  1e:	01 01                	add    %eax,(%rcx)
  20:	1f                   	(bad)  
  21:	03 2a                	add    (%rdx),%ebp
  23:	00 00                	add    %al,(%rax)
  25:	00 49 00             	add    %cl,0x0(%rcx)
  28:	00 00                	add    %al,(%rax)
  2a:	67 00 00             	add    %al,(%eax)
  2d:	00 02                	add    %al,(%rdx)
  2f:	01 1f                	add    %ebx,(%rdi)
  31:	02 0f                	add    (%rdi),%cl
  33:	04 1e                	add    $0x1e,%al
  35:	00 00                	add    %al,(%rax)
  37:	00 01                	add    %al,(%rcx)
  39:	1e                   	(bad)  
  3a:	00 00                	add    %al,(%rax)
  3c:	00 01                	add    %al,(%rcx)
  3e:	8a 00                	mov    (%rax),%al
  40:	00 00                	add    %al,(%rax)
  42:	02 92 00 00 00 02    	add    0x2000000(%rdx),%dl
  48:	05 1a 00 09 02       	add    $0x209001a,%eax
  4d:	29 11                	sub    %edx,(%rcx)
  4f:	00 00                	add    %al,(%rax)
  51:	00 00                	add    %al,(%rax)
  53:	00 00                	add    %al,(%rax)
  55:	14 05                	adc    $0x5,%al
  57:	05 f3 05 10 75       	add    $0x751005f3,%eax
  5c:	05 17 77 05 1d       	add    $0x1d057717,%eax
  61:	f2 05 01 76 31 05    	repnz add $0x5317601,%eax
  67:	15 bb 05 0c d8       	adc    $0xd80c05bb,%eax
  6c:	05 01 59 02 02       	add    $0x2025901,%eax
  71:	00 01                	add    %al,(%rcx)
  73:	01                   	.byte 0x1

Disassembly of section .debug_str:

0000000000000000 <.debug_str>:
   0:	5f                   	pop    %rdi
   1:	5a                   	pop    %rdx
   2:	33 73 75             	xor    0x75(%rbx),%esi
   5:	6d                   	insl   (%dx),%es:(%rdi)
   6:	6d                   	insl   (%dx),%es:(%rdi)
   7:	00 47 4e             	add    %al,0x4e(%rdi)
   a:	55                   	push   %rbp
   b:	20 43 2b             	and    %al,0x2b(%rbx)
   e:	2b 31                	sub    (%rcx),%esi
  10:	37                   	(bad)  
  11:	20 31                	and    %dh,(%rcx)
  13:	31 2e                	xor    %ebp,(%rsi)
  15:	33 2e                	xor    (%rsi),%ebp
  17:	30 20                	xor    %ah,(%rax)
  19:	2d 6d 74 75 6e       	sub    $0x6e75746d,%eax
  1e:	65 3d 67 65 6e 65    	gs cmp $0x656e6567,%eax
  24:	72 69                	jb     8f <__abi_tag-0x2fd>
  26:	63 20                	movsxd (%rax),%esp
  28:	2d 6d 61 72 63       	sub    $0x6372616d,%eax
  2d:	68 3d 78 38 36       	push   $0x3638783d
  32:	2d 36 34 20 2d       	sub    $0x2d203436,%eax
  37:	67 20 2d 66 61 73 79 	and    %ch,0x79736166(%eip)        # 797361a4 <_end+0x7973218c>
  3e:	6e                   	outsb  %ds:(%rsi),(%dx)
  3f:	63 68 72             	movsxd 0x72(%rax),%ebp
  42:	6f                   	outsl  %ds:(%rsi),(%dx)
  43:	6e                   	outsb  %ds:(%rsi),(%dx)
  44:	6f                   	outsl  %ds:(%rsi),(%dx)
  45:	75 73                	jne    ba <__abi_tag-0x2d2>
  47:	2d 75 6e 77 69       	sub    $0x69776e75,%eax
  4c:	6e                   	outsb  %ds:(%rsi),(%dx)
  4d:	64 2d 74 61 62 6c    	fs sub $0x6c626174,%eax
  53:	65 73 20             	gs jae 76 <__abi_tag-0x316>
  56:	2d 66 73 74 61       	sub    $0x61747366,%eax
  5b:	63 6b 2d             	movsxd 0x2d(%rbx),%ebp
  5e:	70 72                	jo     d2 <__abi_tag-0x2ba>
  60:	6f                   	outsl  %ds:(%rsi),(%dx)
  61:	74 65                	je     c8 <__abi_tag-0x2c4>
  63:	63 74 6f 72          	movsxd 0x72(%rdi,%rbp,2),%esi
  67:	2d 73 74 72 6f       	sub    $0x6f727473,%eax
  6c:	6e                   	outsb  %ds:(%rsi),(%dx)
  6d:	67 20 2d 66 73 74 61 	and    %ch,0x61747366(%eip)        # 617473da <_end+0x617433c2>
  74:	63 6b 2d             	movsxd 0x2d(%rbx),%ebp
  77:	63 6c 61 73          	movsxd 0x73(%rcx,%riz,2),%ebp
  7b:	68 2d 70 72 6f       	push   $0x6f72702d
  80:	74 65                	je     e7 <__abi_tag-0x2a5>
  82:	63 74 69 6f          	movsxd 0x6f(%rcx,%rbp,2),%esi
  86:	6e                   	outsb  %ds:(%rsi),(%dx)
  87:	20 2d 66 63 66 2d    	and    %ch,0x2d666366(%rip)        # 2d6663f3 <_end+0x2d6623db>
  8d:	70 72                	jo     101 <__abi_tag-0x28b>
  8f:	6f                   	outsl  %ds:(%rsi),(%dx)
  90:	74 65                	je     f7 <__abi_tag-0x295>
  92:	63 74 69 6f          	movsxd 0x6f(%rcx,%rbp,2),%esi
  96:	6e                   	outsb  %ds:(%rsi),(%dx)
  97:	00 6c 6f 6e          	add    %ch,0x6e(%rdi,%rbp,2)
  9b:	67 20 75 6e          	and    %dh,0x6e(%ebp)
  9f:	73 69                	jae    10a <__abi_tag-0x282>
  a1:	67 6e                	outsb  %ds:(%esi),(%dx)
  a3:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%rcx)
  a8:	74 00                	je     aa <__abi_tag-0x2e2>
  aa:	75 6e                	jne    11a <__abi_tag-0x272>
  ac:	73 69                	jae    117 <__abi_tag-0x275>
  ae:	67 6e                	outsb  %ds:(%esi),(%dx)
  b0:	65 64 20 63 68       	gs and %ah,%fs:0x68(%rbx)
  b5:	61                   	(bad)  
  b6:	72 00                	jb     b8 <__abi_tag-0x2d4>
  b8:	6d                   	insl   (%dx),%es:(%rdi)
  b9:	61                   	(bad)  
  ba:	69 6e 00 6c 6f 6e 67 	imul   $0x676e6f6c,0x0(%rsi),%ebp
  c1:	20 69 6e             	and    %ch,0x6e(%rcx)
  c4:	74 00                	je     c6 <__abi_tag-0x2c6>
  c6:	5f                   	pop    %rdi
  c7:	5f                   	pop    %rdi
  c8:	75 69                	jne    133 <__abi_tag-0x259>
  ca:	6e                   	outsb  %ds:(%rsi),(%dx)
  cb:	74 36                	je     103 <__abi_tag-0x289>
  cd:	34 5f                	xor    $0x5f,%al
  cf:	74 00                	je     d1 <__abi_tag-0x2bb>
  d1:	73 68                	jae    13b <__abi_tag-0x251>
  d3:	6f                   	outsl  %ds:(%rsi),(%dx)
  d4:	72 74                	jb     14a <__abi_tag-0x242>
  d6:	20 75 6e             	and    %dh,0x6e(%rbp)
  d9:	73 69                	jae    144 <__abi_tag-0x248>
  db:	67 6e                	outsb  %ds:(%esi),(%dx)
  dd:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%rcx)
  e2:	74 00                	je     e4 <__abi_tag-0x2a8>
  e4:	73 68                	jae    14e <__abi_tag-0x23e>
  e6:	6f                   	outsl  %ds:(%rsi),(%dx)
  e7:	72 74                	jb     15d <__abi_tag-0x22f>
  e9:	20 69 6e             	and    %ch,0x6e(%rcx)
  ec:	74 00                	je     ee <__abi_tag-0x29e>

Disassembly of section .debug_line_str:

0000000000000000 <.debug_line_str>:
   0:	2f                   	(bad)  
   1:	68 6f 6d 65 2f       	push   $0x2f656d6f
   6:	74 61                	je     69 <__abi_tag-0x323>
   8:	6f                   	outsl  %ds:(%rsi),(%dx)
   9:	2f                   	(bad)  
   a:	70 72                	jo     7e <__abi_tag-0x30e>
   c:	6f                   	outsl  %ds:(%rsi),(%dx)
   d:	6a 65                	push   $0x65
   f:	63 74 73 2f          	movsxd 0x2f(%rbx,%rsi,2),%esi
  13:	63 73 61             	movsxd 0x61(%rbx),%esi
  16:	70 70                	jo     88 <__abi_tag-0x304>
  18:	2f                   	(bad)  
  19:	74 65                	je     80 <__abi_tag-0x30c>
  1b:	73 74                	jae    91 <__abi_tag-0x2fb>
  1d:	2f                   	(bad)  
  1e:	61                   	(bad)  
  1f:	73 73                	jae    94 <__abi_tag-0x2f8>
  21:	43 6f                	rex.XB outsl %ds:(%rsi),(%dx)
  23:	6e                   	outsb  %ds:(%rsi),(%dx)
  24:	64 2e 63 70 70       	fs movsxd %fs:0x70(%rax),%esi
  29:	00 2f                	add    %ch,(%rdi)
  2b:	68 6f 6d 65 2f       	push   $0x2f656d6f
  30:	74 61                	je     93 <__abi_tag-0x2f9>
  32:	6f                   	outsl  %ds:(%rsi),(%dx)
  33:	2f                   	(bad)  
  34:	70 72                	jo     a8 <__abi_tag-0x2e4>
  36:	6f                   	outsl  %ds:(%rsi),(%dx)
  37:	6a 65                	push   $0x65
  39:	63 74 73 2f          	movsxd 0x2f(%rbx,%rsi,2),%esi
  3d:	63 73 61             	movsxd 0x61(%rbx),%esi
  40:	70 70                	jo     b2 <__abi_tag-0x2da>
  42:	2f                   	(bad)  
  43:	62 75                	(bad)  
  45:	69 6c 64 00 2f 68 6f 	imul   $0x6d6f682f,0x0(%rsp,%riz,2),%ebp
  4c:	6d 
  4d:	65 2f                	gs (bad) 
  4f:	74 61                	je     b2 <__abi_tag-0x2da>
  51:	6f                   	outsl  %ds:(%rsi),(%dx)
  52:	2f                   	(bad)  
  53:	70 72                	jo     c7 <__abi_tag-0x2c5>
  55:	6f                   	outsl  %ds:(%rsi),(%dx)
  56:	6a 65                	push   $0x65
  58:	63 74 73 2f          	movsxd 0x2f(%rbx,%rsi,2),%esi
  5c:	63 73 61             	movsxd 0x61(%rbx),%esi
  5f:	70 70                	jo     d1 <__abi_tag-0x2bb>
  61:	2f                   	(bad)  
  62:	74 65                	je     c9 <__abi_tag-0x2c3>
  64:	73 74                	jae    da <__abi_tag-0x2b2>
  66:	00 2f                	add    %ch,(%rdi)
  68:	75 73                	jne    dd <__abi_tag-0x2af>
  6a:	72 2f                	jb     9b <__abi_tag-0x2f1>
  6c:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%rsi),%ebp
  73:	2f                   	(bad)  
  74:	78 38                	js     ae <__abi_tag-0x2de>
  76:	36 5f                	ss pop %rdi
  78:	36 34 2d             	ss xor $0x2d,%al
  7b:	6c                   	insb   (%dx),%es:(%rdi)
  7c:	69 6e 75 78 2d 67 6e 	imul   $0x6e672d78,0x75(%rsi),%ebp
  83:	75 2f                	jne    b4 <__abi_tag-0x2d8>
  85:	62                   	(bad)  
  86:	69 74 73 00 74 79 70 	imul   $0x65707974,0x0(%rbx,%rsi,2),%esi
  8d:	65 
  8e:	73 2e                	jae    be <__abi_tag-0x2ce>
  90:	68 00 73 74 64       	push   $0x64747300
  95:	69 6e 74 2d 75 69 6e 	imul   $0x6e69752d,0x74(%rsi),%ebp
  9c:	74 6e                	je     10c <__abi_tag-0x280>
  9e:	2e                   	cs
  9f:	68                   	.byte 0x68
	...
