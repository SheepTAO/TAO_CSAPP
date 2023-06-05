
add:     file format elf64-x86-64


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
    1020:	ff 35 8a 2f 00 00    	push   0x2f8a(%rip)        # 3fb0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 8b 2f 00 00 	bnd jmp *0x2f8b(%rip)        # 3fb8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nopl   (%rax)
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   $0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop
    1040:	f3 0f 1e fa          	endbr64 
    1044:	68 01 00 00 00       	push   $0x1
    1049:	f2 e9 d1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    104f:	90                   	nop

Disassembly of section .plt.got:

0000000000001050 <__cxa_finalize@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmp *0x2f75(%rip)        # 3fd0 <__cxa_finalize@GLIBC_2.2.5>
    105b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .plt.sec:

0000000000001060 <__cxa_atexit@plt>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	f2 ff 25 55 2f 00 00 	bnd jmp *0x2f55(%rip)        # 3fc0 <__cxa_atexit@GLIBC_2.2.5>
    106b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000001070 <_ZNSt8ios_base4InitC1Ev@plt>:
    1070:	f3 0f 1e fa          	endbr64 
    1074:	f2 ff 25 4d 2f 00 00 	bnd jmp *0x2f4d(%rip)        # 3fc8 <_ZNSt8ios_base4InitC1Ev@GLIBCXX_3.4>
    107b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

Disassembly of section .text:

0000000000001080 <_start>:
    1080:	f3 0f 1e fa          	endbr64 
    1084:	31 ed                	xor    %ebp,%ebp
    1086:	49 89 d1             	mov    %rdx,%r9
    1089:	5e                   	pop    %rsi
    108a:	48 89 e2             	mov    %rsp,%rdx
    108d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1091:	50                   	push   %rax
    1092:	54                   	push   %rsp
    1093:	45 31 c0             	xor    %r8d,%r8d
    1096:	31 c9                	xor    %ecx,%ecx
    1098:	48 8d 3d ef 00 00 00 	lea    0xef(%rip),%rdi        # 118e <main>
    109f:	ff 15 33 2f 00 00    	call   *0x2f33(%rip)        # 3fd8 <__libc_start_main@GLIBC_2.34>
    10a5:	f4                   	hlt    
    10a6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    10ad:	00 00 00 

00000000000010b0 <deregister_tm_clones>:
    10b0:	48 8d 3d 59 2f 00 00 	lea    0x2f59(%rip),%rdi        # 4010 <__TMC_END__>
    10b7:	48 8d 05 52 2f 00 00 	lea    0x2f52(%rip),%rax        # 4010 <__TMC_END__>
    10be:	48 39 f8             	cmp    %rdi,%rax
    10c1:	74 15                	je     10d8 <deregister_tm_clones+0x28>
    10c3:	48 8b 05 16 2f 00 00 	mov    0x2f16(%rip),%rax        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    10ca:	48 85 c0             	test   %rax,%rax
    10cd:	74 09                	je     10d8 <deregister_tm_clones+0x28>
    10cf:	ff e0                	jmp    *%rax
    10d1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10d8:	c3                   	ret    
    10d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

00000000000010e0 <register_tm_clones>:
    10e0:	48 8d 3d 29 2f 00 00 	lea    0x2f29(%rip),%rdi        # 4010 <__TMC_END__>
    10e7:	48 8d 35 22 2f 00 00 	lea    0x2f22(%rip),%rsi        # 4010 <__TMC_END__>
    10ee:	48 29 fe             	sub    %rdi,%rsi
    10f1:	48 89 f0             	mov    %rsi,%rax
    10f4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10f8:	48 c1 f8 03          	sar    $0x3,%rax
    10fc:	48 01 c6             	add    %rax,%rsi
    10ff:	48 d1 fe             	sar    %rsi
    1102:	74 14                	je     1118 <register_tm_clones+0x38>
    1104:	48 8b 05 e5 2e 00 00 	mov    0x2ee5(%rip),%rax        # 3ff0 <_ITM_registerTMCloneTable@Base>
    110b:	48 85 c0             	test   %rax,%rax
    110e:	74 08                	je     1118 <register_tm_clones+0x38>
    1110:	ff e0                	jmp    *%rax
    1112:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    1118:	c3                   	ret    
    1119:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001120 <__do_global_dtors_aux>:
    1120:	f3 0f 1e fa          	endbr64 
    1124:	80 3d e5 2e 00 00 00 	cmpb   $0x0,0x2ee5(%rip)        # 4010 <__TMC_END__>
    112b:	75 2b                	jne    1158 <__do_global_dtors_aux+0x38>
    112d:	55                   	push   %rbp
    112e:	48 83 3d 9a 2e 00 00 	cmpq   $0x0,0x2e9a(%rip)        # 3fd0 <__cxa_finalize@GLIBC_2.2.5>
    1135:	00 
    1136:	48 89 e5             	mov    %rsp,%rbp
    1139:	74 0c                	je     1147 <__do_global_dtors_aux+0x27>
    113b:	48 8b 3d c6 2e 00 00 	mov    0x2ec6(%rip),%rdi        # 4008 <__dso_handle>
    1142:	e8 09 ff ff ff       	call   1050 <__cxa_finalize@plt>
    1147:	e8 64 ff ff ff       	call   10b0 <deregister_tm_clones>
    114c:	c6 05 bd 2e 00 00 01 	movb   $0x1,0x2ebd(%rip)        # 4010 <__TMC_END__>
    1153:	5d                   	pop    %rbp
    1154:	c3                   	ret    
    1155:	0f 1f 00             	nopl   (%rax)
    1158:	c3                   	ret    
    1159:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000001160 <frame_dummy>:
    1160:	f3 0f 1e fa          	endbr64 
    1164:	e9 77 ff ff ff       	jmp    10e0 <register_tm_clones>

0000000000001169 <_Z3addmm>:
#include <iostream>

uint64_t add(uint64_t a, uint64_t b) {
    1169:	f3 0f 1e fa          	endbr64 
    116d:	55                   	push   %rbp
    116e:	48 89 e5             	mov    %rsp,%rbp
    1171:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1175:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    uint64_t c = a + b;
    1179:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    117d:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1181:	48 01 d0             	add    %rdx,%rax
    1184:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    return c;
    1188:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
}
    118c:	5d                   	pop    %rbp
    118d:	c3                   	ret    

000000000000118e <main>:

int main()
{
    118e:	f3 0f 1e fa          	endbr64 
    1192:	55                   	push   %rbp
    1193:	48 89 e5             	mov    %rsp,%rbp
    1196:	48 83 ec 20          	sub    $0x20,%rsp
    uint64_t a = 0x12340000;
    119a:	48 c7 45 e8 00 00 34 	movq   $0x12340000,-0x18(%rbp)
    11a1:	12 
    uint64_t b = 0xabcd;
    11a2:	48 c7 45 f0 cd ab 00 	movq   $0xabcd,-0x10(%rbp)
    11a9:	00 
    uint64_t c = add(a, b);
    11aa:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    11ae:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11b2:	48 89 d6             	mov    %rdx,%rsi
    11b5:	48 89 c7             	mov    %rax,%rdi
    11b8:	e8 ac ff ff ff       	call   1169 <_Z3addmm>
    11bd:	48 89 45 f8          	mov    %rax,-0x8(%rbp)

    return 0;
    11c1:	b8 00 00 00 00       	mov    $0x0,%eax
    11c6:	c9                   	leave  
    11c7:	c3                   	ret    

00000000000011c8 <_Z41__static_initialization_and_destruction_0ii>:
    11c8:	f3 0f 1e fa          	endbr64 
    11cc:	55                   	push   %rbp
    11cd:	48 89 e5             	mov    %rsp,%rbp
    11d0:	48 83 ec 10          	sub    $0x10,%rsp
    11d4:	89 7d fc             	mov    %edi,-0x4(%rbp)
    11d7:	89 75 f8             	mov    %esi,-0x8(%rbp)
    11da:	83 7d fc 01          	cmpl   $0x1,-0x4(%rbp)
    11de:	75 3b                	jne    121b <_Z41__static_initialization_and_destruction_0ii+0x53>
    11e0:	81 7d f8 ff ff 00 00 	cmpl   $0xffff,-0x8(%rbp)
    11e7:	75 32                	jne    121b <_Z41__static_initialization_and_destruction_0ii+0x53>
  extern wostream wclog;	/// Linked to standard error (buffered)
#endif
  ///@}

  // For construction of filebuffers for cout, cin, cerr, clog et. al.
  static ios_base::Init __ioinit;
    11e9:	48 8d 05 21 2e 00 00 	lea    0x2e21(%rip),%rax        # 4011 <_ZStL8__ioinit>
    11f0:	48 89 c7             	mov    %rax,%rdi
    11f3:	e8 78 fe ff ff       	call   1070 <_ZNSt8ios_base4InitC1Ev@plt>
    11f8:	48 8d 05 09 2e 00 00 	lea    0x2e09(%rip),%rax        # 4008 <__dso_handle>
    11ff:	48 89 c2             	mov    %rax,%rdx
    1202:	48 8d 05 08 2e 00 00 	lea    0x2e08(%rip),%rax        # 4011 <_ZStL8__ioinit>
    1209:	48 89 c6             	mov    %rax,%rsi
    120c:	48 8b 05 e5 2d 00 00 	mov    0x2de5(%rip),%rax        # 3ff8 <_ZNSt8ios_base4InitD1Ev@GLIBCXX_3.4>
    1213:	48 89 c7             	mov    %rax,%rdi
    1216:	e8 45 fe ff ff       	call   1060 <__cxa_atexit@plt>
    121b:	90                   	nop
    121c:	c9                   	leave  
    121d:	c3                   	ret    

000000000000121e <_GLOBAL__sub_I__Z3addmm>:
    121e:	f3 0f 1e fa          	endbr64 
    1222:	55                   	push   %rbp
    1223:	48 89 e5             	mov    %rsp,%rbp
    1226:	be ff ff 00 00       	mov    $0xffff,%esi
    122b:	bf 01 00 00 00       	mov    $0x1,%edi
    1230:	e8 93 ff ff ff       	call   11c8 <_Z41__static_initialization_and_destruction_0ii>
    1235:	5d                   	pop    %rbp
    1236:	c3                   	ret    

Disassembly of section .fini:

0000000000001238 <_fini>:
    1238:	f3 0f 1e fa          	endbr64 
    123c:	48 83 ec 08          	sub    $0x8,%rsp
    1240:	48 83 c4 08          	add    $0x8,%rsp
    1244:	c3                   	ret    
