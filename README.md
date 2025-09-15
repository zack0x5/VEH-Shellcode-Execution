<img src=imgs/sleeping.webp/>

What is VEH?
---
**VEH (Vectored Exception Handling)** is an advanced extension of the **SEH (Structured Exception Handling)** mechanism, designed to provide a more flexible way for programs to handle exceptions. Unlike SEH, which is stack-based and tied to the specific thread's call stack, VEH uses a process-wide, doubly linked list to manage its exception handlers.

<img src=imgs/veh-structure.png/>
This structure allows for a more versatile approach to exception handling:

* **Flink:** A pointer to the next structure in the list.
* **Blink:** A pointer to the previous structure in the list.
* **Pointer to VEH:** A pointer to the handler function responsible for treating the exception.


**More depth bro**
---
I did a not-so-decent reverse engineering on it, lol. If you want to see it, check out this link: [https://discord.gg/C3MGmCtGtJ](https://discord.gg/C3MGmCtGtJ). Maybe you'll find something useful there :) </br>
This software demonstrates how we can use this mechanism for **shellcode execution**. I add a handler to the list using the `AddVectoredExceptionHandler` function. Inside this handler, I specifically treat segmentation fault/memory corruption exceptions by modifying the `CONTEXT` record received by VEH. This allows me to change the `RIP` register, which points to the next instruction, to the address of my shellcode.

Articles :
* https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection
* https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers
* https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling
* https://moval0x1.github.io/posts/the-abuse-of-exception-handlers/

⚠️ **Warning** ⚠️
---
I want to make it clear that the content shared here is for **educational purposes only**. It is not advised to use this example to commit any infractions.
