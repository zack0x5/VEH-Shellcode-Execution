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
I did some not-so-decent reverse engineering on the VEH, lol. If you're interested in seeing it, check out this link: https://discord.gg/C3MGmCtGtJ, maybe you'll find something useful there :)</br>
This software demonstrates how we can use this mechanism (VEH) for shellcode execution. In the example code, I add an exception handler using the AddVectoredExceptionHandler function. Then, I intentionally cause a</br> segmentation fault to trigger an exception and redirect it to my handler. The VEH stores the thread's context in the EXCEPTION_POINTERS structure, and through that, I modify one of its registers (RIP) and change it to point</br> to the start of my shellcode.

Articles :
* https://www.ibm.com/think/x-force/using-veh-for-defense-evasion-process-injection
* https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers
* https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling
* https://moval0x1.github.io/posts/the-abuse-of-exception-handlers/

⚠️ **Warning** ⚠️
---
I want to make it clear that the content shared here is for **educational purposes only**. It is not advised to use this example to commit any infractions.
