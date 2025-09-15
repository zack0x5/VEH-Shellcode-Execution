<h2> What is VEH? </h2>

VEH (Vectored Exception Handling) is an extension of SEH, a mechanism responsible for handling exceptions and also for allowing programs to deal with a specific exception. The VEH structure consists of a doubly linked list, which contains a Flink that points to the next structure, a Blink that points to the previous structure, and a Pointer to VEH that points to the handler that will be responsible for treating it.

See the image below, this is what VEH looks like:

I did a pretty decent reverse engineering on it, lol. If you want to see it, access this link -> https://discord.gg/C3MGmCtGtJ, maybe you'll find something useful there :)

This software is a demonstration of how we can use it for shellcode execution. I add a handler to the list using the AddVectoredExceptionHandler function, and in this handler, I handle segmentation fault/memory corruption exceptions by modifying the context received by VEH, changing the RIP register that points to the next instruction to my shellcode.

I want to make it clear that the content shared is for educational purposes only. It is not advised in any way to use this example to commit infractions.
