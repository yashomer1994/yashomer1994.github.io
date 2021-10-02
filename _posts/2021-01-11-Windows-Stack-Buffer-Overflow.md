---
layout: post
title:  "Windows Stack Buffer Overflow"
date:   2021-01-11
categories: C C++ Asssembly
title: Windows Stack Buffer Overflow
---

Buffers are basically the memory area which holds data that is being transferred from one memory area to other. Buffer overflow occurs when a process to write a data in a memory which is not available or the memory is exceeded.

---
[](#header-1)**Pre-Requisite**
---

For this Exploit I have used Windows Server 2008 r2 SP1 - 32 Bit with  VulnServer Application alongside Immunity Debugger and Ollydbg.

VulnServer :  Windows Server Application which has number of vulnerabilities which designed to be target application for research and practice fuzzing.

Windows Firewall : Disabled.

Data Execution Prevention (DEP): Essential Services.

---
[](#header-2)**Attack**
---

I have tried to trigger an Exception in Application by sending Large Chunk of strings with TRUN command. For the demo i will be using Perl Script for this attack which runs on Local Host

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 1.png)

Once we run the Program , the debugger stops the program with **Access Violation Error** as shown on the bottom of screen, and the program execution will be paused in debugger.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 2.png)

Before moving further, we need to check the requirements to be met which will allow us to do Buffer overflow.

- Controling EIP registers, which decides next code to be executed by CPU.
- Indetify the memory address in the code , where we can put our code, which will redirect EIP towards our vulnerable code.

--- 
**Naming Conventions**

**EAX** - Accumulator Register

This is a general purpose register used for the calculations such as addition and subtraction. It is more efficient for writing exploit shellcode as it has the feature to store the return value of function.

EAX register is a 32 Bit Register, AX refers to the 16 bit registers, which can be further divided as AH of 8 bits.

**EBX** - Base Register

It is used as Base Pointer for memory access. It might not have any specific use, but it is used often to set value 0 in function to speed up the calculations.

**ECX** - Counter Register

Counter register is used as a LOOP Operation. Each Time LOOP Instruction is Executed, the counter register is decremented, then checked for 0. If the LOOP is 0 the loop will be terminated and execution of a program continues with the instruction following the LOOP instructions. If count is non zero, it will remain in LOOP and execute the instructions.

**EDX** - Data Register

It is a volatile general-purpose register which is used as function parameter.

**ESI** - Source Index

This register used to stroe a pointer to store to a read location.

**EDI** - Destination Index

EDI is  to store the storage pointers of functions, such as the write address of a string operation.

**EBP** - Base Pointer

EBP is used to store  of the base address  of the stack.  It is often used to reference variables located on the stack by using an offset to the current value of EBP.

**ESP** - Stack Pointer

ESP is used to store  the current memory address  of the stack. As registers are pushed or  poped  the stack ESP increments/decrements accordingly.

**EIP** - Instrcuction Pointer

EIP points to the memory address of the next instruction to be executed by the CPU.

---

The Value of EIP as shown in stack pane is populated wtih 41 bytes, and the ASCII equivalent of 41 is "A", which we have used in our script, this indicates the EIP register is controllable.


![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 3.png)

We will start analysing the location of Instructions exception using debugger by setting breakpoint

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 4.png)

Restart the program execution, this time program execution will be paused on Breakpoint which we have set earlier.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 5.png)

RETN instruction was executed before the exception occured.The RETN instructions stores the top value from the stack, interprets the value as a
memory address and directs it to the EIP.

RETN instruction is used to return back to the previous point in the execution after making a **CALL** statement, which places the address of the following instruction in memory onto the stack before it runs.Since the RETN statment is pulling an invalid value of 41414141 off the stack, the valid memory placed onto the stack by matching CALL statement been overwritten during execution of intermediary instructions. This is because an invalid memory address will not be placed onto the stack by a CALLL instruction, and a properly working proram will not allow a RETN  instruction to run with an invalid address on the stack. 

Setting a New breakpoint at the CALL instruction :

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 6.png)

Restart the program execution and the execution will pause at the new breakpoint address

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 7.png)

Instructions will place address of next instruction in memory on stack and redirect to the CALL instruction.

Address on the stack which stores our return address value is 191f9DC.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 8.png)

Stepping the Instructions three times, instruction is pushed to the current value of EBP on the stack, and copy the current value of ESP register into EBP register, and subtract 7E8 from the ESP register. 


00401811 |. 8B45 08 MOV EAX,DWORD PTR SS:[EBP+8]
00401814 |. 894424 04 MOV DWORD PTR SS:[ESP+4],EAX
00401818 |. 8D85 28F8FFFF LEA EAX,DWORD PTR SS:[EBP-7D8]
0040181E |. 890424 MOV DWORD PTR SS:[ESP],EAX
 
Stack will be filled with lots of zeroes as shown in figure below , which was earlier used by other program functions.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 9.png)

So the second entry on stack we found, interpreted as source operand, is a pointer to pointing to another location in  memory which contains string “TRUN.AAAAA”, data which we sent to the application using our script.

We have found the destination address to our pre-allocated memory on the stack. The **STRCPY** function will copy the data from one memory location to another memory location in the stack.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 10.png)

00401826 |. C9 LEAVE

The **LEAVE** instruction copies the value in the EBP register to the ESP register, and also takes the current value on the stack and uses it to set the EBP register. 

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 11.png)

We changed the value “A” with the shellcode , in the figure below the “A” character is overwritten by a different value as in EIP register.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 12.png)

We were able to Control the value of EIP by changing the string "A" with modified shellcode as shown 

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 13.png)


Once we are able to control the EIP register with our modified shellcode we will try to exploit Arbitrary Code Execution.

[](#header-4)**Bypass ASLR**

We have controlled EIP register , by which we are able to  Bypass the Windows kernel Memory Protection, by injecting a DLL file.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 14.png)


As we  managed retrieve the memory location of our DLL

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 15.png)

We used Base Address of the DLL to inject vulnerable code.

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 16.png)


We were able to successfully exploit SEH base Code Execution .

![](https://yashomer1994.github.io/yash007.github.io/assets/Picture 17.png)


[](#header-3)**References**

[https://www.redscan.com/news/windows-buffer-overflow-attacks-pt-1/](https://www.redscan.com/news/windows-buffer-overflow-attacks-pt-1/)
[https://resources.infosecinstitute.com/topic/stack-based-buffer-overflow-tutorial-part-1-introduction/](https://resources.infosecinstitute.com/topic/stack-based-buffer-overflow-tutorial-part-1-introduction/)