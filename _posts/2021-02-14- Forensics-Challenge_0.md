---
layout: post
title:  "Forensic Basics Challenge_0"
date:   2021-02-14
categories: C C++ Asssembly Python 
title: Forensic Basics Challenge_0
---

I am very curious about memory forensics, so i decided to start with Introdution of Memory Forensics using CTF Challenge Samples.

---
[](#header-1)**Definition**
---

Memory forensic refers to the analysis of the volatile memory dump of Virtual Image or a Physical System Image. This analysis is carried out by security researchers to investigate and identify malicious behaviour or attacks which got missed by UserLand Softwares.

---
[](#header-1)**Memory Dump**
---

A Snapshot of A Virtual Machine image or a physical memory dump which may contain about the valuable forensics data about the system behaviour and root cause of a crash.

---
[](#header-1)**Analysis**
---

Our first stage will be to analyse the Memory dump file using tool Volatility Framework.

We will thing we will use the **PROFILE** to determine the Image specifics.

The **Profile** Tells about the OS of the image from which machine the dump data was extracted.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/imageinfo.png)

Volatility framework provides the details about of image, which profile to be used.

As a Security Researcher, Following specifications are analysed before going any further :

1. Currently Running Processes.
2. Commands executed.
3. Processes which have been terminated.
4. Browser History.

So , to list the current running processes, we will use the following command as shown in image below.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/process.png)

We can see the list of processes which were running when the memory dump was carried out. Output of the command gives a fully formatted view which includes the name, PID, PPID, Threads, Handles, start time.

In the output , there are process which needs to analysed.

1. cmd.exe :- This process executes Command Prompt.We can analyse this process to which commands have been executed.
2. DumpIt.exe :- This is tool which was used to dump the memory.
3. explorer.exe :- This process handles File Explorer.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/process1.png)

As we can **CMD.exe** process was running, lets analyse what commands have been executed.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/cmd.png)

As we can see the executed command : **C:\Python27\python.exe C:\Users\hello\Desktop\demon.py.txt**

Let's see what output we recieved from **stdout**

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/hello.png)

As highlighted above, stdout throws some string "**335d366f5d6031767631707f**" which is in hex encoded format , on decoding the string we found something as shown .

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/hex.png)

Now, we will try to analyse the system environment variable path set.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/xor.png)

Till now we have found some interesting stuff related to the Flag.

1. String with Hex-Encoded.
2. XOR.
3. Password.

Now we will try to extract the NTLM Hash of the system as shown

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge0/ntlm.png)

Using the online NTLM hash crack tool we can retrive the Flag.

 // Flag : **flag{you_are_good_but1_4m_b3tt3r}**

---
[](#header-1)**References**
--- 
1. [https://darkdefender.medium.com/write-up-memory-forensics-in-the-def-con-dfir-ctf-c2b50ed62c6b](https://darkdefender.medium.com/write-up-memory-forensics-in-the-def-con-dfir-ctf-c2b50ed62c6b)

2. [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)

















