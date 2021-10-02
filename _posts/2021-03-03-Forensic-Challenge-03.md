---
layout: post
title:  "Forensic Basics Challenge-03"
date:   2021-03-03
categories: Asssembly Python JPEG
title: Forensic-Challenge-03 Evil's den
---

This is the third blog of forensic series, in which we will try to extract the information from the image .

---
[](#header-1)**Challenge Description**
---

A malicious script encrypted a very secret piece of information I had on my system. Can you recover the information for me please?

Note-1: This challenge is composed of only 1 flag. The flag split into 2 parts.

Note-2: You'll need the first half of the flag to get the second.

---
[](#header-2)**Analysis**
---

We will start by analysing the Raw image file which we got for this challenge.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/image.png)

This image is dump of Windows 7 , as we have seen in our earlier blogs.

Now we will analyse the recently services used or files before this dump was created.

1. Recent Active Processes.
2. Commands executed successfully.
3. Terminated Processes.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/note.png)

Process list shows **notepad.exe** process was mostly used.

Using **cmdline** plugin , to check which files were opened.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/cmd.png)

We saw some interesting files were written such as **evil.py** and **vip.txt**.

To take a closer look of files written we just extract those to an text file.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/filescan.png)

Using offsets found earlier we will dump the file to analyse.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/evil.png)

Python Script Mechanism :

1. User input String as a Command-Line Argument.
2. Breaks the string into characters and **XOR** to each character to 3.
3. Encode the **XOR** to **Base64**.
4. Writes the Base64 Encoded data to **vip.txt**.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/vip.png)

Using online tool we will try to decrypt the **Base64** Encoded **XOR** to reverse the steps.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/chef.png)

---
**FLAG - 01 : inctf{0n3_h4lf**
---

Filescan Output , gives some common file format but we can see something **suspicious**.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/suspicious.png)

Using the offset we tried to dump the following file for better analysis.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/secret.png)

**Extracted Output:**

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/1.png)

We try to find the hidden information from the extracted image.

![](https://yashomer1994.github.io/yash007.github.io/assets/forensics/challenge3/steg.png)

So we found our second flag.

---
**FLAG - 02 : _1s_n0t_3n0ugh}**
---

Appending the two Flags together we will get our Final Flag.

**FINAL-FLAG: inctf{0n3_h4lf_1s_n0t_3n0ugh}**









