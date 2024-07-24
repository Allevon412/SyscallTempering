## What is Syscall Tempering?

This tool is my way of improving upon the syscall tampering module given to us by maldevacademy.com
The way syscall tampering works, is you set a hardware breakpoint at the location of a system call instruction, and register a vector exception handler to process the exception when the breakpoint is hit.
The vector exeception handler will replace the spoofed arguments (usually just a bunch of NULLs) with the ones you actually want to execute.
This hides the arguments from the EDR and if you choose a syscall to tamper that is not hooked, then the arguments are never identified by the EDR.
However, the original implementation i believe could use some improvements hence this repo:

### Syscall Tempering
Syscall Tempering improves upon the previous research and obtains a list of system calls that are not hooked by the currently running EDR solution (tested against sophos). I've used my tool Benign Hunter to perform this task.
Then a randomly chosen benign system call is tampered.
The original implementation additionally only spoofs the first four arguments due to the fact that an edr that does not hook all systemcalls will not be privy to our arguments we're passing to the tampered call. But, just incase all of the system calls are hooked, I have spoofed all arguments up to the first 11.
Any system calls that require more than 11 arguments will require additional code.

I've left the printf statements in incase you would like to see how things are changed by the VEH.

This proof of concept successfully launches the calculator under the supervision of Sophos EDR. Haven't tested against any other EDR (besides defender).

Why did i name it syscall Tempering? When it's supposed to be tampering? Well when i was playing diablo 4 I would randomly brick items due to the tempering system. When I started thinking of the idea of randomly selecting benign syscalls I couldn't get this feature out of my head and it's very similar to tampering so I figured it fit.

### How it works:

1) Creates hardware breakpoints in randomly selected benign syscalls.
2) Passes 11 null arguments to the benign syscall when it calls it.
3) Once syscall is hit, the hardware breakpoint triggers an exception and looks like the following:
![image](https://github.com/user-attachments/assets/9596c617-d5a8-4718-861a-ee8b6480992e)

![image](https://github.com/user-attachments/assets/c92bfeab-7b23-4db7-b337-6780375e9bcc)

- Notice three things, 1 the syscall isn't a hooked one under sophos NtOpenSemaphore, 2 we've stopped at the syscall instruction itself, 3 the arguments list up to the first 11 is null which means they're spoofed.
4) Once the VEH callback routine is triggered, the VEH will handle replacing the arguments on the stack if necessary, the arguments in the registers, and the syscall instruction number itself. Here's what that looks like after it triggers.
![image](https://github.com/user-attachments/assets/b3ffb41d-9f72-4ebb-a3a2-04fabf7cf069)
![image](https://github.com/user-attachments/assets/168c122d-b963-4cc5-a0d8-fa0b7bd9eb65)

5) The hardware breakpoint is then removed. The rest of the syscalls will execute under this path with a randomly chosen benign call every time. The payload itself launches calculator under an environment protected by sophos.
![image](https://github.com/user-attachments/assets/4a9b8a94-0680-4b2f-9034-ec5c534e556b)
