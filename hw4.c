//
// Created by Omer Meushar on 25/01/2023.
//


#include "hw3part.c"

//#include <stdio.h>
//#include <stdarg.h>
//#include <stdlib.h>
//#include <signal.h>
//#include <syscall.h> ///origin
/////#include <sys/syscall.h> ///replacement
/////#include "unistd.h"///replacement
//#include <sys/ptrace.h>
//#include <sys/types.h>
//#include <sys/wait.h>
//#include <sys/reg.h> ///origin
//#include <sys/user.h>
//#include <unistd.h>
//#include <errno.h>
//#include <string.h>
//#include <stdbool.h>
//#include <fcntl.h>

//#include "elf64.h"

pid_t run_target(const char* programname, char* const argv[])
{
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0)
    {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            exit(1); //trace error
        }
        /* Replace this process's image with the given program */
        execv(programname, argv+2);

    } else {
        // fork error
        exit(1);
    }

}

void run_our_debug (Elf64_Addr addr, int isDyn, pid_t child_pid) {

    int wait_status;
    struct user_regs_struct regs;
    //Elf64_Addr actual_address = addr;
    long long int function_counter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    //unsigned long address_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)actual_address, NULL);


    if (isDyn) {
        Elf64_Addr location_address = addr;
        addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) location_address, NULL);
    }

    unsigned long function_start = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, NULL);
    Elf64_Addr function_start_trap = (function_start & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) function_start_trap);

    if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
        exit(1);
    }
    wait(&wait_status);

    while (!WIFEXITED(wait_status))
    {

        function_counter++;

        ///fix rip post-breakpoint
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        regs.rip--;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) function_start);

        ///get return address of function:
        Elf64_Addr rsp_of_ret_address = regs.rsp; ///rsp points to func return address at beginning of func
        unsigned long return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) rsp_of_ret_address, NULL);
        Elf64_Addr rsp_finished_func_iteration = regs.rsp + 8; ///rsp+8 will be reached when iteration of func is done.

        ///place breakpoint in return address..
        unsigned long info_return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) return_address, NULL);
        Elf64_Addr return_address_trap = (info_return_address & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) return_address_trap);

        ///continue until child reached breakpoint (return address):
        //ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); //no need? - assumptions of HW4
        if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
            exit(1);
        }
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

        while (regs.rsp != rsp_finished_func_iteration && !WIFEXITED(wait_status)) ///while recursive calling - iterations pushed on top of stack:
        {
            //check if child tries to exit?
            ///fix rip and breakpoint of return address
            regs.rip--;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) info_return_address);

            ///commit single-step and redo breakpoint
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
                exit(1);
            }
            wait(&wait_status);
            ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) return_address_trap);

            ///continue to return address:
            if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
                exit(1);
            }
            wait(&wait_status);

            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        }

        /** finished after first while - now function returns for real (stack unwind) **/

        ///reached return address - fix rip and breakpoint
        regs.rip--;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) info_return_address);

        int return_value = (regs.rax & 0x100000000) ? (int)(-(~regs.rax+1)) : (int)(regs.rax); ///does it work?

//        ///reached return address - fix rip and breakpoint
//        regs.rip--;
//        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
//        ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) info_return_address);

        ///print return value and counter:
        printf("PRF:: run #%lld returned with %d\n", function_counter, return_value);

        ///place breakpoint again in function call:
        ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) function_start_trap);

        ///wait for signal: next call to function or child exit:
        if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
            exit(1);
        }
        wait(&wait_status);
        //ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

    }

    /** child process exited **/
    /** debug stop **/

}

int main(int argc, char *const argv[]) /// argv[1] func name, 2- execfile, 3..-commandLineParams for func
{
    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);
    if (err == -2)
        printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
    else if (err == -1)
        printf("PRF:: %s not found!\n", argv[1]);
    else if (err == -3)
        printf("PRF:: %s not an executable! :(\n", argv[2]);
    else /// if (err > 0 || err == -4)
    {
        pid_t child = run_target(argv[2] , argv);
        run_our_debug(addr, err==-4, child);
    }
    return 0;
}