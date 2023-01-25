//
// Created by Omer Meushar on 25/01/2023.
//

#include "hw3part.c"
#include "elf64.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h> ///origin
///#include <sys/syscall.h> ///replacement
///#include "unistd.h"///replacement
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h> ///origin
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>

pid_t run_target(const char* programname, char *const argv[])
{
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execl(programname, programname, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }

void debugFunc (char* funcName, char* execFileName, char* commandLineParams)
{

}





//Elf64_Dyn* getDynamicSection(char* execFileName)
//{
//
//    Elf64_Dyn* dynamic = (Elf64_Dyn*) malloc()
//}


//Elf64_Addr findRunTimeSymbolLocation(char* funcName, char* execFileName)
//{
//    int elfDescriptor = open(execFileName, O_RDONLY);
//    Elf64_Ehdr* header = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
//    pread(elfDescriptor,header,sizeof(Elf64_Ehdr),0);
//    Elf64_Shdr* sectionHeaderTable = (Elf64_Shdr*)malloc(header->e_shnum* sizeof(Elf64_Shdr));
//
//    findDynamicSection(char* execFileName)
//}


int main(int argc, char *const argv[]) /// argv[1] func name, 2- execfile, 3..-commandLineParams for func
{
    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);
    if (err == -2)
        printf("%s is not a global symbol! :(\n", argv[1]);
    else if (err == -1)
        printf("%s not found!\n", argv[1]);
    else if (err == -3)
        printf("%s not an executable! :(\n", argv[2]);
    else /// if (err > 0 || err == -4)
    {
        pid_t child = run_target(argv[2] , argv);
    }
//        printf("%s will be loaded to 0x%lx\n", argv[1], addr); ///delete
//    else if (err == -4) ///do stage 5 and continue to stage 6..
//    {
//
//
//    }
//        printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
    return 0;
}