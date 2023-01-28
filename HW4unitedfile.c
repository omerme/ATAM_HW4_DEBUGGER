//
// Created by Omer Meushar on 26/01/2023.
//

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h> ///origin
//#include <sys/syscall.h> ///replacement
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

#include "elf64.h"

#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file

#define SYMTAB_TYPE 2
//#define STRTAB_TYPE 3
#define SHT_RELA 4
//#define SHT_RELA 4
#define DYNAMIC_TYPE 6
#define DYNSYM_TYPE 11

#define STB_GLOBAL 1

/** changes!!
 *  fix includes
 *  fix main
 * **/


void deleteSHT(Elf64_Shdr** sectionHeaderTable, int numOfSections)
{
    for (int i=0; i<numOfSections;i++)
    {
        free(sectionHeaderTable[i]);
    }
    free(sectionHeaderTable);
}

void deleteSymtab(Elf64_Sym** symtab, int numSymbols)
{
    for (int i=0; i<numSymbols;i++)
    {
        free(symtab[i]);
    }
    free(symtab);
}

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {

//    bool symbolFoundInSymtab = false;
//    bool symbolIsGlobal = false;
//    bool symbolDefinedInExecFile = false;

    *error_val=0;
    int elfDescriptor = open(exe_file_name, O_RDONLY);

    Elf64_Ehdr* header = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
    pread(elfDescriptor,header,sizeof(Elf64_Ehdr),0);
    ///check if executable:
    if (header->e_type!=ET_EXEC)
    {
        *error_val = -3;
        close(elfDescriptor);
        free(header);
        return -1;
    }

    /// Section Header Table
    //int SHTSize = (header->e_shentsize)*(header->e_shnum);
    Elf64_Shdr** sectionHeaderTable = (Elf64_Shdr**)malloc(header->e_shnum* sizeof(Elf64_Shdr*));
    Elf64_Off thisSheOffset;
    Elf64_Shdr* symtabSectionHeader = NULL;
    Elf64_Shdr* strtabSectionHeader = NULL;
    for(int sectionNum=0; sectionNum<header->e_shnum; sectionNum++)
    {
        thisSheOffset = header->e_shoff + sectionNum * header->e_shentsize;
        sectionHeaderTable[sectionNum] = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));
        pread(elfDescriptor,sectionHeaderTable[sectionNum],header->e_shentsize,thisSheOffset);
        if(sectionHeaderTable[sectionNum]->sh_type == SYMTAB_TYPE)
        {
            symtabSectionHeader = sectionHeaderTable[sectionNum];
        }
    }
    if(symtabSectionHeader!=NULL)
    {
        strtabSectionHeader = sectionHeaderTable[symtabSectionHeader->sh_link];
    }
    if(symtabSectionHeader==NULL || strtabSectionHeader==NULL) ///no *symtab or strtab* in elf - symbol is not in symtab
    {
        *error_val = -1;
        deleteSHT(sectionHeaderTable, header->e_shnum);
        free(header);
        close(elfDescriptor);
        return -1;
    }

    ///strtab:
    char* strtab = (char*)malloc(strtabSectionHeader->sh_size);
    pread(elfDescriptor,strtab,strtabSectionHeader->sh_size,strtabSectionHeader->sh_offset);

    ///create symtab:
    unsigned long symtabNumOfSections = symtabSectionHeader->sh_size/symtabSectionHeader->sh_entsize;
    Elf64_Sym** symtab = (Elf64_Sym**)malloc(symtabNumOfSections * sizeof(Elf64_Sym*));
    Elf64_Off curSymbolOffset;
    Elf64_Sym* selectedSymbol = NULL;
    bool foundGlobal = false;
    bool foundLocal = false;
//    int symbolNum = 0;
    int UNDCounter=-1;
    for(int symbolNum=0; symbolNum<symtabNumOfSections; symbolNum++) ///search symbol
    {
        curSymbolOffset = symtabSectionHeader->sh_offset + symbolNum * symtabSectionHeader->sh_entsize;
        symtab[symbolNum] = (Elf64_Sym*)malloc(sizeof(Elf64_Sym));
        pread(elfDescriptor,symtab[symbolNum],symtabSectionHeader->sh_entsize,curSymbolOffset);
        if(symtab[symbolNum]->st_shndx == SHN_UNDEF ) {
            if(foundGlobal==false) {
                UNDCounter++;
            }
        }
        if(strcmp(strtab+(symtab[symbolNum]->st_name),symbol_name)==0) ///changed from selectedSymbol to symtab[symbolNum]
        {
            if(ELF64_ST_BIND(symtab[symbolNum]->st_info)==STB_GLOBAL)
            {
                foundGlobal=true;
                selectedSymbol = symtab[symbolNum];
            }
            else
            {
                foundLocal=true;
            }
        }
    }
    if(foundGlobal==false && foundLocal==false) ///symbol not in symtab
    {
        *error_val = -1;
    }
    else if(foundLocal==true && foundGlobal==false) ///symbol is local only
    {
        *error_val = -2;
    }
    else if(selectedSymbol->st_shndx==SHN_UNDEF) ///symbol is local only
    {
        ///part 5
        *error_val = -4;
        Elf64_Shdr* shstrtabSectionHeader = sectionHeaderTable[header->e_shstrndx];
        char* shstrtab = (char*)malloc(shstrtabSectionHeader->sh_size);
        pread(elfDescriptor,shstrtab,shstrtabSectionHeader->sh_size,shstrtabSectionHeader->sh_offset);
        Elf64_Shdr* dynamicSectionHeader = NULL;
        Elf64_Shdr* relaPltHeader = NULL;
///        Elf64_Shdr* dynSymHeader = NULL;
        for(int sectionNum=0; sectionNum<header->e_shnum; sectionNum++)
        {
            if(sectionHeaderTable[sectionNum]->sh_type == DYNAMIC_TYPE)
            {
                dynamicSectionHeader = sectionHeaderTable[sectionNum];
            }
            if(sectionHeaderTable[sectionNum]->sh_type == SHT_RELA)
            {
                char relapltString[] = ".rela.plt";
                if(strcmp(shstrtab+(sectionHeaderTable[sectionNum]->sh_name),relapltString)==0)
                {
                    relaPltHeader = sectionHeaderTable[sectionNum];
                }
            }
///            if(sectionHeaderTable[sectionNum]->sh_type == DYNSYM_TYPE)
///            {
///                dynSymHeader = sectionHeaderTable[sectionNum];
///            }
        }
        unsigned long relaNumOfSections = relaPltHeader->sh_size/relaPltHeader->sh_entsize;
        Elf64_Rela* relaPlt = (Elf64_Rela*)malloc(relaNumOfSections * sizeof(Elf64_Rela));
        pread(elfDescriptor,relaPlt,relaPltHeader->sh_size,relaPltHeader->sh_offset);
        Elf64_Addr dynamicSymbolLocation = 0;
        for(int relaNum=0; relaNum<relaNumOfSections; relaNum++)
        {
            if(ELF64_R_SYM(relaPlt[relaNum].r_info) == UNDCounter) ///assuming dynsym is arranged like symtab.
                ///need? -> dynamicSectionHeader->sh_offset+UNDCounter*dynamicSectionHeader->sh_entsize);
            {
                dynamicSymbolLocation = relaPlt[relaNum].r_offset;
            }
        }
        free(relaPlt);
        free(shstrtab);
        free(strtab);
        deleteSymtab(symtab, symtabNumOfSections);
        deleteSHT(sectionHeaderTable, header->e_shnum);
        free(header);
        close(elfDescriptor);
        return dynamicSymbolLocation;
    }

    if(*error_val<0) ///if errors occurred:
    {
        free(strtab);
        deleteSymtab(symtab, symtabNumOfSections);
        deleteSHT(sectionHeaderTable, header->e_shnum);
        free(header);
        close(elfDescriptor);
        return -1; ///depends on error
    }

    if (*error_val==0) ///if no error occurred
    {
        *error_val=1;
        Elf64_Addr retAddress = selectedSymbol->st_value;
        free(strtab);
        deleteSymtab(symtab, symtabNumOfSections);
        deleteSHT(sectionHeaderTable, header->e_shnum);
        free(header);
        close(elfDescriptor);
        return retAddress;
    }

    /// dont forget close!!!
    /// don't forget frees!!!
}

//int main(int argc, char *const argv[]) {
//	int err = 0;
//	unsigned long addr = find_symbol(argv[1], argv[2], &err);
//	if (err > 0)
//		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
//	else if (err == -2)
//		printf("%s is not a global symbol! :(\n", argv[1]);
//	else if (err == -1)
//		printf("%s not found!\n", argv[1]);
//	else if (err == -3)
//		printf("%s not an executable! :(\n", argv[2]);
//	else if (err == -4)
//		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
//	return 0;
//}


/************** HW4 **************/

//
// Created by Omer Meushar on 25/01/2023.
//


///#include "hw3part.c"

//#include <stdio.h>
//#include <stdarg.h>
//#include <stdlib.h>
//#include <signal.h>
//#include <syscall.h> ///origin
//#include <sys/syscall.h> ///replacement
//#include "unistd.h"///replacement
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
    Elf64_Addr location_address;
    long long int function_counter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    //unsigned long address_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)actual_address, NULL);


    if (isDyn) {
        location_address = addr;
        addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) location_address, NULL);
    }

    unsigned long function_start = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, NULL);
    Elf64_Addr function_start_trap = (function_start & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) function_start_trap);

    if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
        exit(1);
    }
    ///ptrace(PTRACE_CONT, child_pid, NULL, NULL);
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
        ///ptrace(PTRACE_CONT, child_pid, NULL, NULL);
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
            ///ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_POKETEXT, child_pid, (void *) return_address, (void *) return_address_trap);

            ///continue to return address:
            if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
                exit(1);
            }
            ///ptrace(PTRACE_CONT, child_pid, NULL, NULL);
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

        ///change address after first time - lazy binding
        if(isDyn && (function_counter==1) )
        {
            //Elf64_Addr new_location_address = addr;
            addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)location_address, NULL);
            function_start = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, NULL);
            function_start_trap = (function_start & 0xFFFFFFFFFFFFFF00) | 0xCC;
        }

        ///place breakpoint again in function call:
        ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) function_start_trap);

        ///wait for signal: next call to function or child exit:
        if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
            exit(1);
        }
        ///ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        //ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

    }

    /** child process exited **/
    /** debug stop **/

}

int main(int argc, char *const argv[]) /// argv[1] func name, 2- execfile, 3..-commandLineParams for func
{
    int err = 0;
    Elf64_Addr addr = find_symbol(argv[1], argv[2], &err);
    ///unsigned long addr = find_symbol("foo", "program1.out", &err);
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

/////main test 1
//int main(int argc, char *const argv[]) /// argv[1] func name, 2- execfile, 3..-commandLineParams for func
//{
//    int err = 0;
//    char* argvReplace = (char*) malloc(sizeof(char)*13);
//    strcpy(argvReplace,"program1.out\0");
//    unsigned long addr = find_symbol("foo", "program1.out", &err);
//    if (err == -2)
//        printf("PRF:: %s is not a global symbol! :(\n", "foo");
//    else if (err == -1)
//        printf("PRF:: %s not found!\n", "foo");
//    else if (err == -3)
//        printf("PRF:: %s not an executable! :(\n", "program1.out");
//    else /// if (err > 0 || err == -4)
//    {
//        pid_t child = run_target("program1.out" , &argvReplace);
//        run_our_debug(addr, err==-4, child);
//    }
//    return 0;
//}
