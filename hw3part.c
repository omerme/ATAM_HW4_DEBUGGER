#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
///#include <syscall.h> ///origin
#include <sys/syscall.h> ///replacement
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
///#include <sys/reg.h> ///origin
#include "unistd.h"///replacement
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
        if(ELF64_ST_TYPE(symtab[symbolNum]->st_info) == SHN_UNDEF ) {
            UNDCounter++;
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
        for(int sectionNum=0; sectionNum<header->e_shnum; sectionNum++)
        {
            if(sectionHeaderTable[sectionNum]->sh_type == DYNAMIC_TYPE)
            {
                dynamicSectionHeader = sectionHeaderTable[sectionNum];
            }
            if(sectionHeaderTable[sectionNum]->sh_type == SHT_RELA)
            {
                if(strcmp(shstrtab+(sectionHeaderTable[sectionNum]->sh_name),".rela.plt")==0)
                {
                    relaPltHeader = sectionHeaderTable[sectionNum];
                }
            }
        }
        unsigned long relaNumOfSections = relaPltHeader->sh_size/relaPltHeader->sh_entsize;
        Elf64_Rela* relaPlt = (Elf64_Rela*)malloc(relaNumOfSections * sizeof(Elf64_Rela));
        pread(elfDescriptor,relaPlt,relaPltHeader->sh_size,relaPltHeader->sh_offset);
        Elf64_Addr dynamicSymbolLocation = 0;
        for(int relaNum=0; relaNum<relaNumOfSections; relaNum++)
        {
            if(ELF64_R_SYM(relaPlt[relaNum].r_info) == dynamicSectionHeader->sh_offset+UNDCounter*dynamicSectionHeader->sh_entsize);
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
        int retAddress = selectedSymbol->st_value;
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