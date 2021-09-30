//
// Created by guoshichao on 2021/9/30.
//
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
// for using mmap to map the object file into our memory
#include <sys/mman.h>
#include <fcntl.h>

#include <unistd.h>
// for parsing the elf file
#include <elf.h>
#include <error.h>
#include <errno.h>

static uint64_t page_size;

static inline uint64_t page_align(uint64_t n) {
    return (n + (page_size - 1)) & ~(page_size - 1);
}

typedef union {
    const Elf64_Ehdr *hdr;
    const uint8_t *base;
} obj_hdr;

// obj.o memory address
static obj_hdr obj;

static void load_obj(void) {
    // load the obj.o into memory
    struct stat sb;

    int fd = open("test_obj/obj.o", O_RDONLY);
    if (fd <= 0) {
        printf("fatal error!!! fail to open the obj file of \"test_obj/obj.o\", caused by:%s\n", strerror(errno));
        return;
    }

    // get the obj file size, we need the size for mmap system call
    if (fstat(fd, &sb)) {
        printf("fatal error!!! --> fail to get the file info of \"test_obj/obj.o\", caused by:%s\n", strerror(errno));
        return;
    }

    obj.base = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (obj.base == MAP_FAILED) {
        printf("fatal error!!! fail to map the \"test_obj/obj.o\" into memory!!! caused by:%s\n", strerror(errno));
        exit(errno);
    }
    close(fd);
}

// the secion table
static const Elf64_Shdr *sections;
static const char *shstrtab = NULL;

// the symbol table
static const Elf64_Sym *symbols;
// number of entries in the symbol table
static int num_symbols;

static const char *strtab = NULL;

static const Elf64_Shdr *lookup_section(const char *name) {
    size_t name_len = strlen(name);

    for (Elf64_Half i = 0; i < obj.hdr->e_shnum; ++i) {
        // sections table entry does not contain the string name of the section
        // instead, the "sh_name" parameter is the offset in the ".shstrtab" section
        // which points to a string name
        const char *section_name = shstrtab + sections[i].sh_name;
        size_t section_name_len = strlen(section_name);
        if (name_len == section_name_len && !strcmp(name, section_name)) {
            if (sections[i].sh_size) {
                return sections + i;
            } else {
                printf("the section:%s size are 0!!!\n", section_name);
            }
        }
    }
    return NULL;
}

// runtime base address of the imported code
static uint8_t *text_runtime_base;

static void *look_up_function(const char *name) {
    size_t name_len = strlen(name);

    for (int i = 0; i < num_symbols; ++i) {
        if (ELF64_ST_TYPE(symbols[i].st_info) == STT_FUNC) {
            // we need to get the function name based on the .strtab
            const char *function_name = strtab + symbols[i].st_name;
            size_t function_name_len = strlen(function_name);
            if (name_len == function_name_len && !strcmp(function_name, name)) {
                // st_value is an offset in bytes of the function from the beginning of the .text section
                return text_runtime_base + symbols[i].st_value;
            }
        }
    }
    return NULL;
}



static void parse_obj(void) {
    // parse an object file and find add5 and add10 functions
    // here if the parsing procedure
    // 1. find the "ELF" section table, and ".shstrtab" section --> as the ".shstrtab" section contains the name of other secion inside
    // the ELF file
    sections = (const Elf64_Shdr *) (obj.base + obj.hdr->e_shoff);
    // the index of .shstrtab in the secionts table is encoded in the ELF header
    shstrtab = (const char *) (obj.base + sections[obj.hdr->e_shstrndx].sh_offset);
    // 2. find the "symtab" and "strtab" sections(we need the strtab to lookup symbols by name in ".symtab")
    const Elf64_Shdr *symtab_hdr = lookup_section(".symtab");
    if (!symtab_hdr) {
        printf("unexpected exception happened!!! fail to find the \".symtab\" section from ELF file\n");
        exit(ENOEXEC);
    }

    symbols = (const Elf64_Sym *) (obj.base + symtab_hdr->sh_offset);
    num_symbols = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
    printf("the symtab contains symbols count are --> %d\n", num_symbols);

    const Elf64_Shdr *strtab_hdr = lookup_section(".strtab");
    if (!strtab_hdr) {
        printf("unexpected exception happened!!! fail to find the \".strtab\" section from ELF file\n");
        exit(ENOEXEC);
    }

    strtab = (const char *) (obj.base + strtab_hdr->sh_offset);

    // 3. find the ".text" section and copy it to RAM with executable permission
    // get the page size
    page_size = sysconf(_SC_PAGESIZE);
    const Elf64_Shdr *text_hdr = lookup_section(".text");
    if (!text_hdr) {
        printf("fatal error!!! fail to find out the .text section from ELF file\n");
        exit(ENOEXEC);
    }

    // allocate memory for ".text" section
    text_runtime_base = mmap(NULL, page_align(text_hdr->sh_size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                             -1, 0);
    if (text_runtime_base == MAP_FAILED) {
        printf("fatal state error!!! fail to allocate memory for test_obj/obj.o file, caused by:%s\n", strerror(errno));
        return;
    }

    memcpy(text_runtime_base, obj.base + text_hdr->sh_offset, text_hdr->sh_size);

    // now, make the .text section readonly and executable
    if (mprotect(text_runtime_base, page_align(text_hdr->sh_size), PROT_READ | PROT_EXEC)) {
        printf("fatal error!!! fail to make the .text section executable\n");
        exit(errno);
    }

}

static void execute_funcs(void) {
    // 4. find the add5 and add10 function offset from the .symtab
    // 5. execute the add5 and add10 functions
    int (*add5)(int);
    int (*add10)(int);

    add5 = look_up_function("add5");
    if (!add5) {
        printf("fail to find the add5 function, caused by:%s\n", strerror(errno));
        return;
    }
    printf("Now --> start to execute the add5 function --> \n");
    printf("add5(%d) = %d\n", 42, add5(42));

    add10 = look_up_function("add10");
    if (!add10) {
        printf("fail to find the add10 function, caused by:%s\n", strerror(errno));
        return;
    }

    printf("Now --> start to execute the add10 function --> \n");
    printf("add10(%d) = %d\n", 42, add10(42));
}


int main(int argc, char **argv) {
    load_obj();

    parse_obj();

    execute_funcs();

    return 0;
}

