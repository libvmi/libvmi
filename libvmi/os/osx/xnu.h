//
// Created by kvmi on 9/6/23.
//

#ifndef LIBVMI_XNU_H
#define LIBVMI_XNU_H


#define    LC_SEGMENT_64    0x19
#define LC_SEGMENT_KERNEL       LC_SEGMENT_64



// https://github.com/apple-oss-distributions/xnu/tree/aca3beaa3dfbd42498b42c5e5ce20a938e6554e5/osfmk/mach/vm_param.h
#define PAGE_SIZE 0x1000

// https://github.com/apple-oss-distributions/xnu/blob/aca3beaa3dfbd42498b42c5e5ce20a938e6554e5/EXTERNAL_HEADERS/mach-o/loader.h#L54
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_PIE      0x200000

struct mach_header_64 {
    uint32_t magic;        /* mach magic number identifier */
    uint32_t cputype;    /* cpu specifier */
    uint32_t cpusubtype;    /* machine specifier */
    uint32_t filetype;    /* type of file */
    uint32_t ncmds;        /* number of load commands */
    uint32_t sizeofcmds;    /* the size of all the load commands */
    uint32_t flags;        /* flags */
    uint32_t reserved;    /* reserved */
};
typedef struct load_command {
    uint32_t cmd;        /* type of load command */
    uint32_t cmdsize;    /* total size of command in bytes */
} load_command;

struct segment_command_64 { /* for 64-bit architectures */
    uint32_t cmd;        /* LC_SEGMENT_64 */
    uint32_t cmdsize;    /* includes sizeof section_64 structs */
    char segname[16];    /* segment name */
    uint64_t vmaddr;        /* memory address of this segment */
    uint64_t vmsize;        /* memory size of this segment */
    uint64_t fileoff;    /* file offset of this segment */
    uint64_t filesize;    /* amount to map from the file */
//    vm_prot_t	maxprot;	/* maximum VM protection */
//    vm_prot_t	initprot;	/* initial VM protection */
    uint32_t nsects;        /* number of sections in segment */
    uint32_t flags;        /* flags */
};
typedef struct segment_command_64 kernel_segment_command_t;
typedef struct mach_header_64 kernel_mach_header_t;



#endif //LIBVMI_XNU_H
