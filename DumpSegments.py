# -*- coding: UTF-8 -*-
import json

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump segments of the specified module" -f '
        'DumpSegments.dump_segments segments')


def dump_segments(debugger, command, result, internal_dict):
    """
    dump segments of the specified module
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser()
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if args:
        lookup_module_name = ''.join(args)
    else:
        lookup_module_name = ''

    lookup_module_name = lookup_module_name.replace("'", "")
    segments = get_module_segments(debugger, lookup_module_name)

    result.AppendMessage("{}".format(segments))


def get_module_segments(debugger, module):
    command_script = '@import Foundation;'
    command_script += r'''
    struct mach_header_64 {
        uint32_t    magic;        /* mach magic number identifier */
        int32_t        cputype;    /* cpu specifier */
        int32_t        cpusubtype;    /* machine specifier */
        uint32_t    filetype;    /* type of file */
        uint32_t    ncmds;        /* number of load commands */
        uint32_t    sizeofcmds;    /* the size of all the load commands */
        uint32_t    flags;        /* flags */
        uint32_t    reserved;    /* reserved */
    };

    struct segment_command_64 { /* for 64-bit architectures */
        uint32_t    cmd;        /* LC_SEGMENT_64 */
        uint32_t    cmdsize;    /* includes sizeof section_64 structs */
        char        segname[16];    /* segment name */
        uint64_t    vmaddr;        /* memory address of this segment */
        uint64_t    vmsize;        /* memory size of this segment */
        uint64_t    fileoff;    /* file offset of this segment */
        uint64_t    filesize;    /* amount to map from the file */
        int32_t        maxprot;    /* maximum VM protection */
        int32_t        initprot;    /* initial VM protection */
        uint32_t    nsects;        /* number of sections in segment */
        uint32_t    flags;        /* flags */
    };
    struct section_64 { /* for 64-bit architectures */
        char		sectname[16];	/* name of this section */
        char		segname[16];	/* segment this section goes in */
        uint64_t	addr;		/* memory address of this section */
        uint64_t	size;		/* size in bytes of this section */
        uint32_t	offset;		/* file offset of this section */
        uint32_t	align;		/* section alignment (power of 2) */
        uint32_t	reloff;		/* file offset of relocation entries */
        uint32_t	nreloc;		/* number of relocation entries */
        uint32_t	flags;		/* flags (section type and attributes)*/
        uint32_t	reserved1;	/* reserved (for offset or index) */
        uint32_t	reserved2;	/* reserved (for count or sizeof) */
        uint32_t	reserved3;	/* reserved */
    };
    struct linkedit_data_command {
        uint32_t	cmd;		/* LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
                       LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
                       LC_DYLIB_CODE_SIGN_DRS,
                       LC_LINKER_OPTIMIZATION_HINT,
                       LC_DYLD_EXPORTS_TRIE, or
                       LC_DYLD_CHAINED_FIXUPS. */
        uint32_t	cmdsize;	/* sizeof(struct linkedit_data_command) */
        uint32_t	dataoff;	/* file offset of data in __LINKEDIT segment */
        uint32_t	datasize;	/* file size of data in __LINKEDIT segment  */
    };
    #define __LP64__ 1
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #else
    typedef struct mach_header mach_header_t;
    #endif
    struct load_command {
        uint32_t cmd;		/* type of load command */
        uint32_t cmdsize;	/* total size of command in bytes */
    };
    '''
    command_script += 'NSString *x_module_name = @"' + module + '";'
    command_script += r'''
    if (![x_module_name length]) {
        x_module_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }
    
    const mach_header_t *x_mach_header = NULL;
    uint64_t address = 0;
    intptr_t slide = 0;
    BOOL isAddress = [x_module_name hasPrefix:@"0x"];
    if (isAddress) {
        address = strtoull((const char *)[x_module_name UTF8String], 0, 16);
        x_mach_header = (const mach_header_t *)address;
    } else {
        uint32_t image_count = (uint32_t)_dyld_image_count();
        for (uint32_t i = 0; i < image_count; i++) {
            const char *name = (const char *)_dyld_get_image_name(i);
            if (!name) {
                continue;
            }
            const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);
            
            NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
            if ([module_name isEqualToString:x_module_name]) {
                x_mach_header = mach_header;
                slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
                break;
            }
        }
    }
    
    NSMutableString *result = [NSMutableString string];
    if (x_mach_header) {
        uint32_t magic = x_mach_header->magic;
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            uint32_t ncmds = x_mach_header->ncmds;
            if (ncmds > 0) {
                uint64_t cur = (uint64_t)x_mach_header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                uint64_t file_offset = 0;
                uint64_t vmaddr      = 0;
                NSString *(^gen_prot_str)(int32_t) = ^(int32_t prot){
                    NSString *prot_str = @"";
                    if (prot == 0) {
                        prot_str = @"---";
                    } else if (prot == 1) {
                        prot_str = @"r--";
                    } else if (prot == 2) {
                        prot_str = @"-w-";
                    } else if (prot == 3) {
                        prot_str = @"rw-";
                    } else if (prot == 4) {
                        prot_str = @"--x";
                    } else if (prot == 5) {
                        prot_str = @"r-x";
                    } else if (prot == 6) {
                        prot_str = @"-wx";
                    } else {
                        NSLog(@"%d", prot);
                    }
                    
                    return prot_str;
                };
                for (uint32_t i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (sc->cmd == 0x19) { // LC_SEGMENT_64
                        struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                        if (slide == 0 && strcmp(seg->segname, "__TEXT") == 0) {
                            slide = (uint64_t)x_mach_header - seg->vmaddr;
                        }
                        
                        uint32_t nsects = seg->nsects;
                        char *sec_start = (char *)seg + sizeof(struct segment_command_64);
                        [result appendFormat:@"[0x%llx-0x%llx) 0x%llx %s %@/%@\n", seg->vmaddr + slide, seg->vmaddr + slide + seg->vmsize, seg->vmsize, seg->segname, gen_prot_str(seg->initprot), gen_prot_str(seg->maxprot)];
                        
                        size_t sec_size = sizeof(struct section_64);
                        for (uint32_t idx = 0; idx < nsects; idx++) {
                            struct section_64 *sec = (struct section_64 *)sec_start;
                            char *sec_name = strndup(sec->sectname, 16);
                            [result appendFormat:@"\t[0x%llx-0x%llx) 0x%llx %s\n", sec->addr + slide, sec->addr + slide + sec->size, sec->size, sec_name];
                            
                            sec_start += sec_size;
                            if (sec_name) {
                                free(sec_name);
                            }
                        }
                        if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
                            file_offset = seg->fileoff;
                            vmaddr      = seg->vmaddr;
                        }
                    } else if (sc->cmd == 0x1d) { // LC_CODE_SIGNATURE
                        struct linkedit_data_command *lc_signature = (struct linkedit_data_command *)sc;
                        char *sign_ptr = NULL;
                        if (slide == 0) {
                            sign_ptr = (char *)x_mach_header + lc_signature->dataoff;
                        } else {
                            sign_ptr = (char *)vmaddr + lc_signature->dataoff - file_offset + slide;
                        }
                        [result appendFormat:@"[0x%llx-0x%llx) 0x%x Code Signature\n", (uint64_t)sign_ptr, (uint64_t)sign_ptr + lc_signature->datasize, lc_signature->datasize];
                    }
                }
            }
        }
    }
    
    result;
    '''

    ret_str = exe_script(debugger, command_script)

    return ret_str


def exe_script(debugger, command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc -O -- ' + command_script, res)

    if not res.HasResult():
        print(res.GetError())
        return ''

    response = res.GetOutput()

    response = response.strip()
    # 末尾有两个\n
    if response.endswith('\n\n'):
        response = response[:-2]
    # 末尾有一个\n
    if response.endswith('\n'):
        response = response[:-1]

    return response


def generate_option_parser():
    usage = "usage: %prog ModuleName\n" + \
            "Use '%prog -h' for option desc"

    parser = optparse.OptionParser(usage=usage, prog='segments')

    return parser
