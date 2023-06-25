# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "set breakpoints at the specified bytes in user modules" -f '
        'BreakAtBytes.break_at_bytes bab')


def break_at_bytes(debugger, command, result, internal_dict):
    """
    set breakpoints at the specified bytes in user modules
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

    argc = len(args)
    if argc == 1:
        input_bytes = args[0]
    elif argc > 1:
        input_bytes = '\\\\x'.join(args)
    else:
        result.AppendMessage(parser.get_usage())
        return

    target = debugger.GetSelectedTarget()
    instruction_str = find_bytes(debugger, input_bytes)
    if 'empty description' in instruction_str:
        result.AppendMessage("input bytes not found")
        return

    bytes_list = instruction_str.split(';')
    total_count = 0
    for bytes_addr in bytes_list:
        if len(bytes_addr) == 0:
            continue
        addr = int(bytes_addr, 16)
        brkpoint = target.BreakpointCreateByAddress(addr)
        # 判断下断点是否成功
        if not brkpoint.IsValid() or brkpoint.num_locations == 0:
            result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
        else:
            total_count += 1
            result.AppendMessage("Breakpoint {}: where = {}, address = 0x{:x}"
                                 .format(brkpoint.GetID(), target.ResolveLoadAddress(addr), addr))

    result.AppendMessage("set {} breakpoints".format(total_count))


def find_bytes(debugger, input_bytes):
    command_script = '@import Foundation;'
    command_script += r'''struct mach_header_64 {
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
    typedef struct ImageInfo1 {
        const mach_header_t *loadAddress;
        const char *filePath;
        intptr_t slide;
    } ImageInfo1;
    '''
    command_script += "char instruction[] = {"
    comps = input_bytes.split('\\\\x')
    inst_len = 0
    for comp in comps:
        if len(comp) == 0:
            continue
        command_script += "'\\x" + comp + "', "
        inst_len += 1
    command_script += "'\\0'};"
    command_script += 'size_t inst_len = {};'.format(inst_len)
    command_script += r'''
    NSString *bundle_path = [[NSBundle mainBundle] bundlePath];
    uint32_t img_count = (uint32_t)_dyld_image_count();
    ImageInfo1 *infos = (ImageInfo1 *)calloc(img_count, sizeof(ImageInfo1));
    if (!infos) {
        return;
    }
    
    uint32_t user_image_count = 0;
    for (uint32_t idx = 0; idx < img_count; idx++) {
        const mach_header_t *x_mach_header = (const mach_header_t *)_dyld_get_image_header(idx);
        const char *name = (const char *)_dyld_get_image_name(idx);
        intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(idx);
        NSString *image_path = [NSString stringWithUTF8String:name];
        if (![image_path containsString:bundle_path]) {
            continue;
        }
        if ([[image_path lastPathComponent] hasPrefix:@"libswift"]) {
            continue;
        }
        if (x_mach_header->magic != 0xfeedfacf) { // MH_MAGIC_64
            continue;
        }
        // 系统库的__LINKEDIT段是共用的，并且占了大部分size，所以系统库的size大多相近
        infos[user_image_count] = (ImageInfo1){x_mach_header, name, slide};
        user_image_count++;
    }
    
    NSMutableString *result = [NSMutableString string];
    for (size_t image_idx = 0; image_idx < user_image_count; image_idx++) {
        ImageInfo1 image_info = infos[image_idx];
        const mach_header_t *x_mach_header = image_info.loadAddress;
        intptr_t slide = image_info.slide;
        uint32_t ncmds = x_mach_header->ncmds;
        if (ncmds > 0) {
            uint64_t cur = (uint64_t)x_mach_header + sizeof(mach_header_t);
            struct load_command *sc = NULL;
            for (uint32_t i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                sc = (struct load_command *)cur;
                if (sc->cmd != 0x19) { // LC_SEGMENT_64
                    continue;
                }
                struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                if (strcmp(seg->segname, "__TEXT") != 0) {
                    continue;
                }
                uint32_t nsects = seg->nsects;
                char *sec_start = (char *)seg + sizeof(struct segment_command_64);
                
                size_t sec_size = sizeof(struct section_64);
                for (uint32_t idx = 0; idx < nsects; idx++) {
                    struct section_64 *sec = (struct section_64 *)sec_start;
                    NSString *sec_name = [NSString stringWithUTF8String:sec->sectname];
                    if ([sec_name containsString:@"_stub"] ||
                        [sec_name isEqualToString:@"__objc_methname"] ||
                        [sec_name isEqualToString:@"__objc_classname__TEXT"] ||
                        [sec_name isEqualToString:@"__objc_methtype"] ||
                        [sec_name isEqualToString:@"__cstring"] ||
                        [sec_name isEqualToString:@"__ustring"] ||
                        [sec_name isEqualToString:@"__gcc_except_tab__TEXT"] ||
                        [sec_name isEqualToString:@"__const"]
                        ) {
                        sec_start += sec_size;
                        continue;
                    }
                    void *sec_addr = (void *)(sec->addr + slide);
                    size_t big_len = sec->size;
                    while (true) {
                        void *inst = memmem(sec_addr, big_len, &instruction, inst_len);
                        if (inst) {
                            [result appendFormat:@"%p;", inst];
                            size_t off = (uint64_t)inst - (uint64_t)sec_addr;
                            if (off < big_len) {
                                sec_addr = (char *)inst + inst_len;
                                big_len -= off + inst_len;
                                continue;
                            }
                        }
                        break;
                    }
                    sec_start += sec_size;
                }
                
                break;
            }
        }
    }
    free(infos);
    
    result;
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def exe_script(debugger, command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc -O -- ' + command_script, res)

    if not res.HasResult():
        return res.GetError()

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
    usage = "usage: %prog bytes\n" + \
            "for example:\n" + \
            "\t%prog \\xc0\\x03\\x5f\\xd6\n" + \
            "or\n" + \
            "\t%prog c0 03 5f d6"

    parser = optparse.OptionParser(usage=usage, prog='bab')

    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=False,
                      dest="verbose",
                      help="verbose output")

    return parser
