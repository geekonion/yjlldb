# -*- coding: UTF-8 -*-
import json

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump the specified module, see also dmodule_before_load" -f '
        'DumpModule.dump_module dmodule')

    debugger.HandleCommand(
        'command script add -h "dump the specified module before load method called, see also dmodule" -f '
        'DumpModule.dump_module_before_load_called dmodule_before_load')


def dump_module(debugger, command, result, internal_dict):
    """
    dump the specified module, see also dmodule_before_load
    """
    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('dmodule')
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
        lookup_module_name = None

    if not lookup_module_name:
        result.AppendMessage(parser.get_usage())
        return

    lookup_module_name = lookup_module_name.replace("'", "")
    output_dir = os.path.expanduser('~') + '/lldb_dump_macho'
    try_mkdir(output_dir)

    module_info_str = get_module_regions(debugger, lookup_module_name)
    if module_info_str:
        module_info = json.loads(module_info_str)
        print('dumping {}, this may take a while'.format(lookup_module_name))
        dump_message = dump_module_with_info(debugger, module_info, output_dir)

        result.AppendMessage("{}".format(dump_message))


def dump_module_before_load_called(debugger, command, result, internal_dict):
    """
    dump the specified module before load method called, see also dmodule
    """
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_option_parser('dmodule_before_load')
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
        lookup_module_name = None

    if not lookup_module_name:
        result.AppendMessage(parser.get_usage())
        return

    lookup_module_name = lookup_module_name.replace("'", "")
    output_dir = os.path.expanduser('~') + '/lldb_dump_macho'
    try_mkdir(output_dir)

    target = debugger.GetSelectedTarget()
    for module in target.module_iter():
        module_name = module.GetFileSpec().GetFilename()
        if lookup_module_name.lower() == module_name.lower():
            target_module = module
            break

    module_info = {'module_name': module_name}
    module_size = 0
    regions = []
    text_addr = 0
    for seg in target_module.section_iter():
        seg_name = seg.GetName()
        if seg_name == '__PAGEZERO':
            continue
        elif seg_name == '__TEXT':
            header_addr = seg.GetLoadAddress(target)
            slide = header_addr - seg.GetFileAddress()
            is_text_seg = True
        else:
            is_text_seg = False

        module_size += seg.GetFileByteSize()

        sections = []
        nsec = seg.GetNumSubSections()
        for i in range(nsec):
            sec = seg.GetSubSectionAtIndex(i)
            sec_name = sec.GetName()
            # 对于系统库来说，获取到的sec.GetFileOffset()经过修正，而header中的file offset没有修正
            sections.append('0x{:x}-0x{:x}-0x{:x}-{}.{}'.format(sec.GetLoadAddress(target) - slide,
                                                                sec.GetFileByteSize(),
                                                                sec.GetFileOffset(),
                                                                seg_name,
                                                                sec_name))

            if is_text_seg and text_addr == 0:
                text_addr = sec.GetLoadAddress(target)

        seg_info = {
            # 对于系统库来说，获取到的sec.GetFileOffset()经过修正，而header中的file offset没有修正
            'segment': '0x{:x}-0x{:x}-0x{:x}-{}'.format(seg.GetLoadAddress(target) - slide,
                                                        seg.GetFileByteSize(),
                                                        seg.GetFileOffset(),
                                                        seg_name),
            'sections': sections,
            'size': seg.GetFileOffset() + seg.GetFileByteSize()
        }
        regions.append(seg_info)

    header_info = {
        'segment': '0x{:x}-0x{:x}-0x0-header'.format(header_addr - slide, text_addr - header_addr)
    }
    regions.insert(0, header_info)

    module_info['size'] = module_size
    module_info['slide'] = slide
    module_info['regions'] = regions

    print('dumping {}, this may take a while'.format(lookup_module_name))
    dump_message = dump_module_with_info(debugger, module_info, output_dir)

    result.AppendMessage("{}".format(dump_message))


def dump_region(debugger, module_name, slide, region, output_dir):
    comps = region.split('-')
    addr = int(comps[0], 16) + slide
    region_size = int(comps[1], 16)
    file_offset = int(comps[2], 16)
    name = comps[3]

    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    cmd = 'memory read --force --outfile {}/{}/{} --binary --count {} {}' \
        .format(output_dir, module_name, name, region_size, addr)
    interpreter.HandleCommand(cmd, res)

    return {"offset": file_offset, "name": name}


def dump_module_with_info(debugger, module_info, output_dir):
    module_name = module_info["module_name"].replace(' ', '_')
    slide = module_info["slide"]
    module_regions = module_info["regions"]
    module_size = module_info["size"]

    module_dir = '{}/{}'.format(output_dir, module_name)
    try_mkdir(module_dir)

    module_info_write_to_file(module_info, module_dir)

    outputs = []
    for idx, region_info in enumerate(module_regions):
        # print('{} {}'.format(idx, region_info))
        sections = region_info.get("sections")
        if sections and len(sections):
            for section in sections:
                info = dump_region(debugger, module_name, slide, section, output_dir)
                outputs.append(info)
        else:
            info = dump_region(debugger, module_name, slide, region_info["segment"], output_dir)
            outputs.append(info)

    output_path = module_dir + '/macho_' + module_name
    with open(output_path, 'wb+') as x_file:
        header_done = False
        for info in outputs:
            name = info['name']
            offset = info['offset']
            if offset == 0:
                if header_done:
                    print('ignore {}'.format(name))
                    continue
                else:
                    header_done = True

            x_file.seek(offset)
            region_file_path = module_dir + '/' + name
            with open(region_file_path, 'rb') as region_file:
                x_file.write(region_file.read())
                x_file.flush()

                region_file.close()

        x_file.close()

    return '{} bytes dump to {}'.format(module_size, output_path)


def try_mkdir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def module_info_write_to_file(module_info, module_dir):
    module_name = module_info["module_name"].replace(' ', '_')
    json_file_path = module_dir + '/' + module_name + '.json'
    json_fp = open(json_file_path, 'w')
    json.dump(module_info, json_fp, indent=4)
    json_fp.close()


def get_module_regions(debugger, module):
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
    union lc_str {
        uint32_t	offset;	/* offset to the string */
    #ifndef __LP64__
        char		*ptr;	/* pointer to the string */
    #endif 
    };
    struct dylib {
        union lc_str  name;			/* library's path name */
        uint32_t timestamp;			/* library's build time stamp */
        uint32_t current_version;		/* library's current version number */
        uint32_t compatibility_version;	/* library's compatibility vers number*/
    };
    struct dylib_command {
        uint32_t	cmd;		/* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,
                           LC_REEXPORT_DYLIB */
        uint32_t	cmdsize;	/* includes pathname string */
        struct dylib	dylib;		/* the library identification */
    };
    '''
    command_script += 'NSString *keyword = @"' + module + '";'
    command_script += r'''
    if (!keyword) {
        keyword = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }
    
    const mach_header_t *x_mach_header = NULL;
    uint64_t address = 0;
    intptr_t slide = 0;
    NSString *x_module_name = keyword;
    BOOL isAddress = [keyword hasPrefix:@"0x"];
    if (isAddress) {
        address = strtoull((const char *)[keyword UTF8String], 0, 16);
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
    
    NSMutableArray *regions = [NSMutableArray array];
    uint64_t size = 0;
    if (x_mach_header) {
        uint32_t magic = x_mach_header->magic;
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            uint32_t ncmds = x_mach_header->ncmds;
            if (ncmds > 0) {
                uint64_t cur = (uint64_t)x_mach_header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                for (uint32_t i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (sc->cmd != 0x19) { // LC_SEGMENT_64
                        if (isAddress && sc->cmd == 0xd) { //LC_ID_DYLIB
                            struct dylib_command *dc = (struct dylib_command *)sc;
                            char *path = (char *)dc + dc->dylib.name.offset;
                            if (path) {
                                char *lib_path = strdup(path);
                                if (lib_path) {
                                    x_module_name = [[NSString stringWithUTF8String:lib_path] lastPathComponent];
                                    free(lib_path);
                                }
                            }
                        }
                        continue;
                    }
                    
                    struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                    if (strcmp(seg->segname, "__PAGEZERO") == 0) {
                        continue;
                    }
                    
                    if (slide == 0 && strcmp(seg->segname, "__TEXT") == 0) {
                        slide = (uint64_t)x_mach_header - seg->vmaddr;
                    }
                    
                    uint32_t nsects = seg->nsects;
                    char *sec_start = (char *)seg + sizeof(struct segment_command_64);
                    
                    NSMutableDictionary *segs = [NSMutableDictionary dictionary];
                    NSString *seg_info = [NSString stringWithFormat:@"0x%llx-0x%llx-0x%llx-%s", seg->vmaddr, seg->filesize, seg->fileoff, seg->segname];
                    segs[@"segment"] = seg_info;
                    NSMutableArray *sections = [NSMutableArray array];
                    size_t sec_size = sizeof(struct section_64);
                    for (uint32_t idx = 0; idx < nsects; idx++) {
                        struct section_64 *sec = (struct section_64 *)sec_start;
                        char *sec_name = strndup(sec->sectname, 16);
                        NSString *sec_info = [NSString stringWithFormat:@"0x%llx-0x%llx-0x%x-%s.%s", sec->addr, sec->size, sec->offset, sec->segname, sec_name];
                        [sections addObject:sec_info];
                        sec_start += sec_size;
                        if (sec_name) {
                            free(sec_name);
                        }
                    }
                    segs[@"sections"] = sections;
                    uint64_t file_size = seg->fileoff + seg->filesize;
                    segs[@"size"] = @(file_size);
                    [regions addObject:segs];
                    if (file_size > size) {
                        size = file_size;
                    }
                }
                NSMutableDictionary *header = [NSMutableDictionary dictionary];
                NSString *seg_info = [NSString stringWithFormat:@"0x%llx-0x%llx-0x0-header", (uint64_t)x_mach_header - slide, cur - (uint64_t)x_mach_header];
                header[@"segment"] = seg_info;
                [regions insertObject:header atIndex:0];
            }
        }
    }
    
    NSDictionary *module_info = @{
        @"regions": regions,
        @"slide": @(slide),
        @"module_name": x_module_name,
        @"size": @(size)
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:module_info options:kNilOptions error:nil];
    // 4 NSUTF8StringEncoding
    NSString *json_str = [[NSString alloc] initWithData:data encoding:4];
    json_str;
    '''

    ret_str = exe_script(debugger, command_script)

    return ret_str


def exe_script(debugger, command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc -O -- ' + command_script, res)

    if not res.HasResult():
        print('execute JIT code failed:\n{}'.format(res.GetError()))
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


def generate_option_parser(prog):
    usage = "usage: %prog ModuleName\n" + \
            "Use '%prog -h' for option desc"

    parser = optparse.OptionParser(usage=usage, prog=prog)

    return parser
