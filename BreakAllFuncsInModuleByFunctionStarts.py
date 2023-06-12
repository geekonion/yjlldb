# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "set breakpoints to break all functions in the specified module" -f '
        'BreakAllFuncsInModuleByFunctionStarts.break_all_functions_in_module bafs')


def break_all_functions_in_module(debugger, command, result, internal_dict):
    """
    set breakpoints to break all functions in the specified module by function starts section in module
    functions in system sdks, objc_msgSend stubs and c++ destructors are ignored
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
        lookup_module_name = None

    if not lookup_module_name:
        result.AppendMessage(parser.get_usage())
        return

    target = debugger.GetSelectedTarget()

    total_count = 0
    module_found = False

    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()
        module_path = module_file_spec.GetFilename()
        name = os.path.basename(module_path)
        if lookup_module_name != name:
            continue

        module_found = True
        module_list = lldb.SBFileSpecList()
        module_list.Append(module_file_spec)
        comp_unit_list = lldb.SBFileSpecList()
        print("-----break functions in %s-----" % name)
        func_names = set()
        addr_str = get_function_starts(debugger, lookup_module_name)
        if "returned empty description" in addr_str:
            break
        addresses = addr_str.split(';')
        for address in addresses:
            addr = int(address, 16)
            addr_obj = target.ResolveLoadAddress(addr)
            symbol = addr_obj.GetSymbol()

            sym_name = symbol.GetName()
            if not options.individual and not sym_name:
                continue
            # 过滤析构函数
            if "::~" in sym_name:
                continue
            # 过滤objc_msgSend stubs
            if sym_name.startswith("objc_msgSend$"):
                continue

            sym_start_addr = symbol.GetStartAddress()
            # 使用符号路径过滤系统库函数
            if ".platform/Developer/SDKs/" in str(sym_start_addr.GetLineEntry().GetFileSpec()):
                continue

            if options.individual:
                brkpoint = target.BreakpointCreateBySBAddress(sym_start_addr)
                # 判断下断点是否成功
                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                    result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                else:
                    total_count += 1
                    addr = sym_start_addr.GetLoadAddress(target)
                    result.AppendMessage("Breakpoint {}: where = {}`{}, address = 0x{:x}"
                                         .format(brkpoint.GetID(), name, sym_name, addr))
            else:
                func_names.add(sym_name)

        if not options.individual:
            # BreakpointCreateByNames(SBTarget self, char const ** symbol_name, uint32_t num_symbol,
            # uint32_t name_type_mask, SBFileSpecList module_list, SBFileSpecList comp_unit_list) -> SBBreakpoint...
            n_func_names = len(func_names)
            print(f"will set breakpoint for {n_func_names} names")
            if n_func_names > 0:
                brkpoint = target.BreakpointCreateByNames(list(func_names),
                                                          n_func_names,
                                                          lldb.eFunctionNameTypeFull,
                                                          module_list,
                                                          comp_unit_list)
                # 判断下断点是否成功
                if not brkpoint.IsValid() or brkpoint.num_locations == 0:
                    result.AppendWarning("Breakpoint isn't valid or hasn't found any hits")
                else:
                    result.AppendMessage("Breakpoint {}: {} locations"
                                         .format(brkpoint.GetID(), brkpoint.GetNumLocations()))
        break

    if module_found:
        if options.individual:
            result.AppendMessage("set {} breakpoints".format(total_count))
    else:
        result.AppendMessage("module {} not found".format(lookup_module_name))


def get_function_starts(debugger, module):
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
    #ifndef TASK_DYLD_INFO_COUNT
    #define TASK_DYLD_INFO_COUNT    \
                (sizeof(task_dyld_info_data_t) / sizeof(natural_t))
    #endif
    '''
    command_script += 'NSString *x_module_name = @"' + module + '";'
    command_script += r'''
    if (!x_module_name) {
        x_module_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }
    
    const mach_header_t *x_mach_header = NULL;
    intptr_t slide = 0;
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
    
    struct linkedit_data_command *func_starts = NULL;
    uint64_t file_offset = 0;
    uint64_t vmaddr      = 0;
    if (x_mach_header) {
        uint32_t magic = x_mach_header->magic;
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            uint32_t ncmds = x_mach_header->ncmds;
            if (ncmds > 0) {
                uintptr_t cur = (uintptr_t)x_mach_header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (sc->cmd == 0x19) { // LC_SEGMENT_64
                        struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                        if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
                            file_offset = seg->fileoff;
                            vmaddr      = seg->vmaddr;
                        }
                    } else if (sc->cmd == 0x26) { //LC_FUNCTION_STARTS
                        func_starts = (struct linkedit_data_command *)sc;
                        break;
                    }
                }
            }
        }
    }
    
    NSMutableString *addresses = [NSMutableString string];
    if (func_starts) {
        const uint8_t* infoStart = NULL;
        if (slide == 0) {
            infoStart = (uint8_t*)((uint64_t)x_mach_header + func_starts->dataoff);
        } else {
            infoStart = (uint8_t*)((uint64_t)vmaddr + func_starts->dataoff - file_offset + slide);
        }
        const uint8_t* infoEnd = &infoStart[func_starts->datasize];
        uint64_t address = (uint64_t)x_mach_header;
        for (const uint8_t *p = infoStart; (*p != 0) && (p < infoEnd); ) {
            uint64_t delta = 0;
            uint32_t shift = 0;
            bool more = true;
            do {
                uint8_t byte = *p++;
                delta |= ((byte & 0x7F) << shift);
                shift += 7;
                if ( byte < 0x80 ) {
                    address += delta;
                    //printf("0x%llx\n", address);
                    [addresses appendFormat:@"0x%llx;", address];
                    more = false;
                }
            } while (more);
        }
    }
    NSUInteger len = [addresses length];
    if (len > 0) {
        [addresses replaceCharactersInRange:NSMakeRange(len - 1, 1) withString:@""];
    }
    addresses;
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
    usage = "usage: %prog [options] ModuleName\n" + \
            "Use 'bafs -h' for option desc"

    parser = optparse.OptionParser(usage=usage, prog='bafs')

    parser.add_option("-v", "--verbose",
                      action="store_true",
                      default=False,
                      dest="verbose",
                      help="verbose output")

    parser.add_option("-i", "--individual",
                      action="store_true",
                      default=False,
                      dest="individual",
                      help="create breakpoints with individual mode")

    return parser
