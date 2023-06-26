# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
from enum import Enum


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "print codesign entitlements of the specified module if any."'
                           ' -f MachOParser.show_entitlements entitlements')
    debugger.HandleCommand('command script add -h "List current executable and dependent shared library images, sorted by load address."'
                           ' -f MachOParser.image_list image_list')
    debugger.HandleCommand(
        'command script add -h "print executable name."'
        ' -f MachOParser.show_executable_name executable')


def show_entitlements(debugger, command, result, internal_dict):
    """
    print codesign entitlements of the specified module if any.
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
        module_name = ''.join(args)
    else:
        module_name = 'NULL'

    module_name = module_name.replace("'", "")
    ret_str = get_entitlements(debugger, module_name)
    result.AppendMessage(ret_str)


def image_list(debugger, command, result, internal_dict):
    """
    List current executable and dependent shared library images, sorted by load address.
    """

    # 去掉转义符
    command = command.replace('\\', '\\\\')
    # posix=False特殊符号处理相关，确保能够正确解析参数，因为OC方法前有-
    command_args = shlex.split(command, posix=False)
    # 创建parser
    parser = generate_image_list_option_parser()
    # 解析参数，捕获异常
    try:
        # options是所有的选项，key-value形式，args是其余剩余所有参数，不包含options
        (options, args) = parser.parse_args(command_args)
    except Exception as error:
        print(error)
        result.SetError("\n" + parser.get_usage())
        return

    if options.count:
        count = options.count
    else:
        count = '0'

    ret_str = get_sorted_images(debugger, count)
    result.AppendMessage(ret_str)


def show_executable_name(debugger, command, result, internal_dict):
    """
    print executable name
    """
    target = debugger.GetSelectedTarget()
    result.AppendMessage(target.GetExecutable().GetFilename())


def get_entitlements(debugger, keyword):
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
    struct CS_Blob {
        uint32_t magic;                 // magic number
        uint32_t length;                // total length of blob
    };
    
    struct CS_BlobIndex {
        uint32_t type;                  // type of entry
        uint32_t offset;                // offset of entry
    };
    
    struct CS_SuperBlob {
        uint32_t magic;                 // magic number
        uint32_t length;                // total length of SuperBlob
        uint32_t count;                 // number of index entries following
        struct CS_BlobIndex index[];           // (count) entries
        // followed by Blobs in no particular order as indicated by offsets in index
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
    command_script += 'NSString *keyword = @"' + keyword + '";\n'
    command_script += r'''
    uint64_t address = 0;
    BOOL isAddress = [keyword hasPrefix:@"0x"];
    if (isAddress) {
        address = strtoull((const char *)[keyword UTF8String], 0, 16);
    }
    char *ent_str = NULL;
    const mach_header_t *headers[256] = {0};
    int name_count = 0;
    if (!keyword || [@"NULL" isEqualToString:keyword]) {
        keyword = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }
    uint32_t image_count = (uint32_t)_dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);
        if (isAddress) {
            if (address != (uint64_t)mach_header) {
                continue;
            }
        }
        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        NSRange range = [module_name rangeOfString:keyword options:NSCaseInsensitiveSearch];
        if (isAddress || range.location != NSNotFound) {
            headers[name_count] = mach_header;
            name_count++;
        }
        if (isAddress) {
            break;
        }
    }
    
    char *lib_path = NULL;
    if (isAddress && name_count == 0) {
        headers[name_count] = (const mach_header_t *)address;
        name_count++;
    }
    
    NSMutableString *result = [NSMutableString string];
    for (int idx = 0; idx < name_count; idx++) {
        const mach_header_t *mach_header = headers[idx];
        uint32_t header_magic = mach_header->magic;
        if (header_magic != 0xfeedfacf) { //MH_MAGIC_64
            continue;
        }
        
        uint32_t ncmds = mach_header->ncmds;
        if (ncmds == 0) {
            continue;
        }
        
        struct load_command *lc = (struct load_command *)((char *)mach_header + sizeof(mach_header_t));
        struct linkedit_data_command *lc_signature = NULL;
        uint64_t text_file_offset = 0;
        uint64_t text_vmaddr = 0;
        uint64_t file_offset = 0;
        uint64_t li_vmaddr = 0;
        NSString *name = nil;
        BOOL sig_found = NO;
        for (uint32_t i = 0; i < ncmds; i++) {
            if (lc->cmd == 0x19) { // LC_SEGMENT_64
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
                    file_offset = seg->fileoff;
                    li_vmaddr      = seg->vmaddr;
                } else if (strcmp(seg->segname, "__TEXT") == 0) {
                    text_file_offset = seg->fileoff;
                    text_vmaddr = seg->vmaddr;
                }
            } else if (lc->cmd == 0xd) { //LC_ID_DYLIB
                struct dylib_command *dc = (struct dylib_command *)lc;
                char *path = (char *)dc + dc->dylib.name.offset;
                if (path) {
                    lib_path = strdup(path);
                    name = [[NSString stringWithUTF8String:lib_path] lastPathComponent];
                }
            } else if (lc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                lc_signature = (struct linkedit_data_command *)lc;
            }
            lc = (struct load_command *)((char *)lc + lc->cmdsize);
        }
        
        if (lc_signature) {
            sig_found = YES;
            char *sign_ptr = NULL;
            sign_ptr = (char *)mach_header + (li_vmaddr - text_vmaddr) + lc_signature->dataoff - file_offset;
#if __arm64e__
            void *sign = (void *)ptrauth_strip(codeSignature, ptrauth_key_function_pointer);
#else
            void *sign = (void *)sign_ptr;
#endif
            struct CS_SuperBlob *superBlob = (struct CS_SuperBlob *)sign;
            uint32_t super_blob_magic = _OSSwapInt32(superBlob->magic);
            // 签名段数据被破坏
            if (super_blob_magic != 0xfade0cc0) { // CSMAGIC_EMBEDDED_SIGNATURE
                [result appendFormat:@"invalid signature magic found at %@!0x%x, signature: %p, header at: %p\n", name, lc_signature->dataoff, sign, mach_header];
                uint32_t sign_size = lc_signature->datasize;
                const char *prefix = "<?xml";
                char *ent_ptr = (char *)memmem(sign, sign_size, prefix, strlen(prefix));
                if (!ent_ptr) {
                    break;
                }
                const char *suffix = "</plist>";
                size_t data_len = ent_ptr - (char *)sign;
                char *ent_end = (char *)memmem(ent_ptr, data_len, suffix, strlen(suffix));
                if (!ent_end) {
                    break;
                }
                size_t length = ent_end - ent_ptr + strlen(suffix);
                if (length) {
                    ent_str = (char *)calloc(length + 1, sizeof(char));
                    if (ent_str) {
                        memcpy(ent_str, ent_ptr, length);
                        [result appendFormat:@"entitlements of %@:\n%s", name, ent_str];
                        free(ent_str);
                    }
                }
                break;
            }
            uint32_t nblob = _OSSwapInt32(superBlob->count);
            
            BOOL ent_found = NO;
            struct CS_BlobIndex *index = superBlob->index;
            for ( int i = 0; i < nblob; ++i ) {
                struct CS_BlobIndex blobIndex = index[i];
                uint32_t offset = _OSSwapInt32(blobIndex.offset);
                
                uint32_t *blobAddr = (__uint32_t *)((char *)sign + offset);
                
                struct CS_Blob *blob = (struct CS_Blob *)blobAddr;
                uint32_t magic = _OSSwapInt32(blob->magic);
                if ( magic == 0xfade7171 ) { //kSecCodeMagicEntitlement
                    
                    uint32_t header_len = 8;
                    uint32_t length = _OSSwapInt32(blob->length) - header_len;
                    if (length <= 0) {
                        break;
                    }
                    char *ent_ptr = (char *)blobAddr + header_len;
                    ent_str = (char *)calloc(length + 1, sizeof(char));
                    if (ent_str) {
                        memcpy(ent_str, ent_ptr, length);
                        [result appendFormat:@"entitlements of %@:\n%s", name, ent_str];
                        free(ent_str);
                        ent_found = YES;
                    }
                    break;
                }
            }
            if (!ent_found) {
                [result appendFormat:@"%@ apparently does not contain any entitlements, signature: %p\n", name, sign];
            }
        }
        
        if (!sig_found) {
            [result appendFormat:@"%@ apparently does not contain code signature\n", name];
        }
    }
    if (lib_path) {
        free(lib_path);
    }
    
    result;
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_sorted_images(debugger, count):
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
        uint32_t	cmd;		/* LC_SEGMENT_64 */
        uint32_t	cmdsize;	/* includes sizeof section_64 structs */
        char		segname[16];	/* segment name */
        uint64_t	vmaddr;		/* memory address of this segment */
        uint64_t	vmsize;		/* memory size of this segment */
        uint64_t	fileoff;	/* file offset of this segment */
        uint64_t	filesize;	/* amount to map from the file */
        int32_t		maxprot;	/* maximum VM protection */
        int32_t		initprot;	/* initial VM protection */
        uint32_t	nsects;		/* number of sections in segment */
        uint32_t	flags;		/* flags */
    };
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #else
    typedef struct mach_header mach_header_t;
    #endif
    struct load_command {
        uint32_t cmd;		/* type of load command */
        uint32_t cmdsize;	/* total size of command in bytes */
    };
    typedef struct ImageInfo {
        const mach_header_t *loadAddress;
        const char *filePath;
        intptr_t slide;
        uint64_t vm_size;
        uint64_t linkedit_size;
    } ImageInfo;
    '''
    command_script += 'uint32_t count = ' + count + ';\n'
    command_script += r'''
    NSMutableString *result = [NSMutableString string];
    
    uint32_t img_count = (uint32_t)_dyld_image_count();
    ImageInfo *infos = (ImageInfo *)calloc(img_count, sizeof(ImageInfo));
    if (!infos) {
        return;
    }
    intptr_t system_lib_slide = 0;
    for (uint32_t idx = 0; idx < img_count; idx++) {
        const mach_header_t *x_mach_header = (const mach_header_t *)_dyld_get_image_header(idx);
        const char *name = (const char *)_dyld_get_image_name(idx);
        intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(idx);
        if (strcmp(name, "/usr/lib/libSystem.B.dylib") == 0) {
            system_lib_slide = slide;
        }
        
        uint64_t file_size = 0;
        uint64_t linkedit_size = 0;
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
                            continue;
                        }
                        
                        struct segment_command_64 *seg = (struct segment_command_64 *)sc;
                        if (strcmp(seg->segname, "__PAGEZERO") == 0) {
                            continue;
                        } else if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                            linkedit_size = seg->vmsize;
                        }
                        
                        file_size += seg->vmsize;
                    }
                }
            }
        }
        // 系统库的__LINKEDIT段是共用的，并且占了大部分size，所以系统库的size大多相近
        infos[idx] = (ImageInfo){x_mach_header, name, slide, file_size, linkedit_size};
    }
    
    // 排序
    size_t j = 0;
    for (size_t img_idx = 1; img_idx < img_count; img_idx++) {
        ImageInfo image_info = infos[img_idx];
        j = img_idx;
        while (j > 0 &&
               infos[j - 1].loadAddress > image_info.loadAddress
               ) {
            infos[j] = infos[j - 1];
            j--;
        }
        infos[j] = image_info;
    }
    
    [result appendString:@"index   load addr(slide)       vmsize path\n"];
    [result appendString:@"--------------------------------------------------------\n"];
    
    uint32_t r_count = count > 0 ? count : img_count;
    for (size_t image_idx = 0; image_idx < r_count; image_idx++) {
        ImageInfo image_info = infos[image_idx];
        uint64_t file_size = 0;
        if (system_lib_slide == image_info.slide) {
            // 注意：系统库__LINKEDIT段是共用的，此处不计入大小
            file_size = image_info.vm_size - image_info.linkedit_size;
        } else {
            file_size = image_info.vm_size;
        }
        NSString *size_str = nil;
        NSInteger KB = 1000;
        NSInteger MB = KB * KB;
        NSInteger GB = MB * KB;
        if (file_size < KB) {
            size_str = [NSString stringWithFormat:@"%5lluB", file_size];
        } else if (file_size < MB) {
            CGFloat size = ((CGFloat)file_size) / KB;
            size_str = [NSString stringWithFormat:@"%5.1fK", size];
        } else if (file_size < GB) {
            CGFloat size = ((CGFloat)file_size) / MB;
            size_str = [NSString stringWithFormat:@"%5.1fM", size];
        } else {
            CGFloat size = ((CGFloat)file_size) / GB;
            size_str = [NSString stringWithFormat:@"%5.1fG", size];
        }
        
        // 兼容中文需要将路径转为NSString
        [result appendFormat:@"[%3zu] %p(0x%09lx) %@ %@\n", image_idx, image_info.loadAddress, image_info.slide, size_str, [NSString stringWithUTF8String:image_info.filePath]]    
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
    usage = "usage: %prog [module name]\n"

    parser = optparse.OptionParser(usage=usage, prog='entitlements')

    return parser


def generate_image_list_option_parser():
    usage = "usage: %prog [-c]\n"

    parser = optparse.OptionParser(usage=usage, prog='image_list')
    parser.add_option("-c", "--count",
                      dest="count",
                      help="image count")

    return parser
