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

    ret_str = get_entitlements(debugger, module_name)
    result.AppendMessage(ret_str)


def image_list(debugger, command, result, internal_dict):
    """
    List current executable and dependent shared library images, sorted by load address.
    """
    ret_str = get_sorted_images(debugger)
    result.AppendMessage(ret_str)


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
        sscanf((const char *)[keyword UTF8String], "%llx", &address);
    }
    char *ent_str = NULL;
    const mach_header_t *headers[256] = {0};
    NSMutableArray *names = [NSMutableArray array];
    intptr_t slides[256] = {0};
    int count = 0;
    if (!keyword || [@"NULL" isEqualToString:keyword]) {
        const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(0);
        headers[count] = mach_header;
        slides[count] = (intptr_t)_dyld_get_image_vmaddr_slide(0);
        count++;
        [names addObject:[[NSString stringWithUTF8String:(const char *)_dyld_get_image_name(0)] lastPathComponent]];
    } else {
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
                headers[count] = mach_header;
                slides[count] = (intptr_t)_dyld_get_image_vmaddr_slide(i);
                count++;
                [names addObject:module_name];
            }
            if (isAddress) {
                break;
            }
        }
    }
    
    char *lib_path = NULL;
    if (isAddress && names.count == 0) {
        const mach_header_t *header = (const mach_header_t *)address;
        uint32_t magic = header->magic;
        if (magic == 0xfeedfacf) { // MH_MAGIC_64
            uint32_t ncmds = header->ncmds;
            if (ncmds > 50) {
            } else if (ncmds > 0) {
                uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (sc->cmd == 0xd) { //LC_ID_DYLIB
                        struct dylib_command *dc = (struct dylib_command *)sc;
                        char *path = (char *)dc + dc->dylib.name.offset;
                        if (path) {
                            lib_path = strdup(path);
                        }
                        break;
                    }
                }
            }
        }
        if (lib_path) {
            NSString *module_name = [[NSString stringWithUTF8String:lib_path] lastPathComponent];
            headers[count] = header;
            slides[count] = 0;
            count++;
            [names addObject:module_name];
        }
    }
    
    NSMutableString *result = [NSMutableString string];
    for (int idx = 0; idx < count; idx++) {
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
        intptr_t slide       = slides[idx];
        uint64_t file_offset = 0;
        uint64_t vmaddr      = 0;
        BOOL sig_found = NO;
        for (uint32_t i = 0; i < ncmds; i++) {
            if (lc->cmd == 0x19) { // LC_SEGMENT_64
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
                    file_offset = seg->fileoff;
                    vmaddr      = seg->vmaddr;
                }
            } else if (lc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                lc_signature = (struct linkedit_data_command *)lc;
            }
            lc = (struct load_command *)((char *)lc + lc->cmdsize);
        }
        if (lc_signature) {
            sig_found = YES;
            char *sign_ptr = NULL;
            if (slide == 0) {
                sign_ptr = (char *)mach_header + lc_signature->dataoff;
            } else {
                sign_ptr = (char *)vmaddr + lc_signature->dataoff - file_offset + slide;
            }
#if __arm64e__
            void *sign = (void *)ptrauth_strip(codeSignature, ptrauth_key_function_pointer);
#else
            void *sign = (void *)sign_ptr;
#endif
            struct CS_SuperBlob *superBlob = (struct CS_SuperBlob *)sign;
            uint32_t super_blob_magic = _OSSwapInt32(superBlob->magic);
            // 签名段数据被破坏
            if (super_blob_magic != 0xfade0cc0) { // CSMAGIC_EMBEDDED_SIGNATURE
                [result appendFormat:@"invalid signature magic found at %@!0x%x, signature: %p, header at: %p\n", names[idx], lc_signature->dataoff, sign, mach_header];
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
                        [result appendFormat:@"entitlements of %@:\n%s", names[idx], ent_str];
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
                        [result appendFormat:@"entitlements of %@:\n%s", names[idx], ent_str];
                        free(ent_str);
                        ent_found = YES;
                    }
                    break;
                }
            }
            if (!ent_found) {
                [result appendFormat:@"%@ apparently does not contain any entitlements\n", names[idx]];
            }
        }
        
        if (!sig_found) {
            [result appendFormat:@"%@ apparently does not contain code signature\n", names[idx]];
        }
    }
    if (lib_path) {
        free(lib_path);
    }
    
    result;
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_sorted_images(debugger):
    command_script = '@import Foundation;'
    command_script += r'''
    typedef struct ImageInfo {
        const struct mach_header *loadAddress;
        const char *filePath;
        intptr_t slide;
    } ImageInfo;
    '''
    command_script += r'''
    NSMutableString *result = [NSMutableString string];
    
    uint32_t count = (uint32_t)_dyld_image_count();
    ImageInfo *infos = (ImageInfo *)calloc(count, sizeof(ImageInfo));
    if (!infos) {
        return;
    }
    for (uint32_t idx = 0; idx < count; idx++) {
        const struct mach_header *header = (const struct mach_header *)_dyld_get_image_header(idx);
        const char *name = (const char *)_dyld_get_image_name(idx);
        intptr_t slide = (intptr_t)_dyld_get_image_vmaddr_slide(idx);
        infos[idx] = (ImageInfo){header, name, slide};
    }
    
    // 排序
    size_t j = 0;
    for (size_t img_idx = 1; img_idx < count; img_idx++) {
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
    
    [result appendString:@"index   load addr(slide)       path\n"];
    [result appendString:@"--------------------------------------------------------\n"];
    for (size_t image_idx = 0; image_idx < count; image_idx++) {
        ImageInfo image_info = infos[image_idx];
        
        [result appendFormat:@"[%3zu] %p(0x%09lx) %s\n", image_idx, image_info.loadAddress, image_info.slide, image_info.filePath];
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
    # 末尾有两个\n
    if response.endswith('\n'):
        response = response[:-1]

    return response


def generate_option_parser():
    usage = "usage: %prog [module name]\n"

    parser = optparse.OptionParser(usage=usage, prog='entitlements')

    return parser
