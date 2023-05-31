# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
from enum import Enum


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "print codesign entitlements of the specified module if any."'
                           ' -f MachOParser.show_entitlements entitlements')


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


def get_entitlements(debugger, keyword):
    command_script = '@import Foundation;'
    command_script += '''
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
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    typedef struct segment_command_64 segment_command_t;
    #else
    typedef struct mach_header mach_header_t;
    typedef struct segment_command segment_command_t;
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
    '''
    command_script += 'NSString *keyword = @"' + keyword + '";\n'
    command_script += r'''
    char *ent_str = NULL;
    const mach_header_t *headers[256] = {0};
    NSMutableArray *names = [NSMutableArray array];
    int count = 0;
    if (!keyword || [@"NULL" isEqualToString:keyword]) {
        const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(0);
        headers[count] = mach_header;
        count++;
        [names addObject:[[NSString stringWithFormat:@"%s", (const char *)_dyld_get_image_name(0)] lastPathComponent]];
    } else {
        uint32_t image_count = (uint32_t)_dyld_image_count();
        for (uint32_t i = 0; i < image_count; i++) {
            const char *name = (const char *)_dyld_get_image_name(i);
            if (!name) {
                continue;
            }
            NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
            if ([module_name containsString:keyword]) {
                const mach_header_t *mach_header = (const mach_header_t *)_dyld_get_image_header(i);
                headers[count] = mach_header;
                count++;
                [names addObject:[NSString stringWithString: module_name]];
            }
        }
    }
    
    NSMutableString *result = [NSMutableString string];
    for (int idx = 0; idx < count; idx++) {
        const mach_header_t *mach_header = headers[idx];
        uint32_t magic = mach_header->magic;
        if (magic == 0xfeedfacf) { //MH_MAGIC_64
            uint32_t ncmds = mach_header->ncmds;
            [result appendString: names[idx]];
            BOOL sig_found = NO;
            if (ncmds > 0) {
                uintptr_t cur = (uintptr_t)mach_header + sizeof(mach_header_t);
                segment_command_t *sc = NULL;
                for (uint i = 0; i < ncmds; i++, cur += sc->cmdsize) {
                    sc = (segment_command_t *)cur;
                    if (sc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                        sig_found = YES;
                        struct linkedit_data_command *cmd = (struct linkedit_data_command *)sc;
                        void *sign = (char *)mach_header + cmd->dataoff;
                        
                        struct CS_SuperBlob *superBlob = (struct CS_SuperBlob *)sign;
                        uint32_t magic = _OSSwapInt32(superBlob->magic);
                        uint32_t nblob = _OSSwapInt32(superBlob->count);
                        
                        BOOL ent_found = NO;
                        struct CS_BlobIndex *index = superBlob->index;
                        for ( int i = 0; i < nblob; ++i ) {
                            struct CS_BlobIndex blobIndex = index[i];
                            uint32_t offset = _OSSwapInt32(blobIndex.offset);
                            
                            uint32_t *blobAddr = (__uint32_t *)((char *)sign + offset);
                            
                            struct CS_Blob *blob = (struct CS_Blob *)blobAddr;
                            magic = _OSSwapInt32(blob->magic);
                            if ( magic == 0xfade7171 ) { //kSecCodeMagicEntitlement
                                struct CS_Blob *ent = (struct CS_Blob *)blobAddr;
                                
                                uint32_t header_len = 8;
                                uint32_t length = _OSSwapInt32(ent->length) - header_len;
                                if (length <= 0) {
                                    break;
                                }
                                char *ent_ptr = (char *)blobAddr + header_len;
                                ent_str = (char *)calloc(length + 1, sizeof(char));
                                if (ent_str) {
                                    memcpy(ent_str, ent_ptr, length);
                                    [result appendFormat:@":\n%s", ent_str];
                                    free(ent_str);
                                    ent_found = YES;
                                }
                                break;
                            }
                        }
                        if (!ent_found) {
                            [result appendString:@" apparently does not contain any entitlements\n"];
                        }
                        break;
                    }
                }
            }
            if (!sig_found) {
                [result appendString:@" apparently does not contain code signature\n"];
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
