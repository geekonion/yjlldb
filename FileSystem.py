# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
from enum import Enum


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.execute_ls ls')
    debugger.HandleCommand('command script add -h "print Home directory path."'
                           ' -f FileSystem.show_home_directory home_dir')
    debugger.HandleCommand('command script add -h "print bundle path."'
                           ' -f FileSystem.show_bundle_directory bundle_dir')
    debugger.HandleCommand('command script add -h "print Documents path."'
                           ' -f FileSystem.show_doc_directory doc_dir')
    debugger.HandleCommand('command script add -h "print Library path."'
                           ' -f FileSystem.show_library_directory lib_dir')
    debugger.HandleCommand('command script add -h "print tmp path."'
                           ' -f FileSystem.show_tmp_directory tmp_dir')
    debugger.HandleCommand('command script add -h "print Caches path."'
                           ' -f FileSystem.show_caches_directory caches_dir')
    debugger.HandleCommand('command script add -h "print group path."'
                           ' -f FileSystem.show_group_path group_dir')


def execute_ls(debugger, command, result, internal_dict):
    """
    list directory contents, just like ls -lh on mac.
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

    if len(args) == 1:
        show_dir = True
        arg = args[0].lower()
        if arg in "bundle":
            dir_path = get_bundle_directory(debugger)
            dir_type = "bundle"
        elif arg in "home":
            dir_path = get_home_directory(debugger)
            dir_type = "home"
        elif arg in "doc":
            dir_path = get_doc_directory(debugger)
            dir_type = "doc"
        elif arg in "lib":
            dir_path = get_library_directory(debugger)
            dir_type = "lib"
        elif arg in "tmp":
            dir_path = get_tmp_directory(debugger)
            dir_type = "tmp"
        elif arg in "caches":
            dir_path = get_caches_directory(debugger)
            dir_type = "caches"
        elif arg in "group":
            dir_path = get_group_path(debugger)
            dir_type = "group"
        else:
            # arg是经过小写处理的，不能直接使用
            dir_path = command
            show_dir = False

        if 'nil' == dir_path:
            result.AppendMessage(f'{dir_type} dir path is nil')
            return

        if not dir_path:
            result.AppendMessage(dir_path)
            return

        file_list = ls_dir(debugger, dir_path)
        if 'object returned empty description' in file_list:
            file_list = 'total 0'
        if show_dir:
            result.AppendMessage("{}\n{}".format(dir_path, file_list))
        else:
            result.AppendMessage(file_list)
    elif len(args) == 0:
        dir_path = get_home_directory(debugger)
        file_list = ls_dir(debugger, dir_path)
        result.AppendMessage("{}\n{}".format(dir_path, file_list))
    else:
        result.AppendMessage(parser.get_usage())
        return


def ls_dir(debugger, dir_path):
    command_script = '@import Foundation;'
    command_script += 'NSString *dir_path = @"' + dir_path + '";'
    command_script += r'''
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error = nil;
    NSArray *files = (NSArray *)[fileManager contentsOfDirectoryAtPath:dir_path error:&error];
    if (error) {
        NSLog(@"%@", error);
    }
    NSMutableString *result = [NSMutableString string];
    for (NSString *name in files) {
        if ([(NSString *)name isEqualToString:@".com.apple.mobile_container_manager.metadata.plist"]) {
            continue;
        }
        NSString *fullpath = [dir_path stringByAppendingPathComponent:name];
        NSDictionary *attrs = (id)[fileManager attributesOfItemAtPath:fullpath error:nil];
        NSString *filetype = attrs[NSFileType];
        NSString *type_str = nil;
        if ([filetype isEqualToString:NSFileTypeDirectory]) {
            type_str = @"d";
        } else if ([filetype isEqualToString:NSFileTypeSymbolicLink]) {
            type_str = @"l";
        } else if ([filetype isEqualToString:NSFileTypeRegular]) {
            type_str = @"-";
        } else {
            type_str = @"-";
        }
        NSInteger permissions = (NSInteger)[(id)attrs[NSFilePosixPermissions] integerValue];
        NSString *permissions_str = @"";
        if (permissions == 0755) {
            permissions_str = @"rwxr-xr-x";
        } else if (permissions == 0644) {
            permissions_str = @"rw-r--r--";
        }
        NSInteger file_size = (NSInteger)[(id)attrs[NSFileSize] integerValue];
        NSString *size_str = nil;
        NSInteger KB = 1024;
        NSInteger MB = KB * KB;
        NSInteger GB = MB * KB;

        if (file_size < KB) {
            size_str = [NSString stringWithFormat:@"%10luB", file_size];
        } else if (file_size < MB) {
            size_str = [NSString stringWithFormat:@"%10.1fK", ((CGFloat)file_size) / KB];
        } else if (file_size < GB) {
            size_str = [NSString stringWithFormat:@"%10.1fM", ((CGFloat)file_size) / MB];
        } else {
            size_str = [NSString stringWithFormat:@"%10.1fG", ((CGFloat)file_size) / GB];
        }
        NSDate *modificationDate = (id)attrs[(NSFileAttributeKey)NSFileModificationDate];
        [result appendFormat:@"%@%@ %@ %@ %@\n", type_str, permissions_str, size_str, modificationDate, name];
    }
    
    result;
    '''

    ret_str = exe_script(debugger, command_script)

    return ret_str


def show_bundle_directory(debugger, command, result, internal_dict):
    ret_str = get_bundle_directory(debugger)
    result.AppendMessage(ret_str)


def show_home_directory(debugger, command, result, internal_dict):
    ret_str = get_home_directory(debugger)
    result.AppendMessage(ret_str)


def show_doc_directory(debugger, command, result, internal_dict):
    ret_str = get_doc_directory(debugger)
    result.AppendMessage(ret_str)


def show_library_directory(debugger, command, result, internal_dict):
    ret_str = get_library_directory(debugger)
    result.AppendMessage(ret_str)


def show_tmp_directory(debugger, command, result, internal_dict):
    ret_str = get_tmp_directory(debugger)
    result.AppendMessage(ret_str)


def show_caches_directory(debugger, command, result, internal_dict):
    ret_str = get_caches_directory(debugger)
    result.AppendMessage(ret_str)


def show_group_path(debugger, command, result, internal_dict):
    ret_str = get_group_path(debugger)
    result.AppendMessage(ret_str)


def get_bundle_directory(debugger):
    command_script = '@import Foundation;'
    # const char *path = (const char *)[[(NSBundle *)[NSBundle mainBundle] bundlePath] UTF8String];
    command_script += r'''
    NSString *path = (NSString *)[(NSBundle *)[NSBundle mainBundle] bundlePath];

    path
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_home_directory(debugger):
    command_script = '@import Foundation;'
    command_script += r'''
    NSString *path = (NSString *)NSHomeDirectory();

    path
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_doc_directory(debugger):
    command_script = '@import Foundation;'
    command_script += r'''
    NSString *path = (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];

    path
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_library_directory(debugger):
    command_script = '@import Foundation;'
    command_script += r'''
    NSString *path = (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"Library"];

    path
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_tmp_directory(debugger):
    command_script = '@import Foundation;'
    command_script += r'''
    NSString *path = (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"tmp"];

    path
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_caches_directory(debugger):
    command_script = '@import Foundation;'
    command_script += r'''
    NSString *path = (NSString *)[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches"];

    path
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def get_group_path(debugger):
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
    '''
    command_script += r'''
    char *groupID_c = NULL;
    const mach_header_t *mach_header = NULL;
    
    NSString *exe_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    uint32_t image_count = (uint32_t)_dyld_image_count();
    intptr_t slide       = 0;
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        
        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        NSRange range = [module_name rangeOfString:exe_name options:NSCaseInsensitiveSearch];
        if (range.location != NSNotFound) {
            mach_header = (const mach_header_t *)_dyld_get_image_header(i);
            slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    
    uint32_t header_magic = mach_header->magic;
    if (header_magic == 0xfeedfacf) { //MH_MAGIC_64
        uint32_t ncmds = mach_header->ncmds;
        if (ncmds > 0) {
            struct load_command *lc = (struct load_command *)((char *)mach_header + sizeof(mach_header_t));
            struct linkedit_data_command *lc_signature = NULL;
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
                char *sign_ptr = (char *)vmaddr + lc_signature->dataoff - file_offset + slide;
#if __arm64e__
                void *sign = (void *)ptrauth_strip(codeSignature, ptrauth_key_function_pointer);
#else
                void *sign = (void *)sign_ptr;
#endif
                
                struct CS_SuperBlob *superBlob = (struct CS_SuperBlob *)sign;
                uint32_t super_blob_magic = _OSSwapInt32(superBlob->magic);
                if (super_blob_magic == 0xfade0cc0) { //CSMAGIC_EMBEDDED_SIGNATURE
                    uint32_t nblob = _OSSwapInt32(superBlob->count);
                    
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
                            const char *mem_start = (char *)blobAddr + header_len;
                            const char *keyword = "com.apple.security.application-groups";
                            char *group_key = (char *)memmem(mem_start, length, keyword, strlen(keyword));
                            if (!group_key) {
                                break;
                            }
                            
                            const char *prefix = "<string>";
                            size_t prefix_len = strlen(prefix);
                            length -= (uint32_t)(group_key - mem_start);
                            char *group_start = (char *)memmem(group_key, length, prefix, prefix_len);
                            if (!group_start) {
                                break;
                            }
                            group_start += prefix_len;
                            length -= prefix_len;
                            const char *suffix = "</string>";
                            char *group_end = (char *)memmem(group_start, length, suffix, strlen(suffix));
                            if (!group_end) {
                                break;
                            }
                            
                            long len = group_end - group_start;
                            groupID_c = (char *)calloc(len + 1, sizeof(char));
                            if (groupID_c) {
                                memcpy(groupID_c, group_start, len);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    NSString *group_path = nil;
    if (groupID_c) {
        NSString *groupID = [NSString stringWithUTF8String:groupID_c];
        free(groupID_c);
        group_path = [(NSURL *)[[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:groupID] path];
    }
    group_path;
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


def generate_option_parser():
    usage = "usage: %prog [dir type or fullpath]\n" + \
            "supported dir type:\n" + \
            "\tbundle - bundle directory\n" + \
            "\thome - home directory, it's the default option\n" + \
            "\tdoc - Documents directory\n" + \
            "\tlib - Library directory\n" + \
            "\ttmp - tmp directory\n" + \
            "\tcaches - Caches directory\n" + \
            "\tgroup - group directory"

    parser = optparse.OptionParser(usage=usage, prog='ls')

    return parser
