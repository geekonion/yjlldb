# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
from enum import Enum


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "find macho header."'
                           ' -f FindFrida.find_macho_header find_frida')
    debugger.HandleCommand('command script add -h "find macho header."'
                           ' -f FindFrida.find_macho_entitlements find_frida_entitlements')


def find_macho_header(debugger, command, result, internal_dict):
    """
    find macho header
    """

    ret_str = find_macho(debugger)
    result.AppendMessage(ret_str)


def find_macho_entitlements(debugger, command, result, internal_dict):
    """
    find macho header
    """

    ret_str = find_macho_and_entitlements(debugger)
    result.AppendMessage(ret_str)


def find_macho(debugger):
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
    #define data_slice  21214400 //20 * 1024 * 1024
    #define VM_REGION_BASIC_INFO_64         9
    #define VM_REGION_BASIC_INFO_COUNT_64 ((mach_msg_type_number_t) (sizeof(vm_region_basic_info_data_64_t)/sizeof(int)))
    typedef struct mach_header_64 mach_header_t;
    #define VM_REGION_BASIC_INFO_N   VM_REGION_BASIC_INFO_64
    #define VM_REGION_BASIC_INFO_COUNT_N   VM_REGION_BASIC_INFO_COUNT_64
    #define vm_region_basic_info_data_n_t  vm_region_basic_info_data_64_t
    
    #define TASK_DYLD_INFO_COUNT    \
            (sizeof(task_dyld_info_data_t) / sizeof(natural_t))
    #define TASK_DYLD_INFO                  17
    #define KERN_SUCCESS                    0
    
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
    command_script += r'''
    NSMutableString *result = [NSMutableString string];
    /*
     扫描内存的起始位置：第一个machO的结束地址。
     扫描内存的结束位置：第一个系统库的header的起始地址。
     */
    vm_address_t address = 0;
    vm_address_t region_end =  0;
    mach_port_t task = (mach_port_t)mach_task_self();
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) != KERN_SUCCESS) {
        return;
    }
    
    struct dyld_all_image_infos *all_infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    uint32_t ninfo = all_infos->infoArrayCount;
    const struct dyld_image_info *infoArray = all_infos->infoArray;
    struct dyld_image_info *infos = (struct dyld_image_info *)calloc(ninfo, sizeof(struct dyld_image_info));
    if (!infos) {
        return;
    }
    
    memcpy(infos, infoArray, ninfo * sizeof(struct dyld_image_info));
    
    // 排序
    size_t j = 0;
    for (size_t img_idx = 1; img_idx < ninfo; img_idx++) {
        struct dyld_image_info image_info = infos[img_idx];
        j = img_idx;
        while (j > 0 &&
               infos[j - 1].imageLoadAddress > image_info.imageLoadAddress
               ) {
            infos[j] = infos[j - 1];
            j--;
        }
        infos[j] = image_info;
    }
    
    for (size_t image_idx = 0; image_idx < ninfo; image_idx++) {
        struct dyld_image_info image_info = infos[image_idx];
        
        const mach_header_t *header = (const mach_header_t *)image_info.imageLoadAddress;
//        NSLog(@"%s", image_info.imageFilePath);
        vm_address_t macho_end = 0;
        if (header->magic == 0xfeedfacf) { //MH_MAGIC_64
            uint32_t ncmds = header->ncmds;
            if (ncmds > 0) {
                vm_address_t (^get_macho_end)(uintptr_t, uint32_t) = ^(uintptr_t header, uint32_t ncmds) {
                    uintptr_t cur = header + sizeof(mach_header_t);
                    struct load_command *sc = NULL;
                    vm_address_t macho_end = header;
                    for (uint cmd_idx = 0; cmd_idx < ncmds; cmd_idx++, cur += sc->cmdsize) {
                        sc = (struct load_command *)cur;
                        if (cmd_idx < ncmds - 1) {
                            continue;
                        }
                        if (sc->cmd == 0x29 //LC_DATA_IN_CODE
                            || sc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                            struct linkedit_data_command *cmd = (struct linkedit_data_command *)sc;
                            macho_end = (vm_address_t)header + cmd->dataoff + cmd->datasize;
                            break;
                        }
                    }
                    return macho_end;
                };
                
                // header是排过序的，不能直接获取slide，重新匹配，并获取slide
                struct load_command *lc = (struct load_command *)((char *)header + sizeof(mach_header_t));
                struct linkedit_data_command *lc_signature = NULL;
                intptr_t slide       = 0;
                uint32_t image_count = (uint32_t)_dyld_image_count();
                BOOL header_found = NO;
                for (uint32_t i = 0; i < image_count; i++) {
                    const mach_header_t *tmp_header = (const mach_header_t *)_dyld_get_image_header(i);
                    if (tmp_header == header) {
                        slide = (intptr_t)_dyld_get_image_vmaddr_slide(i);
                        header_found = YES;
                        break;
                    }
                }
                
                // 匹配成功
                if (header_found) {
                    uint64_t file_offset = 0;
                    uint64_t vmaddr      = 0;
                    for (uint32_t i = 0; i < ncmds; i++) {
                        if (lc->cmd == 0x19) { // LC_SEGMENT_64
                            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                            if (strcmp(seg->segname, "__LINKEDIT") == 0) { //SEG_LINKEDIT
                                file_offset = seg->fileoff;
                                vmaddr      = seg->vmaddr;
                            }
                        } else if (lc->cmd == 0x29 //LC_DATA_IN_CODE
                                   || lc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                            lc_signature = (struct linkedit_data_command *)lc;
                        }
                        lc = (struct load_command *)((char *)lc + lc->cmdsize);
                    }
                    
                    if (lc_signature) {
                        macho_end = (vm_address_t)vmaddr + lc_signature->dataoff - file_offset + slide + lc_signature->datasize;
                    }
                } else {
                    // 计算macho end
                    macho_end = get_macho_end((uintptr_t)header, ncmds);
                }
            }
        }
        
        // 扫描macho之间的内存间隙，找到注入的macho文件
        if (image_idx > 0) {
            region_end = (vm_address_t)header;
            // 不扫描小于5M的内存空间，因为frida-agent.dylib单个架构也有18M，注入的frida-agent是Fat文件
            if (region_end < address || region_end - address < 0x500000) {
                address = macho_end;
                continue;
            }
//            NSLog(@"scan mem 0x%lx - 0x%lx %s", address, region_end, image_info.imageFilePath);
            vm_size_t read_size = 0;
            vm_size_t region_size = 0;
            
            memory_object_name_t object;
            mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_N;
            vm_region_basic_info_data_n_t basic_info = {0};
            kern_return_t info_ret;
            
            char * (^get_lib_path)(uint64_t) = ^(uint64_t mach_header) {
                const mach_header_t *header = (const mach_header_t *)mach_header;
                uint32_t magic = header->magic;
                char *lib_path = NULL;
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
                
                return lib_path;
            };
            
            //遍历所有 vm_region
            while (true) {
                vm_address_t scan_start = address;
                info_ret = vm_region_64(task, &address, &region_size, VM_REGION_BASIC_INFO_N, (vm_region_info_64_t)&basic_info, &count, &object);
                if (info_ret != KERN_SUCCESS) {
                    break;
                }
                
                if (address >= region_end) {
                    break;
                }
                
                if (scan_start > address) {
                    region_size -= scan_start - address;
                    address = scan_start;
                }
                
                vm_prot_t protection = basic_info.protection;
                //过滤出所有遍历所有含VM_PROT_READ权限的vm_region
                if ((protection & (vm_prot_t)0x01) == 0) { // VM_PROT_READ 0x01
                    address += region_size;
                    continue;
                }
                //系统保留的vm_region，略过
                if (basic_info.reserved) {
                    address += region_size;
                    continue;
                }
                
                vm_address_t end = address + region_size;
                if (end > region_end + 1) {
                    read_size = region_end - address;
                } else {
                    read_size = region_size;
                }
                
                //vm_region内存，分片读取。片大小可调整，默认20M。
                if (read_size > data_slice) {
                    void *data = calloc(1, data_slice);
                    if (!data) {
                        return;
                    }
                    vm_size_t region_size_tmp = read_size;
                    vm_address_t read_addr = address;
                    while (region_size_tmp > 0) {
                        vm_size_t data_size = 0;
                        vm_size_t buff_size = 0;
                        if (region_size_tmp > data_slice) {
                            buff_size = data_slice;
                        } else {
                            buff_size = region_size_tmp;
                            free(data);
                            data = calloc(1, buff_size);
                        }
                        /*
                         直接用原始内存数据搜索MachO magic时，会崩溃
                         读取到自己分配的内存中搜索不会崩溃
                         */
                        kern_return_t ret = vm_read_overwrite(task, read_addr, buff_size, (vm_address_t)data, &data_size);
                        if (ret == KERN_SUCCESS) {
                            // find MachO magic
                            static char macho_magic[] = {'\xcf', '\xfa', '\xed', '\xfe', '\x0c'};
                            void *mach_header = (void *)memmem(data, data_size, &macho_magic, 5);
                            if (mach_header) {
                                // find mach header
                                uint64_t real_header = address + ((char *)mach_header - (char *)data);
                                const char *lib_path = get_lib_path(real_header);
                                NSString *name = [[NSString stringWithUTF8String:lib_path] lastPathComponent];
                                [result appendFormat:@"find %@ macho header at 0x%016llx\n", name, (uint64_t)real_header];
                            }
                        }
                        region_size_tmp -= data_size;
                        read_addr += data_size;
                    }
                    free(data);
                } else {
                    void *data = calloc(1, read_size);
                    if (!data) {
                        return;
                    }
                    vm_size_t data_size = 0;
                    kern_return_t ret = vm_read_overwrite(task, address, read_size, (vm_address_t)data, &data_size);
                    if (ret == KERN_SUCCESS) {
                        // find MachO magic
                        static char macho_magic[] = {'\xcf', '\xfa', '\xed', '\xfe', '\x0c'};
                        void *mach_header = (void *)memmem(data, data_size, &macho_magic, 5);
                        if (mach_header) {
                            // find mach header
                            uint64_t real_header = address + ((char *)mach_header - (char *)data);
                            const char *lib_path = get_lib_path(real_header);
                            NSString *name = nil;
                            if (lib_path) {
                                name = [[NSString stringWithUTF8String:lib_path] lastPathComponent];
                            } else {
                                name = @"unknown";
                            }
                            [result appendFormat:@"find %@ macho header at 0x%016llx\n", name, (uint64_t)real_header];
                        }
                    }
                    free(data);
                }
                address += read_size;
            }
        }
        address = macho_end;
    }
    free(infos);
    
    result;
    '''
    ret_str = exe_script(debugger, command_script)

    return ret_str


def find_macho_and_entitlements(debugger):
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
    #define __LP64__ 1
    #define data_slice  21214400 //20 * 1024 * 1024
    #define VM_REGION_BASIC_INFO_64         9
    #define VM_REGION_BASIC_INFO_COUNT_64 ((mach_msg_type_number_t) (sizeof(vm_region_basic_info_data_64_t)/sizeof(int)))
    #ifdef __LP64__
    typedef struct mach_header_64 mach_header_t;
    #define VM_REGION_BASIC_INFO_N   VM_REGION_BASIC_INFO_64
    #define VM_REGION_BASIC_INFO_COUNT_N   VM_REGION_BASIC_INFO_COUNT_64
    #define vm_region_basic_info_data_n_t  vm_region_basic_info_data_64_t
    #else
    typedef struct mach_header mach_header_t;
    #define VM_REGION_BASIC_INFO_N   VM_REGION_BASIC_INFO
    #define VM_REGION_BASIC_INFO_COUNT_N   VM_REGION_BASIC_INFO_COUNT
    #define vm_region_basic_info_data_n_t  vm_region_basic_info_data_t
    #endif

    #define TASK_DYLD_INFO_COUNT    \
            (sizeof(task_dyld_info_data_t) / sizeof(natural_t))
    #define TASK_DYLD_INFO                  17
    #define KERN_SUCCESS                    0

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
    command_script += r'''
    NSMutableString *result = [NSMutableString string];
    /*
     扫描内存的起始位置：第一个machO的结束地址。
     扫描内存的结束位置：第一个系统库的header的起始地址。
     */
    vm_address_t address = 0;
    vm_address_t region_end =  0;
    mach_port_t task = (mach_port_t)mach_task_self();
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) != KERN_SUCCESS) {
        return;
    }
    
    struct dyld_all_image_infos *all_infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    uint32_t ninfo = all_infos->infoArrayCount;
    const struct dyld_image_info *infoArray = all_infos->infoArray;
    struct dyld_image_info *infos = (struct dyld_image_info *)calloc(ninfo, sizeof(struct dyld_image_info));
    if (!infos) {
        return;
    }
    
    memcpy(infos, infoArray, ninfo * sizeof(struct dyld_image_info));
    
    // 排序
    size_t j = 0;
    for (size_t i = 1; i < ninfo; i++) {
        struct dyld_image_info image_info = infos[i];
        j = i;
        while (j > 0 &&
               infos[j - 1].imageLoadAddress > image_info.imageLoadAddress
               ) {
            infos[j] = infos[j - 1];
            j--;
        }
        infos[j] = image_info;
    }
    
    void (^get_ent)(void *header) = ^(void *header){
        
        char *ent_str = NULL;
        char *lib_path = NULL;
        const mach_header_t *mach_header = (const mach_header_t *)header;
        
        uint32_t header_magic = mach_header->magic;
        if (header_magic != 0xfeedfacf) { //MH_MAGIC_64
            return;
        }
        
        uint32_t ncmds = mach_header->ncmds;
        if (ncmds == 0) {
            return;
        }
        
        struct load_command *lc = (struct load_command *)((char *)mach_header + sizeof(mach_header_t));
        struct linkedit_data_command *lc_signature = NULL;
        
        BOOL sig_found = NO;
        for (uint32_t i = 0; i < ncmds; i++) {
            if (lc->cmd == 0xd) { //LC_ID_DYLIB
                struct dylib_command *dc = (struct dylib_command *)lc;
                char *path = (char *)dc + dc->dylib.name.offset;
                if (path) {
                    lib_path = strdup(path);
                }
            } else if (lc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                lc_signature = (struct linkedit_data_command *)lc;
            }
            lc = (struct load_command *)((char *)lc + lc->cmdsize);
        }
        NSString *module_name = nil;
        if (lib_path) {
            module_name = [[NSString stringWithUTF8String:lib_path] lastPathComponent];
        } else {
            module_name = @"unknown";
        }
        
        if (lc_signature) {
            sig_found = YES;
            char *sign_ptr = (char *)header + lc_signature->dataoff;
#if __arm64e__
            void *sign = (void *)ptrauth_strip(codeSignature, ptrauth_key_function_pointer);
#else
            void *sign = (void *)sign_ptr;
#endif

            struct CS_SuperBlob *superBlob = (struct CS_SuperBlob *)sign;
            uint32_t super_blob_magic = _OSSwapInt32(superBlob->magic);
            // 签名段数据被破坏
            if (super_blob_magic != 0xfade0cc0) { // CSMAGIC_EMBEDDED_SIGNATURE
                [result appendFormat:@"invalid signature magic found at %@!0x%x, signature: %p, header at %p\n", module_name, lc_signature->dataoff, sign, header];
                uint32_t sign_size = lc_signature->datasize;
                const char *prefix = "<?xml";
                char *ent_ptr = (char *)memmem(sign, sign_size, prefix, strlen(prefix));
                if (!ent_ptr) {
                    return;
                }
                const char *suffix = "</plist>";
                size_t data_len = ent_ptr - (char *)sign;
                char *ent_end = (char *)memmem(ent_ptr, data_len, suffix, strlen(suffix));
                if (!ent_end) {
                    return;
                }
                size_t length = ent_end - ent_ptr + strlen(suffix);
                if (length) {
                    ent_str = (char *)calloc(length + 1, sizeof(char));
                    if (ent_str) {
                        memcpy(ent_str, ent_ptr, length);
                        [result appendFormat:@"entitlements of %@:\n%s", module_name, ent_str];
                        free(ent_str);
                    }
                }
                return;
            }
            uint32_t nblob = _OSSwapInt32(superBlob->count);
            
            BOOL ent_found = NO;
            struct CS_BlobIndex *index = superBlob->index;
            for ( int blob_idx = 0; blob_idx < nblob; ++blob_idx ) {
                struct CS_BlobIndex blobIndex = index[blob_idx];
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
                        [result appendFormat:@"entitlements of %@:\n%s", module_name, ent_str];
                        free(ent_str);
                        ent_found = YES;
                    }
                    break;
                }
            }
            if (!ent_found) {
                [result appendFormat:@"%@ apparently does not contain any entitlements\n", module_name];
            }
        }
        
        if (!sig_found) {
            [result appendFormat:@"%@ apparently does not contain code signature\n", module_name];
        }
        if (lib_path) {
            free(lib_path);
        }
    };
    
    for (size_t image_idx = 0; image_idx < ninfo; image_idx++) {
        struct dyld_image_info image_info = infos[image_idx];
        
        const mach_header_t *header = (const mach_header_t *)image_info.imageLoadAddress;
        
        vm_address_t macho_end = (vm_address_t)image_info.imageLoadAddress;
        if (header->magic == 0xfeedfacf) { //MH_MAGIC_64
            uint32_t ncmds = header->ncmds;
            if (ncmds > 0) {
                uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
                struct load_command *sc = NULL;
                for (uint cmd_idx = 0; cmd_idx < ncmds; cmd_idx++, cur += sc->cmdsize) {
                    sc = (struct load_command *)cur;
                    if (cmd_idx < ncmds - 1) {
                        continue;
                    }
                    if (sc->cmd == 0x29 //LC_DATA_IN_CODE
                        || sc->cmd == 0x1d) { //LC_CODE_SIGNATURE
                        struct linkedit_data_command *cmd = (struct linkedit_data_command *)sc;
                        macho_end = (vm_address_t)header + cmd->dataoff + cmd->datasize;
                        break;
                    }
                }
            }
        }
        
        if (image_idx > 0) {
            region_end = (vm_address_t)header;
            // 不再扫描小于5M的内存空间，因为frida-agent.dylib单个架构也有18M，注入的frida-agent是Fat文件
            if (region_end - address < 0x500000) {
                address = macho_end;
                continue;
            }
            
            vm_size_t read_size = 0;
            vm_size_t region_size = 0;
            
            memory_object_name_t object;
            mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_N;
            vm_region_basic_info_data_n_t basic_info = {0};
            kern_return_t info_ret;
            
            //遍历所有 vm_region
            while (true) {
                vm_address_t scan_start = address;
                info_ret = vm_region_64(task, &address, &region_size, VM_REGION_BASIC_INFO_N, (vm_region_info_64_t)&basic_info, &count, &object);

                if (info_ret != KERN_SUCCESS) {
                    break;
                }
                
                if (address >= region_end) {
                    break;
                }
                
                if (scan_start > address) {
                    region_size -= scan_start - address;
                    address = scan_start;
                }
                
                vm_prot_t protection = basic_info.protection;
                //过滤出所有遍历所有含VM_PROT_READ权限的vm_region
                if ((protection & 0x01) == 0) { // VM_PROT_READ 0x01
                    address += region_size;
                    continue;
                }
                //系统保留的vm_region，略过
                if (basic_info.reserved) {
                    address += region_size;
                    continue;
                }
                
                vm_address_t end = address + region_size;
                if (end > region_end + 1) {
                    read_size = region_end - address;
                } else {
                    read_size = region_size;
                }
                
                //vm_region内存，分片读取。片大小可调整，默认20M。
                if (read_size > data_slice) {
                    void *data = calloc(1, data_slice);
                    if (!data) {
                        return;
                    }
                    vm_size_t region_size_tmp = read_size;
                    vm_address_t read_addr = address;
                    while (region_size_tmp > 0) {
                        vm_size_t data_size = 0;
                        vm_size_t buff_size = 0;
                        if (region_size_tmp > data_slice) {
                            buff_size = data_slice;
                        } else {
                            buff_size = region_size_tmp;
                            free(data);
                            data = calloc(1, buff_size);
                        }
                        /*
                         直接用原始内存数据搜索MachO magic时，会崩溃
                         读取到自己分配的内存中搜索不会崩溃
                         */
                        kern_return_t ret = vm_read_overwrite(task, read_addr, buff_size, (vm_address_t)data, &data_size);
                        if (ret == KERN_SUCCESS) {
                            // find MachO magic
                            static char macho_magic[] = {'\xcf', '\xfa', '\xed', '\xfe', '\x0c'};
                            void *mach_header = (void *)memmem(data, data_size, &macho_magic, 5);
                            if (mach_header) {
                                // find mach header
                                void *real_header = (char *)address + ((char *)header - (char *)data);
                                get_ent(real_header);
                            }
                        }
                        region_size_tmp -= data_size;
                        read_addr += data_size;
                    }
                    free(data);
                } else {
                    void *data = calloc(1, read_size);
                    if (!data) {
                        return;
                    }
                    vm_size_t data_size = 0;
                    kern_return_t ret = vm_read_overwrite(task, address, read_size, (vm_address_t)data, &data_size);
                    if (ret == KERN_SUCCESS) {
                        // find MachO magic
                        static char macho_magic[] = {'\xcf', '\xfa', '\xed', '\xfe', '\x0c'};
                        void *header = (void *)memmem(data, data_size, &macho_magic, 5);
                        if (header) {
                            // find mach header
                            void *real_header = (char *)address + ((char *)header - (char *)data);
                            get_ent(real_header);
                        }
                    }
                    free(data);
                }
                address += read_size;
            }
        }
        address = macho_end;
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
    usage = "usage: %prog\n"

    parser = optparse.OptionParser(usage=usage, prog='find_frida')

    return parser
