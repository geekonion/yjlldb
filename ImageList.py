# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


class Module:
    path = ''
    load_address = 0
    slide = 0
    size = 0
    linkedit_size = 0

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "set breakpoints at the specified bytes in user modules" -f '
        'ImageList.image_list image_list')


def image_list(debugger, command, result, internal_dict):
    """
    set breakpoints at the specified bytes in user modules
    """

    target = debugger.GetSelectedTarget()
    modules = []
    symbol_comp = ')/Symbols/'
    symbol_comp_len = len(symbol_comp)
    for module in target.module_iter():
        slide = 0
        header_addr = 0
        linkedit_size = 0
        module_size = 0
        for seg in module.section_iter():
            seg_name = seg.GetName()
            if seg_name == '__PAGEZERO':
                continue
            elif seg_name == '__TEXT':
                header_addr = seg.GetLoadAddress(target)
                slide = header_addr - seg.GetFileAddress()
            elif seg_name == '__LINKEDIT':
                linkedit_size = seg.GetByteSize()

            module_size += seg.GetByteSize()

        platform_file_path = str(module.GetPlatformFileSpec())
        pos = platform_file_path.find(symbol_comp)
        if pos == -1:
            module_path = platform_file_path
        else:
            path_start =  pos + symbol_comp_len - 1
            module_path = platform_file_path[path_start:]
        mod = Module()
        mod.path = module_path
        mod.load_address = header_addr
        mod.slide = slide
        mod.size = module_size
        mod.linkedit_size = linkedit_size
        modules.append(mod)

    sorted_modules = sorted(modules, key=lambda module: module.load_address)

    print("index     load addr(slide)     vmsize path")
    for idx, module in enumerate(sorted_modules):
        mod_size = module.size
        KB = 1000
        MB = KB * KB
        GB = MB * KB
        if mod_size < KB:
            size_str = '{:5}B'.format(mod_size)
        elif mod_size < MB:
            size_str = '{:5.1f}K'.format(mod_size / KB)
        elif mod_size < GB:
            size_str = '{:5.1f}M'.format(mod_size / MB)
        else:
            size_str = '{:5.1f}G'.format(mod_size / GB)

        print("[{:>3}] 0x{:x}(0x{:09x}) {} {}".format(idx, module.load_address, module.slide, size_str, module.path))