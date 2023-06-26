# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "set breakpoints at the specified bytes in user modules" -f '
        'PatchBytesWithNOP.patch_bytes_with_nop patch')


def patch_bytes_with_nop(debugger, command, result, internal_dict):
    """
    set breakpoints at the specified bytes in user modules
    """
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

    if len(args) == 0:
        result.AppendMessage(parser.get_usage())
        return
    elif len(args) == 1:
        input_arg = args[0].replace("'", "")
        comps = input_arg.split('\\x')
        bytes_list = [int(x, 16) for x in comps if len(x) > 0]
    else:
        bytes_list = [int(x, 16) for x in args]

    bytes_len = len(bytes_list)
    if bytes_len % 4 != 0:
        result.SetError("The number of bytes must be a multiple of 4")
        return

    input_bytes = bytes(bytes_list)

    nop_bytes = b'\x1f\x20\x03\xd5'
    loop_count = int(bytes_len / 4)
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    bundle_path = target.GetExecutable().GetDirectory()
    for module in target.module_iter():
        module_file_spec = module.GetFileSpec()

        module_dir = module_file_spec.GetDirectory()
        if bundle_path not in module_dir:
            continue

        name = module_file_spec.GetFilename()
        if name.startswith('libswift'):
            continue

        hits_count = 0
        result.AppendMessage("-----try set breakpoint at %s-----" % name)
        for seg in module.section_iter():
            seg_name = seg.GetName()
            if seg_name != "__TEXT":
                continue

            for sec in seg:
                sec_name = sec.GetName()
                if "_stub" in sec_name or \
                        "__objc_methname" == sec_name or \
                        "__objc_classname" == sec_name or \
                        "__objc_methtype" == sec_name or \
                        "__cstring" == sec_name or \
                        "__ustring" == sec_name or \
                        "__gcc_except_tab" == sec_name or \
                        "__const" == sec_name or \
                        "__unwind_info" == sec_name:
                    continue

                start_addr = sec.GetLoadAddress(target)
                error1 = lldb.SBError()
                sec_size = sec.GetByteSize()

                sec_data = sec.GetSectionData().ReadRawData(error1, 0, sec_size)
                if not error1.Success():
                    print('read section {} data failed!'.format(sec_name))
                    continue

                pos = 0
                while True:
                    pos = sec_data.find(input_bytes, pos)
                    if pos == -1:
                        break

                    hits_count += 1
                    
                    bytes_addr = pos + start_addr
                    for idx in range(loop_count):
                        to_patch = bytes_addr + idx * 4
                        error2 = lldb.SBError()
                        process.WriteMemory(to_patch, nop_bytes, error2)
                        if not error2.Success():
                            print('patch bytes at {} failed!'.format(to_patch))
                            continue

                    pos += bytes_len

        if hits_count == 0:
            result.AppendMessage("input bytes not found")

    result.AppendMessage("patch {} locations".format(hits_count))


def generate_option_parser():
    usage = "usage: %prog bytes\n" + \
            "for example:\n" + \
            "\t%prog \\xc0\\x03\\x5f\\xd6\n" + \
            "or\n" + \
            "\t%prog c0 03 5f d6"

    parser = optparse.OptionParser(usage=usage, prog='patch')

    return parser
