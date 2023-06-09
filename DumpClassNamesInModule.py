# -*- coding: UTF-8 -*-
import json

import lldb
import optparse
import shlex
import os


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -h "dump the specified module" -f '
        'DumpClassNamesInModule.dump_classes_in_module classes')


def dump_classes_in_module(debugger, command, result, internal_dict):
    """
    dump the specified module
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
        lookup_module_name = ''

    class_names_str = get_module_regions(debugger, lookup_module_name)
    class_names = class_names_str.split('\n')
    class_names = sorted(class_names)

    result.AppendMessage("{}".format('\n'.join(class_names)))


def get_module_regions(debugger, module):
    command_script = '@import Foundation;'
    command_script += 'NSString *x_module_name = @"' + module + '";'
    command_script += r'''
    if (![x_module_name length]) {
        x_module_name = [[[NSBundle mainBundle] executablePath] lastPathComponent];
    }
    
    const char *module_path = NULL;
    uint32_t image_count = (uint32_t)_dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = (const char *)_dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        
        NSString *module_name = [[NSString stringWithUTF8String:name] lastPathComponent];
        if ([module_name isEqualToString:x_module_name]) {
            module_path = name;
            break;
        }
    }
    
    NSMutableString *result = [NSMutableString string];
    if (module_path) {
        unsigned int nclass = 0;
        const char **names = (const char **)objc_copyClassNamesForImage(module_path, &nclass);
        if (names) {
            for (unsigned int i = 0; i < nclass; i++) {
                NSString *className = [NSString stringWithUTF8String:names[i]];
                Class cls = NSClassFromString(className);
                if (cls) {
                    [result appendFormat:@"%@ <%p>\n", className, cls];
                } else {
                    [result appendFormat:@"%@\n", className];
                }
            }
            free(names);
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
    usage = "usage: %prog ModuleName\n" + \
            "Use 'classes -h' for option desc"

    parser = optparse.OptionParser(usage=usage, prog='classes')

    return parser
