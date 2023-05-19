# -*- coding: UTF-8 -*-

import lldb
import optparse
import shlex
from enum import Enum


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.execute_ls ls')
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.show_home_directory home_dir')
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.show_bundle_directory bundle_dir')
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.show_doc_directory doc_dir')
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.show_library_directory lib_dir')
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.show_tmp_directory tmp_dir')
    debugger.HandleCommand('command script add -h "list directory contents, just like ls -lh on mac."'
                           ' -f FileSystem.show_caches_directory caches_dir')


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
        arg = args[0].lower()
        if arg in "bundle":
            dir_path = get_bundle_directory(debugger)
        elif arg in "home":
            dir_path = get_home_directory(debugger)
        elif arg in "doc":
            dir_path = get_doc_directory(debugger)
        elif arg in "lib":
            dir_path = get_library_directory(debugger)
        elif arg in "tmp":
            dir_path = get_tmp_directory(debugger)
        elif arg in "caches":
            dir_path = get_caches_directory(debugger)
        else:
            # arg是经过小写处理的，不能直接使用
            dir_path = command

        file_list = ls_dir(debugger, dir_path)
        result.AppendMessage("{}\n{}".format(dir_path, file_list))
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
        NSMutableString *permissions_str = [NSMutableString string];
        if (permissions == 0755) {
            [permissions_str appendString:@"rwxr-xr-x"];
        } else if (permissions == 0644) {
            [permissions_str appendString:@"rw-r--r--"];
        }
        NSInteger file_size = (NSInteger)[(id)attrs[NSFileSize] integerValue];
        NSString *size_str = nil;
        // 文件系统1KB = 1000B
        NSInteger KB = 1000;
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


def exe_script(debugger, command_script):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand('exp -l objc -O -- ' + command_script, res)

    if not res.HasResult():
        return res.GetError()

    response = res.GetOutput()

    # 末尾有两个\n
    if response.endswith('\n\n'):
        response = response[:-2]

    return response


def generate_option_parser():
    usage = "usage: %prog [dir type or fullpath]\n" + \
            "supported dir type:\n" + \
            "\tbundle - bundle directory\n" + \
            "\thome - home directory, it's the default option\n" + \
            "\tdoc - Documents directory\n" + \
            "\tlib - Library directory\n" + \
            "\ttmp - tmp directory\n" + \
            "\tcaches - Caches directory"

    parser = optparse.OptionParser(usage=usage, prog='ls')

    return parser
