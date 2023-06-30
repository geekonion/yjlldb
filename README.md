一些用于调试iOS应用的lldb命令

Some very useful lldb commands for iOS debugging.



#### bab - break at bytes

set breakpoints at the specified bytes in user modules

```stylus
(lldb) bab c0 03 5f d6
Breakpoint 1: where = LLDBCode`-[ViewController viewDidLoad] + 240 at ViewController.m:29:1, address = 0x1029b3008
...
set 728 breakpoints

(lldb) x 0x1029b3008
0x1029b3008: c0 03 5f d6 ff 03 03 d1 fd 7b 0b a9 fd c3 02 91  .._......{......
0x1029b3018: e8 03 01 aa e1 03 02 aa e3 0f 00 f9 a0 83 1f f8  ................
(lldb) dis -s 0x1029b3008 -c 1
LLDBCode`-[ViewController viewDidLoad]:
    0x1029b3008 <+240>: ret
```



#### baf - break all functions in module

break all functions and methods in the specified module

for example，break UIKit

```stylus
(lldb) baf UIKit
-----break functions in UIKit-----
will set breakpoint for 76987 names
Breakpoint 3: 75016 locations
```



#### bdc - breakpoint disable current

disable current breakpoint an continue

```stylus
(lldb) thread info
thread #1: tid = 0x2cb739, 0x000000018354f950 libsystem_kernel.dylib`open, queue = 'com.apple.main-thread', stop reason = breakpoint 5.13

(lldb) bdc
disable breakpoint 5.13 [0x18354f950]libsystem_kernel.dylib`open
and continue
```



#### symbolic

```stylus
(lldb) symbolic (0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0)
backtrace: 
frame #0: 0x1845aed8c CoreFoundation`__exceptionPreprocess + 228
frame #1: 0x1837685ec libobjc.A.dylib`objc_exception_throw + 56
frame #2: 0x18450a448 CoreFoundation`-[__NSArray0 objectEnumerator] + 0
frame #3: 0x104360f78 Interlock`-[ViewController touchesBegan:withEvent:] + at ViewController.m:51:5
...
```

or

```stylus
(lldb) symbolic 0x1845aed8c 0x1837685ec 0x18450a448 0x104360f78 0x18e4fd83c 0x18e3a3760 0x18e39d7c8 0x18e392890 0x18e3911d0 0x18eb72d1c 0x18eb752c8 0x18eb6e368 0x184557404 0x184556c2c 0x18455479c 0x184474da8 0x186459020 0x18e491758 0x104361da0 0x183f05fc0
backtrace: 
frame #0: 0x1845aed8c CoreFoundation`__exceptionPreprocess + 228
frame #1: 0x1837685ec libobjc.A.dylib`objc_exception_throw + 56
frame #2: 0x18450a448 CoreFoundation`-[__NSArray0 objectEnumerator] + 0
frame #3: 0x104360f78 Interlock`-[ViewController touchesBegan:withEvent:] + at ViewController.m:51:5
...
```



#### commads to get common directory

```stylus
(lldb) bundle_dir
/var/containers/Bundle/Application/63954B0E-79FA-42F2-A7EA-3568026008A1/Interlock.app
(lldb) home_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28
(lldb) doc_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Documents
(lldb) caches_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Library/Caches
(lldb) lib_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/Library
(lldb) tmp_dir
/var/mobile/Containers/Data/Application/1161FDFD-5D69-47CD-B5C6-C2724B8E2F28/tmp
(lldb) group_dir
/private/var/mobile/Containers/Shared/AppGroup/9460EA21-AE6A-4220-9BB3-6EC8B971CDAE
```



#### ls 

list directory contents, just like `ls -lh` on Mac

```stylus
(lldb) ls bu
/var/containers/Bundle/Application/D0419A6E-053C-4E35-B422-7C0FD6CAB060/Interlock.app
drwxr-xr-x        128B 1970-01-01 00:00:00 +0000 Base.lproj
drwxr-xr-x         96B 1970-01-01 00:00:00 +0000 _CodeSignature
drwxr-xr-x         64B 1970-01-01 00:00:00 +0000 META-INF
-rw-r--r--        1.5K 2023-05-16 03:17:32 +0000 Info.plist
-rwxr-xr-x      103.0K 2023-05-19 11:07:02 +0000 Interlock
-rw-r--r--          8B 2023-05-16 03:17:32 +0000 PkgInfo
-rw-r--r--      194.7K 2023-05-16 03:17:31 +0000 embedded.mobileprovision
(lldb) ls home
/var/mobile/Containers/Data/Application/09E63130-623F-4124-BCBB-59E20BD28964
drwxr-xr-x         96B 2023-05-19 07:28:01 +0000 Documents
drwxr-xr-x        128B 2023-05-16 04:51:14 +0000 Library
drwxr-xr-x         64B 1970-01-01 00:00:00 +0000 SystemData
drwxr-xr-x         64B 2023-05-16 04:51:14 +0000 tmp
(lldb) ls /var/mobile/Containers/Data/Application/09E63130-623F-4124-BCBB-59E20BD28964/Documents
-rw-r--r--         18B 2023-05-16 05:36:05 +0000 report.txt
```



#### find_el

detects endless loop in all threads at this point

```objective-c
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    int a = 1;
    NSLog(@"%s", __PRETTY_FUNCTION__);
    while (a) {
        a++;
    }
}
```

```stylus
# touch device screen
2023-05-20 12:29:52.604910+0800 Interlock[56660:1841567] -[ViewController touchesBegan:withEvent:]
# pause program execution, then execute find_el in lldb
(lldb) find_el
Breakpoint 1: where = Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.mm:34:5, address = 0x109dd8d48
Breakpoint 2: where = Interlock`main + 110 at main.m:17:5, address = 0x109dd911e
delete breakpoint 2
call Interlock`-[ViewController touchesBegan:withEvent:] + 136 at ViewController.m:34:5, 22 times per second, hit_count: 100
...
```



#### thread_eb

get extended backtrace of thread

```stylus
(lldb) bt
* thread #2, queue = 'com.apple.root.default-qos', stop reason = breakpoint 6.1
  * frame #0: 0x0000000104ab58f8 Concurrency`__41-[ViewController touchesBegan:withEvent:]_block_invoke(.block_descriptor=0x0000000104ab80f8) at ViewController.m:29:13
    frame #1: 0x0000000104df51dc libdispatch.dylib`_dispatch_call_block_and_release + 24
    frame #2: 0x0000000104df519c libdispatch.dylib`_dispatch_client_callout + 16
    frame #3: 0x0000000104e01200 libdispatch.dylib`_dispatch_queue_override_invoke + 968
    frame #4: 0x0000000104e067c8 libdispatch.dylib`_dispatch_root_queue_drain + 604
    frame #5: 0x0000000104e06500 libdispatch.dylib`_dispatch_worker_thread3 + 136
    frame #6: 0x0000000181fc3fac libsystem_pthread.dylib`_pthread_wqthread + 1176
    frame #7: 0x0000000181fc3b08 libsystem_pthread.dylib`start_wqthread + 4

(lldb) thread_eb
thread #4294967295: tid = 0x190c, 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160, queue = 'com.apple.main-thread'
    frame #0: 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160
    frame #1: 0x0000000104ded884 Concurrency`-[ViewController touchesBegan:withEvent:](self=<unavailable>, _cmd=<unavailable>, touches=<unavailable>, event=<unavailable>) at ViewController.m:25:5
    frame #2: 0x000000018bb1583c UIKit`forwardTouchMethod + 340
    frame #3: 0x000000018b9bb760 UIKit`-[UIResponder touchesBegan:withEvent:] + 60
...
```



#### entitlements

print codesign entitlements of the specified module if any

```stylus
(lldb) ent
Interlock:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>JMD2JV9294.com.bangcle.Interlock</string>
	<key>com.apple.developer.team-identifier</key>
	<string>JMD2JV9294</string>
	<key>com.apple.security.application-groups</key>
	<array/>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>
```

```stylus
(lldb) ent UIKit
UIKit apparently does not contain code signature
```



#### dmodule

dump the specified module from memory

```stylus
(lldb) dmodule UIKit
dumping UIKit, this may take a while
ignore __DATA.__bss
ignore __DATA.__common
ignore __DATA_DIRTY.__bss
ignore __DATA_DIRTY.__common
924057600 bytes dump to ~/lldb_dump_macho/UIKit/macho_UIKit
```

> 注意：加载时被修改的数据未恢复



#### segments

dump segments and section info from macho

```stylus
(lldb) segments LLDBCode
[0x4e90000-0x104e90000) 0x100000000 __PAGEZERO ---/---
[0x104e90000-0x104ea0000) 0x10000 __TEXT r-x/r-x
	[0x104e968bc-0x104e9cfb8) 0x66fc __text
	[0x104e9cfb8-0x104e9d210) 0x258 __stubs
	[0x104e9d210-0x104e9d480) 0x270 __stub_helper
	[0x104e9d480-0x104e9db20) 0x6a0 __objc_stubs
	[0x104e9db20-0x104e9edaa) 0x128a __objc_methname
	[0x104e9edaa-0x104e9f2d8) 0x52e __cstring
	[0x104e9f2d8-0x104e9f354) 0x7c __objc_classname__TEXT
	[0x104e9f354-0x104e9fe8e) 0xb3a __objc_methtype
	[0x104e9fe90-0x104e9fe98) 0x8 __const
	[0x104e9fe98-0x104e9ff40) 0xa8 __gcc_except_tab__TEXT
	[0x104e9ff40-0x104e9fff0) 0xb0 __unwind_info
[0x104ea0000-0x104ea4000) 0x4000 __DATA rw-/rw-
	[0x104ea0000-0x104ea0070) 0x70 __got
	[0x104ea0070-0x104ea0200) 0x190 __la_symbol_ptr
	[0x104ea0200-0x104ea0420) 0x220 __const
	[0x104ea0420-0x104ea0ba0) 0x780 __cfstring
	[0x104ea0ba0-0x104ea0bc8) 0x28 __objc_classlist__DATA
	[0x104ea0bc8-0x104ea0be8) 0x20 __objc_protolist__DATA
	[0x104ea0be8-0x104ea0bf0) 0x8 __objc_imageinfo__DATA
	[0x104ea0bf0-0x104ea1f28) 0x1338 __objc_const
	[0x104ea1f28-0x104ea20d8) 0x1b0 __objc_selrefs
	[0x104ea20d8-0x104ea2148) 0x70 __objc_classrefs__DATA
	[0x104ea2148-0x104ea2150) 0x8 __objc_superrefs__DATA
	[0x104ea2150-0x104ea2158) 0x8 __objc_ivar
	[0x104ea2158-0x104ea22e8) 0x190 __objc_data
	[0x104ea22e8-0x104ea2488) 0x1a0 __data
[0x104ea4000-0x104eb0000) 0xc000 __LINKEDIT r--/r--
[0x104eaa510-0x104eaf3e0) 0x4ed0 Code Signature
```



#### classes

dump class names from the specified module

```stylus
(lldb) classes
AppDelegate <0x10468e378>
SceneDelegate <0x10468e418>
ViewController <0x10468e260>
```



#### image_list

List current executable and dependent shared library images, sorted by load address.

```stylus
(lldb) image_list
index   load addr(slide)       vmsize path
--------------------------------------------------------
[  0] 0x1022e4000(0x0022e4000)  81.9K /var/containers/Bundle/Application/C134E909-CC52-4A93-9557-37BA808854D3/LLDBCode.app/LLDBCode
[  1] 0x1022f8000(0x1022f8000) 524.3K /usr/lib/system/introspection/libdispatch.dylib
[  2] 0x1023d0000(0x1023d0000) 163.8K /usr/lib/libsubstitute.dylib
[  3] 0x1023f8000(0x1023f8000)  81.9K /usr/lib/libsubstrate.dylib
...
```



#### executable

print main executable name

```stylus
(lldb) executable
LLDBCode
```



#### slookup

lookup string between start addr and end addr

```stylus
(lldb) image_list -c 10
index   load addr(slide)       vmsize path
--------------------------------------------------------
[  0] 0x1022e4000(0x0022e4000)  81.9K /var/containers/Bundle/Application/C134E909-CC52-4A93-9557-37BA808854D3/LLDBCode.app/LLDBCode
[  1] 0x1022f8000(0x1022f8000) 524.3K /usr/lib/system/introspection/libdispatch.dylib
[  2] 0x1023d0000(0x1023d0000) 163.8K /usr/lib/libsubstitute.dylib
[  3] 0x1023f8000(0x1023f8000)  81.9K /usr/lib/libsubstrate.dylib
[  4] 0x10270c000(0x10270c000)   4.5M /usr/lib/substitute-inserter.dylib
[  5] 0x102b54000(0x102b54000)   3.5M /usr/lib/substitute-loader.dylib
[  6] 0x18406f000(0x004044000)   8.7K /usr/lib/libSystem.B.dylib
[  7] 0x184071000(0x004044000) 394.1K /usr/lib/libc++.1.dylib
[  8] 0x1840ca000(0x004044000) 144.7K /usr/lib/libc++abi.dylib
[  9] 0x1840ec000(0x004044000)   8.7M /usr/lib/libobjc.A.dylib
  
(lldb) slookup PROGRAM 0x18406f000 0x184071000
found at 0x184070f7c where = [0x000000018002cf78-0x000000018002cfb8) libSystem.B.dylib.__TEXT.__const
1 locations found

(lldb) x 0x184070f7c -c 64
0x184070f7c: 50 52 4f 47 52 41 4d 3a 53 79 73 74 65 6d 2e 42  PROGRAM:System.B
0x184070f8c: 20 20 50 52 4f 4a 45 43 54 3a 4c 69 62 73 79 73    PROJECT:Libsys
0x184070f9c: 74 65 6d 2d 31 32 35 32 2e 35 30 2e 34 0a 00 00  tem-1252.50.4...
0x184070fac: 00 00 00 00 00 00 00 00 00 92 93 40 01 00 00 00  ...........@....
```



#### blookup

lookup the specified bytes in user modules

```stylus
(lldb) blookup c0 03 5f d6
-----try lookup bytes in LLDBCode-----
0x104961018
...
0x104969ab8
32 locations found
```



#### patch

patch the specified bytes in user modules

```stylus
(lldb) patch c0 03 5f d6
-----try patch bytes in LLDBCode-----
patch 32 locations
```



#### mtrace

```stylus
// begin trace
(lldb) mtrace LLDBCode
-----trace functions in LLDBCode-----
will trace 35 names
begin trace with Breakpoint 1: 35 locations
(lldb) c

// trace log
frame #0: 0x0000000102dd2fb8 LLDBCode`-[ViewController touchesBegan:withEvent:](self=0x00000001d4108040, _cmd="touchesBegan:withEvent:", touches=0x000000015fd0fff0, event=1 element) at ViewController.m:35
frame #0: 0x0000000102dd3a68 LLDBCode`+[MachoTool findMacho](self=0x00000001c0038c40, _cmd="\xc5\xd1K\xb7\xa1A\U00000001") at MachoTool.m:74
frame #0: 0x0000000102dd4318 LLDBCode`__22+[MachoTool findMacho]_block_invoke(.block_descriptor=0x000000015fd0fff0, header_addr=7852818496) at MachoTool.m:110
...
frame #0: 0x0000000102dd5b20 LLDBCode`+[Image findInstruction:](self=0x00000001c0038c40, _cmd="\xc5\xd1K\xb7\xa1A\U00000001", inst_str="śJ\xb7\xa1\U00000005") at Image.m:281
frame #0: 0x0000000102dd32f8 LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4(.block_descriptor=0x00000001c40a5ac0, downloadProgress=0x000000018f903381) at ViewController.m:57
frame #0: 0x0000000102dd3268 LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3(.block_descriptor=0x00000001c40733c0, task=0x00000001c80394e0, error=0x0000000000000000) at ViewController.m:53
frame #0: 0x0000000102dd318c LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke(.block_descriptor=0x0000000102ec1500) at ViewController.m:45
```



#### bda

disable breakpoint(s) at the specified class

```stylus
(lldb) bda -i ViewController
disable breakpoint 1.8: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_4 at ViewController.m:57, address = 0x00000001040e32f8, unresolved, hit count = 1  Options: disabled 
disable breakpoint 1.14: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_2 at ViewController.m:50, address = 0x00000001040e31e0, unresolved, hit count = 0  Options: disabled 
disable breakpoint 1.18: where = LLDBCode`-[ViewController touchesBegan:withEvent:] at ViewController.m:35, address = 0x00000001040e2fb8, unresolved, hit count = 1  Options: disabled 
disable breakpoint 1.20: where = LLDBCode`-[ViewController ls_dir:] at ViewController.m:62, address = 0x00000001040e335c, unresolved, hit count = 0  Options: disabled 
disable breakpoint 1.22: where = LLDBCode`-[ViewController viewDidLoad] at ViewController.m:24, address = 0x00000001040e2ec4, unresolved, hit count = 0  Options: disabled 
disable breakpoint 1.23: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke_3 at ViewController.m:53, address = 0x00000001040e3268, unresolved, hit count = 1  Options: disabled 
disable breakpoint 1.27: where = LLDBCode`__41-[ViewController touchesBegan:withEvent:]_block_invoke at ViewController.m:45, address = 0x00000001040e318c, unresolved, hit count = 1  Options: disabled 

(lldb) bda -i ViewController(extension)
disable breakpoint 1.23: where = LLDBCode`-[ViewController(extension) test] at ViewController.m:20, address = 0x0000000102ec2e7c, unresolved, hit count = 0  Options: disabled 
```

