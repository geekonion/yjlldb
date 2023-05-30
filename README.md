一些用于调试iOS应用的lldb命令

Some very useful lldb commands for iOS debugging.



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
/var/mobile/Containers/Data/Application/09E63130-623F-4124-BCBB-59E20BD28964/Documents
-rw-r--r--         18B 2023-05-16 05:36:05 +0000 report.txt
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
(lldb) thread_eb
thread #4294967295: tid = 0x190c, 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160, queue = 'com.apple.main-thread'
    frame #0: 0x0000000104e907cc libdispatch.dylib`_dispatch_root_queue_push_override + 160
    frame #1: 0x0000000104ded884 Concurrency`-[ViewController touchesBegan:withEvent:](self=<unavailable>, _cmd=<unavailable>, touches=<unavailable>, event=<unavailable>) at ViewController.m:25:5
    frame #2: 0x000000018bb1583c UIKit`forwardTouchMethod + 340
    frame #3: 0x000000018b9bb760 UIKit`-[UIResponder touchesBegan:withEvent:] + 60
...
```

