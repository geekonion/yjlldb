一些用于调试iOS应用的lldb命令

#### baf - break all functions in module

给一个库中的所有函数/方法下断点

如，给UIKit库下断点

```stylus
(lldb) baf UIKit
```



#### bdc - breakpoint disable current

disable当前命中的断点，并自动继续执行程序

```stylus
(lldb) thread info
thread #1: tid = 0x2cb739, 0x000000018354f950 libsystem_kernel.dylib`open, queue = 'com.apple.main-thread', stop reason = breakpoint 5.13

(lldb) bdc
disable breakpoint 5.13 [0x18354f950]libsystem_kernel.dylib`open
and continue
```

