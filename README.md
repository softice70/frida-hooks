Frida-Hooks
========
Frida是一个面向开发人员、逆向工程师和安全研究人员的动态插桩工具包。[官网：frida.re](https://github.com/frida/frida)
[Frida-Hooks]()则是在frida平台上集成了一些常用的脚本，从而使调试更加高效、易用。

主要功能
--------
- 自动启动frida-server
- 自动启动应用程序，支持spawn模式
- hook网络通讯
- hook指定的类的全部或部分方法
- hook指定so的全部或部分函数
- hook某应用的registerNatives函数
- DEX的动态脱壳
- so文件的动态脱壳
- 运行过程中可以动态地添加或禁用钩子
- 支持屏幕彩色输出，使结果显示更加整齐、美观，便于阅读
- 支持日志功能

安装
------------

* `python setup.py install`

依赖
------------
- Python 3.x 


使用说明
------------
- 查看帮助
```bash
$ python .\frida_hook.py
```
- 设置应用启动后立即挂起，然后注入钩子的模式
    - 参数：  -S, --suspend         suspend during startup
    ```base
    $ python .\frida_hook.py com.xxx.foo -S --hook_class --class com.xxx.foo.community.mgr.CommunityMgr
    ```
- 在手机上运行frida_server
    - frida_server需要放在手机的 /data/local/tmp 目录下，且文件名为 frida_server
    - frida_server需要具备执行权限
    ```base
    $ python .\frida_hook.py --start_server
    ```
- 停止运营frida_server
    ```base
    $ python .\frida_hook.py --stop_server
    ```
- 查看frida_server的运行状态
    ```base
    $ python .\frida_hook.py --status_server
    ```
- 列出手机安装的所有应用
```base
$ python .\frida_hook.py --list_app
```
- 列出手机正在运行的所有应用
```base
$ python .\frida_hook.py --list_app_proc
```
- 列出某应用的全部线程信息
```base
$ python .\frida_hook.py com.xxx.foo --list_thread
```
- 列出某应用加载的所有的类
```base
$ python .\frida_hook.py com.xxx.foo --list_class
```
- hook某应用的某个类的全部方法
```base
$ python .\frida_hook.py com.xxx.foo --hook_class --class com.xxx.foo.community.mgr.CommunityMgr
```
- hook某应用的某个类的指定方法
```base
$ python .\frida_hook.py com.xxx.foo --hook_func --class com.xxx.foo.community.mgr.CommunityMgr --func requestCommunitySearch 
```
- 显示某应用的某个类的方法与成员变量的定义
```base
$ python .\frida_hook.py com.xxx.foo --dump --class com.xxx.foo.community.mgr.CommunityMgr
```
- 列出某应用加载的所有的so
```base
$ python .\frida_hook.py com.xxx.foo --list_so
```
- 列出某应用加载的某so的全部引出函数
```base
$ python .\frida_hook.py com.xxx.foo --list_so_func --module libbtime.so
```
- hook某应用的某so的指定函数
```base
$  python .\frida_hook.py com.xxx.foo --hook_so_func --module libxxx.so --func getSign 
$  python .\frida_hook.py com.xxx.foo --hook_so_func --module libxxx.so --addr 0xe7576777 
```
- hook某应用的registerNatives函数
```base
$  python .\frida_hook.py com.xxx.foo --hook_RegisterNatives --suspend 
```
- hook某应用的okhttp3的通讯层
```base
$  python .\frida_hook.py com.xxx.foo --hook_okhttp3 
```
- 从内存中导出某应用的某so到指定文件
```base
$ python .\frida_hook.py com.xxx.foo --dump_so_to_file --module libxxx.so
```
- 从内存中导出某应用的dex文件
```base
$ python .\frida_hook.py com.xxx.foo --dump_dex
$ python .\frida_hook.py com.xxx.foo --dump_dex --deep_search
```
- 显示内存中指定地址和长度的数据
```base
$ python .\frida_hook.py com.xxx.foo --dump_so_memory --module libxxx.so --offset 0 --length 64
```
- 加载自定义脚本
    - 参考foo.py编写对应的jscode和on_message
    - 加载命令，以 foo.py 为例：
    ```base
    $ python .\frida_hook.py com.xxx.foo -f foo 
    ```
#### 操作  
- 运行状态中可以输入命令
```text
    help        show this help message
    options     print options
    list        show hook list
    config <file>       load the config file
    disable <key>       set disable the hook item by key
    enable <key>        set enable the hook item by key
    remove <key>        remove the hook item by key
    run [options]       run hook option, see also <options>
        example: --hook_class --class com.xxx.xxx.xxxxxx.Classxxx
                 --hook_func --class com.xxx.xxx.xxxxxx.Classxxx --func Funcxxx
                 --hook_so_func --module libxxx.so --func getSign
                 --hook_so_func --module libxxx.so --addr 0xedxxxxxx
    resume      resume connection to phone
    quit        quit
```

相关项目
-------
[https://github.com/hluwa](https://github.com/hluwa)
[https://github.com/liu20082004/DumpAndFix_SO](https://github.com/liu20082004/DumpAndFix_SO)
[https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)

License
-------
Licensed under the Apache License, Version 2.0

ToDo
-------
- [ ] 安装frida server

