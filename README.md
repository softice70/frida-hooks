Frida-Hooks
========
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/banner.jpg)
- Frida是一个面向开发人员、逆向工程师和安全研究人员的动态插桩工具包。[官网：frida.re](https://github.com/frida/frida)
- [Frida-Hooks]()则是在frida平台上集成了一些常用的脚本，从而使调试更加高效、易用。

主要功能
--------
- 自动启动frida-server
- 自动启动应用程序，支持spawn模式
- hook okhttp3网络通讯
- hook指定的类的全部或部分方法
- hook指定so的全部或部分函数
- hook某应用的registerNatives函数
- DEX的动态脱壳
- so文件的动态脱壳
- 运行过程中可以动态地添加或禁用钩子
- 支持http服务及RPC服务 
- 支持用户自定义扩展分析功能，并可方便地引出RPC服务和http接口 
- 支持屏幕彩色输出，使结果显示更加整齐、美观，便于阅读
- 支持日志功能


安装
------------

* `pip install frida-hooks`
* `python setup.py install`

依赖
------------
- Python 3.x 
- frida-server
  - frida_server需要放在手机的 /data/local/tmp 目录下，且文件名为 frida_server
  - frida_server需要具备执行权限
  - 可以使用frida-hooks启动服务，命令如下： 
  ```bash
  $ frida-hooks --start_server
  ```

使用说明
------------
- 查看帮助
```bash
$ frida-hooks
```
- 通常启动时需要指定应用名称，如：
  ```bash
  $ frida-hooks com.xxx.foo
  ```
  - 可以使用"--search_app"查询应用名称，"--app"后面的参数可以名字的一部分，如：
  ```bash
  $ frida-hooks --search_app --app 宝
  ```
- 可以使用spawn模式启动，即设置应用启动后立即挂起，然后注入钩子的模式
    - 参数：  -S, --spawn         spawn mode of Frida, that suspend app during startup
    ```bash
    $ frida_hooks com.xxx.foo -S
    ```
- 使用配置文件启动frida-hooks，这样可以记录跟踪挂载信息，方便持续进行分析
    - 参数：   -c CONFIG, --config_file=CONFIG         load the options from the config file
    ```bash
    $ frida_hooks -c foo.ini
    ```
- 进入frida-hooks后，回车可以看到内部命令帮助
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/internalhelp.jpg)
- 主要的分析功能可以通过run命令执行，如：
    ```bash
    > run --hook_func --class com.xxx.foo.community.mgr.CommunityMgr --func requestCommunitySearch
    ```
- 可以通过内部命令"options"或者"o"查看内置的分析功能列表
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/cmds.jpg)
- 下面是部分命令的结果截图
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/demo1.jpg)
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/demo2.jpg)
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/demo3.jpg)
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/demo4.jpg)
- 加载自定义脚本
    - 参考foo.py编写对应的jscode和on_message
    - 加载命令，以 foo.py 为例：
    ```base
    $ python .\frida_hook.py com.xxx.foo -f foo 
    ```
#### 操作  
- 运行状态中可以输入命令
```text
  help          show this help message
  options       print options
  list          show hook list
  config <file> load the config file
  disable <key> set disable the hook item by key
  enable <key>  set enable the hook item by key
  remove <key>  remove the hook item by key
  run [options] run hook option, see also <options>
       example: --hook_class --class com.xxx.xxx.xxxxxx.Classxxx
                --hook_func --class com.xxx.xxx.xxxxxx.Classxxx --func Funcxxx
                --hook_so_func --module libxxx.so --func getSign
                --hook_so_func --module libxxx.so --addr 0xedxxxxxx
  restart       restart the hook session
  cls           clear screen
  quit          quit
```

Thanks
-------
- [https://github.com/hluwa](https://github.com/hluwa)
- [https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)
- [https://github.com/sensepost/objection](https://github.com/sensepost/objection)
- [https://github.com/lasting-yang/frida_dump](https://github.com/lasting-yang/frida_dump)

License
-------
Licensed under the Apache License, Version 2.0

ToDo
-------
- [ ] 安装frida server，使用frida-push
- [ ] 增加Intent，参考objection
- [ ] 增加结果过滤功能
- [ ] 支持多设备选择
