Frida-Hooks
========
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/banner.jpg)
- Frida是一个面向开发人员、逆向工程师和安全研究人员的动态插桩工具包。[官网：frida.re](https://github.com/frida/frida)
- [Frida-Hooks](https://github.com/softice70/frida-hooks)则是在frida平台上集成了一些常用的脚本，从而使调试更加高效、易用。

主要功能
--------
- 自动启动frida-server
- 自动启动应用程序，支持spawn模式
- hook HttpURLConnection、okhttp和okhttp3网络通讯
- 支持ssl_unpinning
- 支持无代理模式的中间人抓包，可以不用安装Drony就可以在fiddler、Charles或mitmproxy中抓包 
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
- ssl_unpinning的启动方式
  - 建议使用spawn模式启动，并加上 --ssl_unpinning 选项，如
  ```bash
  $ frida-hooks com.xxx.foo -S --ssl_unpinning
  ```
  - 下面是目前支持的ssl_unpinning的列表：
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/ssl-unpinning.jpg)
- bypass_no_proxy
  - 有些应用使用了无代理模式进行通信，此时可以子命令 bypass_no_proxy，关闭应用的无代理模式，从而可以不用安装Drony就可以在fiddler、Charles或mitmproxy中抓包
  ```bash
  > run --bypass_no_proxy
  ```
  - 下面生效时的截图：
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/bypass-no-proxy.jpg)
- 加载自定义脚本
  - 简单说明
    - rpc_define: 定义 frida-hooks 扩展信息
      - func: 要引出的函数名，对应jscode中的函数名
      - api: func的小驼峰命名，注意一定要符合规范，在http请求时使用，在系统内部又会自动将小驼峰转为下划线命名，故如果命名对不上，则系统找不到相应的函数
      - is_option: 是否在内部命令的options中显示，并可以以run的方式执行
      - help: 在options中显示的说明文字
      - persistent: func是否是长期驻留的功能，如果是，则在执行restart命令时重新加载该函数，以保持自动长期驻留
      - params: 参数说明，
        - name:参数名
        - type: 参数类型，包括 string, int, bool等
        - isOptional: 是否是可选参数
    - jscode: 扩展功能的js代码，其中可以使用 frida-hooks 内置的函数，具体可以参考 scripts.js
    - on_message: 自定义的消息处理函数，如果不定义该函数，则使用 frida-hooks 内置的 on_message 方法
    - rpc调用说明:
      - url: 默认地址为 http://127.0.0.1:8989/run ，其中端口可以通过命令行或配置文件修改
      - method: POST
      - body:
        ```json
        {
          "cmd": "search_goods",
          "url": "http://foo.xxx.com/api/search/notes?keyword=",
          "keyword": "phone"
        }
        ```
  - 可以参考example目录下的foo.py编写对应的rpc_define、jscode和on_message
  - 加载命令，以 foo.py 为例：
  ```bash
  $ frida_hooks com.xxx.foo -f foo 
  ``` 
  - 使用"script"命令，方便排查脚本错误
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/demo6.jpg)
- 运行中可以用"list"命令列出已经加载的hook命令，并可以用"disable"和"enable"命令禁用或启用指定的命令
![在这里插入图片描述](https://github.com/softice70/frida-hooks/blob/main/pics/demo5.jpg)
  - "disable"和"enable"命令举例
    - 禁用全部
    ```bash
      > d *
    ```
    - 禁用1号命令
    ```bash
      > d 1
    ```
    - 启用全部
    ```bash
      > e *
    ```
    - 启用1号命令
    ```bash
      > e 1
    ```
Thanks
-------
- [https://github.com/hluwa](https://github.com/hluwa)
- [https://github.com/hluwa/Wallbreaker](https://github.com/hluwa/Wallbreaker)
- [https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)
- [https://github.com/sensepost/objection](https://github.com/sensepost/objection)
- [https://github.com/lasting-yang/frida_dump](https://github.com/lasting-yang/frida_dump)
- [https://github.com/httptoolkit/frida-android-unpinning](https://github.com/httptoolkit/frida-android-unpinning)

License
-------
Licensed under the Apache License, Version 2.0
