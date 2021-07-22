#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
@author Ryan
@desc 本模块是一个 frida-hooks 的扩展模块例子，用来说明 frida-hooks 扩展模块的写法，不可以直接运行
@date 2021/7/22
说明：
rpc_define: 定义 frida-hooks 扩展信息
  func: 要引出的函数名，对应jscode中的函数名
  api: func的小驼峰命名，注意一定要符合规范，在http请求时使用，在系统内部又会自动将小驼峰转为下划线命名，故如果命名对不上，则系统找不到相应的函数
  is_option: 是否在内部命令的options中显示，并可以以run的方式执行
  help: 在options中显示的说明文字
  persistent: func是否是长期驻留的功能，如果是，则在执行restart命令时重新加载该函数，以保持自动长期驻留
  params: 参数说明，
    name:参数名
    type: 参数类型，包括 string, int, bool等
    isOptional: 是否是可选参数
jscode: 扩展功能的js代码，其中可以使用 frida-hooks 内置的函数，具体可以参考 scripts.js
on_message: 自定义的消息处理函数，如果不定义该函数，则使用 frida-hooks 内置的 on_message 方法
rpc调用说明:
  url: 默认地址为 http://127.0.0.1:8989/run ，其中端口可以通过命令行或配置文件修改
  method: POST
  body: {"cmd": "search_goods",
        "url": "http://foo.xxx.com/api/search/notes?keyword=",
        "keyword": "phone"}
"""

rpc_define = [
    {
        'api': 'searchGoods',
        'func': 'search_goods',
        'is_option': True,
        'help': 'search goods',
        'persistent': False,
        'params': [
            {"name": "url", "type": "string"},
            {"name": "keyword", "type": "string"},
            {"name": "is_sort", "type": "bool", "isOptional": True}
        ]
    }
]

jscode = """
        var ret_url = undefined;
        var controller = undefined;
        var entity = undefined;

        function search_goods(keyword, url){
            ret_url = url; 
            return wrap_java_perform(() => {
                var body ='success';
                if(!controller || !entity){
                    Java.choose("com.xxx.foo.search.fragment.SearchController",{
                            onMatch: function(instance){
                                controller = instance;
                            },
                            onComplete: function(){}
                    });
                     
                    Java.choose("com.xxx.foo.search.entity",{
                            onMatch: function(instance){
                                entity = instance;
                            },
                            onComplete: function(){}
                    });
                    
                    hook_func_frame("com.xxx.foo.search.fragment.SearchController$2", "a", function () {
                        if(arguments.length == 1){
                            // 回传数据
                            let args = get_arguments(arguments, arguments.length);
                            let val = args[0].value;
                            send({value: val, retUrl: ret_url});
                        }
                        //调用原应用的方法
                        let ret = this["a"].apply(this, arguments);
                        return ret;
                    });
                }
                if(controller && entity){
                    entity._a.value = keyword;
                    controller.a(entity)
                    return body;
                }else{
                    body ='init failed';
                }
            });
        }
"""


def on_message(message, data):
    if message['type'] == 'send':
        print('[*] {0}'.format(message['payload']))
    else:
        print(message)

