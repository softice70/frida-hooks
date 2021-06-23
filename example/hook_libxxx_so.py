#!/usr/bin/python
# -*- coding: UTF-8 -*-

import re, json

jscode = """
Java.perform(function(){
    var Thread = Java.use("java.lang.Thread");
    //对函数名hook
    var ptr_func = Module.findExportByName("libxxx.so","getSign")
    //var str_name_so = "libxxx.so";    //需要hook的so名
    //var ptr_func = new NativePointer("0xe9740000");
    console.log("libxxx.so: getSign() is hooked...");
    Interceptor.attach(ptr_func,{ 
        //onEnter: 进入该函数前要执行的代码，其中args是传入的参数，一般so层函数第一个参数都是JniEnv，第二个参数是jclass，从第三个参数开始是我们java层传入的参数
        onEnter: function(args) {
            //获取调用栈
            var straces = Thread.currentThread().getStackTrace();
            let data = {type:"stack", data:straces.toString()};
            send(data);
            send("--------------------------  arguments  --------------------------");
            send("args[0]=" + args[0]);
            send("args[1]=" + args[1]);
            send("args[2]=" + args[2]);
            send("args[3]=" + args[3]);
        },
        onLeave: function(ret){ //onLeave: 该函数执行结束要执行的代码，其中ret参数即是返回值
            let data = {type:"return", value:(ret!=null?ret.toString():"null")};
            send(data);
        }
    });
});
"""


def on_message(message, data):
    if message['type'] == 'send':
        msg_data = message['payload']
        if msg_data['type'] == 'stack':
            straces = re.split(',', msg_data['data'])
            print("----------------------------  stack  ----------------------------\n    " + '\n    '.join(straces))
        elif msg_data['type'] == 'arguments':
            args_before = json.loads(msg_data['before'])
            args_after = json.loads(msg_data['after'])
            arg_list = []
            for key in args_before.keys():
                if args_before[key] == args_after[key]:
                    arg_list.append('    ' + key + '\t' + str(args_before[key]))
                else:
                    arg_list.append('    *' + key + '\n    before: ' + str(args_before[key]) \
                                                  + '\n     after: ' + str(args_after[key]))
            print("--------------------------  arguments  --------------------------\n" + '\n'.join(arg_list))
        elif msg_data['type'] == 'return':
            print("---------------------------  return  ---------------------------\n    return: " + msg_data['value'])
        else:
            print('[*] {0}'.format(message['payload']))
    else:
        print(message)

def on_message(message, data):
    if message['type'] == 'send':
        print('[*] {0}'.format(message['payload']))
    else:
        print(message)
