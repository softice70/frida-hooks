function wrap_java_perform(fn){
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      try {
        resolve(fn());
      } catch (e) {
        reject(e);
      }
    });
  });
}

function send_msg(data){
    if(data){
        send(data);
    }
}

function get_application_context() {
  const ActivityThread = Java.use("android.app.ActivityThread");
  return ActivityThread.currentApplication().getApplicationContext();
}

function R(name, type){
  const context = get_application_context();
  // https://github.com/bitpay/android-sdk/issues/14#issue-202495610
  return context.getResources().getIdentifier(name, type, context.getPackageName());
}

//获取字段信息
function get_fields(_this, field_array){
    let fields = {};
    for (var i = 0; i < field_array.length; i++){
        let field = field_array[i]; //当前成员
        let field_name = field.getName();
        let class_name = field.getType().getName();
        let field_val = 'UNKNOWN'
        try {
            let field_val_obj = field.get(_this);
            field_val = field_val_obj == null? field_val_obj: field_val_obj.toString();
        }
        catch(err){
        }
        fields[field_name] = {class: class_name, value: field_val};
    }
    return fields;
}

//获取参数
function get_arguments(arg_list, arg_cnt){
    let args = {};
    //获取参数
    for (var idx_arg = 0; idx_arg < arg_cnt; idx_arg++) {
        args[idx_arg] = '' + arg_list[idx_arg];
    }
    return args;
}

//获取调用栈
function get_stack_trace(){
    return Java.use("java.lang.Thread").currentThread().getStackTrace().toString();
}

function list_class(){
    return wrap_java_perform(() => {
        var classes = []
        Java.enumerateLoadedClasses({
            "onMatch": function (className) {
                classes.push(className);
             },
            "onComplete": function () { }
        });
       send_msg(classes);
       return classes;
    });
}

function list_class_loaders(){
    return wrap_java_perform(() => {
      let loaders = [];
      Java.enumerateClassLoaders({
        onMatch: function(l) {
          if (l == null) {
            return
          }
          loaders.push(l.toString());
        },
        onComplete: function() { }
      });

      send_msg(loaders);
      return loaders;
    });
}

function list_activities() {
    return wrap_java_perform(() => {
      const packageManager = Java.use("android.content.pm.PackageManager");
      const GET_ACTIVITIES = packageManager.GET_ACTIVITIES.value;
      const context = get_application_context();
      var activaties = Array.prototype.concat(context.getPackageManager()
        .getPackageInfo(context.getPackageName(), GET_ACTIVITIES).activities.value.map((activityInfo) => {
          return activityInfo.name.value;
        }),
      );
      send_msg(activaties);
      return activaties;
    });
}

function list_current_activity() {
    return wrap_java_perform(() => {
      const activityThread = Java.use("android.app.ActivityThread");
      const activityClass = Java.use("android.app.Activity");
      const activityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");

      const currentActivityThread = activityThread.currentActivityThread();
      const activityRecords = currentActivityThread.mActivities.value.values().toArray();
      let currentActivity;

      for (const i of activityRecords) {
        const activityRecord = Java.cast(i, activityClientRecord);
        if (!activityRecord.paused.value) {
          currentActivity = Java.cast(Java.cast(activityRecord, activityClientRecord).activity.value, activityClass);
          break;
        }
      }

      let activity = null;
      let fragment = null;

      if (currentActivity) {
        // Discover an active fragment
        const fm = currentActivity.getFragmentManager();
        const curFragment = fm.findFragmentById(R("content_frame", "id"));
        activity = currentActivity.$className;
        fragment = curFragment.$className;
      }
      let ret = {activity: activity, fragment: fragment};
      send_msg(ret)
      return ret;
    });
}

function list_services() {
    return wrap_java_perform(() => {
      const activityThread = Java.use("android.app.ActivityThread");
      const arrayMap = Java.use("android.util.ArrayMap");
      const packageManager = Java.use("android.content.pm.PackageManager");

      const GET_SERVICES = packageManager.GET_SERVICES.value;

      const currentApplication = activityThread.currentApplication();
      // not using the helper as we need other variables too
      const context = currentApplication.getApplicationContext();

      let services = [];
      currentApplication.mLoadedApk.value.mServices.value.values().toArray().map((potentialServices) => {
        Java.cast(potentialServices, arrayMap).keySet().toArray().map((service) => {
          services.push(service.$className);
        });
      });

      services = services.concat(context.getPackageManager()
        .getPackageInfo(context.getPackageName(), GET_SERVICES).services.value.map((activityInfo) => {
          return activityInfo.name.value;
        }),
      );
      send_msg(services);
      return services;
    });
}

function list_broadcast_receivers() {
    return wrap_java_perform(() => {
      const activityThread = Java.use("android.app.ActivityThread");
      const arrayMap = Java.use("android.util.ArrayMap");
      const packageManager = Java.use("android.content.pm.PackageManager");

      const GET_RECEIVERS = packageManager.GET_RECEIVERS.value;
      const currentApplication = activityThread.currentApplication();
      // not using the helper as we need other variables too
      const context = currentApplication.getApplicationContext();

      let receivers = [];
      currentApplication.mLoadedApk.value.mReceivers.value.values().toArray().map((potentialReceivers) => {
        Java.cast(potentialReceivers, arrayMap).keySet().toArray().map((receiver) => {
          receivers.push(receiver.$className);
        });
      });

      receivers = receivers.concat(context.getPackageManager()
        .getPackageInfo(context.getPackageName(), GET_RECEIVERS).receivers.value.map((activityInfo) => {
          return activityInfo.name.value;
        }),
      );

      send_msg(receivers);
      return receivers;
   });
}

function gen_request_data(request, timestamp, from){
    var ByteString = Java.use("okio.ByteString");
    var Buffer = Java.use("okio.Buffer");
    let data = null;
    try{
        if(!timestamp){
            timestamp = (new Date()).getTime();
        }
        var url = request.url().toString();
        var method = request.method();
        var headers = request.headers().toString();
        var body = '';
        var requestBody = request.body();
        var contentLength = requestBody ? requestBody.contentLength() : 0;
        if (contentLength > 0) {
            var BufferObj = Buffer.$new();
            requestBody.writeTo(BufferObj);
            try {
                body = ByteString.of(BufferObj.readByteArray().utf8());
            } catch (error) {
                try {
                    body = ByteString.of(BufferObj.readByteArray()).hex();
                } catch (error) {
                    console.log("error 1:", error);
                }
            }
        }
        data = {type:"request",url:url,method:method,headers:headers,body:body,timestamp:timestamp,from:from};
    } catch (error) {
        console.log("error 2:", error);
    }
    return data;
}

function gen_response_data(response, timestamp, from){
    let data = null;
    try {
        if(!timestamp){
            timestamp = (new Date()).getTime();
        }
        var responseBody = response.body();
        var contentLength = responseBody ? responseBody.contentLength() : 0;
        var body = '';
        if (contentLength > 0) {
            var ContentType = response.headers().get("Content-Type");
            if (ContentType.indexOf("video") == -1 && ContentType.indexOf("application/zip") != 0 && ContentType.indexOf("application") == 0) {
                var source = responseBody.source();
                try {
                    body = source.readUtf8();
                } catch (error) {
                    try {
                        body = source.readByteString().hex();
                    } catch (error) {
                        console.log("error 4:", error);
                    }
                }
            }
        }
        data = {type:"response", response:response.toString(), headers:response.headers().toString(), body:body, timestamp:timestamp, from:from};
    } catch (error) {
        console.log("error 3:", error);
    }
    return data;
}

function hook_func(class_name, method_name){
    return wrap_java_perform(() => {
        var cls = Java.use(class_name);
        var field_array = cls.class.getFields();
        if(cls[method_name] == undefined){
            console.log('error: ' + method_name + ' not found in ' + cls + '!')
        }else{
            var n_overload_cnt = cls[method_name].overloads.length;
            console.log(col_hooked + cls + "." + method_name + "() is hooked..." + col_reset);
            for (var index = 0; index < n_overload_cnt; index++) {
                cls[method_name].overloads[index].implementation = function () {
                    // 获取时间戳
                    var timestamp = (new Date()).getTime();
                    var datas = [];
                    datas.push({type:"stack", data:get_stack_trace(), timestamp:timestamp, hookName:"hook_func", funcName:method_name});
                    let args_before = get_arguments(arguments, arguments.length);
                    let fields_before = get_fields(this, field_array);
                    //调用原应用的方法
                    let ret = this[method_name].apply(this, arguments);
                    let args_after = get_arguments(arguments, arguments.length);
                    let fields_after = get_fields(this, field_array);
                    datas.push({type:"arguments", before:JSON.stringify(args_before), after:JSON.stringify(args_after), timestamp:timestamp, hookName:"hook_func", funcName:method_name});
                    datas.push({type:"fields", before:JSON.stringify(fields_before), after:JSON.stringify(fields_after), timestamp:timestamp, hookName:"hook_func", funcName:method_name});
                    datas.push({type:"return", value:(ret!=null?ret.toString():"null"), timestamp:timestamp, hookName:"hook_func", funcName:method_name});
                    send(datas);
                    return ret;
                }
            }
        }
    });
}

function hook_class(class_name){
    return wrap_java_perform(() => {
        //获取类的所有方法
        var cls = Java.use(class_name);
        var field_array = cls.class.getFields();
        var mhd_array = cls.class.getDeclaredMethods();

        //hook 类所有方法 （所有重载方法也要hook)
        let hooked_methods = '';
        for (var i = 0; i < mhd_array.length; i++){
            let mhd_cur = mhd_array[i]; //当前方法
            let str_mhd_name = mhd_cur.getName(); //当前方法名

            //当前方法重载方法的个数
            let n_overload_cnt = cls[str_mhd_name].overloads.length;
            for (var index = 0; index < n_overload_cnt; index++){
                cls[str_mhd_name].overloads[index].implementation = function (){
                    // 获取时间戳
                    var timestamp = (new Date()).getTime();
                    var datas = [];
                    datas.push({type:"stack", data:get_stack_trace(), timestamp:timestamp, hookName:"hook_class", funcName:str_mhd_name});
                    let args_before = get_arguments(arguments, arguments.length);
                    let fields_before = get_fields(this, field_array);
                    //调用原应用的方法
                    let ret = this[str_mhd_name].apply(this, arguments);
                    let args_after = get_arguments(arguments, arguments.length);
                    let fields_after = get_fields(this, field_array);
                    datas.push({type:"arguments", before:JSON.stringify(args_before), after:JSON.stringify(args_after), timestamp:timestamp, hookName:"hook_class", funcName:str_mhd_name});
                    datas.push({type:"fields", before:JSON.stringify(fields_before), after:JSON.stringify(fields_after), timestamp:timestamp, hookName:"hook_class", funcName:str_mhd_name});
                    datas.push({type:"return", value:(ret!=null?ret.toString():"null"), timestamp:timestamp, hookName:"hook_class", funcName:str_mhd_name});
                    send(datas);
                    return ret;
                }
                hooked_methods = hooked_methods + col_keyword + str_mhd_name + col_reset + (n_overload_cnt > 0?"[" + index + "] \t" : ' \t');
            }
        }
        console.log("methods:\n    " + hooked_methods + "\n" + col_hooked + cls + " is hooked..." + col_reset);
    });
}

function hook_so_func(module_name, func_name, addr_str){
    return wrap_java_perform(() => {
        //对函数名hook
        var ptr_func = func_name != ''?
                        Module.findExportByName(module_name, func_name):
                        new NativePointer(addr_str);
        console.log(col_hooked + module_name +": " + '[' + ptr_func + '] ' + func_name + " is hooked..." + col_reset);
        Interceptor.attach(ptr_func,{
            //onEnter: 进入该函数前要执行的代码，其中args是传入的参数，一般so层函数第一个参数都是JniEnv，第二个参数是jclass，从第三个参数开始是我们java层传入的参数
            onEnter: function(args) {
                var datas = [];
                datas.push({type:"stack", data:get_stack_trace(), hookName:"hook_so_func", funcName:func_name});
                let args_list = get_arguments(args, 4);
                datas.push({type:"asm_args", data:args_list, hookName:"hook_so_func", funcName:func_name});
                send(datas);
            },
            onLeave: function(ret){ //onLeave: 该函数执行结束要执行的代码，其中ret参数即是返回值
                send({type:"return", value:(ret!=null?ret.toString():"null"), hookName:"hook_so_func", funcName:func_name});
            }
        });
    });
}

function hook_so(module_name){
    return wrap_java_perform(() => {
        var libxx = Process.getModuleByName(module_name);
        var exports = libxx.enumerateExports();
        for(var i = 0; i < exports.length; i++) {
            let ptr_func = new NativePointer(exports[i].address);
            let func_name = exports[i].name;
            try {
                Interceptor.attach(ptr_func,{
                    //onEnter: 进入该函数前要执行的代码，其中args是传入的参数，一般so层函数第一个参数都是JniEnv，第二个参数是jclass，从第三个参数开始是我们java层传入的参数
                    onEnter: function(args) {
                        var datas = [];
                        datas.push({type:"stack", data:get_stack_trace(), hookName:"hook_so", funcName:func_name});
                        let args_list = get_arguments(args, 4);
                        datas.push({type:"asm_args", data:args_list, hookName:"hook_so", funcName:func_name});
                        send(datas);
                    },
                    onLeave: function(ret){ //onLeave: 该函数执行结束要执行的代码，其中ret参数即是返回值
                        send({type:"return", value:(ret!=null?ret.toString():"null"), hookName:"hook_so", funcName:func_name});
                    }
                });
                console.log(col_hooked + "%module_name%: " + '[' + ptr_func + '] ' + func_name + " is hooked..." + col_reset);
            }
            catch(err){
            }
        }
    });
}

function hook_okhttp3_execute(){
    return wrap_java_perform(() => {
        var RealCallClass = Java.use('okhttp3.RealCall');
        RealCallClass.execute.implementation = function(){
            var response = this.execute();
            var timestamp = (new Date()).getTime();
            var request = this.request();
            let datas = [];
            datas.push(gen_request_data(request, timestamp, 'Execute'));
            datas.push(gen_response_data(response, timestamp, 'Execute'));
            send_msg(datas)
            return response;
        }
        console.log(col_hooked + "okhttp3.RealCall.execute() is hooked..." + col_reset);
    });
}

function hook_okhttp3_CallServer(){
    return wrap_java_perform(() => {
        var InterceptorClass = Java.use("okhttp3.internal.http.CallServerInterceptor");
        InterceptorClass.intercept.implementation=function(chain){
            var timestamp = (new Date()).getTime();
            var request = chain.request();
            var response = this.intercept(chain);
            let datas = [];
            datas.push(gen_request_data(request, timestamp, 'CallServer'));
            datas.push(gen_response_data(response, timestamp, 'CallServer'));
            send_msg(datas)
            return response;
        }
        console.log(col_hooked + "okhttp3.internal.http.CallServerInterceptor.intercept() is hooked..." + col_reset);
    });
}

function hook_intercept(class_name){
    return wrap_java_perform(() => {
        var InterceptorClass = Java.use(class_name);
        InterceptorClass.intercept.implementation=function(chain){
            var timestamp = (new Date()).getTime();
            var request = chain.request();
            var response = this.intercept(chain);
            let datas = [];
            datas.push(gen_request_data(request, timestamp, class_name));
            datas.push(gen_response_data(response, timestamp, class_name));
            return response;
        }
        console.log(col_hooked + InterceptorClass + ".intercept() is hooked..." + col_reset);
    });
}

function dump_so_memory(module_name, offset, length){
    return wrap_java_perform(() => {
        var libc = Module.findBaseAddress(module_name);
        var data = hexdump(libc, {offset: offset, length: length, header: true, ansi: true});
        send_msg(data);
        return data;
    });
}

function dump_class(class_name){
    return wrap_java_perform(() => {
        //获取类的所有方法
        var cls = Java.use(class_name);
        var mhd_array = cls.class.getDeclaredMethods();
        var msgs = [];
        msgs.push("------------  " + class_name + "  ------------");
        //获取类的所有字段
        var fields = []
        var field_array = cls.class.getFields();
        for (var i = 0; i < field_array.length; i++){
            var field = field_array[i]; //当前成员
            var field_name = field.getName();
            var field_class = field.getType().getName();
            msgs.push("field: " + col_keyword3 + field_name + col_reset + "\tclass: " + field_class);
            fields.push({fieldName: field_name, fieldClass: field_class})
        }
        //hook 类所有方法 （所有重载方法也要hook)
        var methods = [];
        for (var i = 0; i < mhd_array.length; i++){
            var mhd_cur = mhd_array[i]; //当前方法
            var str_mhd_name = mhd_cur.getName(); //当前方法名
            //当前方法重载方法的个数
            var n_overload_cnt = cls[str_mhd_name].overloads.length;
            msgs.push("method: " + col_keyword + str_mhd_name + col_reset + "()\toverload: " + n_overload_cnt);
            methods.push({methodName: str_mhd_name, overloadCount: n_overload_cnt})
        }
        send(msgs.join("\n"));
        return {className: class_name, fields: fields, methods: methods}
    });
}
function list_so(){
    return wrap_java_perform(() => {
        var msgs = []
        var datas = [];
        Process.enumerateModules({
            onMatch: function(module){
                msgs.push('    ' + col_keyword + module.name + col_reset + "\t" + module.base + "\t"+ module.size + "\t" + col_path + module.path + col_reset);
                datas.push(module)
            },
           onComplete: function(){ }
        });
        send_msg(msgs.join("\n"));
        return datas;
    });
}
function dump_so(module_name, file_path){
    return wrap_java_perform(() => {
        var libxx = Process.getModuleByName(module_name);
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            Memory.protect(ptr(libxx.base), libxx.size, 'rwx');
            var libso_buffer = ptr(libxx.base).readByteArray(libxx.size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("dump finished!\noutput: " + col_path + file_path + col_reset);
        }else{
            console.log("failed to dump " + module_name + " to file - " + file_path);
        }
    });
}
function find_so(module_name){
    try {
        var libxx = Process.getModuleByName(module_name);
        return {base: libxx.base, size: libxx.size};
    }
    catch(err){
        console.log(err);
    }
}
function list_so_func(module_name){
    return wrap_java_perform(() => {
        var datas = [];
        var libxx = Process.getModuleByName(module_name);
        datas.push(col_title+"--------------------------  " + libxx.name + "  --------------------------"+col_reset);
        datas.push("    "+col_column+"name"+col_reset+": " + col_keyword + libxx.name + col_reset);
        datas.push("    "+col_column+"base"+col_reset+": " + col_keyword + libxx.base + col_reset);
        datas.push("    "+col_column+"size"+col_reset+": " + col_keyword + ptr(libxx.size) + col_reset);
        datas.push(col_title+"--------------------------  exports  --------------------------"+col_reset);
        datas.push("    "+col_column+"address\toffset\tfunction"+col_reset);

        var exports = libxx.enumerateExports();
        for(var i = 0; i < exports.length; i++) {
            datas.push("    "+exports[i].address+"\t"+ptr(exports[i].address-libxx.base)+"\t"+col_keyword+exports[i].name+col_reset);
        }

        datas.push(col_title+"--------------------------  imports  --------------------------"+col_reset);
        datas.push("    "+col_column+"address\tmodule\t\t\tfunction"+col_reset);
        var imports =  libxx.enumerateImports();
        for(var i = 0; i < imports.length; i++) {
            datas.push("    "+imports[i].address+"\t"+col_path+imports[i].module+col_reset+"\t"+col_keyword+imports[i].name+col_reset);
         }
        /* 暂时没有发现实用价值，先注释掉 by Ryan
        datas.push(col_title+"--------------------------  symbols  --------------------------"+col_reset);
        datas.push("    "+col_column+"address\ttype\tname\tis_global\tsection"+col_reset);
        var symbols = libxx.enumerateSymbols();
        for(var i = 0; i < symbols.length; i++) {
            datas.push("    "+symbols[i].address+"\t"+symbols[i].type+"\t"+symbols[i].name+"\t"+symbols[i].isGlobal+"\t"+JSON.stringify(symbols[i].section));
        }
        */
        send(datas.join("\n"));
        return {module: libxx, exports: exports, imports: imports}
    });
}
function list_thread(){
    return wrap_java_perform(() => {
        var enumerateThreads =  Process.enumerateThreads();
        for(var i = 0; i < enumerateThreads.length; i++) {
            console.log("");
            console.log("id:",enumerateThreads[i].id);
            console.log("state:",enumerateThreads[i].state);
            console.log("context:",JSON.stringify(enumerateThreads[i].context));
        }
        return enumerateThreads;
    });
}
function search_in_memory(module_name, pattern){
    //pattern 是搜索条件，如 "03 49 ?? 50 20 44"，其中 "??" 是通配符
    return wrap_java_perform(() => {
        var libxx = Process.getModuleByName(module_name);
        console.log("base:"+libxx.base)
        //从so的基址开始搜索，搜索大小为so文件的大小，搜指定条件03 49 ?? 50 20 44的数据
        var res = Memory.scan(libxx.base, libxx.size, pattern, {
            onMatch: function(address, size){ //搜索成功
                console.log('搜索到 ' +pattern +" 地址是:"+ address.toString());
            },
            onError: function(reason){ //搜索失败
                console.log('搜索失败');
            },
            onComplete: function(){ //搜索完毕
                console.log("搜索完毕")
            }
          });
    });
}
/*
* dump_dex
* Author: hluwa <hluwa888@gmail.com>
* HomePage: https://github.com/hluwa
* CreatedTime: 2020/1/7 20:44
* */
function verify_by_maps(dexptr, mapsptr) {
    var maps_offset = dexptr.add(0x34).readUInt();
    var maps_size = mapsptr.readUInt();
    for (var i = 0; i < maps_size; i++) {
        var item_type = mapsptr.add(4 + i * 0xC).readU16();
        if (item_type === 4096) {
            var map_offset = mapsptr.add(4 + i * 0xC + 8).readUInt();
            if (maps_offset === map_offset) {
                return true;
            }
        }
    }
    return false;
}
function get_dex_real_size(dexptr, range_base, range_end) {
    var dex_size = dexptr.add(0x20).readUInt();
    var maps_address = get_maps_address(dexptr, range_base, range_end);
    if (!maps_address) {
        return dex_size;
    }
    var maps_end = get_maps_end(maps_address, range_base, range_end);
    if (!maps_end) {
        return dex_size;
    }
    return maps_end - dexptr
}
function get_maps_address(dexptr, range_base, range_end) {
    var maps_offset = dexptr.add(0x34).readUInt();
    if (maps_offset === 0) {
        return null;
    }
    var maps_address = dexptr.add(maps_offset);
    if (maps_address < range_base || maps_address > range_end) {
        return null;
    }
    return maps_address;
}
function get_maps_end(maps, range_base, range_end) {
    var maps_size = maps.readUInt();
    if (maps_size < 2 || maps_size > 50) {
        return null;
    }
    var maps_end = maps.add(maps_size * 0xC + 4);
    if (maps_end < range_base || maps_end > range_end) {
        return null;
    }

    return maps_end;
}
function verify(dexptr, range, enable_verify_maps) {
    if (range != null) {
        var range_end = range.base.add(range.size);
        // verify header_size
        if (dexptr.add(0x70) > range_end) {
            return false;
        }
        // In runtime, the fileSize is can to be clean, so it's not trust.
        // verify file_size
        // var dex_size = dexptr.add(0x20).readUInt();
        // if (dexptr.add(dex_size) > range_end) {
        //     return false;
        // }
        if (enable_verify_maps) {
            var maps_address = get_maps_address(dexptr, range.base, range_end);
            if (!maps_address) {
                return false;
            }
            var maps_end = get_maps_end(maps_address, range.base, range_end);
            if (!maps_end) {
                return false;
            }
            return verify_by_maps(dexptr, maps_address)
        } else {
            return dexptr.add(0x3C).readUInt() === 0x70;
        }
    }
    return false;
}
function memory_dump(address, size) {
    Memory.protect(ptr(address), size, 'rwx');
    return ptr(address).readByteArray(size);
//    return new NativePointer(address).readByteArray(size);
}
function scan_dex(enable_deep_search) {
    var result = [];
    Process.enumerateRanges('r--').forEach(function (range) {
        try {
            Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function (match) {

                if (range.file && range.file.path
                    && (// range.file.path.startsWith("/data/app/") ||
                        range.file.path.startsWith("/data/dalvik-cache/") ||
                        range.file.path.startsWith("/system/"))) {
                    return;
                }

                if (verify(match.address, range, false)) {
                    var dex_size = get_dex_real_size(match.address, range.base, range.base.add(range.size));
                    result.push({
                        "addr": match.address,
                        "size": dex_size
                    });

                    var max_size = range.size - match.address.sub(range.base);
                    if (enable_deep_search && max_size != dex_size) {
                        result.push({
                            "addr": match.address,
                            "size": max_size
                        });
                    }
                }
            });

            if (enable_deep_search) {
                Memory.scanSync(range.base, range.size, "70 00 00 00").forEach(function (match) {
                    var dex_base = match.address.sub(0x3C);
                    if (dex_base < range.base) {
                        return
                    }
                    if (dex_base.readCString(4) != "dex\n" && verify(dex_base, range, true)) {
                        var real_dex_size = get_dex_real_size(dex_base, range.base, range.base.add(range.size));
                        result.push({
                            "addr": dex_base,
                            "size": real_dex_size
                        });
                        var max_size = range.size - dex_base.sub(range.base);
                        if (max_size != real_dex_size) {
                            result.push({
                                "addr": match.address,
                                "size": max_size
                            });
                        }
                    }
                })
            } else {
                if (range.base.readCString(4) != "dex\n" && verify(range.base, range, true)) {
                    var real_dex_size = get_dex_real_size(range.base, range.base, range.base.add(range.size));
                    result.push({
                        "addr": range.base,
                        "size": real_dex_size
                    });
                }
            }

        } catch (e) {
        }
    });

    return result;
}
function hook_RegisterNatives() {
    return wrap_java_perform(() => {
        var symbols = Module.enumerateSymbolsSync("libart.so");
        var addrRegisterNatives = null;
        for (var i = 0; i < symbols.length; i++) {
            var symbol = symbols[i];
            //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
            if (symbol.name.indexOf("art") >= 0 &&
                    symbol.name.indexOf("JNI") >= 0 &&
                    symbol.name.indexOf("RegisterNatives") >= 0 &&
                    symbol.name.indexOf("CheckJNI") < 0) {
                addrRegisterNatives = symbol.address;
                console.log(col_hooked, "RegisterNatives is hooked at ", col_keyword3, symbol.address, symbol.name, col_reset);
            }
        }

        if (addrRegisterNatives != null) {
            Interceptor.attach(addrRegisterNatives, {
                onEnter: function (args) {
                    var env = args[0];
                    var java_class = args[1];
                    var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                    var methods_ptr = ptr(args[2]);
                    var method_count = parseInt(args[3]);
                    var methods = [];
                    for (var i = 0; i < method_count; i++) {
                        var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                        var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                        var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

                        var name = Memory.readCString(name_ptr);
                        var sig = Memory.readCString(sig_ptr);
                        var find_module = Process.findModuleByAddress(fnPtr_ptr);
                        var method_info = {java_class: class_name, name: name, sig: sig, fnPtr: fnPtr_ptr, module_name: find_module.name, module_base: find_module.base, offset: ptr(fnPtr_ptr).sub(find_module.base)};
                        methods.push(method_info);
                    }
                    let data = {type:"registerNatives", methods:JSON.stringify(methods)};
                    send(data);
                }
            });
        }
    });
}

