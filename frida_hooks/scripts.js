var _is_color_mode = true
const clr_reset = () => _is_color_mode? "\x1B[0m": '';

const clr_black = (text) => clr_ansify("\x1B[0;30m", text);
const clr_dark_gray = (text) => clr_ansify("\x1B[1;30m", text);
const clr_blue = (text) => clr_ansify("\x1B[0;34m", text);
const clr_bright_blue = (text) => clr_ansify("\x1B[1;34m", text);
const clr_green = (text) => clr_ansify("\x1B[0;32m", text);
const clr_bright_green = (text) => clr_ansify("\x1B[1;32m", text);
const clr_cyan = (text) => clr_ansify("\x1B[0;36m", text);
const clr_bright_cyan = (text) => clr_ansify("\x1B[1;36m", text);
const clr_red = (text) => clr_ansify("\x1B[0;31m", text);
const clr_bright_red = (text) => clr_ansify("\x1B[1;31m", text);
const clr_purple = (text) => clr_ansify("\x1B[0;35m", text);
const clr_bright_purple = (text) => clr_ansify("\x1B[1;35m", text);
const clr_brown = (text) => clr_ansify("\x1B[0;33m", text);
const clr_yellow = (text) => clr_ansify("\x1B[1;33m", text);
const clr_bright_gray = (text) => clr_ansify("\x1B[0;37m", text);
const clr_white = (text) => clr_ansify("\x1B[1;37m", text);
const clr_bg_black = (text) => clr_ansify("\x1B[40m", text);
const clr_bg_red = (text) => clr_ansify("\x1B[41m", text);
const clr_bg_green = (text) => clr_ansify("\x1B[42m", text);
const clr_bg_yellow = (text) => clr_ansify("\x1B[43m", text);
const clr_bg_blue = (text) => clr_ansify("\x1B[44m", text);
const clr_bg_purple = (text) => clr_ansify("\x1B[45m", text);
const clr_bg_cyan = (text) => clr_ansify("\x1B[46m", text);
const clr_bg_white = (text) => clr_ansify("\x1B[47m", text);
const clr_bright = (text) => clr_ansify("\x1B[1m", text);
const clr_dim = (text) => clr_ansify("\x1B[2m", text);
const clr_underline = (text) => clr_ansify("\x1B[4m", text);
const clr_blink = (text) => clr_ansify("\x1B[5m", text);
const clr_reverse = (text) => clr_ansify("\x1B[7m", text);
const clr_strikethrough = (text) => clr_ansify("\x1B[9m", text);
const clr_overline = (text) => clr_ansify("\x1B[53m", text);

// return an ansified string
const clr_ansify = (color, ...msg) => _is_color_mode? color + msg.join(``) + "\x1B[0m": msg.join(``);

const not_safe_classes = {
    "androidx.appcompat.widget.AppCompatTextClassifierHelper": true,
    "androidx.core.text.PrecomputedTextCompat$Params": true,
    "androidx.core.text.PrecomputedTextCompat": true,
    "android.support.v4.text.c$a": true,
    "android.support.v4.text.c": true,
    "android.support.v4.text.PrecomputedTextCompat$Params": true,
    "android.support.v4.text.PrecomputedTextCompat": true,
    "com.taobao.taopai.business.ShareMainNewActivity": true,
    "com.facebook.imagepipeline.image.EncodedImage": true,
    "com.facebook.imageutils.ImageMetaData": true,
    "androidx.appcompat.widget.k": true,
    "androidx.core.app.JobIntentService$f$a": true,
    "com.amap.api.col.sl2.c9": true,
    "androidx.media.k$a": true,
}

const FLAG_ACTIVITY_NEW_TASK = 0x10000000;
const ACTION_VIEW = "android.intent.action.VIEW";

var dex_list = [];
var native_list = [];

function set_color_mode(is_color_mode){
    _is_color_mode = is_color_mode
}

function sleep(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

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

function java_use_safe(class_name){
    let cls = null;
    try{
        if(!not_safe_classes[class_name]){
            return Java.use(class_name);
        }
    }catch(e){
    }
    return cls;
}

function get_real_class_name(object) {
    const objClass = Java.use("java.lang.Object").getClass.apply(object);
    return Java.use("java.lang.Class").getName.apply(objClass)
}

function is_instance_of(object, className){
    let result = false;
    try {
        const targetClass = Java.use(className);
        const newObject = Java.cast(object, targetClass);
        result = !!newObject;
    } catch (e) {
        result = false;
    }
    return result;
};

function get_methods_safe(class_name){
    let methods = [];
    try{
        if(!not_safe_classes[class_name]){
            let cls = Java.use(class_name);
            methods = cls.class.getDeclaredMethods();
        }
    }catch(e){
    }
    return methods;
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

function trim(str, is_global){
    var result;
    result = str.replace(/(^\s+)|(\s+$)/g,"");
    if(is_global){
        result = result.replace(/\s/g,"");
    }
    return result;
}

function dump_object(_this){
    let class_name = get_real_class_name(_this);
    let fields = get_fields(_this);
    send({type:"fields", before:JSON.stringify(fields), class:class_name});
}

function has_own_property(obj, name) {
    try {
        return obj.hasOwnProperty(name) || name in obj;
    } catch (e) {
        return false;
    }
}

function get_own_property(obj, name) {
    if (!has_own_property(obj, name)) {
        return null;
    }
    let result = null;
    try {
        result = obj[name];
        if (result) {
            return result
        }
    } catch (e) {
    }

    try {
        result = obj.getOwnProperty(name);
        if (result) {
            return result;
        }
    } catch (e) {
    }
    return result
}

function get_class_safe(_this){
    try {
        return _this.getClass().getName();
    } catch (e) {
    }
    return ''
}

//获取字段信息
function get_fields(_this){
    let fields = {};
    var cls = null;
    try {
        cls = _this.getClass();
    } catch (e) {
    }

    while (cls !== null && !cls.equals(Java.use("java.lang.Object").class)) {
        var class_name = get_real_class_name(_this);
        var field_array = cls.getDeclaredFields();
        for (var i = 0; i < field_array.length; i++){
            let field = field_array[i]; //当前成员
            field.setAccessible(true);
            let field_name = field.getName();
            let field_class_name = field.getType().getName();
            let key = class_name + '.' + field_name;
            let field_val = 'UNKNOWN'
            try {
                let field_val_obj = field.get(_this);
                field_val = field_val_obj == null? field_val_obj: field_val_obj.toString();
            }
            catch(err){
            }
            fields[key] = {field: field_name, class: field_class_name, value: field_val};
        }
        break;
        cls = cls.getSuperclass();
    }
    return fields;
}

//获取参数
function get_arguments(arg_list, arg_cnt){
    let args = {};
    //获取参数
    for (var idx_arg = 0; idx_arg < arg_cnt; idx_arg++) {
        var class_name = '';
        var fields = {};
        try {
            class_name = get_real_class_name(arg_list[idx_arg]);
            fields = get_fields(arg_list[idx_arg]);
        } catch (e) {
        }
        args[idx_arg] = {class: class_name, value: '' + arg_list[idx_arg], fields: fields};
    }
    return args;
}

//获取参数
function get_arguments_for_so(arg_list, arg_cnt){
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

function probe_obj_method(_this, cls){
    let class_name = trim(cls.toString().replace(/(class|interface)/g, ''));
    let method_array = get_methods_safe(class_name);
    let ret_values = [];
    for (let i = 0; i < method_array.length; i++) {
        let cur_method = method_array[i]; //当前方法
        let str_method_name = cur_method.getName(); //当前方法名
        let str_ret_type = '' + cur_method.getReturnType();
        str_ret_type = trim(str_ret_type.replace(/(class|interface)/g, ''));
        let str_param_types = trim('' + cur_method.getParameterTypes());
        if(str_param_types == '' && str_ret_type != 'java.lang.Object'
                && str_ret_type != 'boolean' && str_ret_type.indexOf('$') < 0
                && str_method_name != 'toString'){
            try{
                let ret = '' + eval('_this.' + str_method_name + '()');
                ret_values.push({method: str_method_name, ret: ret});
            } catch (e) {
            }
        }
    }
    return ret_values;
}

function open_scheme_url(url){
    return wrap_java_perform(() => {
        const context = get_application_context();
        const AndroidIntent = Java.use("android.content.Intent");
        const Uri = Java.use("android.net.Uri");
        // Init and launch the intent
        const new_intent = AndroidIntent.$new(ACTION_VIEW, Uri.parse(url));
        // new_intent.setFlags(FLAG_ACTIVITY_NEW_TASK);

        context.startActivity(new_intent);
        console.log(clr_yellow("scheme: ") + clr_cyan(url) + clr_yellow(" successfully asked to open."));
    });
}

function dump_map(map_obj){
    let result = {};
    try {
        const MapClass = Java.use("java.util.Map");
        const EntryClass = Java.use("java.util.Map$Entry");
        const entry_set = MapClass.entrySet.apply(map_obj).iterator();
        while (entry_set.hasNext()) {
            const entry = Java.cast(entry_set.next(), EntryClass);
            const key = entry.getKey();
            const value = entry.getValue();
            if (key == null || value == null) {
                continue
            }
            result["" + key] = "" + value;
        }
    } catch (e) {
        console.error(e)
    }
    return result;
}

function dump_collection(collection_obj){
    let result = [];
    try {
        const CollectionClass = Java.use("java.util.Collection");
        const object_array = CollectionClass.toArray.apply(collection_obj);
        object_array.forEach(function (element) {
            result.push("" + element);
        });
    } catch (e) {
        console.error(e)
    }
    return result;
}

function list_class_core(){
    return wrap_java_perform(() => {
        var classes = []
        Java.enumerateLoadedClasses({
            "onMatch": function (className) {
                classes.push(className);
             },
            "onComplete": function () { }
        });
       return classes;
    });
}

function list_class(){
    list_class_core().then(classes => {
       send_msg(classes);
       return classes;
    })
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

function gen_request_data(request){
    var cls = null;
    var request_class = null;
    try {
        cls = request.getClass();
        request_class = Java.use("okhttp3.Request");
    } catch (e) {
    }
    if (cls !== null && request_class != null && cls.equals(request_class.class)) {
        var ByteString = Java.use("okio.ByteString");
        var Buffer = Java.use("okio.Buffer");
        let data = null;
        try{
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
            data = {type: "request", request: (request != null? request.toString(): "null"), url: url,
                    method: method, headers: headers, body: body};
        } catch (error) {
            console.log("error 2:", error);
        }
        return data;
    }else{
        let class_name = trim(cls.toString().replace(/(class|interface)/g, ''));
        let ret_values = probe_obj_method(request, cls)
        return {type: "request", request: (request != null? request.toString(): "null"),
                probe: JSON.stringify(ret_values), class: class_name};
    }
}

function gen_response_data(response){
    var cls = null;
    var response_class = null;
    try {
        cls = response.getClass();
        response_class = Java.use("okhttp3.Response");
    } catch (e) {
    }
    if (cls !== null && response_class != null && cls.equals(response_class.class)) {
        let data = null;
        try {
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
            data = {type:"response", response:response.toString(), headers:response.headers().toString(), body:body};
        } catch (error) {
            console.log("error 3:", error);
        }
        return data;
    }else{
        let class_name = trim(cls.toString().replace(/(class|interface)/g, ''));
        return {type:"response",response:(response!=null?response.toString():"null"),
                class: class_name};
    }
}

function hook_func_frame(class_name, method_name, func){
    return wrap_java_perform(() => {
        var full_func_name = class_name + '.' + method_name;
        try{
            var cls = Java.use(class_name);
            if(cls[method_name] == undefined){
                console.log('error: ' + full_func_name + ' not found in ' + cls + '!')
            }else{
                var n_overload_cnt = cls[method_name].overloads.length;
                for (var index = 0; index < n_overload_cnt; index++) {
                    cls[method_name].overloads[index].implementation = func;
                    console.log(clr_yellow(clr_blink(full_func_name + "() [" + index +  "] is hooked...")));
                }
            }
        }catch(e){
            console.log(clr_red(full_func_name + '() failed to hook.'))
        }
    });
}

function hook_func(class_name, method_name, validate_func){
    return hook_func_frame(class_name, method_name, function () {
        if(!validate_func || validate_func(class_name, method_name, arguments)){
            // console.log(clr_red(clr_blink('enter: ' + class_name + '.' + method_name)));
            var full_func_name = class_name + '.' + method_name + '()';
            // 获取时间戳
            var timestamp = (new Date()).getTime();
            var datas = [];
            datas.push({type:"stack", data:get_stack_trace(), timestamp:timestamp, funcName:full_func_name});
            let args_before = get_arguments(arguments, arguments.length);
            let fields_before = get_fields(this);
            //调用原应用的方法
            let ret = this[method_name].apply(this, arguments);
            let args_after = get_arguments(arguments, arguments.length);
            let fields_after = get_fields(this);
            let ret_fields = get_fields(ret);
            let ret_class = get_class_safe(ret);
            datas.push({type:"arguments", before:JSON.stringify(args_before), after:JSON.stringify(args_after)});
            datas.push({type:"fields", before:JSON.stringify(fields_before), after:JSON.stringify(fields_after), class:class_name});
            datas.push({type:"return", class:ret_class, value:(ret!=null?ret.toString():"null"), fields:JSON.stringify(ret_fields)});
            send(datas);
            return ret;
        }else{
            return this[method_name].apply(this, arguments);
        }
    });
}

function hook_class(class_name){
    return wrap_java_perform(() => {
        // hook 构造函数
        hook_func(class_name, "$init");
        //获取类的所有方法
        var method_array = get_methods_safe(class_name);

        //hook 类所有方法 （所有重载方法也要hook)
        let hooked_methods = {};
        for (var i = 0; i < method_array.length; i++){
            let cur_method = method_array[i]; //当前方法
            let str_method_name = cur_method.getName(); //当前方法名
            if (!hooked_methods[str_method_name]){
                hook_func(class_name, str_method_name);
                hooked_methods[str_method_name] = true;
            }
        }
    });
}

function hook_so_func(module_name, func_name, addr_str){
    return wrap_java_perform(() => {
        //对函数名hook
        var ptr_func = func_name != ''?
                        Module.findExportByName(module_name, func_name):
                        new NativePointer(addr_str);
        var full_func_name = module_name + ": " + '[' + ptr_func + '] ' + func_name + '()';
        console.log(clr_yellow(full_func_name + " is hooked..."));
        Interceptor.attach(ptr_func,{
            //onEnter: 进入该函数前要执行的代码，其中args是传入的参数，一般so层函数第一个参数都是JniEnv，第二个参数是jclass，从第三个参数开始是我们java层传入的参数
            onEnter: function(args) {
                var datas = [];
                datas.push({type:"stack", data:get_stack_trace(), funcName:full_func_name});
                let args_list = get_arguments_for_so(args, 4);
                datas.push({type:"asm_args", data:args_list});
                send(datas);
            },
            onLeave: function(ret){ //onLeave: 该函数执行结束要执行的代码，其中ret参数即是返回值
                send({type:"return", value:(ret!=null?ret.toString():"null"), funcName:func_name});
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
            let func_name = module_name + ": " + '[' + ptr_func + '] ' + exports[i].name + '()';
            try {
                Interceptor.attach(ptr_func,{
                    //onEnter: 进入该函数前要执行的代码，其中args是传入的参数，一般so层函数第一个参数都是JniEnv，第二个参数是jclass，从第三个参数开始是我们java层传入的参数
                    onEnter: function(args) {
                        var datas = [];
                        datas.push({type:"stack", data:get_stack_trace(), funcName:func_name});
                        let args_list = get_arguments_for_so(args, 4);
                        datas.push({type:"asm_args", data:args_list});
                        send(datas);
                    },
                    onLeave: function(ret){ //onLeave: 该函数执行结束要执行的代码，其中ret参数即是返回值
                        send({type:"return", value:(ret!=null?ret.toString():"null"), funcName:func_name});
                    }
                });
                console.log(clr_yellow(func_name + " is hooked..."));
            }
            catch(err){
            }
        }
    });
}

function hook_okhttp_execute(){
    return hook_func_frame('com.android.okhttp.Call', 'execute', function(){
            let datas = [];
            var timestamp = (new Date()).getTime();
            let func_name = "com.android.okhttp.Call.execute()";
            datas.push({type:"stack", data:get_stack_trace(), timestamp:timestamp, funcName:func_name});
            var response = this.execute();
            var request = this.request();
            datas.push(gen_request_data(request));
            datas.push(gen_response_data(response));
            send_msg(datas)
            return response;
        });
}

function hook_okhttp3_execute(){
    return hook_func_frame('okhttp3.RealCall', 'execute', function(){
            let datas = [];
            var timestamp = (new Date()).getTime();
            let func_name = "okhttp3.RealCall.execute()";
            datas.push({type:"stack", data:get_stack_trace(), timestamp:timestamp, funcName:func_name});
            var response = this.execute();
            var request = this.request();
            datas.push(gen_request_data(request));
            datas.push(gen_response_data(response));
            send_msg(datas)
            return response;
        });
}

function hook_okhttp3_CallServer(){
    return wrap_java_perform(() => {
        var InterceptorClass = Java.use("okhttp3.internal.http.CallServerInterceptor");
        InterceptorClass.intercept.implementation=function(chain){
            let datas = [];
            let func_name = "okhttp3.internal.http.CallServerInterceptor.intercept()";
            var timestamp = (new Date()).getTime();
            datas.push({type:"stack", data:get_stack_trace(), timestamp:timestamp, funcName:func_name});
            var request = chain.request();
            var response = this.intercept(chain);
            datas.push(gen_request_data(request));
            datas.push(gen_response_data(response));
            send_msg(datas)
            return response;
        }
        console.log(clr_yellow(clr_blink("okhttp3.internal.http.CallServerInterceptor.intercept() is hooked...")));
    });
}

function hook_intercept(class_name){
    return wrap_java_perform(() => {
        var InterceptorClass = Java.use(class_name);
        InterceptorClass.intercept.implementation=function(chain){
            let datas = [];
            let func_name = class_name + ".intercept()";
            var timestamp = (new Date()).getTime();
            datas.push({type:"stack", data:get_stack_trace(), timestamp:timestamp, funcName:func_name});
            var request = chain.request();
            var response = this.intercept(chain);
            datas.push(gen_request_data(request));
            datas.push(gen_response_data(response));
            send_msg(datas);
            return response;
        }
        console.log(clr_yellow(clr_blink(InterceptorClass + ".intercept() is hooked...")));
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
        var Modifier = Java.use("java.lang.reflect.Modifier");
        var method_array = get_methods_safe(class_name);
        var msgs = [];
        msgs.push(clr_bright_green("------------  " + class_name + "  ------------"));
        //获取类的所有字段
        var fields = []
        var field_array = cls.class.getDeclaredFields();
        for (var i = 0; i < field_array.length; i++) {
            var field = field_array[i]; //当前成员
            var field_name = field.getName();
            var field_class = field.getType().getName();
            let modifier = '' + Modifier.toString(field.getModifiers());
            msgs.push("  "+ clr_cyan(modifier) + " " + clr_blue(field_class) + " " + clr_purple(field_name));
            fields.push({fieldName: field_name, fieldClass: field_class})
        }
        //hook 类所有方法 （所有重载方法也要hook)
        var methods = [];
        for (var i = 0; i < method_array.length; i++) {
            var cur_method = method_array[i]; //当前方法
            var str_method_name = cur_method.getName(); //当前方法名
            let modifier = '' + Modifier.toString(cur_method.getModifiers());
            let str_ret_type = ' ' + cur_method.getReturnType();
            str_ret_type = str_ret_type.replace(/(class|interface)/g, '')
            let str_param_types = ('' + cur_method.getParameterTypes()).split(',');
            let fmt_param_types = []
            for (let j = 0; j < str_param_types.length; j++){
                fmt_param_types.push(clr_bright_blue(str_param_types[j].replace(/(class|interface| )/g, '')))
            }
            msgs.push("  " + clr_cyan(modifier) + clr_yellow(str_ret_type) + " " + clr_bright_purple(str_method_name)
                + clr_dark_gray("(") + fmt_param_types.join(clr_dark_gray(",")) + clr_dark_gray(")"));
            methods.push({name: str_method_name, modifier: modifier, returnType: str_ret_type, parameterTypes: str_param_types.join(",")})
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
                msgs.push('    ' + clr_yellow(module.name) + "\t" + module.base + "\t"+ module.size + "\t" + clr_bright_blue(clr_underline(module.path)));
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
            console.log("dump finished!\noutput: " + clr_bright_blue(clr_underline(file_path)));
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
        datas.push(clr_bright_green("--------------------------  " + libxx.name + "  --------------------------"));
        datas.push("    "+clr_bright_gray(clr_reverse("name"))+": " + clr_cyan(libxx.name));
        datas.push("    "+clr_bright_gray(clr_reverse("base"))+": " + clr_cyan(libxx.base));
        datas.push("    "+clr_bright_gray(clr_reverse("size"))+": " + clr_cyan(ptr(libxx.size)));
        datas.push(clr_bright_green("--------------------------  exports  --------------------------"));
        datas.push("    "+clr_bright_gray(clr_reverse("address\toffset\tfunction")));

        var exports = libxx.enumerateExports();
        for(var i = 0; i < exports.length; i++) {
            datas.push("    "+exports[i].address+"\t"+ptr(exports[i].address-libxx.base)+"\t"+clr_cyan(exports[i].name));
        }

        datas.push(clr_bright_green("--------------------------  imports  --------------------------"));
        datas.push("    "+clr_bright_gray(clr_reverse("address\tmodule\t\t\tfunction")));
        var imports =  libxx.enumerateImports();
        for(var i = 0; i < imports.length; i++) {
            datas.push("    "+imports[i].address+"\t"+clr_bright_blue(clr_underline(imports[i].module))+"\t"+clr_cyan(imports[i].name));
         }
        /* 暂时没有发现实用价值，先注释掉 by Ryan
        datas.push(clr_bright_green("--------------------------  symbols  --------------------------"));
        datas.push("    "+clr_bright_gray(clr_reverse("address\ttype\tname\tis_global\tsection")));
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
    if(dex_list.length > 0){
        return dex_list;
    }
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
function search_class(keyword){
    let pattern = new RegExp(keyword, 'i');
    return wrap_java_perform(() => {
        list_class_core().then(class_names => {
            var msgs = [];
            var clazz = [];
            class_names.forEach((class_name) =>{
                if(class_name.match(pattern)){
                    msgs.push(clr_purple(class_name));
                    clazz.push(class_name)
                }
            })
            send(msgs.join("\n"));
            return {classes: clazz}
        }).catch(function(error){
        })
    });
}

function search_func_core(method_name, exclude, is_exact){
    let pattern = new RegExp(method_name, 'i');
    let Modifier = Java.use("java.lang.reflect.Modifier");
    let exclude_classes = {}
    let exclude_class_array = exclude.split(',');
    exclude_class_array.forEach(item => {
        exclude_classes[item] = true;
    })
    return wrap_java_perform(() => {
        list_class_core().then(class_names => {
            var msgs = [];
            var methods = [];
            for (let m = 0; m < class_names.length; m++) {
                let class_name = class_names[m];
                try{
                    console.log(clr_cyan((m + 1) + '/' + class_names.length), clr_purple(class_name));
                    if(exclude_classes[class_name]){
                        continue;
                    }
                    let cls = java_use_safe(class_name);
                    if(is_exact && (!cls || !cls[method_name] || !cls[method_name].overloads
                            || cls[method_name].overloads.length == 0)){
                        continue;
                    }
                    let method_array = get_methods_safe(class_name);
                    for (let i = 0; i < method_array.length; i++) {
                        let cur_method = method_array[i]; //当前方法
                        let str_method_name = cur_method.getName(); //当前方法名
                        if((is_exact && str_method_name == method_name)
                                || (!is_exact && str_method_name.match(pattern))){
                            let modifier = '' + Modifier.toString(cur_method.getModifiers());
                            let str_ret_type = ' ' + cur_method.getReturnType();
                            str_ret_type = str_ret_type.replace(/(class|interface)/g, '')
                            let str_param_types = ('' + cur_method.getParameterTypes()).split(',');
                            let fmt_param_types = []
                            for (let j = 0; j < str_param_types.length; j++){
                                fmt_param_types.push(clr_bright_blue(str_param_types[j].replace(/(class|interface| )/g, '')))
                            }
                            msgs.push(clr_purple(class_name) + "\t" + clr_cyan(modifier) + clr_yellow(str_ret_type) + " " + clr_bright_purple(str_method_name)
                                + clr_dark_gray("(") + fmt_param_types.join(clr_dark_gray(",")) + clr_dark_gray(")"));
                            methods.push({className: class_name, name: str_method_name, modifier: modifier, returnType: str_ret_type, parameterTypes: str_param_types.join(",")})
                        }
                    }
                } catch (e) {
//                    console.log(class_name, e);
                }
            }
            console.log(clr_green("-------------------------- search result -------------------------"));
            send(msgs.join('\n'));
            return {keyword: keyword, methods: methods}
        }).catch(function(error){
        })
    });
}

function search_func(method_name, exclude){
    return search_func_core(method_name, exclude, true);
}

function fuzzy_search_func(keyword, exclude){
    return search_func_core(keyword, exclude, false);
}

function search_return_core(ret_class, exclude, is_exact){
    let pattern = new RegExp(ret_class, 'i');
    let Modifier = Java.use("java.lang.reflect.Modifier");
    let exclude_classes = {}
    let exclude_class_array = exclude.split(',');
    exclude_class_array.forEach(item => {
        exclude_classes[item] = true;
    })
    return wrap_java_perform(() => {
        list_class_core().then(class_names => {
            var msgs = [];
            var methods = [];
            for (let m = 0; m < class_names.length; m++) {
                let class_name = class_names[m];
                try{
                    console.log(clr_cyan((m + 1) + '/' + class_names.length), clr_purple(class_name));
                    if(exclude_classes[class_name]){
                        continue;
                    }
                    let method_array = get_methods_safe(class_name);
                    for (let i = 0; i < method_array.length; i++) {
                        let cur_method = method_array[i]; //当前方法
                        let str_method_name = cur_method.getName(); //当前方法名
                        let str_ret_type = ' ' + cur_method.getReturnType();
                        str_ret_type = str_ret_type.replace(/(class|interface)/g, '')
                        if((is_exact && trim(str_ret_type, true) == ret_class)
                                || (!is_exact && str_ret_type.match(pattern))){
                            let modifier = '' + Modifier.toString(cur_method.getModifiers());
                            let str_param_types = ('' + cur_method.getParameterTypes()).split(',');
                            let fmt_param_types = []
                            for (let j = 0; j < str_param_types.length; j++){
                                fmt_param_types.push(clr_bright_blue(str_param_types[j].replace(/(class|interface| )/g, '')))
                            }
                            msgs.push(clr_purple(class_name) + "\t" + clr_cyan(modifier) + clr_yellow(str_ret_type) + " " + clr_bright_purple(str_method_name)
                                + clr_dark_gray("(") + fmt_param_types.join(clr_dark_gray(",")) + clr_dark_gray(")"));
                            methods.push({className: class_name, name: str_method_name, modifier: modifier, returnType: str_ret_type, parameterTypes: str_param_types.join(",")})
                        }
                    }
                } catch (e) {
//                    console.log(class_name, e);
                }
            }
            console.log(clr_green("-------------------------- search result -------------------------"));
            send(msgs.join('\n'));
            return {returnType: ret_class, methods: methods}
        }).catch(function(error){
        })
    });
}

function search_return(ret_class, exclude){
    return search_return_core(ret_class, exclude, false);
}

function search_instance(class_name){
    return wrap_java_perform(() => {
        Java.choose(class_name, {
            onMatch: function(instance){
                dump_object(instance);
            },
            onComplete: function(){
                console.log("search finished!");
            }
        });
    });
}

function load_all_class() {
    return wrap_java_perform(() => {
        var DexFileclass = Java.use("dalvik.system.DexFile");
        var BaseDexClassLoaderclass = Java.use("dalvik.system.BaseDexClassLoader");
        var DexPathListclass = Java.use("dalvik.system.DexPathList");
        var total_class = 0;

        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    var basedexclassloaderobj = Java.cast(loader, BaseDexClassLoaderclass);
                    var pathList = basedexclassloaderobj.pathList.value;
                    var pathListobj = Java.cast(pathList, DexPathListclass)
                    var dexElements = pathListobj.dexElements.value;
                    for (var index in dexElements) {
                        var element = dexElements[index];
                        try {
                            var dexfile = element.dexFile.value;
                            var dexfileobj = Java.cast(dexfile, DexFileclass);
                            console.log("dexFile:", dexfileobj);
                            const classNames = [];
                            const enumeratorClassNames = dexfileobj.entries();
                            while (enumeratorClassNames.hasMoreElements()) {
                                var className = enumeratorClassNames.nextElement().toString();
                                classNames.push(className);
                                try {
                                    loader.loadClass(className);
                                    total_class++;
                                } catch (error) {
                                    console.log(clr_red("loadClass error: "), clr_red(error));
                                }
                            }
                        } catch (error) {
                            // console.log(clr_red("dexfile error: "), clr_red(error));
                        }
                    }
                } catch (error) {
                    // console.log(clr_red("loader error: "), clr_red(error));
                }
            },
            onComplete: function () {

            }
        })
        console.log("total of", clr_cyan(total_class), " classes were loaded.");
    });
}

/*
* dump_dex
* Author: lasting-yang
* HomePage: https://github.com/lasting-yang/frida_dump
* */
function hook_lib_art() {
    var libart = Process.findModuleByName("libart.so");
    var symbols = libart.enumerateSymbols();
    var addr_DefineClass = null;
    var addr_RegisterNatives = null;
    for (var index = 0; index < symbols.length; index++) {
        var symbol = symbols[index];
        var symbol_name = symbol.name;
        //这个DefineClass的函数签名是Android9的
        //_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
        if (symbol_name.indexOf("ClassLinker") >= 0 &&
            symbol_name.indexOf("DefineClass") >= 0 &&
            symbol_name.indexOf("Thread") >= 0 &&
            symbol_name.indexOf("DexFile") >= 0) {
//            console.log(symbol_name, symbol.address);
            addr_DefineClass = symbol.address;
        }
        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
                symbol.name.indexOf("JNI") >= 0 &&
                symbol.name.indexOf("RegisterNatives") >= 0 &&
                symbol.name.indexOf("CheckJNI") < 0) {
            addr_RegisterNatives = symbol.address;
        }
    }
    var dex_maps = {};
    if (addr_DefineClass) {
        console.log("[DefineClass:]", clr_cyan(addr_DefineClass));
        Interceptor.attach(addr_DefineClass, {
            onEnter: function(args) {
                var dex_file = args[5];
                //ptr(dex_file).add(Process.pointerSize) is "const uint8_t* const begin_;"
                //ptr(dex_file).add(Process.pointerSize + Process.pointerSize) is "const size_t size_;"
                var base = ptr(dex_file).add(Process.pointerSize).readPointer();
                var size = ptr(dex_file).add(Process.pointerSize + Process.pointerSize).readUInt();
                if (dex_maps[base] == undefined) {
                    dex_maps[base] = size;
                    var magic = ptr(base).readCString();
                    if (magic.indexOf("dex") == 0) {
                        dex_list.push({"addr": base, "size": size});
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
    if (addr_RegisterNatives != null) {
        console.log("[RegisterNatives:]", clr_cyan(addr_RegisterNatives));
        Interceptor.attach(addr_RegisterNatives, {
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
                    var module_name = find_module? find_module.name: 'Unknown';
                    var offset = find_module? ptr(fnPtr_ptr).sub(find_module.base): '';
                    var method_info = {java_class: class_name, name: name, sig: sig, fnPtr: fnPtr_ptr,
                                        module_name: module_name, offset: offset};
                    methods.push(method_info);
                }
                native_list.push({type:"registerNatives", methods:JSON.stringify(methods)});
            },
            onLeave: function(retval) {}
        });
    }
}

function list_register_natives(){
    send_msg(native_list);
    return native_list;
}

/*
* startActivity
* Author: sensepost
* HomePage: https://github.com/sensepost/objection
* */
function start_activity(activity_class){
    // -- Sample Java
    //
    // Intent intent = new Intent(this, DisplayMessageActivity.class);
    // intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    //
    // startActivity(intent);
    return wrap_java_perform(() => {
        const context = get_application_context();

        // Setup a new Intent
        const AndroidIntent = Java.use("android.content.Intent");

        // Get the Activity class's .class
        const NewActivity = Java.use(activity_class).class;

        // Init and launch the intent
        const new_intent = AndroidIntent.$new(context, NewActivity);
        new_intent.setFlags(FLAG_ACTIVITY_NEW_TASK);

        context.startActivity(new_intent);
        console.log(clr_yellow("Activity:") + clr_cyan(activity_class) + clr_yellow(" successfully asked to start."));
    });
}

function hook_json_parser(keyword){
    var validate_parser = function(class_name, method_name, args){
        if(args.length > 0){
            if(keyword != undefined && keyword != null && keyword != ""){
                var val_str = "" + args[0];
                return val_str.indexOf(keyword) >= 0;
            }else{
                return true;
            }
        }else{
            return false;
        }
    }

    hook_func('com.alibaba.fastjson.JSON', 'parseObject', validate_parser);
    hook_func('com.alibaba.fastjson.JSON', 'parseArray', validate_parser);
    hook_func('com.google.gson.JsonParser', 'parse', validate_parser);
    hook_func('com.google.gson.Gson', 'fromJson', validate_parser);
    hook_func('org.codehaus.jackson.JsonFactory', 'createParser', validate_parser);
    hook_func('net.sf.json.JSONObject', 'fromObject', validate_parser);
    hook_func('net.sf.json.JSONArray', 'fromObject', validate_parser);
    hook_func('org.json.JSONObject', '$init', validate_parser);
    hook_func('org.json.JSONArray', '$init', validate_parser);
}
