package com.xingin.xhs;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.file.RandomFileIO;
import com.github.unidbg.memory.Memory;
import okhttp3.*;
import okhttp3.FormBody.Builder;
import okio.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

public class XhsShield extends AbstractJni implements IOResolver<AndroidFileIO> {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static AndroidEmulator createARMEmulator() {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.xingin.xhs")
                .build();
        return emulator;
    }

    private final AndroidEmulator emulator;

    private final VM vm;

    private final Module module;

    private String method = "GET";

    private String url = "";

    private Headers headers;

    private RequestBody requestBody;

    private final Random random = new Random();

    /**
     * 最终结果存放
     */
    private final Map<String, String> result = new HashMap<>();

    private final static String SHIELD = "shield";

    private final static String XY_PLATFORM_INFO = "xy-platform-info";

    private final DvmClass Native;

    private final static String Method_Sign_Initialize = "initialize(Ljava/lang/String;)J";

    private final static String Method_Sign_InitializeNative = "initializeNative()V";

    private final static String Method_Sign_Intercept = "intercept(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;";

    private final static String NameSpace = "unidbg-android/src/test/resources/xhs";
//    private final static String NameSpace = "/Users/wangwei/Desktop/xhs_zhanwai";

    private String currentDeviceId = "";

    private String currentSid = "";

    private String currentSidSet = "";

    private String currentSugSidSet = "";


    private static XhsShield instance = new XhsShield();

    private long ret = 0L;

    private Map<String, String> deviceIdMap = new ConcurrentHashMap<>();

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final static String SID_SEPARATOR = ",";


    private void initDeviceMap() {
        // 初始化deviceIdMap
//        deviceIdMap ;
        deviceIdMap.put("1c3a1a44-bc3f-4007-bcbd-0cb30ca477d1", "knV932VKji1esl7J/A9w8iigG9R45VtATkIE4N0ROzcwqclzH9n+m8xOyUxO9SYZ/0NTgVVXieLcleq2mK6YyF1sc+v37akumnBLdlvwOm5LOJBml3GcnoF4adEIWmep");
    }

    private void initSid() {
    }

    private void initSidSet() {

    }

    private XhsShield() {
        initDeviceMap();
        initSid();
        initSidSet();

        emulator = createARMEmulator();
        emulator.getSyscallHandler().addIOResolver(this);
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());

        File apkFile = new File(NameSpace + "/com.xingin.xhs-7.69.2.1.apk");
        logger.info("apk length:" + apkFile.length());
        vm = emulator.createDalvikVM(apkFile);
        vm.setJni(this);
        vm.setVerbose(false);

        // 加载so
        File soFile = new File(NameSpace + "/libxyass.so");
        DalvikModule dm = vm.loadLibrary(soFile, false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();
        System.out.println(module.name);
        Native = vm.resolveClass("com/xingin/shield/http/XhsHttpInterceptor");

        Native.callStaticJniMethod(emulator, Method_Sign_InitializeNative);

        final DvmObject<?> dvmObject = Native.newObject(null);

        // 获取ptr
        ret = dvmObject.callJniMethodLong(emulator, Method_Sign_Initialize, "main");
        String traceFile = NameSpace+"/l.log";
        PrintStream traceStream = null;
        try { traceStream = new PrintStream(new FileOutputStream(traceFile), true); } catch (FileNotFoundException e) { e.printStackTrace(); } emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
    }


    /**
     * 设置更新sid的header, 固定
     */
    private void setSidHeaders() {
        Headers headers = new Headers.Builder()
                .add("xy-common-params","fid=162374503410be9666b44b627d752bb4a1faffd206ef&device_fingerprint=2021061504171328e8a7ec523956ed8c1b2d310a0e669300df80d3ae9acb9f&device_fingerprint1=&launch_id=1624604736&deviceId=926b5213-db77-389f-97ec-db7f3ffa27ed&sid=&identifier_flag=0").build();
        this.result.put("xy-common-params", "fid=162374503410be9666b44b627d752bb4a1faffd206ef&device_fingerprint=2021061504171328e8a7ec523956ed8c1b2d310a0e669300df80d3ae9acb9f&device_fingerprint1=&launch_id=1624604736&deviceId=926b5213-db77-389f-97ec-db7f3ffa27ed&sid=&identifier_flag=0");
        this.result.put("User-Agent", "Dalvik/2.1.0");
        this.headers = headers;
    }

    private void setSidHeaders(String xyCommons) {
        Headers headers = new Headers.Builder()
                .add("xy-common-params",xyCommons).build();
        this.result.put("xy-common-params", xyCommons);
        this.result.put("User-Agent", "Dalvik/2.1.0");
        this.headers = headers;
    }

    /**
     * 设置session
     */
    private void setHeaders() {
        Headers headers = new Headers.Builder()
                .add("xy-common-params",currentSid).build();
        this.result.put("xy-common-params", currentSid);
        this.result.put("User-Agent", "Dalvik/2.1.0");
        this.headers = headers;
    }

    /**
     * sug的session id
     */
    private void setSugHeaders() {
        String[] sids = currentSugSidSet.split(SID_SEPARATOR);
        String usedSid = sids[random.nextInt(sids.length)];
        Headers headers = new Headers.Builder()
                .add("xy-common-params", usedSid).build();
        this.result.put("xy-common-params", usedSid);
        this.result.put("User-Agent", "Dalvik/2.1.0");
        this.headers = headers;
    }

    /**
     * 随机取session id
     */
    private void setHeadersRandom() {
        String[] sids = currentSidSet.split(SID_SEPARATOR);
        String usedSid = sids[random.nextInt(sids.length)];
        Headers headers = new Headers.Builder()
                .add("xy-common-params", usedSid).build();
        this.result.put("xy-common-params", usedSid);
        this.result.put("User-Agent", "Dalvik/2.1.0");
        this.headers = headers;
    }


    private void setRequestBody(String s) {
        Builder builder = new Builder();
        for (String param:s.split("&")
        ) {
            String[] split = param.split("=");
            if(split.length == 2) {
                builder.add(split[0], split[1]);
            }else {
                builder.add(split[0],"");
            }
        }
        this.requestBody = builder.build();


    }



    /**
     * Base64Helper->decode最终生成的byte[], 该值的生成与deviceId直接相关
     * @param vm
     * @param dvmClass
     * @param signature
     * @param vaList
     * @return
     */
    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if ("java/nio/charset/Charset->defaultCharset()Ljava/nio/charset/Charset;".equals(signature)) {
            return this.vm.resolveClass("java/nio/charset/Charset").newObject(Charset.defaultCharset());
        }
        if ("com/xingin/shield/http/Base64Helper->decode(Ljava/lang/String;)[B".equals(signature)) {
            byte[] bytes = Base64.decode((String)vaList.getObjectArg(0).getValue());
            return new ByteArray(vm, bytes);
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    /**
     * 版本写死
     * @param vm
     * @param dvmObject
     * @param signature
     * @return
     */
    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/pm/PackageInfo->versionCode:I".equals(signature)) {
            return 7070219;
        }
        return super.getIntField(vm, dvmObject, signature);
    }

    /**
     * 生成的deviceId
     * @param vm
     * @param dvmClass
     * @param signature
     * @return
     */
    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/xingin/shield/http/ContextHolder->sLogger:Lcom/xingin/shield/http/ShieldLogger;":{
                return vm.resolveClass("com/xingin/shield/http/ShieldLogger").newObject(signature);
            }
            case "com/xingin/shield/http/ContextHolder->sDeviceId:Ljava/lang/String;":
            case "com/xingin/shield/http/ContextHolder->deviceId:Ljava/lang/String;":
                String[] keys =  deviceIdMap.keySet().toArray(new String[0]);
                currentDeviceId = keys[random.nextInt(keys.length)];
                return new StringObject(vm, currentDeviceId);
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("okhttp3/Response->code()I".equals(signature)) {
            return 200;
        }
        if ("okhttp3/Headers->size()I".equals(signature)) {
            return this.headers.size();
        }
        if ("okio/Buffer->read([B)I".equals(signature)) {
            Buffer buffer = (Buffer) dvmObject.getValue();
            byte[] bytes = (byte[]) vaList.getObjectArg(0).getValue();
            return buffer.read(bytes);
        }

        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }


    /**
     * sAppId与shield的前半部分相关，但不影响校验
     * @param vm
     * @param dvmClass
     * @param signature
     * @return
     */
    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/xingin/shield/http/ContextHolder->sAppId:I":
                return random.nextInt();
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature){
            case "com/xingin/shield/http/ShieldLogger->nativeInitializeStart()V":
            case "com/xingin/shield/http/ShieldLogger->nativeInitializeEnd()V":
            case "com/xingin/shield/http/ShieldLogger->initializeStart()V":
            case "com/xingin/shield/http/ShieldLogger->initializedEnd()V":
            case "com/xingin/shield/http/ShieldLogger->buildSourceStart()V":
            case "com/xingin/shield/http/ShieldLogger->buildSourceEnd()V":
            case "com/xingin/shield/http/ShieldLogger->calculateStart()V":
            case "com/xingin/shield/http/ShieldLogger->calculateEnd()V": {
                return;
            }
            case "okhttp3/RequestBody->writeTo(Lokio/BufferedSink;)V":
                FormBody requestBody = (FormBody) dvmObject.getValue();
                try {
                    Buffer paramsBuffer = (Buffer) vaList.getObjectArg(0).getValue();
                    requestBody.writeTo(paramsBuffer);
                } catch (IOException e) {
                }
                return;
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    /**
     * 必须为true。否则走非常老版本的加密
     * @param vm
     * @param dvmClass
     * @param signature
     * @return
     */
    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/xingin/shield/http/ContextHolder->sExperiment:Z":
                return true;
        }
        return super.getStaticBooleanField(vm, dvmClass, signature);
    }


    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "okhttp3/Interceptor$Chain->request()Lokhttp3/Request;": {
                if (method.equals("GET")) {
//                    return new DvmObject<>(vm.resolveClass("okhttp3/Request"), new Request.Builder().url(this.url).method("GET", null).build());
                    return vm.resolveClass("okhttp3/Request").newObject(new Request.Builder().url(this.url).method("GET", null).build());
                } else {
//                    return new DvmObject<>(vm.resolveClass("okhttp3/Request"),new Request.Builder().url(this.url).method("POST", requestBody).build());
                    return vm.resolveClass("okhttp3/Request").newObject(new Request.Builder().url(this.url).method("POST", requestBody).build());
                }
            }
            case "okhttp3/HttpUrl->encodedPath()Ljava/lang/String;": {
                HttpUrl url = (HttpUrl) dvmObject.getValue();
                return new StringObject(vm,url.encodedPath());
            }
            case "okhttp3/HttpUrl->encodedQuery()Ljava/lang/String;":{
                HttpUrl url = (HttpUrl) dvmObject.getValue();
                String query = url.encodedQuery();
                if (query=="") {
                    query = "";
                }
                return new StringObject(vm, query);
            }
            case "okhttp3/Request->body()Lokhttp3/RequestBody;":{
                if(method.equals("GET")){
//                    return new DvmObject<>(vm.resolveClass("okhttp3/RequestBody"),new Builder().build());
                    return vm.resolveClass("okhttp3/RequestBody").newObject(new Builder().build());

                }
                Request request = (Request) dvmObject.getValue();

//                return new DvmObject<>(vm.resolveClass("okhttp3/RequestBody"),request.body());
                return vm.resolveClass("okhttp3/RequestBody").newObject(request.body());
            }
            case "okhttp3/Request->headers()Lokhttp3/Headers;":{
//                return new DvmObject<>(vm.resolveClass("okhttp3/Headers"), this.headers);
                return vm.resolveClass("okhttp3/Headers").newObject(this.headers);
            }
            case "okhttp3/Headers->name(I)Ljava/lang/String;":{
                return new StringObject(vm, headers.name(vaList.getIntArg(0)));
            }
            case "okhttp3/Headers->value(I)Ljava/lang/String;":{
                return new StringObject(vm, headers.value(vaList.getIntArg(0)));
            }
            case "okio/Buffer->writeString(Ljava/lang/String;Ljava/nio/charset/Charset;)Lokio/Buffer;": {
                String content = (String) vaList.getObjectArg(0).getValue();
                Buffer buffer = (Buffer) dvmObject.getValue();
                buffer.writeString(content, Charset.defaultCharset());

                return dvmObject;
            }
            case "okio/Buffer->clone()Lokio/Buffer;": {
                Buffer buffer = (Buffer) dvmObject.getValue();
                Buffer dvm = buffer.clone();
//                return new DvmObject<>(vm.resolveClass("okio/Buffer"), dvm);
                return vm.resolveClass("okio/Buffer").newObject(dvm);
            }
            case "okhttp3/Request->newBuilder()Lokhttp3/Request$Builder;":
                DvmClass clazz = vm.resolveClass("okhttp3/Request$Builder");
                return clazz.newObject(null);
            case "android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
                return vm.resolveClass("android/content/SharedPreferences").newObject(null);
            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                // 这两处返回的值不为空，Base64Helper->decode的输入即是该值
                if (vaList.getObjectArg(0).getValue().equals("main")) {
                    return new StringObject(vm, deviceIdMap.getOrDefault(currentDeviceId, "s"));
                }
                if (vaList.getObjectArg(0).getValue().equals("main_hmac")) {
                    return new StringObject(vm, deviceIdMap.getOrDefault(currentDeviceId, "s"));
                }
                break;
            case "okhttp3/Request$Builder->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;":
                StringObject name = vaList.getObjectArg(0);
                StringObject value = vaList.getObjectArg(1);
                if (SHIELD.equals(name.getValue()) || XY_PLATFORM_INFO.equals(name.getValue())) {
                    result.put(name.getValue(), value.getValue());
                }
                return dvmObject;
            case "okhttp3/Request$Builder->build()Lokhttp3/Request;":
                clazz = vm.resolveClass("okhttp3/Request");
                return clazz.newObject(null);
            case "okhttp3/Interceptor$Chain->proceed(Lokhttp3/Request;)Lokhttp3/Response;":
                clazz = vm.resolveClass("okhttp3/Response");
                return clazz.newObject(null);
            case "okhttp3/Request->url()Lokhttp3/HttpUrl;": {
                Request request = (Request) dvmObject.getValue();
                HttpUrl url = request.url();
//                return new DvmObject<>(vm.resolveClass("okhttp3/HttpUrl"), url);
                return vm.resolveClass("okhttp3/HttpUrl").newObject(url);
            }
        }

        return super.callObjectMethodV(vm, dvmObject, signature,  vaList);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {

        switch (signature){
            case "okio/Buffer-><init>()V":
//                return new DvmObject<>(vm.resolveClass("okio/Buffer"),new Buffer());
                return vm.resolveClass("okio/Buffer").newObject(new Buffer());
        }

        return super.newObjectV(vm, dvmClass, signature, vaList);
    }


    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        if ("/dev/urandom".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new RandomFileIO(emulator, pathname) {
                @Override
                protected void randBytes(byte[] buf) {
                    ThreadLocalRandom.current().nextBytes(buf);
                }
            });
        }
        return null;
    }


    private void generateShield(long initializePtr){
        DvmObject<?> chain = vm.resolveClass("okhttp3/Interceptor$Chain").newObject(null);
        Native.newObject(null)
                .callJniMethodObject(emulator, Method_Sign_Intercept, chain, initializePtr);
    }

    public static XhsShield getInstance() {
        return instance;
    }

    public synchronized Map<String, String> getXhsHeader(String url) {
        return getXhsHeader(url, "");
    }

    public synchronized Map<String, String> getXhsHeader(String url, String requestBody) {
        if (requestBody!="") {
            instance.setRequestBody(requestBody);
            this.method = "POST";
            instance.setSidHeaders();
        } else {
            this.requestBody = null;
            this.method = "GET";
            instance.setHeaders();
        }
        instance.url = url;
        generateShield(ret);
        Map<String, String> copyMap = new HashMap<>();
        copyMap.putAll(result);
        return copyMap;
    }

    public synchronized Map<String, String> getXhsHeader(String url, String requestBody, String xyCommons) {
        Native.callStaticJniMethod(emulator, Method_Sign_InitializeNative);

        final DvmObject<?> dvmObject = Native.newObject(null);

        // 获取ptr
        ret = dvmObject.callJniMethodLong(emulator, Method_Sign_Initialize, "main");
        if (requestBody!="") {
            instance.setRequestBody(requestBody);
            this.method = "POST";
            instance.setSidHeaders(xyCommons);
        } else {
            this.requestBody = null;
            this.method = "GET";
            instance.setHeaders();
        }
        instance.url = url;
        generateShield(ret);
        Map<String, String> copyMap = new HashMap<>();
        copyMap.putAll(result);
        return copyMap;
    }

    public synchronized Map<String, String> getXhsHeaderWithRandom(String url) {
        this.requestBody = null;
        this.method = "GET";
        instance.setHeadersRandom();

        instance.url = url;
        generateShield(ret);
        Map<String, String> copyMap = new HashMap<>();
        copyMap.putAll(result);
        return copyMap;
    }

    public synchronized Map<String, String> getXhsHeaderWithSid(String url, String sid) {
        this.requestBody = null;
        this.method = "GET";
        Headers headers = new Headers.Builder()
                .add("xy-common-params", sid).build();
        this.result.put("xy-common-params", sid);
        this.result.put("User-Agent", "Dalvik/2.1.0 discover/7.7.0 NetType/WiFi");
        this.headers = headers;

        instance.url = url;
        generateShield(ret);
        Map<String, String> copyMap = new HashMap<>();
        copyMap.putAll(result);
        return copyMap;
    }

    public synchronized Map<String, String> getXhsHeaderForSug(String url) {
        this.requestBody = null;
        this.method = "GET";
        instance.setSugHeaders();
        instance.url = url;
        generateShield(ret);
        Map<String, String> copyMap = new HashMap<>();
        copyMap.putAll(result);
        return copyMap;
    }

    public static void main(String[] args) {
//        XhsShieldGenerator instance = getInstance();
//        long startTime = System.currentTimeMillis();
//        System.out.println("startTime is: " + startTime);
//        for (int i = 0; i< 1; i++) {
//            Map result = instance.getXhsHeader("https://edith.xiaohongshu.com/api/sns/v6/homefeed?oid=homefeed_recommend&cursor_score=&geo=eyJsYXRpdHVkZSI6MC4wMDAwMDAsImxvbmdpdHVkZSI6MC4wMDAwMDB9%0A&trace_id=b44ec53d-bf46-3a85-a518-8ff1ffab6c23&note_index=0&refresh_type=2&client_volume=0.07&preview_ad=&loaded_ad=%7B%22ads_id_list%22%3A%5B%226602047%22%5D%7D&personalization=1&pin_note_id=&pin_note_source=&unread_begin_note_id=&unread_end_note_id=&unread_note_count=0");
//            System.out.println(result);
//        }
//        long endTime = System.currentTimeMillis();
//        System.out.println("totalTime is: " + (endTime - startTime));

        try {
            String sid = "sid=session.";
//            String url = "https://edith.xiaohongshu.com/api/sns/v6/homefeed?oid=homefeed_recommend";
            String url = "https://edith.xiaohongshu.com/api/sns/v5/note/comment/list?note_id=610ff143000000000102e972&start=&num=15&show_priority_sub_comments=0&source=explore&top_comment_id=";

//            String url = "https://edith.xiaohongshu.com/api/sns/v1/note/feed?note_id=611369ff000000000102644c&page=1&has_ads_tag=false&num=5&fetch_mode=1&source=explore&ads_track_id=itemcf_PAGETIME10_610939af000000000102b517%40290savhsmja0gufbq8tsl";

            Request.Builder builder = new Request.Builder();
            Map<String, String> xhsHeader = getInstance().getXhsHeaderWithSid(url, sid);
            for (Map.Entry<String, String> entry : xhsHeader.entrySet()) {
                builder.addHeader(entry.getKey(), entry.getValue());
            }
            System.out.println("xhs headers " + xhsHeader);

            Request request = builder
                    .url(url)
                    .method("GET", null)
                    .build();
            OkHttpClient client = new OkHttpClient().newBuilder().build();

            Response response = client.newCall(request).execute();
            JSONObject bodyJson = JSONObject.parseObject(Objects.requireNonNull(response.body()).string());
            System.out.println(bodyJson);

        } catch (Exception e) {
            System.out.println("check sid error" + e);
        }

    }


}