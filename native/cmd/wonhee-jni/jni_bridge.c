//go:build android && cgo
#include "jni_bridge.h"
#include <pthread.h>
#include <stddef.h>

static JavaVM *g_vm = NULL;
static jobject g_service = NULL;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_protected = 0;
static uint64_t g_failed = 0;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    return JNI_VERSION_1_6;
}

int wn_set_service(JNIEnv *env, jobject service) {
    if (env == NULL || service == NULL) return 0;
    jobject global = (*env)->NewGlobalRef(env, service);
    if (global == NULL) return 0;
    pthread_mutex_lock(&g_lock);
    jobject old = g_service;
    g_service = global;
    g_protected = 0;
    g_failed = 0;
    pthread_mutex_unlock(&g_lock);
    if (old != NULL) (*env)->DeleteGlobalRef(env, old);
    return 1;
}

int wn_clear_service(JNIEnv *env, jobject service) {
    if (env == NULL) return 0;
    pthread_mutex_lock(&g_lock);
    jobject old = NULL;
    if (g_service != NULL && (service == NULL || (*env)->IsSameObject(env, g_service, service))) {
        old = g_service;
        g_service = NULL;
    }
    pthread_mutex_unlock(&g_lock);
    if (old != NULL) (*env)->DeleteGlobalRef(env, old);
    return 1;
}

int wn_has_service(void) {
    pthread_mutex_lock(&g_lock);
    int present = g_service != NULL;
    pthread_mutex_unlock(&g_lock);
    return present;
}

static JNIEnv *wn_thread_env(int *attached) {
    if (g_vm == NULL) return NULL;
    JNIEnv *env = NULL;
    jint result = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
    if (result == JNI_OK) {
        *attached = 0;
        return env;
    }
    if (result != JNI_EDETACHED) return NULL;
    if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return NULL;
    *attached = 1;
    return env;
}

int wn_protect_socket(int fd) {
    int attached = 0;
    JNIEnv *env = wn_thread_env(&attached);
    if (env == NULL) return 0;
    int protected = 0;
    pthread_mutex_lock(&g_lock);
    if (g_service != NULL) {
        jclass cls = (*env)->GetObjectClass(env, g_service);
        jmethodID method = cls == NULL ? NULL
                : (*env)->GetMethodID(env, cls, "protect", "(I)Z");
        if (method != NULL) {
            jboolean result = (*env)->CallBooleanMethod(env, g_service, method, (jint)fd);
            if (!(*env)->ExceptionCheck(env) && result == JNI_TRUE) protected = 1;
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        if (cls != NULL) (*env)->DeleteLocalRef(env, cls);
    }
    if (protected) g_protected++;
    else g_failed++;
    pthread_mutex_unlock(&g_lock);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
    return protected;
}

void wn_protection_stats(uint64_t *success, uint64_t *failed) {
    pthread_mutex_lock(&g_lock);
    if (success != NULL) *success = g_protected;
    if (failed != NULL) *failed = g_failed;
    pthread_mutex_unlock(&g_lock);
}

JNIEXPORT jboolean JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeSetVpnService(
        JNIEnv *env, jclass type, jobject service) {
    (void)type;
    return wn_set_service(env, service) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeClearVpnService(
        JNIEnv *env, jclass type, jobject service) {
    (void)type;
    return wn_clear_service(env, service) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeCreateTestSession(
        JNIEnv *env, jclass type, jstring name) {
    (void)type;
    if (name == NULL) return 0;
    const char *value = (*env)->GetStringUTFChars(env, name, NULL);
    if (value == NULL) return 0;
    int64_t handle = WNCreateTestSession((char *)value);
    (*env)->ReleaseStringUTFChars(env, name, value);
    return (jlong)handle;
}

JNIEXPORT jlong JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeCreatePacketTestSession(
        JNIEnv *env, jclass type, jstring name, jstring allowed_ip) {
    (void)type;
    if (name == NULL || allowed_ip == NULL) return 0;
    const char *name_value = (*env)->GetStringUTFChars(env, name, NULL);
    if (name_value == NULL) return 0;
    const char *route_value = (*env)->GetStringUTFChars(env, allowed_ip, NULL);
    if (route_value == NULL) {
        (*env)->ReleaseStringUTFChars(env, name, name_value);
        return 0;
    }
    int64_t handle = WNCreatePacketTestSession((char *)name_value, (char *)route_value);
    (*env)->ReleaseStringUTFChars(env, allowed_ip, route_value);
    (*env)->ReleaseStringUTFChars(env, name, name_value);
    return (jlong)handle;
}

JNIEXPORT jint JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeInjectPacket(
        JNIEnv *env, jclass type, jlong handle, jbyteArray packet) {
    (void)type;
    if (packet == NULL) return -1;
    jsize length = (*env)->GetArrayLength(env, packet);
    if (length < 20 || length > 1280) return -1;
    jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
    if (bytes == NULL) return -1;
    int result = WNInjectPacket((uint64_t)handle, (char *)bytes, (int)length);
    (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
    return (jint)result;
}

JNIEXPORT jlongArray JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativePacketStats(
        JNIEnv *env, jclass type, jlong handle) {
    (void)type;
    int64_t injected = -1, read_count = -1, dropped = -1;
    int ok = WNPacketStats((uint64_t)handle, &injected, &read_count, &dropped);
    if (!ok) injected = read_count = dropped = -1;
    jlong values[3] = {(jlong)injected, (jlong)read_count, (jlong)dropped};
    jlongArray result = (*env)->NewLongArray(env, 3);
    if (result != NULL) (*env)->SetLongArrayRegion(env, result, 0, 3, values);
    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeCloseSession(
        JNIEnv *env, jclass type, jlong handle) {
    (void)env; (void)type;
    return WNCloseSession((uint64_t)handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlongArray JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeProtectionStats(
        JNIEnv *env, jclass type) {
    (void)type;
    uint64_t success = 0, failed = 0;
    wn_protection_stats(&success, &failed);
    jlong values[2] = {(jlong)success, (jlong)failed};
    jlongArray result = (*env)->NewLongArray(env, 2);
    if (result != NULL) (*env)->SetLongArrayRegion(env, result, 0, 2, values);
    return result;
}

JNIEXPORT jint JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeValidatePeerProfile(
 JNIEnv *env, jclass type, jstring config) {
 (void)type;
 if (config==NULL) return 2;
 const char *value=(*env)->GetStringUTFChars(env,config,NULL);
 if (value==NULL) return 2;
 int result=WNValidatePeerProfile((char *)value);
 (*env)->ReleaseStringUTFChars(env,config,value);
 return (jint)result;
}
JNIEXPORT jlong JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativeCreatePeerSession(
 JNIEnv *env,jclass type,jstring name,jstring config) {
 (void)type;
 if (name==NULL || config==NULL) return -1;
 const char *n=(*env)->GetStringUTFChars(env,name,NULL);
 if (n==NULL) return -1;
 const char *v=(*env)->GetStringUTFChars(env,config,NULL);
 if (v==NULL) {(*env)->ReleaseStringUTFChars(env,name,n);return -1;}
 int64_t h=WNCreatePeerSession((char *)n,(char *)v);
 (*env)->ReleaseStringUTFChars(env,config,v);
 (*env)->ReleaseStringUTFChars(env,name,n);
 return (jlong)h;
}
JNIEXPORT jlongArray JNICALL
Java_com_yooshastan_wonheeproxy_RootlessNativeBridge_nativePeerStats(
 JNIEnv *env,jclass type,jlong handle) {
 (void)type;
 int64_t hs=0,rx=0,tx=0;
 if (!WNPeerStats((uint64_t)handle,&hs,&rx,&tx)) hs=rx=tx=-1;
 jlong values[3]={(jlong)hs,(jlong)rx,(jlong)tx};
 jlongArray a=(*env)->NewLongArray(env,3);
 if(a!=NULL) (*env)->SetLongArrayRegion(env,a,0,3,values);
 return a;
}
