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
    uint64_t handle = WNCreateTestSession((char *)value);
    (*env)->ReleaseStringUTFChars(env, name, value);
    return (jlong)handle;
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
