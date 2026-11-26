#ifndef WONHEE_JNI_BRIDGE_H
#define WONHEE_JNI_BRIDGE_H
#include <jni.h>
#include <stdint.h>

uint64_t WNCreateTestSession(char *name);
int WNCloseSession(uint64_t handle);
int wn_set_service(JNIEnv *env, jobject service);
int wn_clear_service(JNIEnv *env, jobject service);
int wn_has_service(void);
int wn_protect_socket(int fd);
void wn_protection_stats(uint64_t *success, uint64_t *failed);
#endif
