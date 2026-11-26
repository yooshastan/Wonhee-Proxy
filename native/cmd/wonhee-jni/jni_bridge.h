#ifndef WONHEE_JNI_BRIDGE_H
#define WONHEE_JNI_BRIDGE_H
#include <jni.h>
#include <stdint.h>

int64_t WNCreateTestSession(char *name);
int64_t WNCreatePacketTestSession(char *name, char *allowed_ip);
int WNInjectPacket(uint64_t handle, char *data, int length);
int WNPacketStats(uint64_t handle, int64_t *injected, int64_t *read, int64_t *dropped);
int WNCloseSession(uint64_t handle);
int WNValidatePeerProfile(char *config);
int64_t WNCreateProbeSession(char *name,char *config,char *local,char *target,char *stream,int port);
int WNPollProbePacket(uint64_t handle,char *data,int capacity);
int WNRegisterProbePorts(uint64_t handle,int a,int b,int c,int d,int udp);
int64_t WNCreatePeerSession(char *name, char *config);
int WNPeerStats(uint64_t handle, int64_t *hs, int64_t *rx, int64_t *tx);
int wn_set_service(JNIEnv *env, jobject service);
int wn_clear_service(JNIEnv *env, jobject service);
int wn_has_service(void);
int wn_protect_socket(int fd);
void wn_protection_stats(uint64_t *success, uint64_t *failed);
#endif
