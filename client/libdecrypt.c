#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include "Encryption.h"
void decryption (int *v, int *k);
JNIEXPORT jintArray JNICALL Java_Encryption_decrypt(JNIEnv *env, jobject obj, jintArray v, jintArray k){

  jboolean *copyA=0;
  int* value = (*env)->GetIntArrayElements(env,v,copyA);
  int* key = (*env)->GetIntArrayElements(env,k,0);
  jsize size = (*env)->GetArrayLength(env,v);
  jintArray result = (*env)->NewIntArray(env, size);

  if(value==NULL){
    printf("Decrypt Error: Cannot obtain array from JVM\n");
    exit(0);
  }

  decryption(value, key);
  (*env)->SetIntArrayRegion(env,result,0,size,value);
  (*env)->ReleaseIntArrayElements(env,v,value,0);
  return result;
}

void decryption (int *v, int *k){
/* TEA decryption routine */
unsigned int n=32, sum, y=v[0], z=v[1];
unsigned int delta=0x9e3779b9l;

	sum = delta<<5;
	while (n-- > 0){
		z -= (y<<4) + k[2] ^ y + sum ^ (y>>5) + k[3];
		y -= (z<<4) + k[0] ^ z + sum ^ (z>>5) + k[1];
		sum -= delta;
	}
	v[0] = y;
	v[1] = z;
}
