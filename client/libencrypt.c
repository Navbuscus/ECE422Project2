#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include "Encryption.h"
void encryption (int *v, int *k);
JNIEXPORT jintArray JNICALL Java_Encryption_encrypt(JNIEnv *env, jobject obj, jintArray v, jintArray k){

  jboolean *copyA=0;
  int* value = (*env)->GetIntArrayElements(env,v,copyA);
  int* key = (*env)->GetIntArrayElements(env,k,0); 
  jsize size = (*env)->GetArrayLength(env,v);
  jintArray result = (*env)->NewIntArray(env, size);

  if(value==NULL){
    printf("Encrypt Error: Cannot obtain array from JVM\n");
    exit(0);
  }
  encryption(value,key);
  (*env)->SetIntArrayRegion(env,result,0,size,value);
  (*env)->ReleaseIntArrayElements(env,v,value,0);

  return result;

}
void encryption (int *v, int *k){
/* TEA encryption algorithm */
unsigned int y = v[0], z=v[1], sum = 0;
unsigned int delta = 0x9e3779b9, n=32;

	while (n-- > 0){
		sum += delta;
		y += (z<<4) + k[0] ^ z + sum ^ (z>>5) + k[1];
		z += (y<<4) + k[2] ^ y + sum ^ (y>>5) + k[3];
	}

	v[0] = y;
	v[1] = z;
}
