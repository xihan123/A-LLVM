#include "dex2c_runtime.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void error(JNIEnv* env, const char* name, const char* message) {
  if (env->ExceptionCheck()) return;
  jclass type = env->FindClass(name);
  if (type) { env->ThrowNew(type, message); env->DeleteLocalRef(type); }
}
static bool not_null(d2c_frame* f, jobject value) {
  if (value) return true;
  error(f->env, "java/lang/NullPointerException", "dex2c: null reference");
  return false;
}
d2c_frame* d2c_open(JNIEnv* env, jclass owner, int count) {
  if (count < 0 || count > 200000) { error(env, "java/lang/OutOfMemoryError", "dex2c frame is too large"); return nullptr; }
  if (env->PushLocalFrame(count * 2 + 32) < 0) return nullptr;
  auto* frame = static_cast<d2c_frame*>(calloc(1, sizeof(d2c_frame)));
  auto* slots = static_cast<d2c_slot*>(calloc(count ? count : 1, sizeof(d2c_slot)));
  if (!frame || !slots) {
    free(frame); free(slots);
    error(env, "java/lang/OutOfMemoryError", "dex2c frame allocation");
    env->PopLocalFrame(nullptr); return nullptr;
  }
  frame->env = env; frame->owner = owner; frame->slots = slots; frame->count = count;
  return frame;
}
jobject d2c_close(d2c_frame* f, jobject result) {
  JNIEnv* env = f->env;
  free(f->slots); free(f);
  return env->PopLocalFrame(result);
}
static void clear(d2c_frame* f, int slot) {
  if (f->slots[slot].reference) f->env->DeleteLocalRef(f->slots[slot].v.l);
  f->slots[slot] = {};
}
void d2c_ref(d2c_frame* f, int slot, jobject value) {
  clear(f, slot); f->slots[slot].reference = true; f->slots[slot].v.l = value;
}
void d2c_copy(d2c_frame* f, int to, int from) {
  if (to == from) return;
  d2c_slot value = f->slots[from];
  if (value.reference) value.v.l = f->env->NewLocalRef(value.v.l);
  clear(f, to); f->slots[to] = value;
}
#define STORE(member, type) void d2c_##member(d2c_frame* f, int slot, type value) { clear(f, slot); f->slots[slot].v.member = value; }
STORE(i, jint) STORE(j, jlong) STORE(f, jfloat) STORE(d, jdouble)
#undef STORE

jclass d2c_class(d2c_frame* f, const char* name, bool initialize) {
  JNIEnv* env = f->env;
  if (env->ExceptionCheck()) return nullptr;
  jclass cls = env->FindClass("io/github/xihan123/dex2c/runtime/Dex2cRuntime");
  if (!cls) return nullptr;
  jmethodID resolve = env->GetStaticMethodID(cls, "resolveClass", "(Ljava/lang/Class;Ljava/lang/String;Z)Ljava/lang/Class;");
  if (!resolve) {env->DeleteLocalRef(cls);return nullptr;}
  jstring text = env->NewStringUTF(name);
  jobject result = nullptr;
  if (text) { result = env->CallStaticObjectMethod(cls, resolve, f->owner, text, initialize ? JNI_TRUE : JNI_FALSE); env->ExceptionCheck(); }
  env->DeleteLocalRef(text); env->DeleteLocalRef(cls);
  return static_cast<jclass>(result);
}
static char* descriptor(JNIEnv* env,jclass owner,const char* original) {
  jclass cls=env->FindClass("io/github/xihan123/dex2c/runtime/Dex2cRuntime");
  if(!cls)return nullptr;
  jmethodID resolve=env->GetStaticMethodID(cls,"resolveDescriptor","(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;");
  if(!resolve){env->DeleteLocalRef(cls);return nullptr;}
  jstring text=env->NewStringUTF(original);
  jstring result=text?static_cast<jstring>(env->CallStaticObjectMethod(cls,resolve,owner,text)):nullptr;
  env->ExceptionCheck();env->DeleteLocalRef(text);env->DeleteLocalRef(cls);
  if(!result)return nullptr;
  const char* utf=env->GetStringUTFChars(result,nullptr);
  char* copy=nullptr;
  if(utf){copy=static_cast<char*>(malloc(strlen(utf)+1));if(copy)strcpy(copy,utf);env->ReleaseStringUTFChars(result,utf);}
  env->DeleteLocalRef(result);
  if(!copy)error(env,"java/lang/OutOfMemoryError","dex2c descriptor");
  return copy;
}
void d2c_register(JNIEnv* env,jclass owner,const JNINativeMethod* methods,int count) {
  for(int i=0;i<count;++i) {
    JNINativeMethod method=methods[i];
    char* signature=descriptor(env,owner,method.signature);if(!signature)return;
    method.signature=signature;
    int status=env->RegisterNatives(owner,&method,1);free(signature);
    if(status<0){error(env,"java/lang/UnsatisfiedLinkError","dex2c registration failed");return;}
  }
}
jobject d2c_string(d2c_frame* f, const jchar* chars, int length) {
  JNIEnv* env = f->env;
  jstring value = env->NewString(chars, length);
  if (!value) return nullptr;
  jclass cls = env->FindClass("java/lang/String");
  jmethodID intern = cls ? env->GetMethodID(cls,"intern","()Ljava/lang/String;") : nullptr;
  jobject result = intern ? env->CallObjectMethod(value, intern) : nullptr;
  env->ExceptionCheck();
  env->DeleteLocalRef(value); env->DeleteLocalRef(cls); return result;
}
void d2c_allocate(d2c_frame* f, int target, const char* name) {
  jclass cls = d2c_class(f,name,true);
  if (!cls) return;
  // ART replaces String receivers in NewObjectA; AllocObject + <init> loses that replacement.
  d2c_ref(f,target,cls);
  f->slots[target].uninitialized = ++f->allocation;
}
void d2c_new_array(d2c_frame* f, int target, int type, jint size) {
  JNIEnv* env=f->env;
  if(size<0) { error(env,"java/lang/NegativeArraySizeException","dex2c array length"); return; }
  jobject array=nullptr;
  switch(type) {
    case 4: array=env->NewBooleanArray(size); break; case 5: array=env->NewCharArray(size); break;
    case 6: array=env->NewFloatArray(size); break; case 7: array=env->NewDoubleArray(size); break;
    case 8: array=env->NewByteArray(size); break; case 9: array=env->NewShortArray(size); break;
    case 10: array=env->NewIntArray(size); break; case 11: array=env->NewLongArray(size); break;
  }
  d2c_ref(f,target,array);
}
void d2c_object_array(d2c_frame* f,int target,const char* type,jint size) {
  if(size<0) { error(f->env,"java/lang/NegativeArraySizeException","dex2c array length"); return; }
  jclass cls=d2c_class(f,type); if(!cls) return;
  jobject result=f->env->NewObjectArray(size,cls,nullptr);
  f->env->DeleteLocalRef(cls); d2c_ref(f,target,result);
}
static jobject multi(d2c_frame* f,const char* type,const jint* dimensions,int depth) {
  JNIEnv* env=f->env;
  if(type[1]!='[' && type[1]!='L') {
    int code=type[1]=='Z'?4:type[1]=='C'?5:type[1]=='F'?6:type[1]=='D'?7:type[1]=='B'?8:type[1]=='S'?9:type[1]=='I'?10:11;
    switch(code) {
      case 4:return env->NewBooleanArray(*dimensions); case 5:return env->NewCharArray(*dimensions);
      case 6:return env->NewFloatArray(*dimensions); case 7:return env->NewDoubleArray(*dimensions);
      case 8:return env->NewByteArray(*dimensions); case 9:return env->NewShortArray(*dimensions);
      case 10:return env->NewIntArray(*dimensions); default:return env->NewLongArray(*dimensions);
    }
  }
  char* component=nullptr; const char* lookup=type+1;
  if(type[1]=='L') {
    size_t length=strlen(type);
    component=static_cast<char*>(malloc(length));
    if(!component) { error(env,"java/lang/OutOfMemoryError","dex2c array type"); return nullptr; }
    memcpy(component,type+2,length-3); component[length-3]=0; lookup=component;
  }
  jclass cls=d2c_class(f,lookup); free(component); if(!cls) return nullptr;
  jobjectArray result=env->NewObjectArray(*dimensions,cls,nullptr); env->DeleteLocalRef(cls);
  if(!result) return nullptr;
  if(depth>1) for(jint i=0;i<*dimensions;++i) {
    jobject child=multi(f,type+1,dimensions+1,depth-1);
    if(env->ExceptionCheck()) { env->DeleteLocalRef(result); return nullptr; }
    env->SetObjectArrayElement(result,i,child); env->DeleteLocalRef(child);
    if(env->ExceptionCheck()) { env->DeleteLocalRef(result); return nullptr; }
  }
  return result;
}
void d2c_multi_array(d2c_frame* f,int target,const char* type,int depth) {
  jint dimensions[255];
  if(depth<1||depth>255) { error(f->env,"java/lang/VerifyError","invalid array dimensions"); return; }
  for(int i=0;i<depth;++i) {
    dimensions[i]=f->slots[target+i].v.i;
    if(dimensions[i]<0) { error(f->env,"java/lang/NegativeArraySizeException","dex2c array length"); return; }
  }
  d2c_ref(f,target,multi(f,type,dimensions,depth));
}
jint d2c_array_length(d2c_frame* f,jobject array) { return not_null(f,array)?f->env->GetArrayLength(static_cast<jarray>(array)):0; }
static bool bounds(d2c_frame* f,jobject array,jint index) {
  if(!not_null(f,array)) return false;
  jint length=f->env->GetArrayLength(static_cast<jarray>(array));
  if(index>=0&&index<length) return true;
  error(f->env,"java/lang/ArrayIndexOutOfBoundsException","dex2c array index"); return false;
}
static bool boolean_array(JNIEnv* env,jobject array) {
  jclass cls=env->FindClass("[Z"); if(!cls) return false;
  bool result=env->IsInstanceOf(array,cls); env->DeleteLocalRef(cls); return result;
}
void d2c_array_load(d2c_frame* f,int target,int kind) {
  JNIEnv* env=f->env; jobject array=f->slots[target].v.l; jint index=f->slots[target+1].v.i;
  if(!bounds(f,array,index)) return;
  if(kind==4) { d2c_ref(f,target,env->GetObjectArrayElement(static_cast<jobjectArray>(array),index)); return; }
  jvalue value={};
  switch(kind) {
    case 0:env->GetIntArrayRegion(static_cast<jintArray>(array),index,1,&value.i);d2c_i(f,target,value.i);break;
    case 1:env->GetLongArrayRegion(static_cast<jlongArray>(array),index,1,&value.j);d2c_j(f,target,value.j);break;
    case 2:env->GetFloatArrayRegion(static_cast<jfloatArray>(array),index,1,&value.f);d2c_f(f,target,value.f);break;
    case 3:env->GetDoubleArrayRegion(static_cast<jdoubleArray>(array),index,1,&value.d);d2c_d(f,target,value.d);break;
    case 5:
      if(boolean_array(env,array)) {env->GetBooleanArrayRegion(static_cast<jbooleanArray>(array),index,1,&value.z);d2c_i(f,target,value.z);}
      else {env->GetByteArrayRegion(static_cast<jbyteArray>(array),index,1,&value.b);d2c_i(f,target,value.b);}break;
    case 6:env->GetCharArrayRegion(static_cast<jcharArray>(array),index,1,&value.c);d2c_i(f,target,value.c);break;
    case 7:env->GetShortArrayRegion(static_cast<jshortArray>(array),index,1,&value.s);d2c_i(f,target,value.s);break;
  }
}
void d2c_array_store(d2c_frame* f,int target,int kind) {
  JNIEnv* env=f->env; jobject array=f->slots[target].v.l; jint index=f->slots[target+1].v.i; jvalue value=f->slots[target+2].v;
  if(!bounds(f,array,index)) return;
  switch(kind) {
    case 0:env->SetIntArrayRegion(static_cast<jintArray>(array),index,1,&value.i);break;
    case 1:env->SetLongArrayRegion(static_cast<jlongArray>(array),index,1,&value.j);break;
    case 2:env->SetFloatArrayRegion(static_cast<jfloatArray>(array),index,1,&value.f);break;
    case 3:env->SetDoubleArrayRegion(static_cast<jdoubleArray>(array),index,1,&value.d);break;
    case 4:env->SetObjectArrayElement(static_cast<jobjectArray>(array),index,value.l);break;
    case 5:
      if(boolean_array(env,array)) {jboolean x=value.i&1;env->SetBooleanArrayRegion(static_cast<jbooleanArray>(array),index,1,&x);}
      else {jbyte x=static_cast<jbyte>(value.i);env->SetByteArrayRegion(static_cast<jbyteArray>(array),index,1,&x);}break;
    case 6:{jchar x=static_cast<jchar>(value.i);env->SetCharArrayRegion(static_cast<jcharArray>(array),index,1,&x);break;}
    case 7:{jshort x=static_cast<jshort>(value.i);env->SetShortArrayRegion(static_cast<jshortArray>(array),index,1,&x);break;}
  }
}

void d2c_field(d2c_frame* f,int target,const char* owner,const char* name,const char* desc,bool isStatic,bool write) {
  JNIEnv* env=f->env;
  jobject receiver=isStatic?nullptr:f->slots[target].v.l;
  if(!isStatic&&!not_null(f,receiver)) return;
  jclass cls=d2c_class(f,owner); if(!cls) return;
  char* actual=descriptor(env,f->owner,desc);
  if(!actual){env->DeleteLocalRef(cls);return;}
  jfieldID field=isStatic?env->GetStaticFieldID(cls,name,actual):env->GetFieldID(cls,name,actual);free(actual);
  if(!field) {env->DeleteLocalRef(cls);return;}
  jvalue value=f->slots[target+(isStatic?0:1)].v;
#define FIELD(code,Name,member,stored,Type) case code: \
  if(write) {if(isStatic)env->SetStatic##Name##Field(cls,field,static_cast<Type>(value.stored));else env->Set##Name##Field(receiver,field,static_cast<Type>(value.stored));} \
  else {Type result=isStatic?env->GetStatic##Name##Field(cls,field):env->Get##Name##Field(receiver,field);d2c_##stored(f,target,result);} break
  switch(*desc) {
    FIELD('Z',Boolean,z,i,jboolean); FIELD('B',Byte,b,i,jbyte); FIELD('C',Char,c,i,jchar); FIELD('S',Short,s,i,jshort);
    FIELD('I',Int,i,i,jint); FIELD('J',Long,j,j,jlong); FIELD('F',Float,f,f,jfloat); FIELD('D',Double,d,d,jdouble);
    default:
      if(write) {if(isStatic)env->SetStaticObjectField(cls,field,value.l);else env->SetObjectField(receiver,field,value.l);}
      else d2c_ref(f,target,isStatic?env->GetStaticObjectField(cls,field):env->GetObjectField(receiver,field));break;
  }
#undef FIELD
  env->DeleteLocalRef(cls);
}

void d2c_invoke(d2c_frame* f,int target,const char* owner,const char* name,const char* desc,int kind,int count) {
  JNIEnv* env=f->env; jobject receiver=kind?f->slots[target].v.l:nullptr;
  bool constructor=kind==2 && strcmp(name,"<init>")==0;
  if(kind&&!not_null(f,receiver)) return;
  jclass cls=d2c_class(f,owner); if(!cls) return;
  char* actual=descriptor(env,f->owner,desc);
  if(!actual){env->DeleteLocalRef(cls);return;}
  jmethodID method=kind?env->GetMethodID(cls,name,actual):env->GetStaticMethodID(cls,name,actual);free(actual);
  if(!method) {env->DeleteLocalRef(cls);return;}
  auto* args=static_cast<jvalue*>(calloc(count?count:1,sizeof(jvalue)));
  if(!args) {env->DeleteLocalRef(cls);error(env,"java/lang/OutOfMemoryError","dex2c arguments");return;}
  const char* type=desc+1;
  for(int i=0;i<count;++i) {
    jvalue source=f->slots[target+(kind?1:0)+i].v;
    switch(*type) {
      case 'Z':args[i].z=source.i;break;case 'B':args[i].b=source.i;break;
      case 'C':args[i].c=source.i;break;case 'S':args[i].s=source.i;break;
      case 'I':args[i].i=source.i;break;case 'J':args[i].j=source.j;break;
      case 'F':args[i].f=source.f;break;case 'D':args[i].d=source.d;break;
      default:args[i].l=source.l;break;
    }
    while(*type=='[')++type;
    if(*type=='L')while(*type!=';')++type;
    ++type;
  }
  char result=type[1];
  if(constructor) {
    uint64_t token=f->slots[target].uninitialized;
    if(!token) {free(args);env->DeleteLocalRef(cls);error(env,"java/lang/VerifyError","constructor receiver is already initialized");return;}
    jobject value=env->NewObjectA(static_cast<jclass>(receiver),method,args);
    if(!env->ExceptionCheck()) {
      for(int i=0;i<f->count;++i) if(f->slots[i].uninitialized==token) {
        jobject alias=env->NewLocalRef(value);
        if(env->ExceptionCheck()) break;
        d2c_ref(f,i,alias);
      }
    }
    env->DeleteLocalRef(value);free(args);env->DeleteLocalRef(cls);return;
  }
#define CALL(code,Name,stored,Type) case code: { Type value=kind==0?env->CallStatic##Name##MethodA(cls,method,args):kind==2?env->CallNonvirtual##Name##MethodA(receiver,cls,method,args):env->Call##Name##MethodA(receiver,method,args); env->ExceptionCheck(); d2c_##stored(f,target,value); break; }
  switch(result) {
    CALL('Z',Boolean,i,jboolean) CALL('B',Byte,i,jbyte) CALL('C',Char,i,jchar) CALL('S',Short,i,jshort)
    CALL('I',Int,i,jint) CALL('J',Long,j,jlong) CALL('F',Float,f,jfloat) CALL('D',Double,d,jdouble)
    case 'V':
      if(kind==0)env->CallStaticVoidMethodA(cls,method,args);
      else if(kind==2)env->CallNonvirtualVoidMethodA(receiver,cls,method,args);
      else env->CallVoidMethodA(receiver,method,args);env->ExceptionCheck();break;
    default: {
      jobject value=kind==0?env->CallStaticObjectMethodA(cls,method,args):kind==2?env->CallNonvirtualObjectMethodA(receiver,cls,method,args):env->CallObjectMethodA(receiver,method,args);
      env->ExceptionCheck(); d2c_ref(f,target,value);break;
    }
  }
#undef CALL
  free(args);env->DeleteLocalRef(cls);
}
jint d2c_instance(d2c_frame* f,jobject object,const char* type) {
  jclass cls=d2c_class(f,type);if(!cls)return 0;
  jint result=object&&f->env->IsInstanceOf(object,cls);
  f->env->DeleteLocalRef(cls);return result;
}
void d2c_cast(d2c_frame* f,int target,const char* type) {
  jobject object=f->slots[target].v.l;
  if(object&&!d2c_instance(f,object,type)) error(f->env,"java/lang/ClassCastException",type);
}
void d2c_throw(d2c_frame* f,jobject throwable) {
  if(not_null(f,throwable)) f->env->Throw(static_cast<jthrowable>(throwable));
}
void d2c_monitor(d2c_frame* f,jobject object,bool enter) {
  if(!not_null(f,object))return;
  if(enter)f->env->MonitorEnter(object);else f->env->MonitorExit(object);
}
bool d2c_catch(d2c_frame* f,const char* type,int slot) {
  JNIEnv* env=f->env;
  jthrowable pending=env->ExceptionOccurred();if(!pending)return false;
  env->ExceptionClear();
  bool matches=!type||d2c_instance(f,pending,type);
  if(env->ExceptionCheck()) {env->DeleteLocalRef(pending);return false;}
  if(matches) {d2c_ref(f,slot,pending);return true;}
  env->Throw(pending);env->DeleteLocalRef(pending);return false;
}
jint d2c_idiv(d2c_frame* f,jint a,jint b,bool remainder) {
  if(!b) {error(f->env,"java/lang/ArithmeticException","/ by zero");return 0;}
  if(a==INT32_MIN&&b==-1)return remainder?0:a;
  return remainder?a%b:a/b;
}
jlong d2c_jdiv(d2c_frame* f,jlong a,jlong b,bool remainder) {
  if(!b) {error(f->env,"java/lang/ArithmeticException","/ by zero");return 0;}
  if(a==INT64_MIN&&b==-1)return remainder?0:a;
  return remainder?a%b:a/b;
}
jint d2c_to_i(double x) {if(isnan(x))return 0;if(x>=INT32_MAX)return INT32_MAX;if(x<=INT32_MIN)return INT32_MIN;return static_cast<jint>(x);}
jlong d2c_to_j(double x) {if(isnan(x))return 0;if(x>=0x1p63)return INT64_MAX;if(x<=-0x1p63)return INT64_MIN;return static_cast<jlong>(x);}
jfloat d2c_float(uint32_t bits) {jfloat value;memcpy(&value,&bits,sizeof(value));return value;}
jdouble d2c_double(uint64_t bits) {jdouble value;memcpy(&value,&bits,sizeof(value));return value;}
