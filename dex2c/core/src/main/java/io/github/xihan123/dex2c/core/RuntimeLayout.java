package io.github.xihan123.dex2c.core;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.*;
import org.objectweb.asm.tree.*;
import java.io.*;
import java.util.*;

/** Stable artifact-local names; the full method identities remain in the build report. */
final class RuntimeLayout {
    static final String TEMPLATE="io/github/xihan123/dex2c/runtime/Dex2cRuntime";
    static final String ENSURE_DESC="(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;)V";
    final String owner;
    private final String library;

    RuntimeLayout(String library,String packageOwner) {
        this.library=library;
        owner=packageOwner.substring(0,packageOwner.lastIndexOf('/')+1)+name("runtime");
    }
    String name(String role) {return new MethodKey(library,role,"()V").bridge();}
    String ensure() {return owner+"."+name("ensureRegistered")+ENSURE_DESC;}
    static String resolver(String owner) {return new MethodKey(owner,"type","(I)Ljava/lang/Class;").bridge();}

    void install(Map<String,ClassNode> classes,Set<String> changed,Set<String> keep) throws IOException {
        Map<String,String> names=Map.of(TEMPLATE,owner,TEMPLATE+"$Binding",owner+"$"+name("binding"));
        Remapper remapper=new Remapper(Opcodes.ASM9) {
            @Override public String map(String internalName) {return names.getOrDefault(internalName,internalName);}
            @Override public String mapMethodName(String type,String method,String descriptor) {
                return type.equals(TEMPLATE)&&!method.startsWith("<")?name(method):method;
            }
        };
        for(var entry:names.entrySet()) {
            if(classes.containsKey(entry.getValue()))throw new IllegalArgumentException("dex2c: runtime class collision: "+entry.getValue());
            ClassNode node=new ClassNode();
            try(InputStream input=Objects.requireNonNull(RuntimeLayout.class.getResourceAsStream("/"+entry.getKey()+".class"))) {
                new ClassReader(input).accept(new ClassRemapper(node,remapper),ClassReader.SKIP_DEBUG);
            }
            for(MethodNode method:node.methods)for(AbstractInsnNode instruction:method.instructions)
                if(instruction instanceof LdcInsnNode ldc&&ldc.cst instanceof String text&&text.startsWith("dex2c:"))
                    ldc.cst="Native binding:"+text.substring(6);
            classes.remove(entry.getKey());classes.put(node.name,node);changed.add(node.name);
        }
        // JNI resolves these names. All remaining runtime fields and Binding may be shrunk/renamed.
        keep.add("-keep class "+owner.replace('/','.')+" { <methods>; }");
    }

    String typeIndexSource(Map<String,Integer> types) {
        // One encrypted blob avoids a decoder and relocation for every type name.
        return "\njint d2c_type_index(JNIEnv* env,jclass,jstring name) {\n"
                +"if(!name)return -1;const char* text=env->GetStringUTFChars(name,nullptr);if(!text)return -1;\n"
                +"const char* type="+String.join(" \"\\000\" ",types.keySet().stream().map(NativeText::quote).toList())+";\n"
                +"jint result=-1;for(jint i=0;i<"+types.size()+";++i){if(strcmp(text,type)==0){result=i;break;}type+=strlen(type)+1;}\n"
                +"env->ReleaseStringUTFChars(name,text);return result;\n}\n";
    }

    void appendRegistration(StringBuilder out) {
        out.append("jint d2c_type_index(JNIEnv*,jclass,jstring);\n")
            .append("extern \"C\" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm,void*) {\n")
            .append("JNIEnv* env=nullptr;if(vm->GetEnv((void**)&env,JNI_VERSION_1_6)!=JNI_OK)return JNI_ERR;\n")
            .append("jclass cls=env->FindClass(").append(NativeText.quote(owner)).append(");if(!cls)return JNI_ERR;\n")
            .append("const JNINativeMethod methods[]={{(char*)").append(NativeText.quote(name("registerClass")))
            .append(",(char*)\"(Ljava/lang/Class;)V\",(void*)&register_class},{(char*)")
            .append(NativeText.quote(name("typeIndex"))).append(",(char*)\"(Ljava/lang/String;)I\",(void*)&d2c_type_index}};\n")
            .append("jint status=env->RegisterNatives(cls,methods,2);env->DeleteLocalRef(cls);return status==0?JNI_VERSION_1_6:JNI_ERR;\n}\n");
    }
}
