package io.github.xihan123.dex2c.core;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.*;
import org.objectweb.asm.tree.*;
import java.io.*;
import java.util.*;
import static org.objectweb.asm.Opcodes.*;
import static io.github.xihan123.dex2c.core.NativeText.*;
import static io.github.xihan123.dex2c.core.Transformer.json;

/** Extract literals after method conversion, before emitting the rebuilt constant pools. */
final class StringProtection {
    static final String TEMPLATE = "io/github/xihan123/dex2c/runtime/StringRuntime";
    final String owner, getter, decoder, symbol;
    final LinkedHashMap<String,Integer> strings = new LinkedHashMap<>();
    private final List<String> sites = new ArrayList<>(), residuals = new ArrayList<>();
    private final String library;
    private final Set<String> includes, excludes;

    StringProtection(String library, Set<String> includes, Set<String> excludes) {
        this.library = library;
        this.includes = packages(includes);
        this.excludes = packages(excludes);
        owner = "io/github/xihan123/" + new MethodKey(library,"strings-runtime","()V").bridge();
        getter = new MethodKey(library,"strings-get","()V").bridge();
        decoder = new MethodKey(library,"strings-decode","()V").bridge();
        symbol = new MethodKey(library,"strings-native","()V").symbol();
    }

    static Set<String> packages(Set<String> names) {
        Set<String> result = new TreeSet<>();
        for (String name : names) {
            if (!name.matches("[\\p{javaJavaIdentifierStart}][\\p{javaJavaIdentifierPart}]*(\\.[\\p{javaJavaIdentifierStart}][\\p{javaJavaIdentifierPart}]*)*"))
                throw new IllegalArgumentException("strings: invalid package: " + name);
            result.add(name.replace('.', '/') + "/");
        }
        return result;
    }

    void extract(Map<String,ClassNode> classes, Set<String> changed, Set<MethodKey> converted) {
        for (ClassNode cls : classes.values()) {
            if (cls.name.equals(TEMPLATE) || cls.name.equals(RuntimeLayout.TEMPLATE) || cls.name.startsWith(RuntimeLayout.TEMPLATE+"$")) continue;
            if (includes.stream().noneMatch(cls.name::startsWith)) continue;
            if (excludes.stream().anyMatch(cls.name::startsWith)) {
                residuals.add("{\"owner\":"+json(cls.name)+",\"reason\":\"excluded-package\"}");
                continue;
            }
            for (FieldNode field : cls.fields) if (field.value instanceof String)
                residuals.add("{\"owner\":"+json(cls.name)+",\"field\":"+json(field.name)+",\"reason\":\"ConstantValue\"}");
            residuals.add("{\"owner\":"+json(cls.name)+",\"reason\":\"annotations-metadata-and-structural-names-preserved\"}");
            for (MethodNode method : cls.methods) {
                MethodKey key = new MethodKey(cls.name,method.name,method.desc);
                if (converted.contains(key) || (method.access & (ACC_NATIVE|ACC_ABSTRACT)) != 0) continue;
                for (AbstractInsnNode instruction : method.instructions.toArray()) {
                    if (instruction instanceof InvokeDynamicInsnNode indy) {
                        if (indy.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) {
                            method.instructions.insertBefore(indy,DynamicCalls.concat(method,indy,key));
                            method.instructions.remove(indy);
                            changed.add(cls.name);
                        } else if (!indy.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory")
                                || !(indy.bsm.getName().equals("metafactory") || indy.bsm.getName().equals("altMetafactory"))
                                || Arrays.stream(indy.bsmArgs).anyMatch(a -> a instanceof String || a instanceof ConstantDynamic))
                            throw Selector.error(key,"strings: unsupported invokedynamic bootstrap " + indy.bsm.getOwner());
                    } else if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof ConstantDynamic)
                        throw Selector.error(key,"strings: unsupported dynamic constant");
                }
                int ordinal = 0;
                for (AbstractInsnNode instruction : method.instructions.toArray()) {
                    if (instruction.getOpcode() < 0) continue;
                    if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                        int id = strings.computeIfAbsent(value,s -> strings.size());
                        InsnList code = new InsnList();
                        code.add(new LdcInsnNode(id));
                        code.add(new MethodInsnNode(INVOKESTATIC,owner,getter,"(I)Ljava/lang/String;",false));
                        method.instructions.insertBefore(instruction,code);
                        method.instructions.remove(instruction);
                        sites.add("{\"method\":"+json(key.toString())+",\"instruction\":"+ordinal+",\"index\":"+id+"}");
                        changed.add(cls.name);
                    }
                    ordinal++;
                }
            }
        }
    }

    void install(Map<String,ClassNode> classes, Set<String> changed, Set<String> keep) throws IOException {
        if (strings.isEmpty()) return;
        if (classes.containsKey(owner)) throw new IllegalArgumentException("strings: runtime class collision: " + owner);
        Remapper remapper = new Remapper(ASM9) {
            @Override public String map(String type) { return type.equals(TEMPLATE) ? owner : type; }
            @Override public String mapMethodName(String type,String name,String desc) {
                if (!type.equals(TEMPLATE)) return name;
                return name.equals("get") ? getter : name.equals("decode") ? decoder : name;
            }
        };
        ClassNode node = new ClassNode();
        try (InputStream input = Objects.requireNonNull(StringProtection.class.getResourceAsStream("/"+TEMPLATE+".class"))) {
            new ClassReader(input).accept(new ClassRemapper(node,remapper),ClassReader.SKIP_DEBUG);
        }
        for (MethodNode method : node.methods) {
            if (!method.name.equals("size") && !method.name.equals("library")) continue;
            method.instructions.clear();
            method.instructions.add(new LdcInsnNode(method.name.equals("size") ? strings.size() : library));
            method.instructions.add(new InsnNode(method.name.equals("size") ? IRETURN : ARETURN));
        }
        classes.remove(TEMPLATE);
        classes.put(owner,node);changed.add(owner);
        keep.add("-keep class "+owner.replace('/','.')+" { *; }");
    }

    String source() {
        if (strings.isEmpty()) return "";
        StringBuilder out = new StringBuilder("\nextern \"C\" jobject "+symbol+"(JNIEnv* env,jclass,jint index) {\n switch(index) {\n");
        for (var entry : strings.entrySet()) {
            String value = entry.getKey();
            // A nonzero sentinel also gives empty/all-NUL strings a CSE-eligible constant array.
            String record="ndkp_string_"+entry.getValue();
            out.append("case ").append(entry.getValue()).append(": { static const jchar ").append(record).append("[]={");
            for (int i=0;i<value.length();i++) out.append((int)value.charAt(i)).append(',');
            out.append("1}; return env->NewString(").append(record).append(',').append(value.length()).append("); }\n");
        }
        return out.append("default: { jclass e=env->FindClass(\"java/lang/IndexOutOfBoundsException\"); if(e){env->ThrowNew(e,\"Invalid string index\");env->DeleteLocalRef(e);} return nullptr; }\n}}\n").toString();
    }

    String registration() {
        if (strings.isEmpty()) return "";
        return "\nextern \"C\" jobject "+symbol+"(JNIEnv*,jclass,jint);\n"
            +"static jint register_strings(JNIEnv* env) {\njclass cls=env->FindClass("+quote(owner)+");if(!cls)return JNI_ERR;\n"
            +"const JNINativeMethod methods[]={{(char*)"+quote(decoder)+",(char*)\"(I)Ljava/lang/String;\",(void*)&"+symbol+"}};\n"
            +"jint result=env->RegisterNatives(cls,methods,1);env->DeleteLocalRef(cls);return result;\n}\n";
    }

    String report() {
        return "{\"schemaVersion\":1,\"uniqueStrings\":"+strings.size()+",\"occurrences\":"+sites.size()
            +",\"runtime\":"+json(owner)+",\"getter\":"+json(getter)+",\"decoder\":"+json(decoder)
            +",\"symbol\":"+json(symbol)+",\"includes\":["+String.join(",",includes.stream().map(Transformer::json).toList())
            +"],\"excludes\":["+String.join(",",excludes.stream().map(Transformer::json).toList())
            +"],\"sites\":["+String.join(",",sites)+"],\"residuals\":["+String.join(",",residuals)
            +"],\"boundaries\":[\"resources\",\"outside-selected-packages-including-inlined-copies\",\"debug-attributes\"]}";
    }
}
