package io.github.xihan123.dex2c.core;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import static org.objectweb.asm.Opcodes.*;
import static io.github.xihan123.dex2c.core.NativeText.*;

public final class Transformer {
    public record Result(List<MethodKey> methods, Path classes, Path nativeSource, Path registration, Path rules, Path report) {}

    public Result transform(List<Path> inputs,Path output,String library) throws IOException {
        return transform(inputs,output,library,Set.of());
    }

    public Result transform(List<Path> inputs,Path output,String library,Set<String> inheritedMethods) throws IOException {
        if(!library.matches("[A-Za-z][A-Za-z0-9_]*"))throw new IllegalArgumentException("dex2c: invalid library name");
        SortedMap<String,ClassNode> classes=new TreeMap<>();Map<String,byte[]> original=new TreeMap<>();
        for(Path input:inputs) {
            if(Files.isDirectory(input)) {
                try(var paths=Files.walk(input)) {
                    for(Path file:paths.filter(p->p.toString().endsWith(".class")).sorted().toList())add(Files.readAllBytes(file),classes,original);
                }
            } else try(JarFile jar=new JarFile(input.toFile())) {
                for(JarEntry entry:jar.stream().filter(e->e.getName().endsWith(".class")&&!e.getName().startsWith("META-INF/versions/")).sorted(Comparator.comparing(JarEntry::getName)).toList())
                    try(InputStream stream=jar.getInputStream(entry)){add(stream.readAllBytes(),classes,original);}
            }
        }
        Selector selector=new Selector(classes);selector.run(inheritedMethods);
        RuntimeLayout runtime=new RuntimeLayout(library,selector.selected.isEmpty()?"Runtime":selector.selected.firstKey().owner());
        Set<String> changed=new HashSet<>(),keep=new TreeSet<>(),ids=new HashSet<>();
        Map<String,Set<String>> resolverTypes=new TreeMap<>();
        StringBuilder cpp=new StringBuilder("#include \"dex2c_runtime.h\"\n");
        StringBuilder nativeCpp=new StringBuilder("#include \"dex2c_runtime.h\"\n");
        StringBuilder registration=new StringBuilder("#include \"dex2c_runtime.h\"\n#include <string.h>\n");
        SortedMap<String,List<String>> registrations=new TreeMap<>();
        Map<String,ClassNode> interfaceBridges=new HashMap<>();
        SortedMap<MethodKey,MethodKey> bridges=new TreeMap<>();
        for(MethodKey key:selector.selected.keySet()) {
            if(!ids.add(key.id()))throw Selector.error(key,"method identifier collision");
            ClassNode owner=classes.get(key.owner());MethodNode method=selector.method(key);
            ClassNode bridgeOwner=owner;
            if((owner.access&ACC_INTERFACE)!=0) {
                bridgeOwner=interfaceBridges.get(owner.name);
                if(bridgeOwner==null) {
                    String name=owner.name+"$"+new MethodKey(owner.name,"interface","()V").bridge();
                    if(classes.containsKey(name))throw Selector.error(key,"interface bridge class collision");
                    bridgeOwner=new ClassNode();
                    bridgeOwner.visit(owner.version,ACC_FINAL|ACC_SYNTHETIC,name,null,"java/lang/Object",null);
                    interfaceBridges.put(owner.name,bridgeOwner);classes.put(name,bridgeOwner);changed.add(name);
                }
            }
            DynamicCalls.lower(owner,method,key);
            (selector.policies.get(key)==Selector.Policy.NATIVE_TREE?nativeCpp:cpp)
                    .append(new CppEmitter(key,method,keep,resolverTypes.computeIfAbsent(bridgeOwner.name,n->new TreeSet<>())).emit());
            registration.append("extern \"C\" ").append(ctype(Type.getReturnType(method.desc))).append(' ').append(key.symbol())
                    .append('(').append(CppEmitter.parameters(key,method)).append(");\n");
            String descriptor=(method.access&ACC_STATIC)!=0?method.desc:"(L"+owner.name+";"+method.desc.substring(1);
            registrations.computeIfAbsent(bridgeOwner.name,n->new ArrayList<>()).add("{(char*)"+quote(key.bridge())+",(char*)"+quote(descriptor)+",(void*)&"+key.symbol()+"}");
            if(Selector.find(bridgeOwner,key.bridge(),descriptor)!=null)throw Selector.error(key,"native bridge name collision");
            bridgeOwner.methods.add(new MethodNode((bridgeOwner==owner?ACC_PRIVATE:0)|ACC_STATIC|ACC_NATIVE|ACC_SYNTHETIC,key.bridge(),descriptor,null,null));
            bridges.put(key,new MethodKey(bridgeOwner.name,key.bridge(),descriptor));
            replace(bridgeOwner,method,key,descriptor,library,runtime);
            keep.add("-keep,includedescriptorclasses class "+bridgeOwner.name.replace('/','.')+" { native <methods>; }");
            changed.add(owner.name);
        }
        registration.append("static void register_class(JNIEnv* env,jclass,jclass owner) {\n")
                .append("jclass cls=env->FindClass(\"java/lang/Class\"); if(!cls)return;\n")
                .append("jmethodID getName=env->GetMethodID(cls,\"getName\",\"()Ljava/lang/String;\"); env->DeleteLocalRef(cls); if(!getName)return;\n")
                .append("jstring name=(jstring)env->CallObjectMethod(owner,getName); if(env->ExceptionCheck()||!name)return;\n")
                .append("const char* text=env->GetStringUTFChars(name,nullptr); if(!text){env->DeleteLocalRef(name);return;}\n");
        for(var entry:registrations.entrySet()) {
            registration.append("if(strcmp(text,").append(quote(entry.getKey().replace('/','.'))).append(")==0){\n")
                    .append("static const JNINativeMethod methods[]={").append(String.join(",",entry.getValue())).append("};\n")
                    .append("env->ReleaseStringUTFChars(name,text);env->DeleteLocalRef(name);\n")
                    .append("d2c_register(env,owner,methods,").append(entry.getValue().size()).append(");return;}\n");
        }
        registration.append("env->ReleaseStringUTFChars(name,text);env->DeleteLocalRef(name);\njclass error=env->FindClass(\"java/lang/UnsatisfiedLinkError\");if(error){env->ThrowNew(error,\"dex2c: class missing from native protection manifest\");env->DeleteLocalRef(error);}\n}\n");
        Map<String,Integer> typeIndices=new TreeMap<>();
        resolverTypes.values().forEach(types->types.forEach(type->typeIndices.put(type,0)));
        int typeIndex=0;for(var entry:typeIndices.entrySet())entry.setValue(typeIndex++);
        if(!selector.selected.isEmpty()) {
            runtime.install(classes,changed,keep);
            runtime.appendRegistration(registration);
        }
        keep.add("-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod");
        if(selector.selected.keySet().stream().anyMatch(key -> Selector.annotation(classes.get(key.owner()).visibleAnnotations,"Lkotlin/Metadata;")!=null))
            keep.add("-keep class kotlin.Metadata { *; }");
        for(var entry:resolverTypes.entrySet()) {
            ClassNode owner=classes.get(entry.getKey());
            String resolver=RuntimeLayout.resolver(owner.name);
            if(Selector.find(owner,resolver,"(I)Ljava/lang/Class;")!=null)
                throw new IllegalArgumentException("dex2c: type resolver collision: "+owner.name);
            owner.methods.add(typeResolver(owner.name,entry.getValue(),typeIndices).methods.getFirst());
            keep.add("-keepclassmembers class "+owner.name.replace('/','.')+" { java.lang.Class "+resolver+"(int); }");
        }
        for(ClassNode owner:classes.values()) {
            boolean stripped=stripAnnotation(owner.invisibleAnnotations)|stripAnnotation(owner.visibleAnnotations);
            for(MethodNode method:owner.methods)stripped|=stripAnnotation(method.invisibleAnnotations)|stripAnnotation(method.visibleAnnotations);
            if(stripped)changed.add(owner.name);
        }
        Files.createDirectories(output);
        Path jarPath=output.resolve("classes.jar");
        try(JarOutputStream jar=new JarOutputStream(Files.newOutputStream(jarPath))) {
            for(var entry:classes.entrySet()) {
                byte[] bytes=original.get(entry.getKey());
                if(changed.contains(entry.getKey())) {ClassWriter writer=new ClassWriter(ClassWriter.COMPUTE_MAXS);entry.getValue().accept(writer);bytes=writer.toByteArray();}
                JarEntry item=new JarEntry(entry.getKey()+".class");item.setTime(0);jar.putNextEntry(item);jar.write(bytes);jar.closeEntry();
            }
        }
        verifyBytecode(jarPath,bridges,runtime);
        Path source=output.resolve("protected.cpp"),reg=output.resolve("registration.cpp"),rules=output.resolve("keep-rules.pro"),report=output.resolve("selection.json");
        Files.writeString(source,cpp);Files.writeString(reg,registration);
        Files.writeString(output.resolve("native.cpp"),nativeCpp);
        Files.writeString(rules,String.join("\n",keep)+"\n");
        for(boolean nativeOnly:List.of(false,true)) {
            var symbols=selector.selected.keySet().stream().filter(k->(selector.policies.get(k)==Selector.Policy.NATIVE_TREE)==nativeOnly).map(MethodKey::symbol).toList();
            Files.writeString(output.resolve(nativeOnly?"native-symbols.txt":"symbols.txt"),String.join("\n",symbols)+(symbols.isEmpty()?"":"\n"));
        }
        StringBuilder json=new StringBuilder("{\"schemaVersion\":3,\"bytecodeVerified\":true,\"library\":").append(json(library))
                .append(",\"registrationCall\":").append(json(runtime.ensure())).append(",\"methods\":[");
        boolean first=true;
        for(var entry:selector.selected.entrySet()) {
            if(!first)json.append(',');first=false;
            json.append("{\"method\":").append(json(entry.getKey().toString())).append(",\"symbol\":").append(json(entry.getKey().symbol()))
                    .append(",\"reason\":").append(json(entry.getValue()))
                    .append(",\"protection\":").append(json(selector.policies.get(entry.getKey())==Selector.Policy.NATIVE_TREE?"native-cse":"vmp"))
                    .append(",\"bridge\":").append(json(bridges.get(entry.getKey()).toString())).append('}');
        }
        json.append("],\"inherited\":{");first=true;
        for(var entry:selector.inherited.entrySet()) {
            if(!first)json.append(',');first=false;
            json.append(json(entry.getKey())).append(':').append(json(entry.getValue().toString()));
        }
        json.append("},\"excluded\":[");first=true;
        for(var entry:selector.excluded.entrySet()) {
            if(!first)json.append(',');first=false;
            json.append("{\"method\":").append(json(entry.getKey().toString())).append(",\"reason\":").append(json(entry.getValue())).append('}');
        }
        Files.writeString(report,json.append("]}\n"));
        for(String resource:List.of("dex2c_runtime.h","dex2c_runtime.cpp")) {
            try(InputStream in=Objects.requireNonNull(Transformer.class.getResourceAsStream("/native/"+resource))) {
                String text=new String(in.readAllBytes(),StandardCharsets.UTF_8)
                        .replace(RuntimeLayout.TEMPLATE,runtime.owner)
                        .replace("\"resolveClass\"",quote(runtime.name("resolveClass")))
                        .replace("\"resolveDescriptor\"",quote(runtime.name("resolveDescriptor")));
                if(resource.endsWith(".cpp")&&!selector.selected.isEmpty())text+=runtime.typeIndexSource(typeIndices);
                Files.writeString(output.resolve(resource),text);
            }
        }
        return new Result(List.copyOf(selector.selected.keySet()),jarPath,source,reg,rules,report);
    }

    private static void add(byte[] bytes,Map<String,ClassNode> classes,Map<String,byte[]> originals) {
        ClassReader reader=new ClassReader(bytes);String name=reader.getClassName();
        if(name.equals("module-info"))return;
        byte[] previous=originals.putIfAbsent(name,bytes);
        if(previous!=null) {
            if(!Arrays.equals(previous,bytes))throw new IllegalArgumentException("dex2c: conflicting class inputs: "+name);
            return;
        }
        ClassNode node=new ClassNode();reader.accept(node,0);classes.put(name,node);
    }
    private static boolean stripAnnotation(List<AnnotationNode> annotations) {
        return annotations!=null&&annotations.removeIf(annotation->annotation.desc.equals(Selector.ANNOTATION));
    }
    private static void verifyBytecode(Path jar,Map<MethodKey,MethodKey> bridges,RuntimeLayout runtime) throws IOException {
        Map<String,ClassNode> classes=new HashMap<>();
        try(JarFile input=new JarFile(jar.toFile())) {
            for(var entry:bridges.entrySet()) {
                MethodKey original=entry.getKey(),bridge=entry.getValue();
                for(String owner:List.of(original.owner(),bridge.owner())) if(!classes.containsKey(owner)) {
                    ClassNode node=new ClassNode();
                    try(InputStream bytes=input.getInputStream(input.getJarEntry(owner+".class"))) {new ClassReader(bytes).accept(node,0);}
                    classes.put(owner,node);
                }
                MethodNode wrapper=Selector.find(classes.get(original.owner()),original.name(),original.descriptor());
                MethodNode nativeMethod=Selector.find(classes.get(bridge.owner()),bridge.name(),bridge.descriptor());
                if(wrapper==null||nativeMethod==null||(nativeMethod.access&ACC_NATIVE)==0)
                    throw Selector.error(original,"missing wrapper or native bridge in output jar");
                List<MethodInsnNode> calls=new ArrayList<>();
                for(AbstractInsnNode instruction:wrapper.instructions) {
                    int op=instruction.getOpcode();
                    if(instruction instanceof MethodInsnNode call)calls.add(call);
                    if(op>=0 && op!=LDC && !(op>=ILOAD&&op<=ALOAD) && op!=INVOKESTATIC && !(op>=IRETURN&&op<=RETURN))
                        throw Selector.error(original,"original algorithm remains in output jar");
                }
                if(calls.size()!=2 || !new MethodKey(calls.getFirst().owner,calls.getFirst().name,calls.getFirst().desc).toString().equals(runtime.ensure())
                        || !new MethodKey(calls.getLast().owner,calls.getLast().name,calls.getLast().desc).equals(bridge))
                    throw Selector.error(original,"invalid native forwarding wrapper");
            }
        }
    }
    private static ClassNode typeResolver(String name,Set<String> types,Map<String,Integer> indices) {
        // DEX class literals follow framework type relocation; native string constants cannot.
        ClassWriter writer=new ClassWriter(ClassWriter.COMPUTE_FRAMES|ClassWriter.COMPUTE_MAXS);
        writer.visit(V17,ACC_PUBLIC|ACC_FINAL|ACC_SYNTHETIC,name,null,"java/lang/Object",null);
        MethodVisitor method=writer.visitMethod(ACC_PRIVATE|ACC_STATIC|ACC_SYNTHETIC,RuntimeLayout.resolver(name),"(I)Ljava/lang/Class;",null,null);
        method.visitCode();
        Label fallback=new Label();Label[] labels=types.stream().map(type->new Label()).toArray(Label[]::new);
        method.visitVarInsn(ILOAD,0);
        method.visitLookupSwitchInsn(fallback,types.stream().mapToInt(indices::get).toArray(),labels);
        int index=0;
        for(String type:types) {
            method.visitLabel(labels[index++]);method.visitLdcInsn(Type.getObjectType(type));method.visitInsn(ARETURN);
        }
        method.visitLabel(fallback);
        method.visitInsn(ACONST_NULL);method.visitInsn(ARETURN);method.visitMaxs(0,0);method.visitEnd();writer.visitEnd();
        ClassNode node=new ClassNode();new ClassReader(writer.toByteArray()).accept(node,0);return node;
    }
    private static void replace(ClassNode owner,MethodNode method,MethodKey key,String descriptor,String library,RuntimeLayout runtime) {
        InsnList code=new InsnList();
        code.add(new LdcInsnNode(Type.getObjectType(owner.name)));code.add(new LdcInsnNode(library));
        code.add(new LdcInsnNode(RuntimeLayout.resolver(owner.name)));
        code.add(new MethodInsnNode(INVOKESTATIC,runtime.owner,runtime.name("ensureRegistered"),RuntimeLayout.ENSURE_DESC,false));
        int local=0;
        if((method.access&ACC_STATIC)==0){code.add(new VarInsnNode(ALOAD,0));local=1;}
        for(Type type:Type.getArgumentTypes(method.desc)){code.add(new VarInsnNode(type.getOpcode(ILOAD),local));local+=type.getSize();}
        code.add(new MethodInsnNode(INVOKESTATIC,owner.name,key.bridge(),descriptor,false));
        code.add(new InsnNode(Type.getReturnType(method.desc).getOpcode(IRETURN)));
        method.instructions=code;method.tryCatchBlocks.clear();method.localVariables=null;
        method.visibleLocalVariableAnnotations=null;method.invisibleLocalVariableAnnotations=null;
        method.maxLocals=local;method.maxStack=local+2;
    }
    public static String json(String value) {
        StringBuilder result=new StringBuilder("\"");
        for(char c:value.toCharArray())switch(c){case '"'->result.append("\\\"");case '\\'->result.append("\\\\");case '\n'->result.append("\\n");case '\r'->result.append("\\r");case '\t'->result.append("\\t");default->{if(c<32)result.append(String.format("\\u%04x",(int)c));else result.append(c);}}
        return result.append('"').toString();
    }
    public static void main(String[] arguments) throws IOException {
        if(arguments.length<3)throw new IllegalArgumentException("Usage: Transformer <output-directory> <library-name> <class-directory-or-jar>...");
        Result result=new Transformer().transform(Arrays.stream(arguments).skip(2).map(Path::of).toList(),Path.of(arguments[0]),arguments[1]);
        System.out.println("dex2c: selected "+result.methods().size()+" methods; "+result.report());
    }
}
