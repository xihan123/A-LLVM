package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.*;
import static org.objectweb.asm.Opcodes.*;
import static org.junit.jupiter.api.Assertions.*;

class StringRuntimeTest {
    /** Replace only the native boundary so cache behavior can be tested independently of a toolchain. */
    private Class<?> runtime(StringProtection protection) throws Exception {
        Map<String,ClassNode> classes=new HashMap<>();
        protection.install(classes,new HashSet<>(),new HashSet<>());
        ClassNode node=classes.get(protection.owner);
        node.fields.add(new FieldNode(ACC_PUBLIC|ACC_STATIC,"count","I",null,null));
        node.fields.add(new FieldNode(ACC_PUBLIC|ACC_STATIC,"failures","I",null,null));
        node.fields.add(new FieldNode(ACC_PUBLIC|ACC_STATIC,"payload","Ljava/lang/String;",null,null));
        for(MethodNode method:node.methods) {
            if(method.name.equals("load")) {
                method.instructions.clear();method.instructions.add(new InsnNode(RETURN));
            }
            if(!method.name.equals(protection.decoder))continue;
            method.access&=~ACC_NATIVE;
            InsnList code=method.instructions;
            LabelNode success=new LabelNode();
            code.add(new FieldInsnNode(GETSTATIC,node.name,"failures","I"));
            code.add(new JumpInsnNode(IFEQ,success));
            code.add(new InsnNode(ICONST_0));code.add(new FieldInsnNode(PUTSTATIC,node.name,"failures","I"));
            code.add(new TypeInsnNode(NEW,"java/lang/OutOfMemoryError"));code.add(new InsnNode(DUP));
            code.add(new MethodInsnNode(INVOKESPECIAL,"java/lang/OutOfMemoryError","<init>","()V",false));
            code.add(new InsnNode(ATHROW));code.add(success);
            code.add(new FieldInsnNode(GETSTATIC,node.name,"count","I"));code.add(new InsnNode(ICONST_1));code.add(new InsnNode(IADD));
            code.add(new FieldInsnNode(PUTSTATIC,node.name,"count","I"));
            code.add(new TypeInsnNode(NEW,"java/lang/String"));code.add(new InsnNode(DUP));
            code.add(new FieldInsnNode(GETSTATIC,node.name,"payload","Ljava/lang/String;"));
            code.add(new MethodInsnNode(INVOKESPECIAL,"java/lang/String","<init>","(Ljava/lang/String;)V",false));
            code.add(new InsnNode(ARETURN));
        }
        ClassWriter writer=new ClassWriter(ClassWriter.COMPUTE_FRAMES|ClassWriter.COMPUTE_MAXS);node.accept(writer);
        byte[] bytes=writer.toByteArray();
        return new ClassLoader(null) {
            Class<?> install() {return defineClass(node.name.replace('/','.'),bytes,0,bytes.length);}
        }.install();
    }
    @Test void failuresAreRetriedConcurrentFirstUseDecodesOnceAndLoadersHaveIndependentCaches() throws Exception {
        StringProtection protection=new StringProtection("cache_test",Set.of("sample"),Set.of());
        protection.strings.put("placeholder",0);
        Class<?> first=runtime(protection),second=runtime(protection);
        first.getField("payload").set(null,"first-loader");second.getField("payload").set(null,"second-loader");
        first.getField("failures").setInt(null,1);
        Method getter=first.getMethod(protection.getter,int.class);
        assertInstanceOf(OutOfMemoryError.class,assertThrows(InvocationTargetException.class,()->getter.invoke(null,0)).getCause());
        assertEquals(0,first.getField("count").getInt(null));
        ExecutorService pool=Executors.newFixedThreadPool(8);
        try {
            List<Future<Object>> values=new ArrayList<>();
            for(int i=0;i<64;i++)values.add(pool.submit(()->getter.invoke(null,0)));
            for(var value:values)assertSame("first-loader",value.get());
        } finally {pool.shutdown();}
        assertEquals(1,first.getField("count").getInt(null));
        assertSame("second-loader",second.getMethod(protection.getter,int.class).invoke(null,0));
        assertEquals(1,second.getField("count").getInt(null));
        assertSame("first-loader",getter.invoke(null,0));
        assertEquals(1,first.getField("count").getInt(null));
        assertInstanceOf(IndexOutOfBoundsException.class,assertThrows(InvocationTargetException.class,()->getter.invoke(null,-1)).getCause());
    }
}
