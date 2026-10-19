package io.github.xihan123.dex2c.core;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import java.util.*;
import static org.objectweb.asm.Opcodes.*;

final class DynamicCalls {
    static void lower(ClassNode owner, MethodNode method, MethodKey key) {
        int factory = 0;
        for (AbstractInsnNode ins : method.instructions.toArray()) {
            if (!(ins instanceof InvokeDynamicInsnNode indy)) continue;
            if (indy.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")) {
                method.instructions.insertBefore(indy, concat(method, indy, key));
                method.instructions.remove(indy);
            } else if (indy.bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory")) {
                // Keep only the VM's lambda construction scaffold. Its implementation handle
                // points to a selected method whose body is replaced by a native bridge.
                String name = new MethodKey(key.owner(),key.name()+"$factory$"+factory++,key.descriptor()).bridge();
                if (Selector.find(owner,name,indy.desc)!=null) throw Selector.error(key,"generated factory name collision");
                MethodNode helper = new MethodNode(ACC_PRIVATE|ACC_STATIC|ACC_SYNTHETIC,name,indy.desc,null,null);
                int slot=0;
                for (Type argument:Type.getArgumentTypes(indy.desc)) {
                    helper.instructions.add(new VarInsnNode(argument.getOpcode(ILOAD),slot)); slot+=argument.getSize();
                }
                helper.instructions.add(new InvokeDynamicInsnNode(indy.name,indy.desc,indy.bsm,indy.bsmArgs));
                helper.instructions.add(new InsnNode(ARETURN));
                helper.maxLocals=slot;helper.maxStack=slot+1;
                owner.methods.add(helper);
                method.instructions.set(indy,new MethodInsnNode(INVOKESTATIC,owner.name,name,indy.desc,(owner.access&ACC_INTERFACE)!=0));
            } else throw Selector.error(key,"unsupported invokedynamic bootstrap "+indy.bsm.getOwner());
        }
    }
    private static InsnList concat(MethodNode method,InvokeDynamicInsnNode indy,MethodKey key) {
        Type[] arguments=Type.getArgumentTypes(indy.desc);int[] locals=new int[arguments.length];
        for(int i=0;i<arguments.length;i++){locals[i]=method.maxLocals;method.maxLocals+=arguments[i].getSize();}
        InsnList code=new InsnList();
        for(int i=arguments.length-1;i>=0;i--)code.add(new VarInsnNode(arguments[i].getOpcode(ISTORE),locals[i]));
        code.add(new TypeInsnNode(NEW,"java/lang/StringBuilder"));code.add(new InsnNode(DUP));
        code.add(new MethodInsnNode(INVOKESPECIAL,"java/lang/StringBuilder","<init>","()V",false));
        String recipe;
        int constant=1;
        if(indy.bsm.getName().equals("makeConcat"))recipe="\u0001".repeat(arguments.length);
        else if(indy.bsm.getName().equals("makeConcatWithConstants") && indy.bsmArgs.length>0 && indy.bsmArgs[0] instanceof String s)recipe=s;
        else throw Selector.error(key,"unsupported StringConcatFactory form");
        StringBuilder literal=new StringBuilder();int argument=0;
        for(int p=0;p<=recipe.length();p++) {
            char c=p==recipe.length()?0:recipe.charAt(p);
            if(p!=recipe.length()&&c!=1&&c!=2){literal.append(c);continue;}
            if(!literal.isEmpty()){code.add(new LdcInsnNode(literal.toString()));append(code,Type.getType(String.class));literal.setLength(0);}
            if(c==1) {
                if(argument>=arguments.length)throw Selector.error(key,"invalid string concat argument count");
                code.add(new VarInsnNode(arguments[argument].getOpcode(ILOAD),locals[argument]));append(code,arguments[argument++]);
            } else if(c==2) {
                if(constant>=indy.bsmArgs.length)throw Selector.error(key,"invalid string concat constants");
                Object value=indy.bsmArgs[constant++];
                if(!(value instanceof String || value instanceof Number))throw Selector.error(key,"unsupported string concat constant");
                code.add(new LdcInsnNode(value.toString()));append(code,Type.getType(String.class));
            }
        }
        if(argument!=arguments.length||constant!=(indy.bsm.getName().equals("makeConcat")?1:indy.bsmArgs.length))
            throw Selector.error(key,"invalid string concat recipe");
        code.add(new MethodInsnNode(INVOKEVIRTUAL,"java/lang/StringBuilder","toString","()Ljava/lang/String;",false));
        method.maxStack+=4;return code;
    }
    private static void append(InsnList code,Type type) {
        String descriptor=switch(type.getSort()) {
            case Type.BYTE,Type.SHORT,Type.INT->"I";case Type.ARRAY->"Ljava/lang/Object;";
            case Type.OBJECT->type.getInternalName().equals("java/lang/String")?"Ljava/lang/String;":"Ljava/lang/Object;";
            default->type.getDescriptor();
        };
        code.add(new MethodInsnNode(INVOKEVIRTUAL,"java/lang/StringBuilder","append","("+descriptor+")Ljava/lang/StringBuilder;",false));
    }
}
