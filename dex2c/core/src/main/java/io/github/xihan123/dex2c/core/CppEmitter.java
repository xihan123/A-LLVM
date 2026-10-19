package io.github.xihan123.dex2c.core;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.*;
import java.util.*;
import static org.objectweb.asm.Opcodes.*;
import static io.github.xihan123.dex2c.core.NativeText.*;

/** A typed JVM operand stack is lowered to scalar C++ and explicit exception edges. */
final class CppEmitter {
    private final MethodKey key;
    private final MethodNode method;
    private final Frame<BasicValue>[] frames;
    private final StringBuilder out = new StringBuilder();
    private final Set<String> keep;
    private final Set<String> types;
    private final int base, scratch;
    private int index;

    CppEmitter(MethodKey key, MethodNode method, Set<String> keep, Set<String> types) {
        this.key = key; this.method = method; this.keep = keep; this.types = types;
        base = method.maxLocals; scratch = base + method.maxStack;
        try { frames = new Analyzer<>(new BasicInterpreter()).analyze(key.owner(), method); }
        catch (AnalyzerException e) { throw Selector.error(key, "invalid bytecode: " + e.getMessage()); }
    }

    String emit() {
        Type result = Type.getReturnType(method.desc);
        keepMember(key.owner(),key.name(),method.desc,false);
        line("extern \"C\" D2C_PROTECTED " + ctype(result) + " " + key.symbol() + "(" + parameters(key, method) + ") {");
        line("d2c_frame* f = d2c_open(env, owner, " + (scratch + 8) + ");");
        line("if (!f) " + defaultReturn(result));
        int local = 0;
        if ((method.access & ACC_STATIC) == 0) { line("d2c_ref(f, 0, env->NewLocalRef(receiver));"); local++; }
        Type[] args = Type.getArgumentTypes(method.desc);
        for (int a = 0; a < args.length; a++) {
            if (member(args[a]).equals("l")) line("d2c_ref(f, " + local + ", env->NewLocalRef(a" + a + "));");
            else put(local, member(args[a]), "a" + a);
            local += args[a].getSize();
        }
        line("if (env->ExceptionCheck()) goto failed;");
        for (index = 0; index < method.instructions.size(); index++) {
            AbstractInsnNode instruction = method.instructions.get(index);
            line("L" + index + ":;");
            if (instruction.getOpcode() < 0 || frames[index] == null) continue;
            try { instruction(instruction, frames[index]); }
            catch (IllegalArgumentException e) { throw Selector.error(key, "instruction " + index + ": " + e.getMessage()); }
            int op = instruction.getOpcode();
            if (!(op >= IRETURN && op <= RETURN) && op != GOTO && op != TABLESWITCH && op != LOOKUPSWITCH)
                line("if (env->ExceptionCheck()) goto E" + index + ";");
        }
        line("goto failed;");
        for (index = 0; index < method.instructions.size(); index++) {
            if (method.instructions.get(index).getOpcode() < 0 || frames[index] == null) continue;
            line("E" + index + ":;");
            for (TryCatchBlockNode handler : method.tryCatchBlocks) {
                if (index >= at(handler.start) && index < at(handler.end)) {
                    if (handler.type != null) keepClass(handler.type);
                    line("if (d2c_catch(f, " + (handler.type == null ? "nullptr" : quote(handler.type)) + ", " + base + ")) goto L" + at(handler.handler) + ";");
                }
            }
            line("goto failed;");
        }
        line("failed: d2c_close(f, nullptr); " + defaultReturn(result));
        line("}");
        return out.toString();
    }

    static String parameters(MethodKey key, MethodNode method) {
        StringBuilder s = new StringBuilder("JNIEnv* env, jclass owner");
        if ((method.access & ACC_STATIC) == 0) s.append(", jobject receiver");
        Type[] args = Type.getArgumentTypes(method.desc);
        for (int i = 0; i < args.length; i++) s.append(", ").append(ctype(args[i])).append(" a").append(i);
        return s.toString();
    }
    private static String defaultReturn(Type result) { return result.getSort() == Type.VOID ? "return;" : "return 0;"; }
    private String v(int slot, String member) { return "f->slots[" + slot + "].v." + member; }
    private void put(int slot, String member, String expression) {
        line("d2c_" + member + "(f, " + slot + ", " + expression + ");");
    }
    private void copy(int target, int source) { line("d2c_copy(f, " + target + ", " + source + ");"); }
    private void line(String s) { out.append(s).append('\n'); }
    private int at(LabelNode label) { return method.instructions.indexOf(label); }
    private void keepClass(String internalName) {
        Type t = internalName.startsWith("[") ? Type.getType(internalName) : Type.getObjectType(internalName);
        if (t.getSort() == Type.ARRAY) t = t.getElementType();
        if (t.getSort() == Type.OBJECT) {
            keep.add("-keep,allowoptimization class " + t.getClassName());
            types.add(t.getInternalName());
        }
    }
    private void keepMember(String owner, String name, String desc, boolean field) {
        keepClass(owner);
        Type t = Type.getType(desc);
        if (field) {
            keepType(t);
            keep.add("-keepclassmembers,includedescriptorclasses class " + owner.replace('/', '.') + " { " + t.getClassName() + " " + name + "; }");
        } else {
            keepType(t.getReturnType());
            for (Type argument : t.getArgumentTypes()) keepType(argument);
            String arguments = String.join(",", Arrays.stream(t.getArgumentTypes()).map(Type::getClassName).toList());
            String declaration = name.equals("<init>") ? "<init>(" + arguments + ")"
                    : t.getReturnType().getClassName() + " " + name + "(" + arguments + ")";
            keep.add("-keepclassmembers,includedescriptorclasses class " + owner.replace('/', '.') + " { " + declaration + "; }");
        }
    }
    private void keepType(Type type) { if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) keepClass(type.getInternalName()); }

    private void instruction(AbstractInsnNode ins, Frame<BasicValue> frame) {
        int op = ins.getOpcode(), n = frame.getStackSize(), top = base + n - 1;
        if (ins instanceof VarInsnNode var) {
            if (op >= ILOAD && op <= ALOAD) copy(top + 1, var.var);
            else if (op >= ISTORE && op <= ASTORE) copy(var.var, top);
            else throw new IllegalArgumentException("unsupported local instruction " + op);
            return;
        }
        if (ins instanceof IincInsnNode inc) { put(inc.var, "i", "(jint)((uint32_t)" + v(inc.var,"i") + " + (uint32_t)(" + inc.incr + "))"); return; }
        if (ins instanceof LdcInsnNode ldc) { constant(top + 1, ldc.cst); return; }
        if (ins instanceof IntInsnNode integer) {
            if (op == NEWARRAY) line("d2c_new_array(f," + top + "," + integer.operand + "," + v(top,"i") + ");");
            else put(top + 1,"i",Integer.toString(integer.operand));
            return;
        }
        if (ins instanceof TypeInsnNode type) {
            keepClass(type.desc);
            switch (op) {
                case NEW -> line("d2c_allocate(f," + (top + 1) + "," + quote(type.desc) + ");");
                case ANEWARRAY -> line("d2c_object_array(f," + top + "," + quote(type.desc) + "," + v(top,"i") + ");");
                case CHECKCAST -> line("d2c_cast(f," + top + "," + quote(type.desc) + ");");
                case INSTANCEOF -> put(top,"i","d2c_instance(f," + v(top,"l") + "," + quote(type.desc) + ")");
                default -> throw new IllegalArgumentException("unsupported type instruction " + op);
            }
            return;
        }
        if (ins instanceof MultiANewArrayInsnNode array) {
            keepClass(array.desc);
            line("d2c_multi_array(f," + (top-array.dims+1) + "," + quote(array.desc) + "," + array.dims + ");"); return;
        }
        if (ins instanceof FieldInsnNode field) {
            keepMember(field.owner,field.name,field.desc,true);
            int target = switch(op) { case GETSTATIC -> top+1; case PUTSTATIC,GETFIELD -> top; default -> top-1; };
            line("d2c_field(f," + target + "," + quote(field.owner) + "," + quote(field.name) + "," + quote(field.desc)
                    + "," + (op == GETSTATIC || op == PUTSTATIC ? "true" : "false")
                    + "," + (op == PUTFIELD || op == PUTSTATIC ? "true" : "false") + ");"); return;
        }
        if (ins instanceof MethodInsnNode call) {
            keepMember(call.owner,call.name,call.desc,false);
            int count=Type.getArgumentTypes(call.desc).length, target=top-count+(op==INVOKESTATIC?1:0);
            line("d2c_invoke(f," + target + "," + quote(call.owner) + "," + quote(call.name) + "," + quote(call.desc)
                    + "," + (op==INVOKESTATIC ? 0 : op==INVOKESPECIAL ? 2 : 1) + "," + count + ");"); return;
        }
        if (ins instanceof JumpInsnNode jump) {
            String condition;
            if (op == GOTO) { line("goto L" + at(jump.label) + ";"); return; }
            if (op >= IFEQ && op <= IFLE) condition = v(top,"i") + comparison(op-IFEQ) + "0";
            else if (op >= IF_ICMPEQ && op <= IF_ICMPLE) condition = v(top-1,"i") + comparison(op-IF_ICMPEQ) + v(top,"i");
            else if (op == IF_ACMPEQ || op == IF_ACMPNE) condition = (op==IF_ACMPNE ? "!" : "") + "env->IsSameObject(" + v(top-1,"l") + "," + v(top,"l") + ")";
            else if (op == IFNULL || op == IFNONNULL) condition = v(top,"l") + (op==IFNULL?" == ":" != ") + "nullptr";
            else throw new IllegalArgumentException("unsupported branch " + op);
            line("if (" + condition + ") goto L" + at(jump.label) + ";"); return;
        }
        if (ins instanceof TableSwitchInsnNode table) {
            line("switch(" + v(top,"i") + ") {");
            for(int i=0;i<table.labels.size();i++) line("case " + (table.min+i) + ": goto L" + at(table.labels.get(i)) + ";");
            line("default: goto L" + at(table.dflt) + "; }"); return;
        }
        if (ins instanceof LookupSwitchInsnNode table) {
            line("switch(" + v(top,"i") + ") {");
            for(int i=0;i<table.labels.size();i++) line("case " + table.keys.get(i) + ": goto L" + at(table.labels.get(i)) + ";");
            line("default: goto L" + at(table.dflt) + "; }"); return;
        }
        if (ins instanceof InvokeDynamicInsnNode) throw new IllegalArgumentException("invokedynamic was not normalized");
        if (op == NOP || op == POP || op == POP2) return;
        if (op == ACONST_NULL) { line("d2c_ref(f," + (top+1) + ",nullptr);"); return; }
        if (op >= ICONST_M1 && op <= ICONST_5) { put(top+1,"i",Integer.toString(op-ICONST_0)); return; }
        if (op >= LCONST_0 && op <= LCONST_1) { put(top+1,"j",(op-LCONST_0)+"LL"); return; }
        if (op >= FCONST_0 && op <= FCONST_2) { put(top+1,"f",(op-FCONST_0)+".0f"); return; }
        if (op >= DCONST_0 && op <= DCONST_1) { put(top+1,"d",(op-DCONST_0)+".0"); return; }
        if (op >= IALOAD && op <= SALOAD) { line("d2c_array_load(f," + (top-1) + "," + (op-IALOAD) + ");"); return; }
        if (op >= IASTORE && op <= SASTORE) { line("d2c_array_store(f," + (top-2) + "," + (op-IASTORE) + ");"); return; }
        if (op >= DUP && op <= SWAP) { stack(op,frame); return; }
        if (op >= IADD && op <= DREM) {
            String m = new String[]{"i","j","f","d"}[(op-IADD)%4];
            int operation = (op-IADD)/4;
            String a=v(top-1,m), b=v(top,m), expression;
            if (m.equals("i") || m.equals("j")) {
                if (operation>=3) expression="d2c_"+m+"div(f,"+a+","+b+","+(operation==4?"true":"false")+")";
                else { String u=m.equals("i")?"uint32_t":"uint64_t"; expression="("+(m.equals("i")?"jint":"jlong")+")(("+u+")"+a+new String[]{" + "," - "," * "}[operation]+"("+u+")"+b+")"; }
            } else expression = operation==4 ? (m.equals("f")?"fmodf":"fmod")+"("+a+","+b+")" : a+new String[]{" + "," - "," * "," / "}[operation]+b;
            put(top-1,m,expression); return;
        }
        if (op >= INEG && op <= DNEG) {
            String m=new String[]{"i","j","f","d"}[op-INEG];
            put(top,m,m.equals("i")?"(jint)(0u-(uint32_t)"+v(top,m)+")":m.equals("j")?"(jlong)(0ULL-(uint64_t)"+v(top,m)+")":"-"+v(top,m)); return;
        }
        if (op >= ISHL && op <= LXOR) {
            boolean wide=(op-ISHL)%2==1; String m=wide?"j":"i", a=v(top-1,m), b=v(top, op<=LUSHR?"i":m), expression;
            int kind=(op-ISHL)/2; String mask=wide?"63":"31", u=wide?"uint64_t":"uint32_t", c=wide?"jlong":"jint";
            expression=switch(kind) {
                case 0 -> "("+c+")(("+u+")"+a+" << ("+b+" & "+mask+"))";
                case 1 -> a+" >> ("+b+" & "+mask+")";
                case 2 -> "("+c+")(("+u+")"+a+" >> ("+b+" & "+mask+"))";
                default -> a+new String[]{" & "," | "," ^ "}[kind-3]+b;
            }; put(top-1,m,expression); return;
        }
        if (op >= I2L && op <= I2S) {
            String[] from={"i","i","i","j","j","j","f","f","f","d","d","d","i","i","i"};
            String[] to={"j","f","d","i","f","d","i","j","d","i","j","f","i","i","i"};
            int c=op-I2L; String expression;
            if ((from[c].equals("f")||from[c].equals("d"))&&(to[c].equals("i")||to[c].equals("j"))) expression="d2c_to_"+to[c]+"("+v(top,from[c])+")";
            else expression="("+(op==I2B?"jbyte":op==I2C?"jchar":op==I2S?"jshort":switch(to[c]){case "i"->"jint";case "j"->"jlong";case "f"->"jfloat";default->"jdouble";})+")"+v(top,from[c]);
            put(top,to[c],expression); return;
        }
        if (op >= LCMP && op <= DCMPG) {
            String m=op==LCMP?"j":op<=FCMPG?"f":"d", a=v(top-1,m),b=v(top,m);
            String expression="("+a+" > "+b+" ? 1 : "+a+" == "+b+" ? 0 : -1)";
            if(op==FCMPG||op==DCMPG) expression="("+a+" < "+b+" ? -1 : "+a+" == "+b+" ? 0 : 1)";
            put(top-1,"i",expression); return;
        }
        if (op >= IRETURN && op <= RETURN) {
            Type result=Type.getReturnType(method.desc);
            if(op==RETURN) line("d2c_close(f,nullptr); return;");
            else if(op==ARETURN) line("return d2c_close(f,"+v(top,"l")+");");
            else line("{ "+ctype(result)+" result=("+ctype(result)+")"+v(top,member(result))+"; d2c_close(f,nullptr); return result; }");
            return;
        }
        switch(op) {
            case ARRAYLENGTH -> put(top,"i","d2c_array_length(f,"+v(top,"l")+")");
            case ATHROW -> line("d2c_throw(f,"+v(top,"l")+");");
            case MONITORENTER,MONITOREXIT -> line("d2c_monitor(f,"+v(top,"l")+","+(op==MONITORENTER?"true":"false")+");");
            default -> throw new IllegalArgumentException("unsupported opcode " + op);
        }
    }
    private static String comparison(int n) { return new String[]{" == "," != "," < "," >= "," > "," <= "}[n]; }
    private void constant(int slot,Object value) {
        if(value instanceof Integer i) put(slot,"i","(jint)"+Integer.toUnsignedString(i)+"u");
        else if(value instanceof Long l) put(slot,"j","(jlong)"+Long.toUnsignedString(l)+"ULL");
        else if(value instanceof Float f) put(slot,"f","d2c_float("+Integer.toUnsignedString(Float.floatToRawIntBits(f))+"u)");
        else if(value instanceof Double d) put(slot,"d","d2c_double("+Long.toUnsignedString(Double.doubleToRawLongBits(d))+"ULL)");
        else if(value instanceof String s) line("d2c_ref(f,"+slot+",d2c_string(f,"+utf16(s)+","+s.length()+"));");
        else if(value instanceof Type t && t.getSort()!=Type.METHOD) { keepType(t); line("d2c_ref(f,"+slot+",d2c_class(f,"+quote(t.getInternalName())+"));"); }
        else throw new IllegalArgumentException("unsupported constant " + value);
    }
    private void stack(int op,Frame<BasicValue> frame) {
        int n=frame.getStackSize(),a=n-1,b=n-2,c=n-3,d=n-4;
        boolean a2=frame.getStack(a).getSize()==2;
        int[] order=switch(op) {
            case DUP -> new int[]{a,a};
            case DUP_X1 -> new int[]{a,b,a};
            case DUP_X2 -> frame.getStack(b).getSize()==2?new int[]{a,b,a}:new int[]{a,c,b,a};
            case DUP2 -> a2?new int[]{a,a}:new int[]{b,a,b,a};
            case DUP2_X1 -> a2?new int[]{a,b,a}:new int[]{b,a,c,b,a};
            case DUP2_X2 -> a2?(frame.getStack(b).getSize()==2?new int[]{a,b,a}:new int[]{a,c,b,a})
                    :(frame.getStack(c).getSize()==2?new int[]{b,a,c,b,a}:new int[]{b,a,d,c,b,a});
            case SWAP -> new int[]{a,b};
            default -> throw new IllegalArgumentException("invalid stack instruction");
        };
        int low=Arrays.stream(order).min().orElseThrow();
        for(int i=low;i<n;i++) copy(scratch+i-low,base+i);
        for(int i=0;i<order.length;i++) copy(base+low+i,scratch+order[i]-low);
    }
}
