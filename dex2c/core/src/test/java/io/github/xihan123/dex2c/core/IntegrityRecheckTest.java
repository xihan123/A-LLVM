package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.tree.*;
import javax.tools.ToolProvider;
import java.io.InputStream;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.objectweb.asm.Opcodes.*;

class IntegrityRecheckTest {
    @TempDir Path temp;
    @Test void explicitMethodsAndRegistrationAreMarkedWithoutPropagatingToHelpers() throws Exception {
        Path source=temp.resolve("Run.java"),classes=Files.createDirectories(temp.resolve("classes"));
        try(InputStream input=getClass().getResourceAsStream("/fixtures/recheck/Run.java")){Files.copy(Objects.requireNonNull(input),source);}
        assertEquals(0,ToolProvider.getSystemJavaCompiler().run(null,null,null,"-g","-classpath",System.getProperty("java.class.path"),"-d",classes.toString(),source.toString()));
        var result=new Transformer().transform(List.of(classes),temp.resolve("generated"),"recheck");
        String cpp=Files.readString(result.nativeSource()),nativeCpp=Files.readString(result.nativeSource().resolveSibling("native.cpp"));
        assertEquals(1,cpp.lines().filter(line->line.contains("D2C_RECHECK")).count());
        assertEquals(1,nativeCpp.lines().filter(line->line.contains("D2C_RECHECK")).count());
        assertTrue(Files.readString(result.registration()).contains("D2C_RECHECK jint JNICALL JNI_OnLoad"));
        assertEquals(2,Files.readAllLines(result.nativeSource().resolveSibling("recheck-symbols.txt")).size());
        String report=Files.readString(result.report());
        assertEquals(2,report.split("\\\"integrityRecheck\\\":true",-1).length-1);
        assertTrue(report.contains("\"registrationIntegrityRecheck\":true"));
    }
    @Test void classWideOrMalformedCheckpointIsRejectedAndDefaultIsEmpty() {
        var owner=new ClassNode();owner.name="Example";owner.superName="java/lang/Object";
        var method=new MethodNode(ACC_STATIC,"run","()V",null,null);method.instructions.add(new InsnNode(RETURN));owner.methods.add(method);
        var annotation=new AnnotationNode(Selector.ANNOTATION);
        method.invisibleAnnotations=List.of(annotation);
        var selector=new Selector(Map.of(owner.name,owner));selector.run();assertTrue(selector.rechecks.isEmpty());
        annotation.values=new ArrayList<>(List.of("integrityRecheck",true));
        selector=new Selector(Map.of(owner.name,owner));selector.run();assertEquals(1,selector.rechecks.size());
        annotation.values.set(1,"true");
        assertThrows(IllegalArgumentException.class,()->new Selector(Map.of(owner.name,owner)).run());
        annotation.values.set(1,true);owner.invisibleAnnotations=List.of(annotation);
        assertThrows(IllegalArgumentException.class,()->new Selector(Map.of(owner.name,owner)).run());
    }
    @Test void inheritedImplementationsAndSyntheticHelpersDoNotCopyCheckpoint() {
        var root=new ClassNode();root.name="Root";root.superName="java/lang/Object";
        var child=new ClassNode();child.name="Child";child.superName="Root";
        var entry=new MethodNode(ACC_PUBLIC,"entry","()V",null,null);
        var annotation=new AnnotationNode(Selector.ANNOTATION);
        annotation.values=new ArrayList<>(List.of("integrityRecheck",true));entry.invisibleAnnotations=List.of(annotation);
        entry.instructions.add(new MethodInsnNode(INVOKESTATIC,"Root","lambda$entry$0","()V",false));
        entry.instructions.add(new InsnNode(RETURN));root.methods.add(entry);
        var callback=new MethodNode(ACC_STATIC|ACC_SYNTHETIC,"lambda$entry$0","()V",null,null);
        callback.instructions.add(new InsnNode(RETURN));root.methods.add(callback);
        var override=new MethodNode(ACC_PUBLIC,"entry","()V",null,null);
        override.instructions.add(new InsnNode(RETURN));child.methods.add(override);
        var selector=new Selector(Map.of(root.name,root,child.name,child));selector.run(Set.of("Root#entry()V"));
        assertEquals(Set.of(new MethodKey("Root","entry","()V")),selector.rechecks);
        assertEquals(Selector.Policy.VMP_TREE,selector.policies.get(new MethodKey("Root","entry","()V")));
        assertEquals(Selector.Policy.VMP_ENTRY,selector.policies.get(new MethodKey("Child","entry","()V")));
        assertTrue(selector.selected.containsKey(new MethodKey("Root","lambda$entry$0","()V")));
    }
    @Test void omittedPropertyDoesNotMarkGeneratedRegistration() throws Exception {
        Path source=temp.resolve("Plain.java"),classes=Files.createDirectories(temp.resolve("plain-classes"));
        Files.writeString(source,"import io.github.xihan123.dex2c.annotation.dex2c; @dex2c class Plain { static int run(){return 1;} }");
        assertEquals(0,ToolProvider.getSystemJavaCompiler().run(null,null,null,"-classpath",System.getProperty("java.class.path"),"-d",classes.toString(),source.toString()));
        var result=new Transformer().transform(List.of(classes),temp.resolve("plain-generated"),"plain");
        assertFalse(Files.readString(result.nativeSource()).contains("D2C_RECHECK"));
        assertFalse(Files.readString(result.registration()).contains("D2C_RECHECK"));
        assertTrue(Files.readString(result.nativeSource().resolveSibling("recheck-symbols.txt")).isEmpty());
        assertTrue(Files.readString(result.report()).contains("\"registrationIntegrityRecheck\":false"));
    }
    private static String ir(boolean segmented) {
        String guard=segmented?"ndkp_cse_module_recheck_v2":"ndkp_cse_module_recheck";
        return "define void @entry() {\n call void @"+guard+"()\n ret void\n}\n"
                +"define private void @"+guard+"() {\n"+(segmented?"":" %a = load volatile ptr, ptr @module\n".repeat(5))
                +" call void @"+(segmented?"ndkp_qseg_recheck()":"ndkp_cse_recheck_module_v1(ptr %module)")+"\n ret void\n}\n";
    }
    @Test void receiptRequiresEntryCallAndCorrectRuntimeInBothModes() {
        for(boolean segmented:List.of(false,true)) {
            String valid=ir(segmented);
            String runtime=segmented?"ndkp_qseg_recheck":"ndkp_cse_recheck_module_v1";
            String bypass=valid.replace(" call void @"+runtime," br label %skip\ncheck:\n call void @"+runtime);
            int end=bypass.lastIndexOf("\n}");bypass=bypass.substring(0,end)+"\nskip:\n ret void"+bypass.substring(end);
            assertDoesNotThrow(()->NativeCompiler.verifyRecheckIr(valid,"entry",segmented));
            for(String broken:List.of(valid.replaceFirst(" call void @ndkp_cse_module_recheck[^\\n]+\\n", ""),
                    valid.replaceFirst(" call void @ndkp_cse_module_recheck", " br label %later\nlater:\n call void @ndkp_cse_module_recheck"),
                    valid.replace("@ndkp_qseg_recheck(","@wrong_runtime(" ).replace("@ndkp_cse_recheck_module_v1(","@wrong_runtime("),
                    bypass,
                    valid.replace("load volatile", "load"),valid+"!ndkp.cse.recheck.prepare !0\n")) {
                if(segmented&&broken.equals(valid))continue;
                assertThrows(IllegalStateException.class,()->NativeCompiler.verifyRecheckIr(broken,"entry",segmented));
            }
            assertThrows(IllegalStateException.class,()->NativeCompiler.verifyRecheckIr(valid,"entry",!segmented));
            String runtimeCall="call void @"+runtime+(segmented?"()":"(ptr %module)");
            for(String fake:List.of("call void %callback(ptr @"+runtime+"())",
                    "call void asm sideeffect \"call void @"+runtime+"()\", \"\"()",
                    "; call void @"+runtime+"()")) {
                String changed=valid.replace(runtimeCall,fake);
                assertThrows(IllegalStateException.class,()->NativeCompiler.verifyRecheckIr(changed,"entry",segmented));
            }
        }
        assertEquals("ndkp_qseg_recheck",NativeCompiler.verifyRecheckIr("define void @entry() {\n call void @ndkp_qseg_recheck()\n ret void\n}\n","entry",true));
    }
    @Test void indirectInvokeOrAsmCannotPrecedeTheFirstCheckpointCall() {
        for(boolean segmented:List.of(false,true)) {
            String valid=ir(segmented).replace("@entry()","@entry(ptr %callback)");
            String guard=segmented?"ndkp_cse_module_recheck_v2":"ndkp_cse_module_recheck";
            for(String earlier:List.of("call void %callback()",
                    "invoke void %callback() to label %next unwind label %error",
                    "invoke void @business() to label %next unwind label %error",
                    "call void asm sideeffect \"\", \"\"()",
                    "call void asm sideeffect \"@"+guard+"(\", \"\"()",
                    "call void %callback(ptr @"+guard+")")) {
                String changed=valid.replace(" call void @"+guard," "+earlier+"\n call void @"+guard);
                assertThrows(IllegalStateException.class,()->NativeCompiler.verifyRecheckIr(changed,"entry",segmented));
            }
            String skipped=valid.replace(" call void @"+guard,
                    " call void @llvm.dbg.value(metadata i32 0)\n call void @llvm.lifetime.start.p0(i64 1, ptr null)\n call void @"+guard);
            assertEquals(guard,NativeCompiler.verifyRecheckIr(skipped,"entry",segmented));
        }
    }
    @Test void guardConditionalBypassFailsAndBothCheckedBranchesPass() {
        for(boolean segmented:List.of(false,true)) {
            String valid=ir(segmented),runtime=segmented?"ndkp_qseg_recheck":"ndkp_cse_recheck_module_v1";
            String split=valid.replace(" call void @"+runtime,
                    " br i1 true, label %check, label %skip\ncheck:\n call void @"+runtime);
            int end=split.lastIndexOf("\n}");
            String bypass=split.substring(0,end)+"\nskip:\n ret void"+split.substring(end);
            assertThrows(IllegalStateException.class,()->NativeCompiler.verifyRecheckIr(bypass,"entry",segmented));
            String both=bypass.replace("\nskip:\n ret void","\nskip:\n call void @"+runtime+"()\n ret void");
            assertDoesNotThrow(()->NativeCompiler.verifyRecheckIr(both,"entry",segmented));
        }
    }
}
