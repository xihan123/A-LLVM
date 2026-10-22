package io.github.xihan123.dex2c.core;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ReceiptTest {
    @Test void cryptoCoresRequireVmBodiesAndIntegrityWithoutBootstrapDependencies() {
        StringBuilder ir=new StringBuilder();
        int id=0;
        for(String symbol:NativeCompiler.CSE_VMP_SYMBOLS) {
            ir.append("@gv_code_seg_").append(symbol).append(" = internal constant [1 x i8] c\"a\"\n")
                    .append("define void @").append(symbol).append("() !ndkp.vmp.protected !").append(++id)
                    .append(" {\n call void @vm_test()\n call i64 @ndkp_selfcheck_one()\n store i64 1, ptr @key, !ndkp.vmpkey.entry !0\n ret void\n}\n")
                    .append("!").append(id).append(" = !{ptr @gv_code_seg_").append(symbol).append(", ptr @vm_test}\n");
        }
        ir.append("define void @vm_test() {\n ret void\n}\n");
        String valid=ir.toString();
        assertDoesNotThrow(()->NativeCompiler.verifyCryptoIr(valid));
        for(String broken:List.of(valid.replace("!ndkp.vmp.protected", "!unprotected"),
                valid.replace("@ndkp_selfcheck_one", "@ordinary"),
                valid.replace("!ndkp.vmpkey.entry", "!unbound"),
                valid+"declare void @ndkp_certbind_mix()\n",
                valid+"@strings = global [1 x i8] zeroinitializer, section \".ndkp.cse\"\n"))
            assertThrows(IllegalStateException.class,()->NativeCompiler.verifyCryptoIr(broken));
    }
    @Test void postReceiptMustMatchNativeControlFlow() {
        String symbol="d2c_0123456789abcdef01234567";
        String ir="@gv_code_seg_"+symbol+" = internal global [1 x i8] c\"a\"\n"
                +"define void @"+symbol+"() !ndkp.vmp.protected !1 !ndkp.vmp.post !2 {\n call void @vm_test()\n ret void\n}\n"
                +"define void @vm_test() section \".s0\" !ndkp.vmp.post !3 {\n indirectbr ptr %p, [label %a, label %b]\n}\n"
                +"define void @dispatch() section \".s0\" !ndkp.vmp.post !2 {\n ret void\n}\n"
                +"!1 = !{ptr @gv_code_seg_"+symbol+", ptr @vm_test}\n!2 = !{i32 0, i32 0}\n!3 = !{i32 1, i32 1}\n";
        var methods=List.of(symbol);
        assertEquals(3,NativeCompiler.verifyPostIr(ir,methods).size());
        for(String broken:List.of(
                ir.replace("!ndkp.vmp.post !2", ""),
                ir.replace("!ndkp.vmp.post !3", ""),
                ir.replace("i32 1, i32 1", "i32 2, i32 2"),
                ir.replace("i32 1, i32 1", "i32 2, i32 1"),
                ir.replace(" indirectbr", " br i1 %cond, label %a, label %b\n indirectbr"),
                ir.replace(" indirectbr", " switch i32 %x, label %a []\n indirectbr")))
            assertThrows(IllegalStateException.class,()->NativeCompiler.verifyPostIr(broken,methods));
    }
    @Test void receiptRequiresActualBytecodeAndInterpreterCall() {
        String symbol="d2c_0123456789abcdef01234567";
        String ir="@gv_code_seg_"+symbol+" = internal global [1 x i8] c\"a\"\n"
                +"define i32 @"+symbol+"() !ndkp.vmp.protected !1 {\n call void @vm_test()\n ret i32 0\n}\n"
                +"define void @vm_test() {\n ret void\n}\n"
                +"!1 = !{ptr @gv_code_seg_"+symbol+", ptr @vm_test}\n";
        assertDoesNotThrow(()->NativeCompiler.verifyIr(ir,List.of(symbol)));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(ir.replace("call void @vm_test()","call void @ordinary_native()"),List.of(symbol)));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(ir.replace("[1 x i8]","[0 x i8]"),List.of(symbol)));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(ir.replace("!ndkp.vmp.protected !1",""),List.of(symbol)));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(ir.replace(" ret i32 0"," call void @_Z10d2c_invoke()\n ret i32 0"),List.of(symbol)));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyHardenedIr(ir,List.of(symbol)));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(ir+ir,List.of(symbol)),
                "duplicate indexed definitions must fail closed");
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(ir+"!1 = !{}\n",List.of(symbol)),
                "duplicate metadata must fail closed");
    }
    @Test void cseRequiresPayloadAndRemovesPlaintext() {
        String ir="@payload = private global [1 x i8] c\"a\", section \".ndkp.cse\"\ndeclare void @ndkp_cse_decode_region_v1()\n";
        assertDoesNotThrow(()->NativeCompiler.verifyCseIr(ir));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyCseIr(ir.replace(".ndkp.cse",".data")));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyCseIr(ir+"@.str = private constant [7 x i8] c\"secret\\00\"\n"));
    }
    @Test void segmentedReceiptRequiresRetainedDescriptorAndAccessor() {
        String symbol="d2c_0123456789abcdef01234567";
        String ir="@gv_code_seg_"+symbol+" = internal constant i8 0, !ndkp.qseg !2\n"
                +"@ref = private constant [24 x i8] c\"abcdefghijklmnopqrstuvwx\", section \".text.ndkp.qseg.refs\"\n"
                +"define i32 @"+symbol+"() !ndkp.vmp.protected !1 {\n %p = call ptr @ndkp_qseg_get(ptr @ref)\n call void @vm_test()\n ret i32 0\n}\n"
                +"define void @vm_test() {\n ret void\n}\n"
                +"!1 = !{ptr @gv_code_seg_"+symbol+", ptr @vm_test}\n!2 = !{ptr @ref}\n";
        assertDoesNotThrow(()->NativeCompiler.verifyIr(ir,List.of(symbol)));
        for(String broken:List.of(ir.replace("[24 x i8]","[23 x i8]"),
                ir.replace("!2 = !{ptr @ref}","!2 = !{ptr @missing}"),
                ir.replace(".text.ndkp.qseg.refs",".data"),ir.replace("@ndkp_qseg_get(","@ordinary(")))
            assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(broken,List.of(symbol)));
    }
    @Test void finalLibraryMustContainVerifiedBytecode() {
        String symbol="d2c_0123456789abcdef01234567";
        var code=NativeCompiler.bytecodes("@gv_code_seg_"+symbol+" = internal global [4 x i8] c\"a\\00\\\\\\22\"\n",List.of(symbol));
        assertArrayEquals(new byte[]{97,0,92,34},code.get(symbol));
        assertDoesNotThrow(()->NativeCompiler.verifyBytecodesInLibrary(new byte[]{1,97,0,92,34,2},code));
        assertThrows(IllegalStateException.class,()->NativeCompiler.verifyBytecodesInLibrary(new byte[]{1,97,0,93,34,2},code));
    }

    @Test void segmentedLeaseRequiresPairedCallsAndLifetimeReceipt() {
        String symbol="d2c_0123456789abcdef01234567";
        String ir="@gv_code_seg_"+symbol+" = internal constant i8 0, !ndkp.qseg !2\n"
                +"@ref = private constant [24 x i8] c\"abcdefghijklmnopqrstuvwx\", section \".text.ndkp.qseg.refs\"\n"
                +"define i32 @"+symbol+"() !ndkp.vmp.protected !1 !ndkp.qseg.lifetime !3 {\n"
                +" %p = call ptr @ndkp_qseg_acquire_v1(ptr @ref)\n call void @vm_test()\n"
                +" call void @ndkp_qseg_release_v1(ptr @ref)\n ret i32 0\n}\n"
                +"define void @vm_test() {\n ret void\n}\n"
                +"!1 = !{ptr @gv_code_seg_"+symbol+", ptr @vm_test}\n!2 = !{ptr @ref}\n!3 = !{!\"lease-v1\"}\n";
        assertDoesNotThrow(()->NativeCompiler.verifyIr(ir,List.of(symbol)));
        for(String broken:List.of(ir.replace(" call void @ndkp_qseg_release_v1(ptr @ref)\n", ""),
                ir.replace("!ndkp.qseg.lifetime !3", ""), ir.replace("lease-v1", "unknown"),
                ir.replace("@ndkp_qseg_acquire_v1", "@ndkp_qseg_get")))
            assertThrows(IllegalStateException.class,()->NativeCompiler.verifyIr(broken,List.of(symbol)));
    }
}
