package io.github.xihan123.dex2c.core;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;

/** Compile once to verified VMP IR, then emit the object from those exact bytes. */
public final class NativeCompiler {
    static final List<String> CSE_VMP_SYMBOLS=List.of(
            "_ZN8ndkp_cse3vmp6deriveEPKhS2_S2_Ph",
            "_ZN8ndkp_cse3vmp4openEPKhS2_S2_mPhmS2_");
    public void compile(Path generated,Path output,Path ndk,Path compiler,String library,int minSdk,
                        Path certificate,Path python) throws Exception {
        compile(generated,output,ndk,compiler,library,minSdk,certificate,python,false);
    }
    public void compile(Path generated,Path output,Path ndk,Path compiler,String library,int minSdk,
                        Path certificate,Path python,boolean segmented) throws Exception {
        compile(generated,output,ndk,compiler,library,minSdk,certificate,python,segmented,false);
    }
    public void compile(Path generated,Path output,Path ndk,Path compiler,String library,int minSdk,
                        Path certificate,Path python,boolean segmented,boolean verifyApkSignature) throws Exception {
        long started=System.nanoTime();
        if(minSdk<26)throw new IllegalArgumentException("dex2c requires minSdk >= 26");
        if(!library.matches("[A-Za-z][A-Za-z0-9_]*"))throw new IllegalArgumentException("invalid dex2c library name");
        Files.createDirectories(output);
        Files.createDirectories(output.resolve("assets"));
        try(var files=Files.list(output.resolve("assets"))){for(Path file:files.toList())Files.delete(file);}
        Path packaged=output.resolve("jniLibs/arm64-v8a/lib"+library+".so");
        // This task owns jniLibs; a renamed namespace must not leave the previous library packaged.
        if(Files.exists(output.resolve("jniLibs")))try(var files=Files.walk(output.resolve("jniLibs"))) {
            for(Path file:files.filter(Files::isRegularFile).toList())Files.delete(file);
        }
        for(String name:List.of("protection.json","segments.json","protected.ll","protected.o","native.ll","native.o","registration.o","dex2c_runtime.o","linked.so"))
            Files.deleteIfExists(output.resolve(name));
        List<String> symbols=Files.readAllLines(generated.resolve("symbols.txt")).stream().filter(s->!s.isBlank()).toList();
        List<String> nativeSymbols=Files.exists(generated.resolve("native-symbols.txt"))
                ?Files.readAllLines(generated.resolve("native-symbols.txt")).stream().filter(s->!s.isBlank()).toList():List.of();
        if(symbols.isEmpty() && nativeSymbols.isEmpty()) {
            Files.createDirectories(packaged.getParent());
            Files.writeString(output.resolve("protection.json"),"{\"schemaVersion\":1,\"protectedMethods\":0}\n");return;
        }
        if(certificate==null)throw new IllegalArgumentException("dex2c: certificateFile must contain the APK signing certificate (public DER/PEM)");
        byte[] certBytes;
        try(InputStream input=Files.newInputStream(certificate)) {
            certBytes=CertificateFactory.getInstance("X.509").generateCertificate(input).getEncoded();
        }
        Path publicCert=output.resolve("signing-cert.der");Files.write(publicCert,certBytes);
        if(python==null)throw new IllegalArgumentException("dex2c: Python 3 is required to seal hardened CSE; set pythonExecutable");
        Path runtime=Files.createDirectories(output.resolve("a_llvm"));
        for(String name:List.of("ndkp_apkcert.cpp","ndkp_cse_runtime.cpp","cse_crypto.h","cse_region.h","apkcert.h","apkcert_io.h","sha256.h","seal_cse.py","seal_qseg.py","qseg.h","ndkp_qseg_runtime.cpp")) {
            try(InputStream input=Objects.requireNonNull(NativeCompiler.class.getResourceAsStream("/a_llvm/"+name))) {
                Files.copy(input,runtime.resolve(name),StandardCopyOption.REPLACE_EXISTING);
            }
        }
        if(verifyApkSignature)ApkVerifierBuild.prepare(runtime,certBytes);
        Properties properties=new Properties();
        try(Reader reader=Files.newBufferedReader(ndk.resolve("source.properties"))){properties.load(reader);}
        if(!properties.getProperty("Pkg.Revision","").startsWith("30."))throw new IllegalArgumentException("dex2c requires NDK r30");
        String host=System.getProperty("os.name").startsWith("Windows")?"windows-x86_64":"linux-x86_64";
        Path prebuilt=ndk.resolve("toolchains/llvm/prebuilt/"+host);
        if(compiler==null)compiler=prebuilt.resolve("bin/clang"+(host.startsWith("windows")?".exe":""));
        run(List.of(compiler.toString(),"--version"),output.resolve("compiler.log"));
        String version=Files.readString(output.resolve("compiler.log"));
        if(!Pattern.compile("clang version 21\\.").matcher(version).find())throw new IllegalArgumentException("dex2c requires Clang 21: "+version.strip());
        Path resource;
        try(var paths=Files.list(prebuilt.resolve("lib/clang"))){resource=paths.filter(Files::isDirectory).filter(p->p.getFileName().toString().startsWith("21")).findFirst().orElseThrow(()->new IOException("NDK r30 Clang 21 resource directory missing"));}
        List<String> common=List.of(compiler.toString(),"--driver-mode=g++","--target=aarch64-linux-android"+minSdk,
                "--sysroot="+prebuilt.resolve("sysroot"),"-resource-dir="+resource,"-std=gnu++17","-fPIC","-fvisibility=hidden",
                "-fno-exceptions","-frtti","-fno-fast-math","-ffp-contract=off","-ffunction-sections","-fdata-sections","-I"+generated.toAbsolutePath());
        if(verifyApkSignature)common=command(common,"-DNDKP_APK_VERIFY");
        List<String> hardened=command(common,"-mllvm","-irobf-cse","-mllvm","-irobf-cse-hardened",
                "-mllvm","-irobf-cert-bind","-mllvm","-irobf-cert-file="+publicCert.toAbsolutePath());
        String runtimeKey=runtimeFingerprint(runtime,compiler,ndk,resource,publicCert);
        Path runtimeCache=output.resolve("runtime-cache");
        Path ir=output.resolve("protected.ll"),object=output.resolve("protected.o");
        Path rawIr=output.resolve("protected.raw.ll");
        List<Path> stages=new ArrayList<>();
        Path protectedStage=output.resolve("staging/protected");
        run(command(segmentFlags(hardened,segmented && !symbols.isEmpty(),protectedStage,stages),"-O1","-fno-vectorize","-fno-slp-vectorize","-fno-unroll-loops","-DD2C_VMP",
                "-mllvm","-irobf-vmp","-mllvm","-irobf-vmp-strict","-mllvm","-irobf-selfcheck","-mllvm","-irobf-selfcheck-entry",
                "-S","-emit-llvm",generated.resolve("protected.cpp").toString(),"-o",rawIr.toString()),output.resolve("vmp.log"));
        IrIndex rawIndex=new IrIndex(Files.readString(rawIr));
        if(!symbols.isEmpty())verifyHardenedIr(rawIndex,symbols);
        // The post pass runs after size optimization; no optimizer may run after verification.
        run(command(symbols.isEmpty()?common:command(common,"-mllvm","-irobf-vmp-post"),"-Oz","-S","-emit-llvm",rawIr.toString(),"-o",ir.toString()),output.resolve("optimize.log"));
        IrIndex index=new IrIndex(Files.readString(ir));
        if(!symbols.isEmpty())verifyHardenedIr(index,symbols);
        Map<String,Integer> postBranches=verifyPostIr(index,symbols);
        Map<String,byte[]> bytecodes=symbols.isEmpty()?Map.of():segmented?stagedBytecodes(protectedStage,symbols):bytecodes(index,symbols);
        Map<String,byte[]> originalBytecodes=segmented?bytecodes:bytecodes(rawIndex,symbols);
        if(segmented && !symbols.isEmpty())verifySegmentedIrPair(rawIndex,index,symbols);
        for(String symbol:symbols)if(!Arrays.equals(bytecodes.get(symbol),originalBytecodes.get(symbol)))
            throw new IllegalStateException("dex2c: VM bytecode changed during size optimization: "+symbol);
        String irHash=hash(ir);
        run(command(common,"-Oz","-Xclang","-disable-llvm-passes","-c",ir.toString(),"-o",object.toString()),output.resolve("object.log"));
        if(!irHash.equals(hash(ir)))throw new IOException("dex2c: verified IR changed during object compilation");
        List<String> objects=new ArrayList<>();objects.add(object.toString());
        if(verifyApkSignature)objects.addAll(ApkVerifierBuild.compile(common,runtime,output,runtimeCache,runtimeKey));
        if(!nativeSymbols.isEmpty()) {
            Path nativeIr=output.resolve("native.ll"),nativeObject=output.resolve("native.o");
            run(command(segmentFlags(hardened,segmented,output.resolve("staging/native"),stages),"-Oz","-S","-emit-llvm",generated.resolve("native.cpp").toString(),"-o",nativeIr.toString()),output.resolve("native.log"));
            verifyNativeIr(Files.readString(nativeIr),nativeSymbols);
            String nativeIrHash=hash(nativeIr);
            run(command(common,"-Oz","-Xclang","-disable-llvm-passes","-c",nativeIr.toString(),"-o",nativeObject.toString()),output.resolve("native-object.log"));
            if(!nativeIrHash.equals(hash(nativeIr)))throw new IOException("dex2c: verified native IR changed during compilation");
            objects.add(nativeObject.toString());
        }
        for(String source:List.of("registration","dex2c_runtime")) {
            Path target=output.resolve(source+".o");
            Path helperIr=output.resolve(source+".ll");
            // Flatten the registration boundary. Inflating generic JNI arithmetic/array helpers adds no business protection.
            List<String> helperFlags=source.equals("registration")?command(hardened,"-mllvm","-irobf-fla"):hardened;
            run(command(segmentFlags(helperFlags,segmented,output.resolve("staging/"+source),stages),"-Oz","-S","-emit-llvm",generated.resolve(source+".cpp").toString(),"-o",helperIr.toString()),output.resolve(source+".log"));
            verifyCseIr(Files.readString(helperIr));
            run(command(common,"-Oz","-Xclang","-disable-llvm-passes","-c",helperIr.toString(),"-o",target.toString()),output.resolve(source+"-object.log"));
            objects.add(target.toString());
        }
        Path certObject=output.resolve("ndkp_apkcert.o");
        cachedRun(command(common,"-Oz","-fno-lto","-c",runtime.resolve("ndkp_apkcert.cpp").toString(),"-o",certObject.toString()),output.resolve("ndkp_apkcert.log"),certObject,runtimeCache,runtimeKey);
        objects.add(certObject.toString());
        // No CSE/cert-bind on the bootstrap TU: only the annotated crypto cores
        // are virtualized, so reading certificate and code inputs cannot recurse.
        Path cseRaw=output.resolve("cse-runtime.raw.ll"),cseIr=output.resolve("cse-runtime.ll");
        Path cseObject=output.resolve("ndkp_cse_runtime.o");
        List<String> cryptoCommon=segmented?command(common,"-DNDKP_QSEG"):common;
        cachedRun(command(cryptoCommon,"-O1","-fno-lto","-fno-vectorize","-fno-slp-vectorize","-fno-unroll-loops",
                "-DNDKP_CSE_VMP","-mllvm","-irobf-vmp","-mllvm","-irobf-vmp-strict",
                "-mllvm","-irobf-vmp-memops","-mllvm","-irobf-selfcheck","-mllvm","-irobf-selfcheck-entry",
                "-S","-emit-llvm",runtime.resolve("ndkp_cse_runtime.cpp").toString(),"-o",cseRaw.toString()),output.resolve("cse-vmp.log"),cseRaw,runtimeCache,runtimeKey);
        IrIndex cseRawIndex=new IrIndex(Files.readString(cseRaw));
        verifyCryptoIr(cseRawIndex);
        cachedRun(command(common,"-Oz","-mllvm","-irobf-vmp-post","-S","-emit-llvm",cseRaw.toString(),"-o",cseIr.toString()),output.resolve("cse-optimize.log"),cseIr,runtimeCache,runtimeKey+hash(cseRaw));
        IrIndex cseIndex=new IrIndex(Files.readString(cseIr));
        verifyCryptoIr(cseIndex);
        Map<String,Integer> cseBranches=verifyPostIr(cseIndex,CSE_VMP_SYMBOLS);
        Map<String,byte[]> cseBytecodes=bytecodes(cseIndex,CSE_VMP_SYMBOLS);
        Map<String,byte[]> cseOriginal=bytecodes(cseRawIndex,CSE_VMP_SYMBOLS);
        for(String symbol:CSE_VMP_SYMBOLS)if(!Arrays.equals(cseBytecodes.get(symbol),cseOriginal.get(symbol)))
            throw new IllegalStateException("dex2c: CSE VM bytecode changed during optimization: "+symbol);
        String cseIrHash=hash(cseIr);
        cachedRun(command(common,"-Oz","-fno-lto","-Xclang","-disable-llvm-passes","-c",cseIr.toString(),"-o",cseObject.toString()),output.resolve("cse-object.log"),cseObject,runtimeCache,runtimeKey+cseIrHash);
        if(!cseIrHash.equals(hash(cseIr)))throw new IOException("dex2c: verified CSE IR changed during compilation");
        objects.add(cseObject.toString());
        Path container=output.resolve("assets/"+library+".qseg");
        List<String> sealSegments=new ArrayList<>(List.of(python.toString(),runtime.resolve("seal_qseg.py").toString(),
                "--cert-file",publicCert.toString()));
        for(Path stage:stages)sealSegments.addAll(List.of("--staging",stage.toString()));
        if(segmented) {
            Path imageSource=output.resolve("qseg-image.cpp"),imageObject=output.resolve("qseg-image.o");
            run(command(sealSegments,"--asset","assets/"+library+".qseg","--source",imageSource.toString()),output.resolve("qseg-prepare.log"));
            run(command(common,"-Oz","-fno-lto","-c",imageSource.toString(),"-o",imageObject.toString()),output.resolve("qseg-image.log"));
            objects.add(imageObject.toString());
            Path loaderObject=output.resolve("qseg-runtime.o");
            cachedRun(command(common,"-Oz","-fno-lto","-c",runtime.resolve("ndkp_qseg_runtime.cpp").toString(),"-o",loaderObject.toString()),output.resolve("qseg-runtime.log"),loaderObject,runtimeCache,runtimeKey);
            objects.add(loaderObject.toString());
        }
        Files.createDirectories(packaged.getParent());
        Path exports=output.resolve("exports.map"),linked=output.resolve("linked.so");
        Files.writeString(exports,"{ global: JNI_OnLoad; local: *; };\n");
        List<String> link=new ArrayList<>(common);link.addAll(objects);
        if(verifyApkSignature)link.add("-lz");
        if(segmented)link.addAll(List.of("-lz","-Wl,--rosegment"));
        link.addAll(List.of("--ld-path="+prebuilt.resolve("bin/ld.lld"+(host.startsWith("windows")?".exe":"")),"-shared","-static-libstdc++",
                "-Wl,--gc-sections","-Wl,--exclude-libs,ALL","-Wl,--version-script="+exports.toAbsolutePath(),
                "-Wl,--no-undefined","-Wl,-z,max-page-size=16384","-Wl,-z,common-page-size=16384","-lm","-ldl","-llog","-o",linked.toString()));
        run(link,output.resolve("link.log"));
        if(segmented)run(command(sealSegments,"--input",linked.toString(),"--output",packaged.toString(),"--container",container.toString(),
                "--receipt",output.resolve("segments.json").toString()),output.resolve("seal.log"));
        else run(List.of(python.toString(),runtime.resolve("seal_cse.py").toString(),"--input",linked.toString(),"--output",packaged.toString()),output.resolve("seal.log"));
        Path strip=prebuilt.resolve("bin/llvm-strip"+(host.startsWith("windows")?".exe":""));
        run(List.of(strip.toString(),"--strip-unneeded","-R",".comment",packaged.toString()),output.resolve("strip.log"));
        if(segmented) {
            run(command(sealSegments,"--input",packaged.toString(),"--verify","--container",container.toString()),output.resolve("seal-verify.log"));
            byte[] finalLibrary=Files.readAllBytes(packaged);
            for(byte[] code:bytecodes.values())if(indexOf(finalLibrary,code)>=0)throw new IllegalStateException("dex2c: external VM duplicate survived in SO");
        } else {
            run(List.of(python.toString(),runtime.resolve("seal_cse.py").toString(),"--input",packaged.toString(),"--verify","--cert-file",publicCert.toString()),output.resolve("seal-verify.log"));
            verifyBytecodesInLibrary(Files.readAllBytes(packaged),bytecodes);
        }
        verifyBytecodesInLibrary(Files.readAllBytes(packaged),cseBytecodes);
        Files.writeString(output.resolve("protection.json"),"{\"schemaVersion\":"+(segmented?5:4)+",\"abi\":\"arm64-v8a\",\"protectedMethods\":"+(symbols.size()+nativeSymbols.size())
                +",\"vmpMethods\":"+symbols.size()+",\"nativeMethods\":"+nativeSymbols.size()
                +",\"apkSignatureVerification\":"+verifyApkSignature
                +",\"cseVmpMethods\":"+CSE_VMP_SYMBOLS.size()+",\"cseRuntimeIrSha256\":"+Transformer.json(cseIrHash)
                +",\"cseVmpIndirectBranches\":{"+String.join(",",cseBranches.entrySet().stream().map(e->Transformer.json(e.getKey())+":"+e.getValue()).toList())+"}"
                +",\"nativeSymbols\":["+String.join(",",nativeSymbols.stream().map(Transformer::json).toList())+"]"
                +",\"vmpStrict\":true,\"cseHardened\":true,\"selfCheckEntry\":true,\"certificateBound\":true,\"registrationFlattening\":true"
                +",\"vmpPost\":true,\"nativeIndirectBranches\":{"
                +String.join(",",postBranches.entrySet().stream().map(e->Transformer.json(e.getKey())+":"+e.getValue()).toList())+"}"
                +",\"certificateSha256\":"+Transformer.json(hash(publicCert))+",\"compileMillis\":"+(System.nanoTime()-started)/1000000
                +",\"irSha256\":"+Transformer.json(irHash)+",\"objectSha256\":"+Transformer.json(hash(object))
                +",\"selectionSha256\":"+Transformer.json(hash(generated.resolve("selection.json")))
                +",\"nativeIrSha256\":"+(nativeSymbols.isEmpty()?"null":Transformer.json(hash(output.resolve("native.ll"))))
                +",\"librarySha256\":"+Transformer.json(hash(packaged))+",\"libraryBytes\":"+Files.size(packaged)
                +",\"segmentedData\":"+segmented+",\"containerSha256\":"+(segmented?Transformer.json(hash(container)):"null")
                +",\"qsegLifetimeAbi\":"+(segmented?1:0)+",\"idlePlaintextBudgetBytes\":"+(segmented?1048576:0)
                +",\"vmLifetimePolicies\":{"+(segmented?String.join(",",symbols.stream().map(symbol->
                    Transformer.json(symbol)+":"+Transformer.json(segmentLifetime(index,symbol))).toList()):"")+"}"
                +",\"containerBytes\":"+(segmented?Files.size(container):0)+",\"segmentsReceiptSha256\":"+(segmented?Transformer.json(hash(output.resolve("segments.json"))):"null")
                +",\"bytecodeVerifiedInLibrary\":"+!segmented+",\"bytecodeVerifiedInContainer\":"+segmented+",\"methodBytecodeBytes\":{"
                +String.join(",",bytecodes.entrySet().stream().map(e->Transformer.json(e.getKey())+":"+e.getValue().length).toList())+"}"
                +",\"symbols\":["+String.join(",",symbols.stream().map(Transformer::json).toList())+"]}\n");
    }
    private record IrFunction(String header,String body) {}
    private record VmReceipt(String code,String interpreter) {}
    /** Index definitions once; per-method full-module regex searches dominate large VM IR. */
    private static final class IrIndex {
        final String text;
        final Map<String,IrFunction> functions=new LinkedHashMap<>();
        final Map<String,String> metadata=new HashMap<>(),globals=new HashMap<>();
        IrIndex(String text) {
            this.text=text;
            Matcher definitions=Pattern.compile("(?m)^(define [^\\n]*@([A-Za-z0-9_.$]+)\\([^\\n]* \\{)\\n").matcher(text);
            while(definitions.find()) {
                int end=text.indexOf("\n}",definitions.end());
                if(end<0)throw new IllegalStateException("dex2c: unterminated IR function");
                if(functions.put(definitions.group(2),new IrFunction(definitions.group(1),
                        text.substring(definitions.end(),end)))!=null)
                    throw new IllegalStateException("dex2c: duplicate IR function");
                definitions.region(end+2,text.length());
            }
            Matcher nodes=Pattern.compile("(?m)^!(\\d+) = ([^\\n]*)$").matcher(text);
            while(nodes.find())if(metadata.put(nodes.group(1),nodes.group(2))!=null)
                throw new IllegalStateException("dex2c: duplicate IR metadata");
            Matcher code=Pattern.compile("(?m)^@([A-Za-z0-9_.$]+) = ([^\\n]*)$").matcher(text);
            while(code.find())if(globals.put(code.group(1),code.group(2))!=null)
                throw new IllegalStateException("dex2c: duplicate VM bytecode");
        }
        VmReceipt receipt(String symbol) {
            IrFunction function=functions.get(symbol);
            Matcher marker=Pattern.compile("!ndkp\\.vmp\\.protected !(\\d+)").matcher(function==null?"":function.header());
            if(!marker.find())throw new IllegalStateException("dex2c: missing VMP receipt for "+symbol);
            Matcher receipt=Pattern.compile("!\\{ptr @(gv_code_seg_"+Pattern.quote(symbol)+"), ptr @([A-Za-z0-9_.$]+)}")
                    .matcher(metadata.getOrDefault(marker.group(1),""));
            if(!receipt.matches())throw new IllegalStateException("dex2c: invalid VMP receipt for "+symbol);
            return new VmReceipt(receipt.group(1),receipt.group(2));
        }
    }
    public static void verifyNativeIr(String ir,List<String> symbols) {
        IrIndex index=new IrIndex(ir);
        for(String symbol:symbols) {
            if(!symbol.matches("d2c_[a-f0-9]{24}"))throw new IllegalArgumentException("invalid protected symbol: "+symbol);
            if(!index.functions.containsKey(symbol))
                throw new IllegalStateException("dex2c: missing native implementation for "+symbol);
        }
        if(ir.contains("!ndkp.vmp.protected"))throw new IllegalStateException("dex2c: native callback unexpectedly virtualized");
        if(Pattern.compile("(?m)^@\\.str[^\\n]*\\bconstant\\b[^\\n]*c\"").matcher(ir).find())
            throw new IllegalStateException("dex2c: plaintext string survived native CSE");
        if(ir.contains("section \".ndkp.cse\""))verifyCseIr(ir);
    }
    public static void verifyIr(String ir,List<String> symbols) {
        verifyIr(new IrIndex(ir),symbols);
    }
    private static void verifyIr(IrIndex ir,List<String> symbols) {
        for(String symbol:symbols) {
            if(!symbol.matches("d2c_[a-f0-9]{24}") && !CSE_VMP_SYMBOLS.contains(symbol))throw new IllegalArgumentException("invalid protected symbol: "+symbol);
            VmReceipt receipt=ir.receipt(symbol);
            if(ir.globals.getOrDefault(receipt.code(),"").contains("!ndkp.qseg"))segmentDescriptor(ir,symbol);
            IrFunction function=ir.functions.get(symbol);
            if(Pattern.compile("\\b(call|invoke)\\b[^\\n]*@(?:_Z[0-9]+)?d2c_").matcher(function.body()).find()
                    || ir.functions.containsKey(symbol+"_original"))
                throw new IllegalStateException("dex2c: original implementation survived VMP for "+symbol);
            if(!(Pattern.compile("\\[[1-9][0-9]* x i8] c\"").matcher(ir.globals.getOrDefault(receipt.code(),"")).find()
                    || (ir.globals.getOrDefault(receipt.code(),"").contains("!ndkp.qseg") &&
                        (function.body().contains("@ndkp_qseg_get(") || function.body().contains("@ndkp_qseg_acquire_v1("))))
                    || !ir.functions.containsKey(receipt.interpreter())
                    || !Pattern.compile("\\bcall\\b[^\\n]*@"+Pattern.quote(receipt.interpreter())+"\\(").matcher(function.body()).find())
                throw new IllegalStateException("dex2c: missing bytecode or interpreter call for "+symbol);
            if(ir.globals.getOrDefault(receipt.code(),"").contains("!ndkp.qseg"))verifySegmentLifetime(ir,symbol);
        }
    }
    public static void verifyHardenedIr(String ir,List<String> symbols) {
        verifyHardenedIr(new IrIndex(ir),symbols);
    }
    private static void verifyHardenedIr(IrIndex ir,List<String> symbols) {
        verifyIr(ir,symbols);verifyCseIr(ir.text);
        for(String symbol:symbols) {
            String body=ir.functions.get(symbol).body();
            if(!body.contains("@ndkp_cert_k64") || !body.contains("@ndkp_selfcheck_one")
                    || !body.contains("!ndkp.vmpkey.entry"))
                throw new IllegalStateException("dex2c: missing certificate/integrity key binding for "+symbol);
        }
        if(!ir.text.contains("call void @ndkp_certbind_mix("))throw new IllegalStateException("dex2c: missing certificate runtime initialization");
    }
    public static void verifyCseIr(String ir) {
        if((!ir.contains("section \".ndkp.cse\"") || !ir.contains("@ndkp_cse_decode_region_v1("))
                && (!ir.contains("@ndkp_qseg_copy(") || !ir.contains("section \".text.ndkp.qseg.refs\"")))
            throw new IllegalStateException("dex2c: missing hardened CSE payload/runtime");
        if(Pattern.compile("(?m)^@\\.str[^\\n]*\\bconstant\\b[^\\n]*c\"").matcher(ir).find())
            throw new IllegalStateException("dex2c: plaintext string survived CSE");
    }
    static void verifyCryptoIr(String ir) {
        verifyCryptoIr(new IrIndex(ir));
    }
    private static void verifyCryptoIr(IrIndex ir) {
        verifyIr(ir,CSE_VMP_SYMBOLS);
        for(String symbol:CSE_VMP_SYMBOLS) {
            String body=ir.functions.get(symbol).body();
            if(!body.contains("@ndkp_selfcheck_one") || !body.contains("!ndkp.vmpkey.entry"))
                throw new IllegalStateException("dex2c: missing CSE VM integrity binding for "+symbol);
        }
        if(ir.text.contains("section \".ndkp.cse\"") || ir.text.contains("@ndkp_certbind_mix("))
            throw new IllegalStateException("dex2c: CSE runtime must not depend on bound strings/cert initialization");
    }
    /** Verify the actual native CFG as well as the compiler's post-pass receipts. */
    public static Map<String,Integer> verifyPostIr(String ir,List<String> symbols) {
        return verifyPostIr(new IrIndex(ir),symbols);
    }
    private static Map<String,Integer> verifyPostIr(IrIndex ir,List<String> symbols) {
        verifyIr(ir,symbols);
        Set<String> required=new HashSet<>(symbols);
        for(String symbol:symbols) {
            required.add(ir.receipt(symbol).interpreter());
        }
        Map<String,Integer> result=new LinkedHashMap<>();
        for(var entry:ir.functions.entrySet()) {
            String header=entry.getValue().header(),name=entry.getKey(),body=entry.getValue().body();
            if(!required.contains(name) && !header.contains("section \".s0\"") && !header.contains("section \".AProtect.text\""))continue;
            Matcher marker=Pattern.compile("!ndkp\\.vmp\\.post !(\\d+)").matcher(header);
            if(!marker.find())throw new IllegalStateException("dex2c: missing VMP post receipt for "+name+" (requires A-LLVM p11)");
            Matcher receipt=Pattern.compile("!\\{i32 (\\d+), i32 (\\d+)}").matcher(ir.metadata.getOrDefault(marker.group(1),""));
            long branches=Pattern.compile("(?m)^\\s*indirectbr ").matcher(body).results().count();
            if(!receipt.matches() || Long.parseLong(receipt.group(1))!=branches || Long.parseLong(receipt.group(2))!=branches
                    || Pattern.compile("(?m)^\\s*(switch\\s|br\\s+i1\\s)").matcher(body).find())
                throw new IllegalStateException("dex2c: invalid VMP post control flow for "+name);
            result.put(name,Math.toIntExact(branches));
        }
        if(!result.keySet().containsAll(required))throw new IllegalStateException("dex2c: unverified native VMP artifacts");
        return result;
    }
    static Map<String,byte[]> bytecodes(String ir,List<String> symbols) {
        return bytecodes(new IrIndex(ir),symbols);
    }
    private static Map<String,byte[]> bytecodes(IrIndex ir,List<String> symbols) {
        Map<String,byte[]> result=new LinkedHashMap<>();
        for(String symbol:symbols) {
            Matcher global=Pattern.compile("\\[([0-9]+) x i8] c\"([^\"\\n]+)\"").matcher(ir.globals.getOrDefault("gv_code_seg_"+symbol,""));
            if(!global.find())throw new IllegalStateException("dex2c: bytecode missing: "+symbol);
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();String value=global.group(2);
            for(int i=0;i<value.length();i++) {
                char c=value.charAt(i);
                if(c!='\\')bytes.write(c);
                else if(value.charAt(i+1)=='\\'){bytes.write('\\');i++;}
                else {bytes.write(Integer.parseInt(value.substring(i+1,i+3),16));i+=2;}
            }
            if(bytes.size()!=Integer.parseInt(global.group(1)))throw new IllegalStateException("dex2c: invalid bytecode length: "+symbol);
            result.put(symbol,bytes.toByteArray());
        }
        return result;
    }
    static void verifyBytecodesInLibrary(byte[] library,Map<String,byte[]> bytecodes) {
        String contents=new String(library,java.nio.charset.StandardCharsets.ISO_8859_1);
        for(var entry:bytecodes.entrySet())if(!contents.contains(new String(entry.getValue(),java.nio.charset.StandardCharsets.ISO_8859_1)))
            throw new IllegalStateException("dex2c: verified bytecode missing from SO: "+entry.getKey());
    }
    private static int indexOf(byte[] bytes,byte[] value) {
        return new String(bytes,java.nio.charset.StandardCharsets.ISO_8859_1).indexOf(new String(value,java.nio.charset.StandardCharsets.ISO_8859_1));
    }
    private static List<String> segmentFlags(List<String> flags,boolean enabled,Path directory,List<Path> stages) throws IOException {
        if(!enabled)return flags;
        Files.createDirectories(directory);
        // A failed compile cannot accidentally reuse a previous staging manifest.
        try(var files=Files.list(directory)){for(Path file:files.toList())Files.delete(file);}
        stages.add(directory);
        return command(flags,"-mllvm","-irobf-segmented-data","-mllvm","-irobf-segmented-output="+directory.toAbsolutePath());
    }
    private static Map<String,byte[]> stagedBytecodes(Path stage,List<String> symbols) throws IOException {
        Map<String,byte[]> result=new LinkedHashMap<>();
        for(String symbol:symbols) {
            byte[] data=Files.readAllBytes(stage.resolve(symbol+".bin"));
            if(data.length==0)throw new IllegalStateException("empty staged bytecode");
            result.put(symbol,data);
        }
        return result;
    }
    private static String segmentDescriptor(IrIndex index,String symbol) {
        String token=index.globals.getOrDefault("gv_code_seg_"+symbol,"");
        Matcher marker=Pattern.compile("!ndkp\\.qseg !(\\d+)").matcher(token);
        if(!marker.find())throw new IllegalStateException("missing segmented receipt for "+symbol);
        Matcher ref=Pattern.compile("!\\{ptr @([A-Za-z0-9_.$]+)}").matcher(index.metadata.getOrDefault(marker.group(1),""));
        if(!ref.matches())throw new IllegalStateException("invalid segmented receipt for "+symbol);
        String global=index.globals.getOrDefault(ref.group(1),"");
        Matcher bytes=Pattern.compile("\\[24 x i8] c\"([^\"]*)\"").matcher(global);
        if(!bytes.find() || !global.contains(".text.ndkp.qseg.refs"))throw new IllegalStateException("invalid segmented descriptor");
        return bytes.group(1);
    }
    private static String segmentLifetime(IrIndex index,String symbol) {
        IrFunction function=index.functions.get(symbol);
        Matcher marker=Pattern.compile("!ndkp\\.qseg\\.lifetime !(\\d+)").matcher(function.header());
        if(!marker.find())return "pinned-legacy";
        String node=index.metadata.getOrDefault(marker.group(1),"");
        Matcher mode=Pattern.compile("!\\{!\"([^\"]+)\"}").matcher(node);
        if(!mode.matches())throw new IllegalStateException("dex2c: invalid segmented lifetime receipt for "+symbol);
        return mode.group(1);
    }
    private static void verifySegmentLifetime(IrIndex index,String symbol) {
        IrFunction function=index.functions.get(symbol);
        String mode=segmentLifetime(index,symbol);
        if(mode.equals("pinned-legacy")) {
            if(!function.body().contains("@ndkp_qseg_get("))
                throw new IllegalStateException("dex2c: missing segmented lifetime receipt for "+symbol);
            return; // 旧编译器固定驻留接口保留兼容，不能宣称可回收。
        }
        long acquired=Pattern.compile("@ndkp_qseg_acquire_v1\\(").matcher(function.body()).results().count();
        long released=Pattern.compile("@ndkp_qseg_release_v1\\(").matcher(function.body()).results().count();
        boolean pinned=function.body().contains("@ndkp_qseg_get(");
        if(acquired!=released || (mode.equals("lease-v1") ? pinned || acquired==0 :
                !mode.equals("pinned-unproven-unwind") || !pinned))
            throw new IllegalStateException("dex2c: invalid segmented lifetime calls for "+symbol);
    }
    private static void verifySegmentedIrPair(IrIndex raw,IrIndex optimized,List<String> symbols) {
        for(String symbol:symbols) {
            if(!segmentDescriptor(raw,symbol).equals(segmentDescriptor(optimized,symbol)))
                throw new IllegalStateException("segmented VM descriptor changed during optimization: "+symbol);
            if(!segmentLifetime(raw,symbol).equals(segmentLifetime(optimized,symbol)))
                throw new IllegalStateException("segmented VM lifetime changed during optimization: "+symbol);
            verifySegmentLifetime(raw,symbol); verifySegmentLifetime(optimized,symbol);
        }
    }
    private static List<String> command(List<String> prefix,String... arguments) {List<String> result=new ArrayList<>(prefix);result.addAll(List.of(arguments));return result;}
    static String runtimeFingerprint(Path runtime,Path compiler,Path ndk,Path resource,Path certificate) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        for(Path file:List.of(compiler,ndk.resolve("source.properties"),certificate))digest.update(hash(file).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for(Path directory:List.of(runtime,resource.resolve("include"),ndk.resolve("toolchains/llvm/prebuilt/"+
                (System.getProperty("os.name").startsWith("Windows")?"windows-x86_64":"linux-x86_64")+"/sysroot/usr/include"))) {
            try(var paths=Files.walk(directory)) {
                for(Path path:paths.filter(Files::isRegularFile)
                        .filter(p->!directory.equals(runtime)||!runtime.relativize(p).startsWith("__pycache__"))
                        .sorted().toList()) {
                    digest.update(directory.relativize(path).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    digest.update(hash(path).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    static void cachedRun(List<String> command,Path log,Path artifact,Path cache,String inputs) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        digest.update(inputs.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for(String argument:command){digest.update((byte)0);digest.update(argument.getBytes(java.nio.charset.StandardCharsets.UTF_8));}
        Path entry=cache.resolve(HexFormat.of().formatHex(digest.digest()));
        Path cached=entry.resolve("artifact"),receipt=entry.resolve("sha256");
        if(Files.isRegularFile(cached)&&Files.isRegularFile(receipt)&&hash(cached).equals(Files.readString(receipt).strip())) {
            Files.copy(cached,artifact,StandardCopyOption.REPLACE_EXISTING);
            Files.writeString(log,"dex2c: runtime cache hit; sha256="+hash(artifact)+"\n");return;
        }
        run(command,log);
        Files.createDirectories(entry);
        Files.copy(artifact,cached,StandardCopyOption.REPLACE_EXISTING);
        Files.writeString(receipt,hash(cached)+"\n");
    }
    private static void run(List<String> command,Path log) throws IOException,InterruptedException {
        Process process=new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if(!process.waitFor(20,TimeUnit.MINUTES)){process.destroyForcibly();throw new IOException("dex2c compiler timed out; "+log);}
        if(process.exitValue()!=0) {
            String text=Files.readString(log);
            throw new IOException("dex2c command failed ("+process.exitValue()+"): "+command.getFirst()+"; "+log+"\n"+text.substring(0,Math.min(text.length(),12000)));
        }
    }
    private static String hash(Path path) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream input=Files.newInputStream(path)){byte[] buffer=new byte[65536];for(int n;(n=input.read(buffer))!=-1;)digest.update(buffer,0,n);}
        return HexFormat.of().formatHex(digest.digest());
    }
}
