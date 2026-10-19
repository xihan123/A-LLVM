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
    public void compile(Path generated,Path output,Path ndk,Path compiler,String library,int minSdk,
                        Path certificate,Path python) throws Exception {
        long started=System.nanoTime();
        if(minSdk<26)throw new IllegalArgumentException("dex2c requires minSdk >= 26");
        if(!library.matches("[A-Za-z][A-Za-z0-9_]*"))throw new IllegalArgumentException("invalid dex2c library name");
        Files.createDirectories(output);
        Path packaged=output.resolve("jniLibs/arm64-v8a/lib"+library+".so");
        // This task owns jniLibs; a renamed namespace must not leave the previous library packaged.
        if(Files.exists(output.resolve("jniLibs")))try(var files=Files.walk(output.resolve("jniLibs"))) {
            for(Path file:files.filter(Files::isRegularFile).toList())Files.delete(file);
        }
        for(String name:List.of("protection.json","protected.ll","protected.o","registration.o","dex2c_runtime.o","linked.so"))
            Files.deleteIfExists(output.resolve(name));
        List<String> symbols=Files.readAllLines(generated.resolve("symbols.txt")).stream().filter(s->!s.isBlank()).toList();
        if(symbols.isEmpty()) {
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
        for(String name:List.of("ndkp_apkcert.cpp","ndkp_cse_runtime.cpp","cse_crypto.h","cse_region.h","apkcert.h","apkcert_io.h","sha256.h","seal_cse.py")) {
            try(InputStream input=Objects.requireNonNull(NativeCompiler.class.getResourceAsStream("/a_llvm/"+name))) {
                Files.copy(input,runtime.resolve(name),StandardCopyOption.REPLACE_EXISTING);
            }
        }
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
        List<String> hardened=command(common,"-mllvm","-irobf-cse","-mllvm","-irobf-cse-hardened",
                "-mllvm","-irobf-cert-bind","-mllvm","-irobf-cert-file="+publicCert.toAbsolutePath());
        Path ir=output.resolve("protected.ll"),object=output.resolve("protected.o");
        Path rawIr=output.resolve("protected.raw.ll");
        run(command(hardened,"-O1","-fno-vectorize","-fno-slp-vectorize","-fno-unroll-loops","-DD2C_VMP",
                "-mllvm","-irobf-vmp","-mllvm","-irobf-vmp-strict","-mllvm","-irobf-selfcheck","-mllvm","-irobf-selfcheck-entry",
                "-S","-emit-llvm",generated.resolve("protected.cpp").toString(),"-o",rawIr.toString()),output.resolve("vmp.log"));
        verifyHardenedIr(Files.readString(rawIr),symbols);
        // The post pass runs after size optimization; no optimizer may run after verification.
        run(command(common,"-Oz","-mllvm","-irobf-vmp-post","-S","-emit-llvm",rawIr.toString(),"-o",ir.toString()),output.resolve("optimize.log"));
        verifyHardenedIr(Files.readString(ir),symbols);
        Map<String,Integer> postBranches=verifyPostIr(Files.readString(ir),symbols);
        Map<String,byte[]> bytecodes=bytecodes(Files.readString(ir),symbols);
        Map<String,byte[]> originalBytecodes=bytecodes(Files.readString(rawIr),symbols);
        for(String symbol:symbols)if(!Arrays.equals(bytecodes.get(symbol),originalBytecodes.get(symbol)))
            throw new IllegalStateException("dex2c: VM bytecode changed during size optimization: "+symbol);
        String irHash=hash(ir);
        run(command(common,"-Oz","-Xclang","-disable-llvm-passes","-c",ir.toString(),"-o",object.toString()),output.resolve("object.log"));
        if(!irHash.equals(hash(ir)))throw new IOException("dex2c: verified IR changed during object compilation");
        List<String> objects=new ArrayList<>();objects.add(object.toString());
        for(String source:List.of("registration","dex2c_runtime")) {
            Path target=output.resolve(source+".o");
            Path helperIr=output.resolve(source+".ll");
            // Flatten the registration boundary. Inflating generic JNI arithmetic/array helpers adds no business protection.
            List<String> helperFlags=source.equals("registration")?command(hardened,"-mllvm","-irobf-fla"):hardened;
            run(command(helperFlags,"-Oz","-S","-emit-llvm",generated.resolve(source+".cpp").toString(),"-o",helperIr.toString()),output.resolve(source+".log"));
            verifyCseIr(Files.readString(helperIr));
            run(command(common,"-Oz","-Xclang","-disable-llvm-passes","-c",helperIr.toString(),"-o",target.toString()),output.resolve(source+"-object.log"));
            objects.add(target.toString());
        }
        for(String source:List.of("ndkp_apkcert","ndkp_cse_runtime")) {
            Path target=output.resolve(source+".o");
            run(command(common,"-Oz","-fno-lto","-c",runtime.resolve(source+".cpp").toString(),"-o",target.toString()),output.resolve(source+".log"));
            objects.add(target.toString());
        }
        Files.createDirectories(packaged.getParent());
        Path exports=output.resolve("exports.map"),linked=output.resolve("linked.so");
        Files.writeString(exports,"{ global: JNI_OnLoad; local: *; };\n");
        List<String> link=new ArrayList<>(common);link.addAll(objects);
        link.addAll(List.of("--ld-path="+prebuilt.resolve("bin/ld.lld"+(host.startsWith("windows")?".exe":"")),"-shared","-static-libstdc++",
                "-Wl,--gc-sections","-Wl,--exclude-libs,ALL","-Wl,--version-script="+exports.toAbsolutePath(),
                "-Wl,--no-undefined","-Wl,-z,max-page-size=16384","-Wl,-z,common-page-size=16384","-lm","-ldl","-llog","-o",linked.toString()));
        run(link,output.resolve("link.log"));
        run(List.of(python.toString(),runtime.resolve("seal_cse.py").toString(),"--input",linked.toString(),"--output",packaged.toString()),output.resolve("seal.log"));
        Path strip=prebuilt.resolve("bin/llvm-strip"+(host.startsWith("windows")?".exe":""));
        run(List.of(strip.toString(),"--strip-unneeded","-R",".comment",packaged.toString()),output.resolve("strip.log"));
        run(List.of(python.toString(),runtime.resolve("seal_cse.py").toString(),"--input",packaged.toString(),"--verify","--cert-file",publicCert.toString()),output.resolve("seal-verify.log"));
        verifyBytecodesInLibrary(Files.readAllBytes(packaged),bytecodes);
        Files.writeString(output.resolve("protection.json"),"{\"schemaVersion\":3,\"abi\":\"arm64-v8a\",\"protectedMethods\":"+symbols.size()
                +",\"vmpStrict\":true,\"cseHardened\":true,\"selfCheckEntry\":true,\"certificateBound\":true,\"registrationFlattening\":true"
                +",\"vmpPost\":true,\"nativeIndirectBranches\":{"
                +String.join(",",postBranches.entrySet().stream().map(e->Transformer.json(e.getKey())+":"+e.getValue()).toList())+"}"
                +",\"certificateSha256\":"+Transformer.json(hash(publicCert))+",\"compileMillis\":"+(System.nanoTime()-started)/1000000
                +",\"irSha256\":"+Transformer.json(irHash)+",\"objectSha256\":"+Transformer.json(hash(object))
                +",\"librarySha256\":"+Transformer.json(hash(packaged))+",\"libraryBytes\":"+Files.size(packaged)
                +",\"bytecodeVerifiedInLibrary\":true,\"methodBytecodeBytes\":{"
                +String.join(",",bytecodes.entrySet().stream().map(e->Transformer.json(e.getKey())+":"+e.getValue().length).toList())+"}"
                +",\"symbols\":["+String.join(",",symbols.stream().map(Transformer::json).toList())+"]}\n");
    }
    public static void verifyIr(String ir,List<String> symbols) {
        for(String symbol:symbols) {
            if(!symbol.matches("d2c_[a-f0-9]{24}"))throw new IllegalArgumentException("invalid protected symbol: "+symbol);
            Matcher function=Pattern.compile("(?m)^define [^\\n]*@"+symbol+"\\([^\\n]*!ndkp\\.vmp\\.protected !(\\d+)[^\\n]* \\{\\n([\\s\\S]*?)^}").matcher(ir);
            if(!function.find())throw new IllegalStateException("dex2c: missing VMP receipt for "+symbol);
            if(Pattern.compile("\\b(call|invoke)\\b[^\\n]*@(?:_Z[0-9]+)?d2c_").matcher(function.group(2)).find()
                    || Pattern.compile("(?m)^define [^\\n]*@"+symbol+"_original\\(").matcher(ir).find())
                throw new IllegalStateException("dex2c: original implementation survived VMP for "+symbol);
            Matcher receipt=Pattern.compile("(?m)^!"+function.group(1)+" = !\\{ptr @(gv_code_seg_"+symbol+"), ptr @([A-Za-z0-9_.$]+)}$").matcher(ir);
            if(!receipt.find())throw new IllegalStateException("dex2c: invalid VMP receipt for "+symbol);
            String code=receipt.group(1),interpreter=receipt.group(2);
            if(!Pattern.compile("(?m)^@"+Pattern.quote(code)+" = .*\\[[1-9][0-9]* x i8] c\"").matcher(ir).find()
                    || !Pattern.compile("(?m)^define [^\\n]*@"+Pattern.quote(interpreter)+"\\(").matcher(ir).find()
                    || !Pattern.compile("\\bcall\\b[^\\n]*@"+Pattern.quote(interpreter)+"\\(").matcher(function.group(2)).find())
                throw new IllegalStateException("dex2c: missing bytecode or interpreter call for "+symbol);
        }
    }
    public static void verifyHardenedIr(String ir,List<String> symbols) {
        verifyIr(ir,symbols);verifyCseIr(ir);
        for(String symbol:symbols) {
            Matcher function=Pattern.compile("(?m)^define [^\\n]*@"+symbol+"\\([^\\n]*\\{\\n([\\s\\S]*?)^}").matcher(ir);
            if(!function.find() || !function.group(1).contains("@ndkp_cert_k64")
                    || !function.group(1).contains("@ndkp_selfcheck_one")
                    || !function.group(1).contains("!ndkp.vmpkey.entry"))
                throw new IllegalStateException("dex2c: missing certificate/integrity key binding for "+symbol);
        }
        if(!ir.contains("call void @ndkp_certbind_mix("))throw new IllegalStateException("dex2c: missing certificate runtime initialization");
    }
    public static void verifyCseIr(String ir) {
        if(!ir.contains("section \".ndkp.cse\"") || !ir.contains("@ndkp_cse_decode_region_v1("))
            throw new IllegalStateException("dex2c: missing hardened CSE payload/runtime");
        if(Pattern.compile("(?m)^@\\.str[^\\n]*\\bconstant\\b[^\\n]*c\"").matcher(ir).find())
            throw new IllegalStateException("dex2c: plaintext string survived CSE");
    }
    /** Verify the actual native CFG as well as the compiler's post-pass receipts. */
    public static Map<String,Integer> verifyPostIr(String ir,List<String> symbols) {
        verifyIr(ir,symbols);
        Set<String> required=new HashSet<>(symbols);
        for(String symbol:symbols) {
            Matcher receipt=Pattern.compile("(?m)^!\\d+ = !\\{ptr @gv_code_seg_"+symbol+", ptr @([A-Za-z0-9_.$]+)}$").matcher(ir);
            if(!receipt.find())throw new IllegalStateException("dex2c: missing VMP receipt for "+symbol);
            required.add(receipt.group(1));
        }
        Map<String,Integer> result=new LinkedHashMap<>();
        Matcher functions=Pattern.compile("(?m)^(define [^\\n]*@([A-Za-z0-9_.$]+)\\([^\\n]* \\{)\\n([\\s\\S]*?)^}").matcher(ir);
        while(functions.find()) {
            String header=functions.group(1),name=functions.group(2),body=functions.group(3);
            if(!required.contains(name) && !header.contains("section \".s0\"") && !header.contains("section \".AProtect.text\""))continue;
            Matcher marker=Pattern.compile("!ndkp\\.vmp\\.post !(\\d+)").matcher(header);
            if(!marker.find())throw new IllegalStateException("dex2c: missing VMP post receipt for "+name+" (requires A-LLVM p11)");
            Matcher receipt=Pattern.compile("(?m)^!"+marker.group(1)+" = !\\{i32 (\\d+), i32 (\\d+)}$").matcher(ir);
            long branches=Pattern.compile("(?m)^\\s*indirectbr ").matcher(body).results().count();
            if(!receipt.find() || Long.parseLong(receipt.group(1))!=branches || Long.parseLong(receipt.group(2))!=branches
                    || Pattern.compile("(?m)^\\s*(switch\\s|br\\s+i1\\s)").matcher(body).find())
                throw new IllegalStateException("dex2c: invalid VMP post control flow for "+name);
            result.put(name,Math.toIntExact(branches));
        }
        if(!result.keySet().containsAll(required))throw new IllegalStateException("dex2c: unverified native VMP artifacts");
        return result;
    }
    static Map<String,byte[]> bytecodes(String ir,List<String> symbols) {
        Map<String,byte[]> result=new LinkedHashMap<>();
        for(String symbol:symbols) {
            Matcher global=Pattern.compile("(?m)^@gv_code_seg_"+symbol+" = .*?\\[([0-9]+) x i8] c\"([^\"\\n]+)\"").matcher(ir);
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
    private static List<String> command(List<String> prefix,String... arguments) {List<String> result=new ArrayList<>(prefix);result.addAll(List.of(arguments));return result;}
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
