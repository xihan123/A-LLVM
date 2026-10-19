"""Check shipped strings, native exports, VM entries and the final APK's DEX wrappers."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import zipfile

from artifacts import verify_wrappers


def literal_leaks(data, strings):
    # Symbol names are ABI metadata, not protected JNI string constants.
    shoff=struct.unpack_from("<Q",data,40)[0]
    size,count=struct.unpack_from("<HH",data,58)
    metadata=[]
    for index in range(count):
        header=shoff+index*size
        if struct.unpack_from("<I",data,header+4)[0]==3:  # SHT_STRTAB
            offset,length=struct.unpack_from("<QQ",data,header+24)
            metadata.append((offset,offset+length))
    leaked=[]; collisions=[]
    diagnostic=b"DW_OP_deref_size with bad size\0"
    for value in strings:
        start=0
        while (offset:=data.find(value,start))>=0:
            start=offset+1
            if any(begin<=offset and offset+len(value)<=end for begin,end in metadata):
                collisions.append({"literalHex":value.hex(),"offset":offset,"reason":"ELF string table"})
            elif value==b"size\0" and data[max(0,offset-len(diagnostic)+len(value)):offset+len(value)]==diagnostic:
                collisions.append({"literalHex":value.hex(),"offset":offset,"reason":"libunwind diagnostic suffix"})
            else:
                leaked.append(value)
    return leaked,collisions


def inspect(generated, native, ndk, apk=None, baseline=None):
    protection=json.loads((native / "protection.json").read_text())
    library=next((native / "jniLibs/arm64-v8a").glob("*.so"))
    data=library.read_bytes()
    assert hashlib.sha256(data).hexdigest()==protection["librarySha256"]
    assert all(protection[k] for k in ("vmpStrict","vmpPost","cseHardened","selfCheckEntry","certificateBound","registrationFlattening","bytecodeVerifiedInLibrary"))
    strings=set()
    for name in ("protected.cpp","registration.cpp","dex2c_runtime.cpp"):
        source=(generated / name).read_text()
        source=re.sub(r'^#include.*$', '',source,flags=re.M)
        for literal in re.findall(r'"(?:\\.|[^"\\])*"',source):
            value=ast.literal_eval(literal).encode("latin1")
            if len(value)>=4:
                strings.add(value+b"\0")
        for values in re.findall(r'\(const jchar\[\]\)\{([0-9,]+)\}',source):
            value=b"".join(struct.pack("<H",int(n)) for n in values.split(","))
            if len(value)>=8:
                strings.add(value)
    leaked,collisions=literal_leaks(data,strings)
    assert not leaked,repr(leaked)
    tools=ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin"
    symbols=subprocess.check_output([tools / "llvm-nm.exe","--dynamic","--defined-only",library],text=True)
    exports=[line.split()[-1] for line in symbols.splitlines() if line.split()]
    assert exports==["JNI_OnLoad"],exports
    sections=subprocess.check_output([tools / "llvm-readelf.exe","--sections",library],text=True)
    assert ".comment" not in sections
    phoff=struct.unpack_from("<Q",data,32)[0]
    entry_size,count=struct.unpack_from("<HH",data,54)
    for i in range(count):
        offset=phoff+i*entry_size
        if struct.unpack_from("<I",data,offset)[0]==1:
            assert struct.unpack_from("<Q",data,offset+48)[0]>=16384
    ir=(native / "protected.ll").read_text()
    entries=[]
    for symbol in protection["symbols"]:
        function=re.search(r'^define [^\n]*@'+symbol+r'\([^\n]*!ndkp.vmp.protected !(\d+)[^\n]* \{\n([\s\S]*?)^}',ir,re.M)
        receipt=re.search(r'^!'+function[1]+r' = !\{ptr @gv_code_seg_'+symbol+r', ptr @([\w.$]+)\}',ir,re.M)
        assert receipt and receipt[1] in function[2]
        assert not re.search(r'\b(call|invoke)\b[^\n]*@(?:_Z[0-9]+)?d2c_',function[2])
        entries.append({"symbol":symbol,"interpreter":receipt[1],"bytecodeBytes":protection["methodBytecodeBytes"][symbol]})
    for name,count in protection["nativeIndirectBranches"].items():
        function=re.search(r'^define [^\n]*@'+re.escape(name)+r'\([^\n]*!ndkp.vmp.post !(\d+)[^\n]* \{\n([\s\S]*?)^}',ir,re.M)
        assert function, name
        body=function[2]
        assert not re.search(r'^\s*(switch\s|br\s+i1\s)',body,re.M), name
        assert len(re.findall(r'^\s*indirectbr ',body,re.M))==count, name
    assert all(e["interpreter"] in protection["nativeIndirectBranches"] for e in entries)
    assert len(set(e["interpreter"] for e in entries))==len(entries)
    result={"protection":protection,"vmEntries":entries,"checkedStringCount":len(strings),"plaintextLeaks":0,"knownLiteralCollisions":collisions,
            "exports":exports,"elf16kAligned":True,"commentSectionRemoved":True}
    if baseline:
        old=baseline.read_bytes()
        result.update(baselineBytes=len(old),reductionPercent=round((1-len(data)/len(old))*100,2),
                      baselinePlaintextCount=sum(s in old for s in strings))
    if apk:
        selection=json.loads((generated / "selection.json").read_text())
        verify_wrappers(apk,selection)
        result["dexWrappers"]={"verified":True,"methods":len(selection["methods"])}
        with zipfile.ZipFile(apk) as archive:
            info=archive.getinfo("lib/arm64-v8a/"+library.name)
            assert archive.read(info)==data
            assert info.compress_type==zipfile.ZIP_STORED
            with apk.open("rb") as stream:
                stream.seek(info.header_offset)
                n,x=struct.unpack_from("<HH",stream.read(30),26)
            assert (info.header_offset+30+n+x)%16384==0
            assert not any(name.endswith((".cpp",".ll",".o")) for name in archive.namelist())
        result.update(apkBytes=apk.stat().st_size,apkSha256=hashlib.sha256(apk.read_bytes()).hexdigest(),apk16kAligned=True)
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("generated","native","ndk","report"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--apk",type=Path)
    parser.add_argument("--baseline",type=Path)
    args=parser.parse_args()
    result=inspect(args.generated,args.native,args.ndk,args.apk,args.baseline)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2)+"\n")
    print("[ok] VM entries, encrypted strings, export table, ELF/APK alignment;",args.report)
