// SPDX-License-Identifier: Apache-2.0
#include "llvm/Transforms/Obfuscation/SegmentedData.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Base64.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Path.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
using namespace llvm;
static cl::opt<bool> Enabled("irobf-segmented-data", cl::init(false),
    cl::desc("Externalize protected data to authenticated APK segments (Android arm64)."));
static cl::opt<std::string> Output("irobf-segmented-output", cl::init(""),
    cl::desc("Build-only directory for segmented payloads; required with segmented-data."));
bool llvm::isSegmentedDataEnabled() { return Enabled; }
void llvm::validateSegmentedData(Module &M) {
  if (!Enabled) return;
  Triple T(M.getTargetTriple());
  if (!T.isAndroid() || T.getArch() != Triple::aarch64 || Output.empty())
    report_fatal_error("segmented-data requires Android arm64 and -irobf-segmented-output=<directory>");
}
GlobalVariable *llvm::stageSegment(Module &M, StringRef Name, uint32_t Kind,
                                 ArrayRef<uint8_t> Bytes) {
  if (Bytes.empty() || Bytes.size() > (1u << 24))
    report_fatal_error("segmented payload must contain 1..16 MiB");
  CryptoUtils Random;
  uint8_t Ref[24];
  for (unsigned I = 0; I < 16; ++I) Ref[I] = Random.get_uint8_t();
  for (unsigned I = 0; I < 4; ++I) {
    Ref[16 + I] = uint8_t(Bytes.size() >> (8 * I));
    Ref[20 + I] = uint8_t(Kind >> (8 * I));
  }
  auto *Init = ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Ref));
  auto *GV = new GlobalVariable(M, Init->getType(), true, GlobalValue::PrivateLinkage,
                                Init, "ndkp_qseg_ref");
  GV->setSection(".text.ndkp.qseg.refs"); GV->setAlignment(Align(4));
  GV->setMetadata("noobf", MDNode::get(M.getContext(), {}));
  M.getOrInsertNamedMetadata("ndkp.qseg.stage")->addOperand(MDNode::get(M.getContext(), {
      ValueAsMetadata::get(GV), MDString::get(M.getContext(), Name),
      MDString::get(M.getContext(), StringRef(reinterpret_cast<const char *>(Bytes.data()), Bytes.size()))}));
  return GV;
}
Value *llvm::segmentVMData(IRBuilder<> &B, GlobalVariable *Code) {
  auto *MD = Code->getMetadata("ndkp.qseg");
  if (!MD) return Code;
  auto *Ref = mdconst::extract<Constant>(MD->getOperand(0));
  Module &M = *Code->getParent();
  auto Get = M.getOrInsertFunction("ndkp_qseg_get",
      FunctionType::get(B.getPtrTy(), {B.getPtrTy()}, false));
  cast<Function>(Get.getCallee())->setVisibility(GlobalValue::HiddenVisibility);
  return B.CreateCall(Get, {Ref});
}
void llvm::finishSegmentedData(Module &M) {
  if (!Enabled) return;
  if (std::error_code EC = sys::fs::create_directories(Output))
    report_fatal_error(Twine("cannot create segmented staging: ") + EC.message());
  auto *Stages = M.getNamedMetadata("ndkp.qseg.stage");
  json::Array Items;
  if (Stages) {
    for (MDNode *MD : Stages->operands()) {
      auto *Ref = mdconst::extract<GlobalVariable>(MD->getOperand(0));
      StringRef Desc = cast<ConstantDataArray>(Ref->getInitializer())->getRawDataValues();
      StringRef Name = cast<MDString>(MD->getOperand(1))->getString();
      StringRef Bytes = cast<MDString>(MD->getOperand(2))->getString();
      std::string ID;
      static const char Hex[] = "0123456789abcdef";
      for (uint8_t C : Desc.take_front(16).bytes()) { ID += Hex[C >> 4]; ID += Hex[C & 15]; }
      SmallString<256> File(Output.getValue()); sys::path::append(File, ID + ".bin");
      std::error_code EC; raw_fd_ostream Stream(File, EC, sys::fs::OF_None);
      if (EC) report_fatal_error(Twine("cannot write segmented staging: ") + EC.message());
      Stream << Bytes; Stream.close();
      if (Stream.has_error()) report_fatal_error("cannot finish segmented staging");
      if (uint8_t(Desc[20]) == 1) {
        SmallString<256> VMFile(Output.getValue()); sys::path::append(VMFile, Name.str() + ".bin");
        raw_fd_ostream VMStream(VMFile, EC, sys::fs::OF_None);
        if (EC) report_fatal_error("cannot write VM receipt staging");
        VMStream << Bytes; VMStream.close();
        if (VMStream.has_error()) report_fatal_error("cannot finish VM receipt staging");
      }
      Items.push_back(json::Object{{"id", ID}, {"name", Name},
          {"kind", unsigned(uint8_t(Desc[20]))}, {"bytes", int64_t(Bytes.size())}});
    }
    M.eraseNamedMetadata(Stages);
  }
  SmallString<256> Manifest(Output.getValue()); sys::path::append(Manifest, "manifest.json");
  std::error_code EC; raw_fd_ostream Stream(Manifest, EC, sys::fs::OF_Text);
  if (EC) report_fatal_error(Twine("cannot write segmented manifest: ") + EC.message());
  Stream << formatv("{0:2}", json::Value(std::move(Items))); Stream.close();
  if (Stream.has_error()) report_fatal_error("cannot finish segmented manifest");
  SmallVector<GlobalVariable *> Codes;
  for (GlobalVariable &GV : M.globals()) if (GV.getMetadata("ndkp.qseg")) Codes.push_back(&GV);
  for (GlobalVariable *Old : Codes) {
    auto *New = new GlobalVariable(M, Type::getInt8Ty(M.getContext()), true,
        Old->getLinkage(), ConstantInt::get(Type::getInt8Ty(M.getContext()), 0));
    New->setSection(".AProtect.data"); New->takeName(Old);
    New->setMetadata("ndkp.qseg", Old->getMetadata("ndkp.qseg"));
    Old->replaceAllUsesWith(New); Old->eraseFromParent();
  }
}
