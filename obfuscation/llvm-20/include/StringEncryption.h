#ifndef OBFUSCATION_STRING_ENCRYPTION_H
#define OBFUSCATION_STRING_ENCRYPTION_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class ModulePass;
class PassRegistry;
class ObfuscationOptions;

ModulePass* createStringEncryptionPass(ObfuscationOptions *argsOptions);
void initializeStringEncryptionPass(PassRegistry &Registry);

struct CseRecheckPreparePass : public PassInfoMixin<CseRecheckPreparePass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};
void removeCseRecheckMarkers(Module &M);

}

#endif
