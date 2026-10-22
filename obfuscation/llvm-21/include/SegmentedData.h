// SPDX-License-Identifier: Apache-2.0
#ifndef LLVM_OBFUSCATION_SEGMENTED_DATA_H
#define LLVM_OBFUSCATION_SEGMENTED_DATA_H
#include "llvm/IR/IRBuilder.h"
namespace llvm {
bool isSegmentedDataEnabled();
void validateSegmentedData(Module &M);
GlobalVariable *stageSegment(Module &M, StringRef Name, uint32_t Kind,
                             ArrayRef<uint8_t> Bytes);
Value *segmentVMData(IRBuilder<> &B, GlobalVariable *Code, bool Lease = false);
void releaseVMData(IRBuilder<> &B, GlobalVariable *Code);
void setSegmentLifetime(Function &F, GlobalVariable *Code, bool Lease);
void finishSegmentedData(Module &M);
}
#endif
