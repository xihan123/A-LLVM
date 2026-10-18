// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef LLVM_TRANSFORMS_OBFUSCATION_AVMP_MEMORY_OPS_H
#define LLVM_TRANSFORMS_OBFUSCATION_AVMP_MEMORY_OPS_H

namespace llvm {
class Function;
bool lowerVMPMemoryOps(Function &F);
}

#endif
