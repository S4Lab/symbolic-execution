//                   In the name of GOD
/*
 * Twinner: An unpacker which utilizes concolic execution.
 * Copyright © 2013-2017 Behnam Momeni
 *
 * This program comes with ABSOLUTELY NO WARRANTY.
 * See the COPYING file distributed with this work for information
 * regarding copyright ownership.
 *
 * This file is part of Twinner project.
 */

#include "InstructionSymbolicExecuter.h"


#include "Instrumenter.h"

#include "edu/sharif/twinner/operationgroup/DummyOperationGroup.h"
#include "edu/sharif/twinner/operationgroup/SubtractOperationGroup.h"
#include "edu/sharif/twinner/operationgroup/AdditionOperationGroup.h"
#include "edu/sharif/twinner/operationgroup/AddWithCarryOperationGroup.h"
#include "edu/sharif/twinner/operationgroup/BitwiseAndOperationGroup.h"
#include "edu/sharif/twinner/operationgroup/ShiftArithmeticRightOperationGroup.h"
#include "edu/sharif/twinner/operationgroup/ShiftRightOperationGroup.h"
#include "edu/sharif/twinner/operationgroup/ShiftLeftOperationGroup.h"

#include "edu/sharif/twinner/trace/ExpressionImp.h"
#include "edu/sharif/twinner/trace/Constraint.h"
#include "edu/sharif/twinner/trace/StateSummary.h"
#include "edu/sharif/twinner/trace/SyscallInvocation.h"
#include "edu/sharif/twinner/trace/FunctionInvocation.h"

#include "edu/sharif/twinner/trace/syscall/Syscall.h"
#ifdef TARGET_IS_32BITS_WINDOWS7_SP1
#include "edu/sharif/twinner/trace/syscall/X86Windows7Sp1Syscall.h"
#endif

#include "edu/sharif/twinner/trace/exptoken/RegisterEmergedSymbol.h"

#include "edu/sharif/twinner/trace/cv/ConcreteValue64Bits.h"
#include "edu/sharif/twinner/trace/cv/ConcreteValue128Bits.h"

#include "edu/sharif/twinner/trace-twintool/TraceImp.h"
#include "edu/sharif/twinner/trace-twintool/FunctionInfo.h"

#include "edu/sharif/twinner/util/max.h"
#include "edu/sharif/twinner/util/Logger.h"
#include "edu/sharif/twinner/util/memory.h"
#include "edu/sharif/twinner/util/MemoryManager.h"

#include <stdexcept>

namespace edu {
namespace sharif {
namespace twinner {
namespace twintool {

#ifdef TARGET_IA32E
static const int STACK_OPERATION_UNIT_SIZE = 8; // bytes
#else
static const int STACK_OPERATION_UNIT_SIZE = 4; // bytes
#endif

InstructionSymbolicExecuter::InstructionSymbolicExecuter (
    Instrumenter *_im, bool _disabled, bool _measureMode) :
    im (_im),
    lazyTrace (new edu::sharif::twinner::trace::TraceImp ()),
    memoryManager (lazyTrace->getMemoryManager ()),
    trackedReg (REG_INVALID_), operandSize (-1), hook (0),
    disabled (_disabled),
    measureMode (_measureMode), numberOfExecutedInstructions (0),
    endOfSafeFuncRetAddress (0), withinSafeFunc (false) {
}

edu::sharif::twinner::trace::Trace *InstructionSymbolicExecuter::getTrace () {
  return lazyTrace;
}

const edu::sharif::twinner::trace::Trace *InstructionSymbolicExecuter::getTrace () const {
  InstructionSymbolicExecuter *me = const_cast<InstructionSymbolicExecuter *> (this);
  return me->lazyTrace;
}

void InstructionSymbolicExecuter::disable () {
  disabled = true;
}

void InstructionSymbolicExecuter::enable () {
  disabled = false;
}

void InstructionSymbolicExecuter::syscallInvoked (const CONTEXT *context,
    edu::sharif::twinner::trace::syscall::Syscall s) {
  runHooks (context);
  if (disabled) {
    return;
  }
  getTrace ()->terminateTraceSegment
      (new edu::sharif::twinner::trace::SyscallInvocation (s));
  if (measureMode) {
    numberOfExecutedInstructions++;
  }
}

void InstructionSymbolicExecuter::startNewTraceSegment (
    CONTEXT *context) const {
  if (disabled) {
    edu::sharif::twinner::util::Logger::warning ()
        << "startNewTraceSegment is called while the ISE is disabled\n";
    return;
  }
  const edu::sharif::twinner::trace::Trace *trace = getTrace ();
  trace->initializeNewTraceSegment (context);
}

edu::sharif::twinner::util::MemoryManager *
InstructionSymbolicExecuter::getTraceMemoryManager () const {
  return memoryManager;
}

void InstructionSymbolicExecuter::analysisRoutineBeforeCallingSafeFunction (
    ADDRINT retAddress, const FunctionInfo &fi,
    UINT32 insAssembly, const CONTEXT *context) {
  if (disabled) {
    return;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineBeforeCallingSafeFunction(INS: "
      << insAssemblyStr << "): before calling " << fi << '\n';
  registerSafeFunction (fi, context);
  endOfSafeFuncRetAddress = retAddress;
  withinSafeFunc = true;
}

void InstructionSymbolicExecuter::analysisRoutineSyscall (ADDRINT syscallNumber,
    ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3,
    ADDRINT arg4, ADDRINT arg5,
    UINT32 insAssembly) {
  // we should report syscalls even while the ise is disabled
  disassembledInstruction = insAssembly;
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  if (measureMode) {
    numberOfExecutedInstructions++;
    return;
  }
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
#ifdef TARGET_IS_32BITS_WINDOWS7_SP1
  edu::sharif::twinner::trace::syscall::Syscall const &syscall =
      edu::sharif::twinner::trace::syscall::X86Windows7Sp1Syscall
      (syscallNumber, arg0, arg1, arg2, arg3, arg4, arg5);
#else
  edu::sharif::twinner::trace::syscall::Syscall const &syscall =
      edu::sharif::twinner::trace::syscall::Syscall
      (syscallNumber, arg0, arg1, arg2, arg3, arg4, arg5);
#endif
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineSyscall(INS: "
      << insAssemblyStr << "): syscall-representation: "
      << syscall.getRepresentation () << '\n';
  syscallAnalysisRoutine (syscall);
}

bool InstructionSymbolicExecuter::logDstRegSrcReg (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineDstRegSrcReg(INS: "
      << insAssemblyStr << "): dst reg: " << REG_StringShort (dstReg)
      << ", src reg: " << REG_StringShort (srcReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcRegAuxReg (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    REG auxReg, const ConcreteValue &auxRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineDstRegSrcRegAuxReg(INS: "
      << insAssemblyStr << "): dst reg: " << REG_StringShort (dstReg)
      << ", src reg: " << REG_StringShort (srcReg)
      << ", aux reg: " << REG_StringShort (auxReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcRegAuxImd (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    const ConcreteValue &auxImmediateValue,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstRegSrcRegAuxImd(INS: "
      << insAssemblyStr << "): dst reg: " << REG_StringShort (dstReg)
      << ", src reg: " << REG_StringShort (srcReg)
      << ", aux imd: 0x" << auxImmediateValue << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcMem (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstRegSrcMem(INS: "
      << insAssemblyStr << "): dst reg: " << REG_StringShort (dstReg)
      << ", src mem addr: 0x" << srcMemoryEa << ", mem read bytes: 0x" << memReadBytes
      << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcMemAuxReg (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    REG auxReg, const ConcreteValue &auxRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstRegSrcMemAuxReg(INS: "
      << insAssemblyStr << "): dst reg: " << REG_StringShort (dstReg)
      << ", src mem addr: 0x" << srcMemoryEa << ", mem read bytes: 0x" << memReadBytes
      << ", aux reg: " << REG_StringShort (auxReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcMemAuxImd (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    const ConcreteValue &auxImmediateValue,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstRegSrcMemAuxImd(INS: "
      << insAssemblyStr << "): dst reg: " << REG_StringShort (dstReg)
      << ", src mem addr: 0x" << srcMemoryEa << ", mem read bytes: 0x" << memReadBytes
      << ", aux imd: 0x" << auxImmediateValue << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcImd (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstRegSrcImd(INS: "
      << insAssemblyStr << "): dst reg: " << REG_StringShort (dstReg)
      << ", src imd: 0x" << srcImmediateValue << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstMemSrcReg (
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstMemSrcReg(INS: "
      << insAssemblyStr << "): dst mem addr: 0x" << dstMemoryEa
      << ", src reg: " << REG_StringShort (srcReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstMemSrcRegAuxReg (
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    REG auxReg, const ConcreteValue &auxRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstMemSrcRegAuxReg(INS: "
      << insAssemblyStr << "): dst mem addr: 0x" << dstMemoryEa
      << ", src reg: " << REG_StringShort (srcReg)
      << ", aux reg: " << REG_StringShort (auxReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstMemSrcRegAuxImd (
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    const ConcreteValue &auxImmediateValue,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstMemSrcRegAuxImd(INS: "
      << insAssemblyStr << "): dst mem addr: 0x" << dstMemoryEa
      << ", src reg: " << REG_StringShort (srcReg)
      << ", aux imd: " << auxImmediateValue << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstMemSrcImd (
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  if (insAssemblyStr) {
    logger << "analysisRoutineDstMemSrcImd(INS: "
        << insAssemblyStr << ")";
  }
  logger << std::hex << ": dst mem addr: 0x" << dstMemoryEa
      << ", src imd: 0x" << srcImmediateValue << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstMemSrcImdAuxReg (
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    const ConcreteValue &srcImmediateValue,
    REG auxReg, const ConcreteValue &auxRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  if (insAssemblyStr) {
    logger << "analysisRoutineDstMemSrcImdAuxReg(INS: "
        << insAssemblyStr << ")";
  }
  logger << std::hex << ": dst mem addr: 0x" << dstMemoryEa
      << ", src imd: 0x" << srcImmediateValue
      << ", aux reg: " << REG_StringShort (auxReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstMemSrcMemAuxReg (
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    REG auxReg, const ConcreteValue &auxRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstMemSrcMemAuxReg(INS: "
      << insAssemblyStr << "): dst mem addr: 0x" << dstMemoryEa
      << ", src mem addr: 0x" << srcMemoryEa << ", mem read bytes: 0x" << memReadBytes
      << ", aux reg: " << REG_StringShort (auxReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logConditionalBranch (
    BOOL branchTaken,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineConditionalBranch(INS: "
      << insAssemblyStr << "): branch taken: " << branchTaken << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcAdg (
    REG dstReg, const ConcreteValue &dstRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstRegSrcAdg(INS: "
      << insAssemblyStr << ") [AFTER execution of instruction]: dst reg: "
      << REG_StringShort (dstReg) << ", dst reg value: 0x"
      << dstRegVal << '\n';
  return true;
}

void InstructionSymbolicExecuter::analysisRoutineBeforeRet (REG reg) {
  if (withinSafeFunc) {
    edu::sharif::twinner::util::Logger::debug ()
        << "analysisRoutineBeforeRet\n";
    trackedReg = reg;
    hook = &InstructionSymbolicExecuter::checkForEndOfSafeFunc;
  }
}

void InstructionSymbolicExecuter::analysisRoutineBeforeChangeOfReg (
    SuddenlyChangedRegAnalysisRoutine routine,
    REG reg,
    UINT32 insAssembly) {
  if (disabled) {
    return;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineBeforeChangeOfReg(INS: "
      << insAssemblyStr << ")\n"
      "\tregistering register to be tracked...";
  trackedReg = reg;
  hook = routine;
  logger << "done\n";
}

void InstructionSymbolicExecuter::analysisRoutineBeforeChangeOfRegWithArg (
    SuddenlyChangedRegWithArgAnalysisRoutine routine,
    REG reg, ADDRINT argImmediateValue,
    UINT32 insAssembly) {
  if (disabled) {
    return;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineBeforeChangeOfRegWithArg(INS: "
      << insAssemblyStr << ")\n"
      "\tregistering register to be tracked...";
  trackedReg = reg;
  arg = argImmediateValue;
  hookWithArg = routine;
  logger << "done\n";
}

bool InstructionSymbolicExecuter::logTwoDstRegOneSrcReg (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineTwoDstRegOneSrcReg(INS: "
      << insAssemblyStr << "): left dst reg: " << REG_StringShort (dstLeftReg)
      << ", right dst reg: " << REG_StringShort (dstRightReg)
      << ", src reg: " << REG_StringShort (srcReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logTwoDstRegOneSrcMem (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineTwoDstRegOneSrcMem(INS: "
      << insAssemblyStr << "): left dst reg: " << REG_StringShort (dstLeftReg)
      << ", right dst reg: " << REG_StringShort (dstRightReg)
      << ", src mem addr: 0x" << srcMemoryEa << ", mem read bytes: 0x" << memReadBytes
      << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logOneMemTwoReg (
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineOneMemTwoReg(INS: "
      << insAssemblyStr << "): dst mem: 0x" << dstMemoryEa
      << ", dst reg: " << REG_StringShort (dstReg)
      << ", src reg: " << REG_StringShort (srcReg)
      << ", mem read bytes: 0x" << memReadBytes << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logTwoRegTwoMem (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    ADDRINT dstMemoryEa, ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineTwoRegTwoMem(INS: "
      << insAssemblyStr << "): left dst reg: " << REG_StringShort (dstLeftReg)
      << ", right dst reg: " << REG_StringShort (dstRightReg)
      << ", dst mem addr: 0x" << dstMemoryEa << ", src mem addr: 0x" << srcMemoryEa
      << ", mem read bytes: 0x" << memReadBytes << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logAfterOperandLessInstruction (
    const CONTEXT *context,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineAfterOperandLessInstruction(INS: "
      << insAssemblyStr << "): [AFTER execution of instruction]: operand-less ins\n";
  return true;
}

bool InstructionSymbolicExecuter::logDstRegSrcImplicit (
    REG dstReg, const ConcreteValue &dstRegVal,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineDstRegSrcImplicit(INS: "
      << insAssemblyStr << "): reg operand: " << REG_StringShort (dstReg) << '\n';
  return true;
}

bool InstructionSymbolicExecuter::logDstMemSrcImplicit (
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  if (disabled) {
    return false;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return false;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << std::hex << "analysisRoutineDstMemSrcImplicit(INS: "
      << insAssemblyStr << "): src mem addr: 0x" << dstMemoryEa
      << ", mem read bytes: 0x" << memReadBytes << '\n';
  return true;
}

void InstructionSymbolicExecuter::analysisRoutineRunHooks (const CONTEXT *context) {
  runHooks (context);
}

void InstructionSymbolicExecuter::analysisRoutineInitializeRegisters (
    CONTEXT *context) const {
  edu::sharif::twinner::util::Logger::loquacious () << "analysisRoutineInitializeRegisters\n";
  startNewTraceSegment (context);
  PIN_ExecuteAt (context); // never returns
}

void InstructionSymbolicExecuter::analysisRoutineRepEqualOrRepNotEqualPrefix (
    REG repReg, const ConcreteValue &repRegVal,
    BOOL executing, BOOL repEqual,
    UINT32 insAssembly) {
  if (disabled) {
    return;
  }
  disassembledInstruction = insAssembly;
  if (measureMode) {
    numberOfExecutedInstructions++;
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const char *insAssemblyStr =
      trace->getMemoryManager ()->getPointerToAllocatedMemory (insAssembly);
  edu::sharif::twinner::util::Logger logger =
      edu::sharif::twinner::util::Logger::loquacious ();
  logger << "analysisRoutineRepEqualOrRepNotEqualPrefix(INS: "
      << insAssemblyStr << "): rep reg: " << REG_StringShort (repReg)
      << ", executing: " << executing
      << ", rep equal: " << repEqual << '\n';
  repAnalysisRoutine (repReg, repRegVal, executing, repEqual);
}

void InstructionSymbolicExecuter::analysisRoutinePrefetchMem (
    ADDRINT memoryEa, UINT32 memReadBytes) {
  if (disabled) {
    return;
  }
  if (measureMode) {
    numberOfExecutedInstructions++;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "analysisRoutinePrefetchMem(...): mem addr: 0x"
      << std::hex << memoryEa << ", mem read bytes: 0x" << memReadBytes
      << '\n';
  if ((memoryEa % memReadBytes) == 0) {
    alignedCheckForOverwritingMemory (memoryEa, memReadBytes, trace);
  } else {
    alignedCheckForOverwritingMemory
        (memoryEa - (memoryEa % memReadBytes),
         memReadBytes,
         trace);
    alignedCheckForOverwritingMemory
        (memoryEa - (memoryEa % memReadBytes) + memReadBytes,
         memReadBytes,
         trace);
  }
}

void InstructionSymbolicExecuter::alignedCheckForOverwritingMemory (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace) const {
  edu::sharif::twinner::trace::cv::ConcreteValue *cv;
  bool ok = true;
  if (memReadBytes == 16) {
    UINT64 cvlsb;
    ok = ok && edu::sharif::twinner::util::readMemoryContent
        (cvlsb, memoryEa, 8);
    UINT64 cvmsb;
    ok = ok && edu::sharif::twinner::util::readMemoryContent
        (cvmsb, memoryEa + 8, 8);
    cv = new edu::sharif::twinner::trace::cv::ConcreteValue128Bits (cvmsb, cvlsb);
  } else {
    UINT64 cvval;
    ok = ok && edu::sharif::twinner::util::readMemoryContent
        (cvval, memoryEa, memReadBytes);
    cv = edu::sharif::twinner::trace::cv::ConcreteValue64Bits (cvval)
        .clone (memReadBytes * 8);
  }
  if (!ok) {
    edu::sharif::twinner::util::Logger::error ()
        << "alignedCheckForOverwritingMemory (...):"
        " error reading memory value\n";
    abort ();
  }
  edu::sharif::twinner::trace::StateSummary state;
  (void) trace->tryToGetSymbolicExpressionByMemoryAddress
      (memReadBytes * 8, memoryEa, *cv, state);
  delete cv;
}

edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::getMemExpression (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace) const {
  edu::sharif::twinner::trace::StateSummary state;
  edu::sharif::twinner::trace::Expression *exp;
  if ((memoryEa % memReadBytes) == 0) {
    exp = getAlignedMemExpression (memoryEa, memReadBytes, trace, state);
    if (exp) {
      exp = exp->clone ();
    }
  } else {
    exp = getUnalignedMemExpression (memoryEa, memReadBytes, trace, state);
  }
  if (state.isWrongState ()) {
    edu::sharif::twinner::util::Logger::error () << state.getMessage () << '\n';
    abort ();
  }
  return exp;
}

edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::getMemExpression (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::StateSummary &state) const {
  edu::sharif::twinner::trace::Expression *exp;
  if ((memoryEa % memReadBytes) == 0) {
    exp = getAlignedMemExpression (memoryEa, memReadBytes, trace, state);
    if (exp) {
      exp = exp->clone ();
    }
  } else {
    exp = getUnalignedMemExpression (memoryEa, memReadBytes, trace, state);
  }
  return exp;
}

edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::getAlignedMemExpression (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::StateSummary &state) const {
  edu::sharif::twinner::trace::cv::ConcreteValue *cv;
  bool ok = true;
  if (memReadBytes == 16) {
    UINT64 cvlsb;
    ok = ok &&
        edu::sharif::twinner::util::readMemoryContent (cvlsb, memoryEa, 8);
    UINT64 cvmsb;
    ok = ok &&
        edu::sharif::twinner::util::readMemoryContent (cvmsb, memoryEa + 8, 8);
    cv = new edu::sharif::twinner::trace::cv::ConcreteValue128Bits (cvmsb, cvlsb);
  } else {
    UINT64 cvval;
    ok = ok && edu::sharif::twinner::util::readMemoryContent
        (cvval, memoryEa, memReadBytes);
    cv = edu::sharif::twinner::trace::cv::ConcreteValue64Bits (cvval)
        .clone (memReadBytes * 8);
  }
  if (!ok) {
    edu::sharif::twinner::util::Logger::error ()
        << "alignedMemoryRead: error reading memory value\n";
    abort ();
  }
  edu::sharif::twinner::trace::Expression *exp =
      trace->getSymbolicExpressionByMemoryAddress
      (memReadBytes * 8, memoryEa, *cv, 0, state);
  delete cv;
  if (exp == 0) {
    return 0;
  }
  if (trace->doesLastGetterCallNeedPropagation ()) {
    expCache.clear ();
    propagateChangeDownwards (memReadBytes * 8, memoryEa, trace, *exp, false);
    emptyExpressionCache ();
    ADDRINT address = memoryEa;
    while (memReadBytes <= 8) {
      const bool doubleAligned = (address % (memReadBytes * 2) == 0);
      if (!doubleAligned) {
        address -= memReadBytes;
      }
      memReadBytes *= 2;
      trace->setSymbolicExpressionByMemoryAddress (memReadBytes * 8, address, NULL);
    }
  }
  return exp;
}

void InstructionSymbolicExecuter::propagateChangeDownwards (int size,
    ADDRINT memoryEa,
    edu::sharif::twinner::trace::Trace *trace,
    const edu::sharif::twinner::trace::Expression &changedExp, bool ownExp) const {
  expCache.insert (make_pair (make_pair (memoryEa, size),
                              make_pair (&changedExp, ownExp)));
  size /= 2;
  if (size >= 8) {
    if (expCache.find (make_pair (memoryEa, size)) == expCache.end ()) {
      edu::sharif::twinner::trace::Expression *exp = changedExp.clone ();
      exp->truncate (size); // LSB (left-side in little-endian)
      actualPropagateChangeDownwards (size, memoryEa, trace, exp);
      // exp is now owned by the expCache and will be deleted by it later
    }
    memoryEa += size / 8;
    if (expCache.find (make_pair (memoryEa, size)) == expCache.end ()) {
      edu::sharif::twinner::trace::Expression *exp = changedExp.clone ();
      exp->shiftToRight (size); // MSB (right-side in little-endian)
      exp->truncate (size);
      actualPropagateChangeDownwards (size, memoryEa, trace, exp);
      // exp is now owned by the expCache and will be deleted by it later
    }
  }
}

void InstructionSymbolicExecuter::actualPropagateChangeDownwards (int size,
    ADDRINT memoryEa,
    edu::sharif::twinner::trace::Trace *trace,
    const edu::sharif::twinner::trace::Expression *exp) const {
  trace->setSymbolicExpressionByMemoryAddress (size, memoryEa, exp);
  propagateChangeDownwards (size, memoryEa, trace, *exp, true);
}

void InstructionSymbolicExecuter::propagateChangeUpwards (int size,
    ADDRINT memoryEa, edu::sharif::twinner::trace::Trace *trace,
    const edu::sharif::twinner::trace::Expression &changedExp,
    edu::sharif::twinner::trace::StateSummary &state) const {
  if (size <= 64) {
    const bool twoSizeBitsAligned = (memoryEa % (size / 4) == 0);
    ADDRINT neighborEa;
    if (twoSizeBitsAligned) {
      neighborEa = memoryEa + size / 8;
    } else { // changedExp is right-side (i.e. MSB in little-endian)
      memoryEa -= size / 8;
      neighborEa = memoryEa;
    }
    bool visited = false;
    const edu::sharif::twinner::trace::Expression *neighbor =
        getNeighborExpression (size, neighborEa, trace, visited, state);
    if (neighbor == 0) {
      return;
    }
    if (!visited) {
      propagateChangeDownwards (size, neighborEa, trace, *neighbor, false);
    }
    edu::sharif::twinner::trace::Expression *exp;
    if (twoSizeBitsAligned) {
      exp = neighbor->clone (2 * size); // MSB
      exp->shiftToLeft (size);
      exp->bitwiseOr (&changedExp); // changedExp will be cloned internally
    } else {
      exp = changedExp.clone (2 * size); // MSB
      exp->shiftToLeft (size);
      exp->bitwiseOr (neighbor); // neighbor will be cloned internally
    }
    size *= 2;
    trace->setSymbolicExpressionByMemoryAddress (size, memoryEa, exp);
    std::pair < AddrSizeToExpMap::iterator, bool > res =
        expCache.insert (make_pair (make_pair (memoryEa, size),
                                    make_pair (exp, true)));
    if (!res.second) {
      std::pair < const edu::sharif::twinner::trace::Expression *, bool > &p =
          res.first->second;
      if (p.second) {
        delete p.first;
      }
      p.first = exp;
      p.second = true;
      // exp is now owned by the expCache and will be deleted by it later
    }
    propagateChangeUpwards (size, memoryEa, trace, *exp, state);
  }
}

const edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::getNeighborExpression (int size,
    ADDRINT address, edu::sharif::twinner::trace::Trace *trace,
    bool &readFromCache,
    edu::sharif::twinner::trace::StateSummary &state) const {
  AddrSizeToExpMap::const_iterator it = expCache.find (make_pair (address, size));
  if (it != expCache.end ()) {
    readFromCache = true;
    return it->second.first;
  }
  UINT64 cv;
  if (!edu::sharif::twinner::util::readMemoryContent (cv, address, size / 8)) {
    edu::sharif::twinner::util::Logger::error ()
        << "getNeighborExpression (...): error reading memory value\n";
    abort ();
  }
  edu::sharif::twinner::trace::cv::ConcreteValue *cvObj =
      edu::sharif::twinner::trace::cv::ConcreteValue64Bits (cv).clone (size);
  const edu::sharif::twinner::trace::Expression *neighbor =
      trace->getSymbolicExpressionByMemoryAddress
      (size, address, *cvObj, 0, state);
  delete cvObj;
  readFromCache = false;
  return neighbor;
}

void InstructionSymbolicExecuter::emptyExpressionCache () const {
  for (AddrSizeToExpMap::iterator it = expCache.begin (); it != expCache.end (); ++it) {
    std::pair < const edu::sharif::twinner::trace::Expression *, bool > &p = it->second;
    if (p.second) {
      delete p.first;
    }
  }
}

edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::getUnalignedMemExpression (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::StateSummary &state) const {
  /**
   * Example for 64-bits (each character is showing one byte):
   * Memory state:           0 1 2 3 4 5 6 7 8 9 a b c d e f
   *                               X Y Z W P Q R T
   * Expected expression (little-endian): T R Q P W Z Y X
   * reading two 64-bits from memory:    P W Z Y X 2 1 0      f e d c b T R Q
   * After shift & truncation:           - - - P W Z Y X      T R Q - - - - -
   * After bitwise or:                   T R Q P W Z Y X
   */
  edu::sharif::twinner::trace::Expression *leftExp =
      getMemExpression (memoryEa - (memoryEa % memReadBytes),
                        memReadBytes,
                        trace);
  if (leftExp == 0) {
    return 0;
  }
  edu::sharif::twinner::trace::Expression *rightExp =
      getMemExpression (memoryEa - (memoryEa % memReadBytes) + memReadBytes,
                        memReadBytes,
                        trace);
  if (rightExp == 0) {
    return 0;
  }
  leftExp->shiftToRight (8 * (memoryEa % memReadBytes));
  rightExp->shiftToLeft (8 * (memReadBytes - (memoryEa % memReadBytes)));
  leftExp->bitwiseOr (rightExp);
  delete rightExp;
  leftExp->truncate (memReadBytes * 8);
  return leftExp;
}

void InstructionSymbolicExecuter::setMemExpression (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::Expression *exp, bool shouldDeleteExp) const {
  const edu::sharif::twinner::trace::Expression *newExp =
      setMemExpressionWithoutChangeNotification
      (memoryEa, memReadBytes, trace, exp, shouldDeleteExp);
  if (!newExp) {
    return;
  }
  edu::sharif::twinner::trace::StateSummary state;
  memoryValueIsChanged (memoryEa, memReadBytes, trace, *newExp, state);
  if (shouldDeleteExp) {
    delete newExp;
  }
  if (state.isWrongState ()) {
    edu::sharif::twinner::util::Logger::error () << state.getMessage () << '\n';
    return; // abort ();
  }
}

const edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::setMemExpressionWithoutChangeNotification (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::Expression *exp, bool &shouldDeleteExp) const {
  if (!shouldDeleteExp) {
    exp = exp->clone ();
  }
  exp->truncate (memReadBytes * 8);
  // following call clones the exp and so we should delete ours
  const edu::sharif::twinner::trace::Expression *newExp;
  if ((memoryEa % memReadBytes) == 0) {
    newExp = setAlignedMemExpression (memoryEa, memReadBytes, trace, exp);
    shouldDeleteExp = false;
  } else {
    newExp = setUnalignedMemExpression (memoryEa, memReadBytes, trace, exp);
    shouldDeleteExp = true;
  }
  delete exp;
  return newExp;
}

const edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::setAlignedMemExpression (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::Expression *exp) const {
  edu::sharif::twinner::trace::Expression *newExp =
      trace->setSymbolicExpressionByMemoryAddress (memReadBytes * 8, memoryEa, exp);
  return newExp;
}

const edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::setUnalignedMemExpression (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::Expression *exp) const {
  /**
   * Example for 64-bits (each character is showing one byte):
   * Trying to set this expression (little-endian): T R Q P W Z Y X
   * Expected Memory state:           0 1 2 3 4 5 6 7 8 9 a b c d e f
   *                                        X Y Z W P Q R T
   * After shift & truncation:           P W Z Y X - - -      - - - - - T R Q
   * reading two 64-bits from memory:    7 6 5 4 3 2 1 0      f e d c b a 9 8
   * After masking and bitwise or:       P W Z Y X 2 1 0      f e d c b T R Q
   */
  edu::sharif::twinner::trace::Expression *right = exp->clone ();
  right->shiftToRight (8 * (memReadBytes - (memoryEa % memReadBytes)));
  right->truncate (8 * (memoryEa % memReadBytes));
  edu::sharif::twinner::trace::Expression *left = exp->clone ();
  left->shiftToLeft (8 * (memoryEa % memReadBytes));
  left->truncate (8 * memReadBytes);
  edu::sharif::twinner::trace::Expression *curLeft =
      getMemExpression (memoryEa - (memoryEa % memReadBytes),
                        memReadBytes,
                        trace);
  if (curLeft == 0) {
    return 0;
  }
  edu::sharif::twinner::trace::Expression *curRight =
      getMemExpression (memoryEa - (memoryEa % memReadBytes) + memReadBytes,
                        memReadBytes,
                        trace);
  if (curRight == 0) {
    return 0;
  }
  curLeft->truncate (8 * (memoryEa % memReadBytes));
  left->bitwiseOr (curLeft);
  delete curLeft;
  curRight->makeLeastSignificantBitsZero (8 * (memoryEa % memReadBytes));
  right->bitwiseOr (curRight);
  delete curRight;
  setAlignedMemExpression (memoryEa - (memoryEa % memReadBytes),
                           memReadBytes, trace, left);
  setAlignedMemExpression (memoryEa - (memoryEa % memReadBytes) + memReadBytes,
                           memReadBytes, trace, right);
  left->shiftToRight (8 * (memoryEa % memReadBytes));
  right->shiftToLeft (8 * (memReadBytes - (memoryEa % memReadBytes)));
  left->bitwiseOr (right);
  delete right;
  left->truncate (8 * memReadBytes);
  return left;
}

void InstructionSymbolicExecuter::memoryValueIsChanged (
    ADDRINT memoryEa, int memReadBytes,
    edu::sharif::twinner::trace::Trace *trace,
    const edu::sharif::twinner::trace::Expression &changedExp,
    edu::sharif::twinner::trace::StateSummary &state) const {
  edu::sharif::twinner::util::Logger::loquacious ()
      << "(memory value is changed to " << &changedExp << ")\n";
  expCache.clear ();
  const int size = memReadBytes * 8;
  // ASSERT: changedExp was returned from setMemExpressionWithoutChangeNotification () method
  if ((memoryEa % memReadBytes) == 0) {
    propagateChangeDownwards (size, memoryEa, trace, changedExp, false);
    propagateChangeUpwards (size, memoryEa, trace, changedExp, state);
  } else {
    const ADDRINT leftAlignedAddress = memoryEa - (memoryEa % memReadBytes);
    const ADDRINT rightAlignedAddress = leftAlignedAddress + memReadBytes;
    /*
     * As changedExp is returned by setMemExpressionWithoutChangeNotification () method,
     * we can safely ignore it (as it is passed just for performance improvement).
     * Aligned left/right expressions are set by setMemExpressionWithoutChangeNotification
     * and so reading them (without checking stored concrete value) will succeed.
     * Read left/right expressions are linked to underlying expressions and are not
     * owned by us (no deleting is required).
     */
    const edu::sharif::twinner::trace::Expression *left =
        trace->getSymbolicExpressionByMemoryAddress (size, leftAlignedAddress);
    const edu::sharif::twinner::trace::Expression *right =
        trace->getSymbolicExpressionByMemoryAddress (size, rightAlignedAddress);
    propagateChangeDownwards (size, leftAlignedAddress, trace, *left, false);
    propagateChangeDownwards (size, rightAlignedAddress, trace, *right, false);
    propagateChangeUpwards (size, leftAlignedAddress, trace, *left, state);
    if (!state.isWrongState ()) {
      propagateChangeUpwards (size, rightAlignedAddress, trace, *right, state);
    }
  }
  emptyExpressionCache ();
}

edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::getRegExpression (
    REG reg, const ConcreteValue &regVal,
    edu::sharif::twinner::trace::Trace *trace) const {
  edu::sharif::twinner::trace::StateSummary state;
  edu::sharif::twinner::trace::Expression *exp =
      trace->getSymbolicExpressionByRegister
      (REG_Size (reg) * 8, reg, regVal, 0, state);
  if (state.isWrongState ()) {
    edu::sharif::twinner::util::Logger::error () << state.getMessage () << '\n';
    abort ();
  }
  return exp ? exp->clone () : 0;
}

void InstructionSymbolicExecuter::setRegExpression (
    REG reg, edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::Expression *exp, bool shouldDeleteExp) const {
  const edu::sharif::twinner::trace::Expression *newExp =
      setRegExpressionWithoutChangeNotification (reg, trace, exp, shouldDeleteExp);
  if (!newExp) {
    return;
  }
  edu::sharif::twinner::trace::StateSummary state;
  registerValueIsChanged (reg, trace, *newExp, state);
  if (state.isWrongState ()) {
    edu::sharif::twinner::util::Logger::error () << state.getMessage () << '\n';
    return; // abort ();
  }
}

const edu::sharif::twinner::trace::Expression *
InstructionSymbolicExecuter::setRegExpressionWithoutChangeNotification (
    REG reg, edu::sharif::twinner::trace::Trace *trace,
    edu::sharif::twinner::trace::Expression *exp, bool shouldDeleteExp) const {
  if (!shouldDeleteExp) {
    exp = exp->clone ();
  }
  edu::sharif::twinner::trace::StateSummary state;
  exp->truncate (REG_Size (reg) * 8);
  // following call clones the exp and so we should delete ours
  const edu::sharif::twinner::trace::Expression *newExp =
      trace->setSymbolicExpressionByRegister (REG_Size (reg) * 8, reg, exp);
  delete exp;
  if (state.isWrongState ()) {
    edu::sharif::twinner::util::Logger::error () << state.getMessage () << '\n';
    return 0; // abort ();
  }
  return newExp;
}

void InstructionSymbolicExecuter::registerValueIsChanged (
    REG reg,
    edu::sharif::twinner::trace::Trace *trace,
    const edu::sharif::twinner::trace::Expression &changedExp,
    edu::sharif::twinner::trace::StateSummary &state) const {
  typedef edu::sharif::twinner::trace::exptoken::RegisterEmergedSymbol Reg;
  edu::sharif::twinner::util::Logger::loquacious () << "(register value is changed to "
      << &changedExp << ")\n";
  const int regIndex = Reg::getRegisterIndex (REG_FullRegName (reg));
  if (regIndex == -1) {
    if (Reg::is128BitsRegister (reg)) { // there is no subregister at all
      return;
    }
    edu::sharif::twinner::util::Logger::warning ()
        << "RegisterResidentExpressionValueProxy::valueIsChanged (...):"
        " Unhandled register: " << REG_StringShort (reg) << '\n';
    return;
  }
  const edu::sharif::twinner::trace::Expression *constReg16 = &changedExp;
  edu::sharif::twinner::trace::Expression *temp;
  const Reg::RegisterType regType = Reg::getRegisterType (reg, REG_Size (reg));
  switch (regType) {
#ifdef TARGET_IA32E
  case Reg::REG_32_BITS_TYPE:
    trace->setSymbolicExpressionByRegister
        (64, Reg::getOverlappingRegisterByIndex (regIndex, 0), &changedExp);
    break;
#endif
  case Reg::REG_8_BITS_UPPER_HALF_TYPE:
  {
    temp = changedExp.clone (16);
    temp->shiftToLeft (8);
    edu::sharif::twinner::trace::Expression *reg16 =
        trace->getSymbolicExpressionByRegister
        (16, Reg::getOverlappingRegisterByIndex (regIndex, 2));
    reg16->truncate (8);
    reg16->bitwiseOr (temp);
    delete temp;
    constReg16 = reg16;
    break;
  }
  default: // second switch-case will address the default case
    break;
  }
  switch (regType) {
#ifdef TARGET_IA32E
  case Reg::REG_64_BITS_TYPE:
    trace->setSymbolicExpressionByRegister
        (32, Reg::getOverlappingRegisterByIndex (regIndex, 1), &changedExp)->truncate (32);
#endif
  case Reg::REG_32_BITS_TYPE:
    trace->setSymbolicExpressionByRegister
        (16, Reg::getOverlappingRegisterByIndex (regIndex, 2), &changedExp)->truncate (16);
  case Reg::REG_16_BITS_TYPE:
    if (Reg::getOverlappingRegisterByIndex (regIndex, 3) != REG_INVALID_) {
      temp = changedExp.clone (16);
      temp->shiftToRight (8);
      trace->setSymbolicExpressionByRegister
          (8, Reg::getOverlappingRegisterByIndex (regIndex, 3), temp)->truncate (8);
      delete temp;
    }
  {
    const REG lowest8Bits = Reg::getOverlappingRegisterByIndex (regIndex, 4);
    if (lowest8Bits != REG_INVALID_) {
      trace->setSymbolicExpressionByRegister
          (8, lowest8Bits, &changedExp)->truncate (8);
    }
  }
    if (regType != Reg::REG_16_BITS_TYPE) {
      break;
    }
  case Reg::REG_8_BITS_UPPER_HALF_TYPE:
    temp = constReg16->clone (16);
#ifdef TARGET_IA32E
    putExpressionInLeastSignificantBitsOfRegister
        (trace, 64, Reg::getOverlappingRegisterByIndex (regIndex, 0), 16, temp);
#endif
    putExpressionInLeastSignificantBitsOfRegister
        (trace, 32, Reg::getOverlappingRegisterByIndex (regIndex, 1), 16, temp);
    delete temp;
    break;
  case Reg::REG_8_BITS_LOWER_HALF_TYPE:
    temp = changedExp.clone (8);
#ifdef TARGET_IA32E
    putExpressionInLeastSignificantBitsOfRegister
        (trace, 64, Reg::getOverlappingRegisterByIndex (regIndex, 0), 8, temp);
#endif
    putExpressionInLeastSignificantBitsOfRegister
        (trace, 32, Reg::getOverlappingRegisterByIndex (regIndex, 1), 8, temp);
    putExpressionInLeastSignificantBitsOfRegister
        (trace, 16, Reg::getOverlappingRegisterByIndex (regIndex, 2), 8, temp);
    delete temp;
    break;
  }
}

void InstructionSymbolicExecuter::putExpressionInLeastSignificantBitsOfRegister (
    edu::sharif::twinner::trace::Trace *trace, int rsize, REG r, int bits,
    const edu::sharif::twinner::trace::Expression *exp) const {
  edu::sharif::twinner::trace::Expression *dst =
      trace->getSymbolicExpressionByRegister (rsize, r);
  dst->makeLeastSignificantBitsZero (bits);
  dst->bitwiseOr (exp);
}

void InstructionSymbolicExecuter::runHooks (const CONTEXT *context) {
  if (trackedReg != REG_INVALID_) {
    ConcreteValue *value =
        edu::sharif::twinner::util::readRegisterContent (context, trackedReg);
    if (hook) {
      Hook hfunc = hook;
      trackedReg = REG_INVALID_;
      hook = 0;
      (this->*hfunc) (context, *value);
    } else {
      HookWithArg hfunc = hookWithArg;
      trackedReg = REG_INVALID_;
      hookWithArg = 0;
      (this->*hfunc) (context, *value, arg);
    }
    delete value;

  } else if (operandSize > 0) {
    edu::sharif::twinner::trace::cv::ConcreteValue64Bits os (operandSize);
    Hook hfunc = hook;
    operandSize = -1;
    hook = 0;
    (this->*hfunc) (context, os);
  }
}

void InstructionSymbolicExecuter::registerSafeFunction (const FunctionInfo &fi,
    const CONTEXT *context) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::trace::FunctionInvocation *f =
      instantiateFunctionInvocation (fi, trace, context);
  edu::sharif::twinner::util::Logger::loquacious ()
      << '\t' << f->getCallingLine ();
  getTrace ()->terminateTraceSegment (f);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

edu::sharif::twinner::trace::FunctionInvocation *
InstructionSymbolicExecuter::instantiateFunctionInvocation (
    const FunctionInfo &fi, edu::sharif::twinner::trace::Trace *trace,
    const CONTEXT *context) const {
  std::string name = fi.getName ();
  std::list<edu::sharif::twinner::trace::Expression *> args;
  if (!fi.isAutoArgs ()) {
    const int argsNo = fi.getArgsNo ();
    for (int i = 0; i < argsNo; ++i) {
      args.push_back (fi.getArgument (i, trace, context));
    }
    return new edu::sharif::twinner::trace::FunctionInvocation
        (name, args, fi.getTypes ());
  }
  std::string firstArgumentAsString;
  std::list<std::string> types;
  if (name == "printf") {
    /*
     * Assuming that printf arguments are marked by simple %d, %s, etc.
     * in the format string. Pointing to arguments by their position numbers
     * causes wrong number of arguments to be guessed here.
     */
    // TODO: Support all cases of the printf format string
    edu::sharif::twinner::trace::Expression *formatString =
        fi.getArgument (0, trace, context);
    args.push_back (formatString);
    types.push_back ("const char *");
    const ADDRINT formatStringPointer =
        formatString->getLastConcreteValue ().toUint64 ();
    if (!edu::sharif::twinner::util::readStringFromMemory
        (firstArgumentAsString, formatStringPointer)) {
      edu::sharif::twinner::util::Logger::warning ()
          << "first argument of the ``printf'' cannot be read as a C string";
      return new edu::sharif::twinner::trace::FunctionInvocation
          (name, args, types);
    }
    int argsNo = 0; // extra args after the format string
    for (int i = 0, len = firstArgumentAsString.length (); i < len; ++i) {
      if (firstArgumentAsString[i] == '%') {
        if (i + 1 < len && firstArgumentAsString[i + 1] == '%') {
          ++i;
          continue;
        }
        ++argsNo;
        types.push_back ("UINT64");
      }
    }
    for (int i = 0; i < argsNo; ++i) {
      args.push_back (fi.getArgument (i + 1, trace, context));
    }
    return new edu::sharif::twinner::trace::FunctionInvocation
        (name, args, types, firstArgumentAsString);

  } else if (name == "puts") {
    edu::sharif::twinner::trace::Expression *stringArg =
        fi.getArgument (0, trace, context);
    args.push_back (stringArg);
    types.push_back ("const char *");
    const ADDRINT formatStringPointer =
        stringArg->getLastConcreteValue ().toUint64 ();
    if (!edu::sharif::twinner::util::readStringFromMemory
        (firstArgumentAsString, formatStringPointer)) {
      edu::sharif::twinner::util::Logger::warning ()
          << "first argument of the ``puts'' cannot be read as a C string";
      return new edu::sharif::twinner::trace::FunctionInvocation
          (name, args, types);
    }
    return new edu::sharif::twinner::trace::FunctionInvocation
        (name, args, types, firstArgumentAsString);

  } else {
    edu::sharif::twinner::util::Logger::warning () << "argsNo=auto but "
        << name << " function is not supported by auto yet";
    return new edu::sharif::twinner::trace::FunctionInvocation (name);
  }
}

void InstructionSymbolicExecuter::syscallAnalysisRoutine (
    edu::sharif::twinner::trace::syscall::Syscall const &syscall) {
  edu::sharif::twinner::util::Logger::loquacious ()
      << "syscallAnalysisRoutine(...)\n";
  if (syscall.isProcessTerminatingSyscall ()) {
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tsyscall is a process terminating one; exit code is 0x"
        << std::hex << syscall.getExitCodeArgument () << '\n';
  }
}

void InstructionSymbolicExecuter::cmpxchgAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    REG auxReg, const ConcreteValue &auxRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcRegAuxReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal,
                              auxReg, auxRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cmpxchgAnalysisRoutine(...)\n"
      << "\tcomparison part...";
  cmpAnalysisRoutine (auxReg, auxRegVal, dstMemoryEa, memReadBytes);
  edu::sharif::twinner::util::Logger::loquacious () << "\texchange part...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  if (zero) { // equal
    movAnalysisRoutine (dstMemoryEa, memReadBytes, srcReg, srcRegVal);
  } else {
    movAnalysisRoutine (auxReg, auxRegVal, dstMemoryEa, memReadBytes);
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cmpxchgAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    REG auxReg, const ConcreteValue &auxRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcRegAuxReg (dstReg, dstRegVal, srcReg, srcRegVal,
                              auxReg, auxRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cmpxchgAnalysisRoutine(...)\n"
      << "\tcomparison part...";
  cmpAnalysisRoutine (auxReg, auxRegVal, dstReg, dstRegVal);
  edu::sharif::twinner::util::Logger::loquacious () << "\texchange part...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  if (zero) { // equal
    movAnalysisRoutine (dstReg, dstRegVal, srcReg, srcRegVal);
  } else {
    movAnalysisRoutine (auxReg, auxRegVal, dstReg, dstRegVal);
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::palignrAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    const ConcreteValue &shiftImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcMemAuxImd (dstReg, dstRegVal, srcMemoryEa, memReadBytes,
                              shiftImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "palignrAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting shift imd...";
  const int bits = shiftImmediateValue.toUint64 () * 8;
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting...";
  srcexp->shiftToRight (bits);
  dstexp->shiftToLeft (REG_Size (dstReg) * 8 - bits);
  srcexp->bitwiseOr (dstexp);
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::palignrAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    const ConcreteValue &shiftImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcRegAuxImd (dstReg, dstRegVal, srcReg, srcRegVal, shiftImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "palignrAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting shift imd...";
  const int bits = shiftImmediateValue.toUint64 () * 8;
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting...";
  srcexp->shiftToRight (bits);
  dstexp->shiftToLeft (REG_Size (dstReg) * 8 - bits);
  srcexp->bitwiseOr (dstexp);
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pshufdAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    const ConcreteValue &orderImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcMemAuxImd (dstReg, dstRegVal, srcMemoryEa, memReadBytes,
                              orderImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pshufdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting order byte...";

  struct OrderByte {
    unsigned int b0 : 2;
    unsigned int b1 : 2;
    unsigned int b2 : 2;
    unsigned int b3 : 2;
  } orderByte;
  *reinterpret_cast<UINT8 *> (&orderByte) =
      UINT8 (orderImmediateValue.toUint64 ());
  const unsigned int ob[] = {orderByte.b0, orderByte.b1, orderByte.b2, orderByte.b3};
  edu::sharif::twinner::trace::Expression *res =
      new edu::sharif::twinner::trace::ExpressionImp
      (new edu::sharif::twinner::trace::cv::ConcreteValue128Bits ());
  edu::sharif::twinner::util::Logger::loquacious () << "\tshuffling words...";
  for (int i = 0; i < 4; ++i) {
    edu::sharif::twinner::trace::Expression *exp = srcexp->clone ();
    exp->shiftToRight (ob[i] * 32);
    exp->truncate (32);
    exp->shiftToLeft (i * 32);
    res->bitwiseOr (exp);
    delete exp;
  }
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, res);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pshufdAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    const ConcreteValue &orderImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcRegAuxImd (dstReg, dstRegVal, srcReg, srcRegVal, orderImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pshufdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting order byte...";

  struct OrderByte {
    unsigned int b0 : 2;
    unsigned int b1 : 2;
    unsigned int b2 : 2;
    unsigned int b3 : 2;
  } orderByte;
  *reinterpret_cast<UINT8 *> (&orderByte) =
      UINT8 (orderImmediateValue.toUint64 ());
  const unsigned int ob[] = {orderByte.b0, orderByte.b1, orderByte.b2, orderByte.b3};
  edu::sharif::twinner::trace::Expression *res =
      new edu::sharif::twinner::trace::ExpressionImp
      (new edu::sharif::twinner::trace::cv::ConcreteValue128Bits ());
  edu::sharif::twinner::util::Logger::loquacious () << "\tshuffling words...";
  for (int i = 0; i < 4; ++i) {
    edu::sharif::twinner::trace::Expression *exp = srcexp->clone ();
    exp->shiftToRight (ob[i] * 32);
    exp->truncate (32);
    exp->shiftToLeft (i * 32);
    res->bitwiseOr (exp);
    delete exp;
  }
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, res);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shldAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    const ConcreteValue &shiftImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcRegAuxImd (dstMemoryEa, memReadBytes, srcReg, srcRegVal,
                              shiftImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shldAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting shift exp...";
  edu::sharif::twinner::trace::Expression *shiftexp =
      new edu::sharif::twinner::trace::ExpressionImp (shiftImmediateValue);
  if (memReadBytes == 8) {
    shiftexp->bitwiseAnd (0x3F); // % 64
  } else {
    shiftexp->bitwiseAnd (0x1F); // % 32
  }
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToLeft (shiftexp);
  // truncate bits which are shifted left, outside of dst boundaries
  dstexp->truncate (memReadBytes * 8);
  // fill lower bits with src
  edu::sharif::twinner::trace::Expression *fillexp =
      new edu::sharif::twinner::trace::ExpressionImp
      (srcexp->getLastConcreteValue ().getSize ());
  fillexp->minus (shiftexp);
  srcexp->shiftToRight (fillexp);
  delete fillexp;
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  delete dstexpOrig;
  delete shiftexp;
  eflags.setFlags (new edu::sharif::twinner::operationgroup::DummyOperationGroup
                   ("ShiftDoubleLeftOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shldAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    const ConcreteValue &shiftImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcRegAuxImd (dstReg, dstRegVal, srcReg, srcRegVal, shiftImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shldAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting shift exp...";
  edu::sharif::twinner::trace::Expression *shiftexp =
      new edu::sharif::twinner::trace::ExpressionImp (shiftImmediateValue);
  if (REG_Size (dstReg) == 8) {
    shiftexp->bitwiseAnd (0x3F); // % 64
  } else {
    shiftexp->bitwiseAnd (0x1F); // % 32
  }
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToLeft (shiftexp);
  // truncate bits which are shifted left, outside of dst boundaries
  dstexp->truncate (REG_Size (dstReg) * 8);
  // fill lower bits with src
  edu::sharif::twinner::trace::Expression *fillexp =
      new edu::sharif::twinner::trace::ExpressionImp
      (srcexp->getLastConcreteValue ().getSize ());
  fillexp->minus (shiftexp);
  srcexp->shiftToRight (fillexp);
  delete fillexp;
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  delete dstexpOrig;
  delete shiftexp;
  eflags.setFlags (new edu::sharif::twinner::operationgroup::DummyOperationGroup
                   ("ShiftDoubleLeftOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shldAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    REG shiftReg, const ConcreteValue &shiftRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcRegAuxReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal,
                              shiftReg, shiftRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shldAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting shift exp...";
  edu::sharif::twinner::trace::Expression *shiftexp =
      getRegExpression (shiftReg, shiftRegVal, trace);
  if (memReadBytes == 8) {
    shiftexp->bitwiseAnd (0x3F); // % 64
  } else {
    shiftexp->bitwiseAnd (0x1F); // % 32
  }
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToLeft (shiftexp);
  // truncate bits which are shifted left, outside of dst boundaries
  dstexp->truncate (memReadBytes * 8);
  // fill lower bits with src
  edu::sharif::twinner::trace::Expression *fillexp =
      new edu::sharif::twinner::trace::ExpressionImp
      (srcexp->getLastConcreteValue ().getSize ());
  fillexp->minus (shiftexp);
  srcexp->shiftToRight (fillexp);
  delete fillexp;
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  delete dstexpOrig;
  delete shiftexp;
  eflags.setFlags (new edu::sharif::twinner::operationgroup::DummyOperationGroup
                   ("ShiftDoubleLeftOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shldAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    REG shiftReg, const ConcreteValue &shiftRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcRegAuxReg (dstReg, dstRegVal, srcReg, srcRegVal,
                              shiftReg, shiftRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shldAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting shift exp...";
  edu::sharif::twinner::trace::Expression *shiftexp =
      getRegExpression (shiftReg, shiftRegVal, trace);
  if (REG_Size (dstReg) == 8) {
    shiftexp->bitwiseAnd (0x3F); // % 64
  } else {
    shiftexp->bitwiseAnd (0x1F); // % 32
  }
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToLeft (shiftexp);
  // truncate bits which are shifted left, outside of dst boundaries
  dstexp->truncate (REG_Size (dstReg) * 8);
  // fill lower bits with src
  edu::sharif::twinner::trace::Expression *fillexp =
      new edu::sharif::twinner::trace::ExpressionImp
      (srcexp->getLastConcreteValue ().getSize ());
  fillexp->minus (shiftexp);
  srcexp->shiftToRight (fillexp);
  delete fillexp;
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  delete dstexpOrig;
  delete shiftexp;
  eflags.setFlags (new edu::sharif::twinner::operationgroup::DummyOperationGroup
                   ("ShiftDoubleLeftOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xchgAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xchgAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting src exp...";
  setRegExpression (srcReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xchgAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xchgAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting src exp...";
  setRegExpression (srcReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xaddAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xaddAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting src exp...";
  srcexp->add (dstexp);
  setRegExpression (srcReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xaddAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xaddAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting src exp...";
  srcexp->add (dstexp);
  setRegExpression (srcReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movlpdAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "movlpdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmoving low 64-bits of src to low 64-bits of dst...";
  srcexp->truncate (64);
  edu::sharif::twinner::trace::Expression *res = srcexp->clone (64);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, res);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movlpdAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "movlpdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmoving 64-bits from src to low 64-bits of dst..."
      << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  ConcreteValue *mask =
      new edu::sharif::twinner::trace::cv::ConcreteValue128Bits (-1, 0);
  dstexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *res = srcexp->clone (128);
  res->bitwiseOr (dstexp);
  delete dstexp;
  delete srcexp;
  setRegExpression (dstReg, trace, res);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movhpdAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "movhpdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmoving high 64-bits of src to low 64-bits of dst...";
  srcexp->shiftToRight (64);
  edu::sharif::twinner::trace::Expression *res = srcexp->clone (64);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, res);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movhpdAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "movhpdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmoving 64-bits from src to high 64-bits of dst..."
      << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  dstexp->truncate (64);
  edu::sharif::twinner::trace::Expression *res = srcexp->clone (128);
  res->shiftToLeft (64);
  res->bitwiseOr (dstexp);
  delete dstexp;
  delete srcexp;
  setRegExpression (dstReg, trace, res);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  movAnalysisRoutine (dstMemoryEa, memReadBytes, srcReg, srcRegVal);
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal) {
  edu::sharif::twinner::trace::Trace * trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "movAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "movAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "movAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  movAnalysisRoutine (dstReg, dstRegVal, srcMemoryEa, memReadBytes);
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "movAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  movAnalysisRoutine (dstReg, dstRegVal, srcReg, srcRegVal);
}

void InstructionSymbolicExecuter::movAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "movAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movsxAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "movsxAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsign-extending...";
  edu::sharif::twinner::trace::Expression *signExtendedExp =
      srcexp->signExtended (REG_Size (dstReg) * 8);
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, signExtendedExp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movsxAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "movsxAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsign-extending...";
  edu::sharif::twinner::trace::Expression *signExtendedExp =
      srcexp->signExtended (REG_Size (dstReg) * 8);
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, signExtendedExp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cdqAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cdqAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tinstantiating constraint...";
  bool sign;
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  cc.push_back
      (edu::sharif::twinner::trace::Constraint::instantiateLessConstraint
       (sign, srcexp, disassembledInstruction));
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (sign) {
    edu::sharif::twinner::trace::cv::ConcreteValue64Bits fullOne (UINT64 (-1));
    dstexp = new edu::sharif::twinner::trace::ExpressionImp
        (fullOne.clone (REG_Size (dstReg) * 8));
  } else {
    edu::sharif::twinner::trace::cv::ConcreteValue64Bits fullZero (UINT64 (0));
    dstexp = new edu::sharif::twinner::trace::ExpressionImp
        (fullZero.clone (REG_Size (dstReg) * 8));
  }
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::movsAnalysisRoutine (
    REG rdiReg, const ConcreteValue &rdiRegVal,
    REG rsiReg, const ConcreteValue &rsiRegVal,
    ADDRINT dstMemoryEa, ADDRINT srcMemoryEa,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoRegTwoMem (rdiReg, rdiRegVal, rsiReg, rsiRegVal,
                        dstMemoryEa, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::util::Logger::loquacious () << "movsAnalysisRoutine(...)\n";
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  adjustRsiRdiRegisters (memReadBytes, rdiReg, rdiRegVal, rsiReg, rsiRegVal);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cmpsAnalysisRoutine (
    REG rdiReg, const ConcreteValue &rdiRegVal,
    REG rsiReg, const ConcreteValue &rsiRegVal,
    ADDRINT dstMemoryEa, ADDRINT srcMemoryEa,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoRegTwoMem (rdiReg, rdiRegVal, rsiReg, rsiRegVal,
                        dstMemoryEa, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::util::Logger::loquacious () << "cmpsAnalysisRoutine(...)\n";
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  const edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexp, srcexp));
  adjustRsiRdiRegisters (memReadBytes, rdiReg, rdiRegVal, rsiReg, rsiRegVal);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::adjustRsiRdiRegisters (int size,
    REG rdiReg, const ConcreteValue &rdiRegVal,
    REG rsiReg, const ConcreteValue &rsiRegVal) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsi/rdi values...";
  edu::sharif::twinner::trace::Expression *rdiexp =
      getRegExpression (rdiReg, rdiRegVal, trace);
  edu::sharif::twinner::trace::Expression *rsiexp =
      getRegExpression (rsiReg, rsiRegVal, trace);
  if (eflags.getDirectionFlag ()) { // DF == 1
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tdecrementing index register...";
    rdiexp->minus (size);
    rsiexp->minus (size);
  } else { // DF == 0
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tincrementing index register...";
    rdiexp->add (size);
    rsiexp->add (size);
  }
  setRegExpression (rdiReg, trace, rdiexp);
  setRegExpression (rsiReg, trace, rsiexp);
}

void InstructionSymbolicExecuter::pushfdAnalysisRoutine (
    ADDRINT stackMemoryEa, int stackReadBytes,
    REG flagsReg, const ConcreteValue &flagsRegVal,
    REG rspReg, const ConcreteValue &rspRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcRegAuxReg (stackMemoryEa, stackReadBytes, flagsReg, flagsRegVal,
                              rspReg, rspRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pushfdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  uint32_t flagsConcreteValue = flagsRegVal.toUint64 ();
  edu::sharif::twinner::trace::Expression *flagsexp =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (flagsConcreteValue));
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.getFlagsExpression (flagsConcreteValue, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraints...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (stackMemoryEa, stackReadBytes, trace, flagsexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsp...";
  edu::sharif::twinner::trace::Expression *rspexp =
      getRegExpression (rspReg, rspRegVal, trace);
  rspexp->minus (stackReadBytes);
  setRegExpression (rspReg, trace, rspexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pushAnalysisRoutine (
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa, int memReadBytes,
    REG rspReg, const ConcreteValue &rspRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcMemAuxReg (dstMemoryEa, srcMemoryEa, memReadBytes,
                              rspReg, rspRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pushAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsp...";
  edu::sharif::twinner::trace::Expression *rspexp =
      getRegExpression (rspReg, rspRegVal, trace);
  rspexp->minus (STACK_OPERATION_UNIT_SIZE);
  setRegExpression (rspReg, trace, rspexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pushAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    REG rspReg, const ConcreteValue &rspRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcImdAuxReg (dstMemoryEa, memReadBytes, srcImmediateValue,
                              rspReg, rspRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pushAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsp...";
  edu::sharif::twinner::trace::Expression *rspexp =
      getRegExpression (rspReg, rspRegVal, trace);
  rspexp->minus (STACK_OPERATION_UNIT_SIZE);
  setRegExpression (rspReg, trace, rspexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pushAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    REG rspReg, const ConcreteValue &rspRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcRegAuxReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal,
                              rspReg, rspRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pushAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsp...";
  edu::sharif::twinner::trace::Expression *rspexp =
      getRegExpression (rspReg, rspRegVal, trace);
  rspexp->minus (STACK_OPERATION_UNIT_SIZE);
  setRegExpression (rspReg, trace, rspexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::popAnalysisRoutine (
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa, int memReadBytes,
    REG rspReg, const ConcreteValue &rspRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcMemAuxReg (dstMemoryEa, srcMemoryEa, memReadBytes,
                              rspReg, rspRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "popAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsp...";
  edu::sharif::twinner::trace::Expression *rspexp =
      getRegExpression (rspReg, rspRegVal, trace);
  rspexp->add (STACK_OPERATION_UNIT_SIZE);
  setRegExpression (rspReg, trace, rspexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::popAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    REG rspReg, const ConcreteValue &rspRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcMemAuxReg (dstReg, dstRegVal, srcMemoryEa, memReadBytes, rspReg, rspRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "popAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsp...";
  edu::sharif::twinner::trace::Expression *rspexp =
      getRegExpression (rspReg, rspRegVal, trace);
  rspexp->add (STACK_OPERATION_UNIT_SIZE);
  setRegExpression (rspReg, trace, rspexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::lodsdAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    REG rsiReg, const ConcreteValue &rsiRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcMemAuxReg (dstReg, dstRegVal, srcMemoryEa, memReadBytes, rsiReg, rsiRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "lodsdAnalysisRoutine(...)\n";
  movAnalysisRoutine (dstReg, dstRegVal, srcMemoryEa, memReadBytes);
  edu::sharif::twinner::trace::Expression *rsiexp =
      getRegExpression (rsiReg, rsiRegVal, trace);
  if (eflags.getDirectionFlag ()) { // DF == 1
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tdecrementing rsi/index register...";
    rsiexp->minus (REG_Size (dstReg));
  } else { // DF == 0
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tincrementing rsi/index register...";
    rsiexp->add (REG_Size (dstReg));
  }
  setRegExpression (rsiReg, trace, rsiexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::addAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "addAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->add (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AdditionOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::addAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "addAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->add (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AdditionOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::addAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "addAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->add (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AdditionOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::addAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "addAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->add (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AdditionOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::addAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "addAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->add (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AdditionOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::adcAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "adcAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = carryexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->add (srcexp);
  exp->add (dstexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, exp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AddWithCarryOperationGroup
       (dstexp, srcexp, carryexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::adcAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "adcAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = carryexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->add (srcexp);
  exp->add (dstexp);
  setRegExpression (dstReg, trace, exp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AddWithCarryOperationGroup
       (dstexp, srcexp, carryexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::adcAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "adcAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = carryexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->add (srcexp);
  exp->add (dstexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, exp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AddWithCarryOperationGroup
       (dstexp, srcexp, carryexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::adcAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "adcAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = carryexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->add (srcexp);
  exp->add (dstexp);
  setRegExpression (dstReg, trace, exp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AddWithCarryOperationGroup
       (dstexp, srcexp, carryexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::adcAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "adcAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = carryexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->add (srcexp);
  exp->add (dstexp);
  setRegExpression (dstReg, trace, exp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AddWithCarryOperationGroup
       (dstexp, srcexp, carryexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::subAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "subAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->minus (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::subAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "subAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->minus (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::subAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "subAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->minus (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::subAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "subAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->minus (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::subAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "subAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->minus (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sbbAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sbbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = dstexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->minus (srcexp);
  exp->minus (carryexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, exp);
  delete dstexp;
  delete srcexp;
  delete carryexp;
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::DummyOperationGroup
       ("SubtractWithBorrowOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sbbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sbbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = dstexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->minus (srcexp);
  exp->minus (carryexp);
  setRegExpression (dstReg, trace, exp);
  delete dstexp;
  delete srcexp;
  delete carryexp;
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::DummyOperationGroup
       ("SubtractWithBorrowOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sbbAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sbbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = dstexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->minus (srcexp);
  exp->minus (carryexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, exp);
  delete dstexp;
  delete srcexp;
  delete carryexp;
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::DummyOperationGroup
       ("SubtractWithBorrowOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sbbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sbbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = dstexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->minus (srcexp);
  exp->minus (carryexp);
  setRegExpression (dstReg, trace, exp);
  delete dstexp;
  delete srcexp;
  delete carryexp;
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::DummyOperationGroup
       ("SubtractWithBorrowOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sbbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sbbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting carry exp...";
  const edu::sharif::twinner::trace::Expression *carryexp = eflags.getCarryFlag ();
  edu::sharif::twinner::trace::Expression *exp = dstexp->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  exp->minus (srcexp);
  exp->minus (carryexp);
  setRegExpression (dstReg, trace, exp);
  delete dstexp;
  delete srcexp;
  delete carryexp;
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::DummyOperationGroup
       ("SubtractWithBorrowOperationGroup"));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cmpAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cmpAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexp, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cmpAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cmpAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexp, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cmpAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cmpAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexp, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cmpAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  cmpAnalysisRoutine (dstReg, dstRegVal, srcMemoryEa, memReadBytes);
}

void InstructionSymbolicExecuter::cmpAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cmpAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexp, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::cmpAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  cmpAnalysisRoutine (dstReg, dstRegVal, srcReg, srcRegVal);
}

void InstructionSymbolicExecuter::cmpAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cmpAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexp, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::leaAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcAdgVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcAdg (dstReg, dstRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "leaAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcAdgVal);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, srcexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jnzAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jnzAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  if (zero == branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jnzAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JNZ branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jzAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jzAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  if (zero != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jzAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JZ branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jleAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jleAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool lessOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessOrEqualCase
      (lessOrEqual, disassembledInstruction);
  if (lessOrEqual != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jleAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JLE branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jnleAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jnleAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool lessOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessOrEqualCase
      (lessOrEqual, disassembledInstruction);
  if (lessOrEqual == branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jnleAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JNLE branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jlAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jlAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool less;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessCase (less, disassembledInstruction);
  if (less != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jlAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JL branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jnlAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jnlAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool less;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessCase (less, disassembledInstruction);
  if (less == branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jnlAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JNL branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jbeAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jbeAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool belowOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowOrEqualCase
      (belowOrEqual, disassembledInstruction);
  if (belowOrEqual != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jbeAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JBE branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jnbeAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jnbeAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool belowOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowOrEqualCase
      (belowOrEqual, disassembledInstruction);
  if (belowOrEqual == branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jnbeAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JNBE branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jnbAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jnbAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool below;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowCase (below, disassembledInstruction);
  if (below == branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jnbAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JNB branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jbAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jbAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool below;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowCase (below, disassembledInstruction);
  if (below != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jbAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JB branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::joAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "joAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool overflow;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForOverflowCase (overflow, disassembledInstruction);
  if (overflow != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::joAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        "JO branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jpAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jpAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool parity;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForParityCase (parity, disassembledInstruction);
  if (parity != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jpAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        "JP branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jnpAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jnpAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool parity;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForParityCase (parity, disassembledInstruction);
  if (parity == branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jnpAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        "JNP branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jsAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jsAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool sign;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForSignCase (sign, disassembledInstruction);
  if (sign != branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jsAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        "JS branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jnsAnalysisRoutine (bool branchTaken,
    UINT32 insAssembly) {
  if (!logConditionalBranch (branchTaken, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jnsAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool sign;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForSignCase (sign, disassembledInstruction);
  if (sign == branchTaken) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::jnsAnalysisRoutine"
        " (branchTaken=" << branchTaken << "):"
        " JNS branching and last known EFLAGS state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::callAnalysisRoutine (const CONTEXT *context,
    const ConcreteValue &rspRegVal) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "callAnalysisRoutine(...)\n"
      << "\tgetting rsp reg exp...";
  edu::sharif::twinner::trace::Expression *rsp =
#ifdef TARGET_IA32E
      trace->tryToGetSymbolicExpressionByRegister (64, REG_RSP);
#else
      trace->tryToGetSymbolicExpressionByRegister (32, REG_ESP);
#endif
  if (rsp) { // If we are not tracking RSP yet, it's not required to adjust its value
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tadjusting rsp...";
    const ConcreteValue &oldVal = rsp->getLastConcreteValue ();
    if (oldVal > rspRegVal) {
      // some items have been pushed into stack by CALL and so RSP is decremented
      ConcreteValue *cv = oldVal.clone ();
      (*cv) -= rspRegVal;
      if ((*cv) == STACK_OPERATION_UNIT_SIZE) {
        edu::sharif::twinner::util::Logger::loquacious ()
            << "\tupdating stack (pushing the ret address)...";
        edu::sharif::twinner::trace::StateSummary state;
        edu::sharif::twinner::trace::Expression *exp =
            getMemExpression (rspRegVal.toUint64 (),
                              STACK_OPERATION_UNIT_SIZE,
                              trace,
                              state);
        if (exp) {
          delete exp;
        }
        if (state.isWrongState ()) {
          edu::sharif::twinner::trace::Expression *exp =
              new edu::sharif::twinner::trace::ExpressionImp
              (state.getExpectedStateValue ());
          setMemExpression (rspRegVal.toUint64 (),
                            STACK_OPERATION_UNIT_SIZE,
                            trace, exp);
        }
      } else {
        edu::sharif::twinner::util::Logger::warning ()
            << "CALL decremented RSP more/less than "
            << STACK_OPERATION_UNIT_SIZE << " bytes;"
            " check for CALL_FAR instruction!\n";
      }
      rsp->minus (cv);
      // TODO: call valueIsChanged from an expression proxy to address ESP, SP, and SPL

    } else {
      edu::sharif::twinner::util::Logger::warning ()
          << "RSP is not decremented at all after CALL instruction!\n";
    }
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::checkForEndOfSafeFunc (const CONTEXT *context,
    const ConcreteValue &ripRegVal) {
  if (endOfSafeFuncRetAddress == ripRegVal.toUint64 ()) {
    im->afterSafeFunction (context);
    withinSafeFunc = false;
  }
}

void InstructionSymbolicExecuter::retAnalysisRoutine (const CONTEXT *context,
    const ConcreteValue &rspRegVal) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "retAnalysisRoutine(...)\n"
      << "\tgetting rsp reg exp...";
  edu::sharif::twinner::trace::Expression *rsp =
#ifdef TARGET_IA32E
      trace->tryToGetSymbolicExpressionByRegister (64, REG_RSP);
#else
      trace->tryToGetSymbolicExpressionByRegister (32, REG_ESP);
#endif
  if (rsp) { // If we are not tracking RSP yet, it's not required to adjust its value
    const ConcreteValue &oldVal = rsp->getLastConcreteValue ();
    if (oldVal < rspRegVal) {
      // some items have been popped out from the stack by RET and so RSP is incremented
      ConcreteValue *cv = rspRegVal.clone ();
      (*cv) -= oldVal;
      edu::sharif::twinner::util::Logger::loquacious ()
          << "\tadjusting rsp, amount = " << *cv;
      const bool normalRetInstruction = ((*cv) == STACK_OPERATION_UNIT_SIZE)
          || ((*cv) == 2 * STACK_OPERATION_UNIT_SIZE);
      if (!normalRetInstruction) {
        edu::sharif::twinner::util::Logger::error ()
            << "InstructionSymbolicExecuter::retAnalysisRoutine (...): "
            "ret instruction must pop either "
            << STACK_OPERATION_UNIT_SIZE << " or "
            << (2 * STACK_OPERATION_UNIT_SIZE) << " bytes\n";
        return; // abort ();
      }
      rsp->add (cv);
      // TODO: call valueIsChanged from an expression proxy to address ESP, SP, and SPL

    } else {
      edu::sharif::twinner::util::Logger::warning ()
          << "RSP is not incremented at all after RET instruction!\n";
    }
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::retWithArgAnalysisRoutine (
    const CONTEXT *context, const ConcreteValue &rspRegVal, ADDRINT offset) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "retWithArgAnalysisRoutine(...)\n"
      << "\tgetting rsp reg exp...";
  edu::sharif::twinner::trace::Expression *rsp =
#ifdef TARGET_IA32E
      trace->tryToGetSymbolicExpressionByRegister (64, REG_RSP);
#else
      trace->tryToGetSymbolicExpressionByRegister (32, REG_ESP);
#endif
  if (rsp) { // If we are not tracking RSP yet, it's not required to adjust its value
    const ConcreteValue &oldVal = rsp->getLastConcreteValue ();
    if (oldVal < rspRegVal) {
      // some items have been popped out from the stack by RET and so RSP is incremented
      ConcreteValue *cv = rspRegVal.clone ();
      (*cv) -= oldVal;
      edu::sharif::twinner::util::Logger::loquacious ()
          << "\tadjusting rsp, amount = " << *cv;
      const bool normalRetInstruction =
          ((*cv) == STACK_OPERATION_UNIT_SIZE + offset)
          || ((*cv) == 2 * STACK_OPERATION_UNIT_SIZE + offset);
      if (!normalRetInstruction) {
        edu::sharif::twinner::util::Logger::error ()
            << "InstructionSymbolicExecuter::retWithArgAnalysisRoutine (...): "
            "ret instruction must pop either "
            << (STACK_OPERATION_UNIT_SIZE + offset) << " or "
            << (2 * STACK_OPERATION_UNIT_SIZE + offset) << " bytes\n";
        return; // abort ();
      }
      rsp->add (cv);
      // TODO: call valueIsChanged from an expression proxy to address ESP, SP, and SPL

    } else {
      edu::sharif::twinner::util::Logger::warning ()
          << "RSP is not incremented at all after RET instruction!\n";
    }
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::jmpAnalysisRoutine (const CONTEXT *context,
    const ConcreteValue &rspRegVal) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "jmpAnalysisRoutine(...)\n"
      << "\tgetting rsp reg exp...";
  edu::sharif::twinner::trace::Expression *rsp =
#ifdef TARGET_IA32E
      trace->tryToGetSymbolicExpressionByRegister (64, REG_RSP);
#else
      trace->tryToGetSymbolicExpressionByRegister (64, REG_ESP);
#endif
  if (rsp) { // If we are not tracking RSP yet, it's not required to adjust its value
    const ConcreteValue &oldVal = rsp->getLastConcreteValue ();
    if (oldVal != rspRegVal) { // This jump had side-effect on RSP
      if (oldVal < rspRegVal) {
        ConcreteValue *cv = rspRegVal.clone ();
        (*cv) -= oldVal;
        edu::sharif::twinner::util::Logger::warning ()
            << "JMP instruction popped items out of stack"
            ", amount = " << *cv << '\n';
      } else { // oldVal > rspRegVal
        ConcreteValue *cv = oldVal.clone ();
        (*cv) -= rspRegVal;
        edu::sharif::twinner::util::Logger::warning ()
            << "JMP instruction pushed items into stack"
            ", amount = " << *cv << '\n';
      }
      edu::sharif::twinner::util::Logger::error ()
          << "InstructionSymbolicExecuter::jmpAnalysisRoutine (...):"
          " jmp instruction must not have any side effect"
          " (it changed the RSP)\n";
      return; // abort ();
    }
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::repAnalysisRoutine (
    REG repReg, const ConcreteValue &repRegVal,
    bool executing, bool repEqual) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "repAnalysisRoutine(...)\n"
      << "\tgetting dst (rep) reg exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (repReg, repRegVal, trace);
  bool zero;
  edu::sharif::twinner::trace::Constraint *cc =
      edu::sharif::twinner::trace::Constraint::instantiateEqualConstraint
      (zero, dstexp, disassembledInstruction);
  if (zero == executing) {
    edu::sharif::twinner::util::Logger::error ()
        << "InstructionSymbolicExecuter::repAnalysisRoutine (...): "
        "REP count and executing state do not match\n";
    return; // abort ();
  }
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  if (executing) {
    edu::sharif::twinner::util::Logger::loquacious () << "\tdecrementing count reg...";
    dstexp->minus (1);
    setRegExpression (repReg, trace, dstexp, false);
  }
  delete dstexp;
  std::list <edu::sharif::twinner::trace::Constraint *> ccList;
  ccList.push_front (cc);
  trace->addPathConstraints (ccList);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pslldqAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "pslldqAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  srcexp->multiply (8); // convert byte to bits
  edu::sharif::twinner::trace::cv::ConcreteValue *cv =
      srcexp->getLastConcreteValue ().clone ();
  dstexp->shiftToLeft (cv);
  // truncate bits which are shifted left, outside of dst boundaries
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftLeftOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shlAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shlAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  // src was an immediate value
  dstexp->shiftToLeft (srcexp->getLastConcreteValue ().clone ());
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftLeftOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shlAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shlAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  // src was an immediate value
  dstexp->shiftToLeft (srcexp->getLastConcreteValue ().clone ());
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftLeftOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shlAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shlAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  // src was CL register
  dstexp->shiftToLeft (srcexp);
  // truncate bits which are shifted left, outside of dst boundaries
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftLeftOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shlAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shlAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  // src was CL register
  dstexp->shiftToLeft (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftLeftOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shrAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shrAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToRight (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftRightOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shrAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shrAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToRight (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftRightOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shrAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shrAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToRight (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftRightOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::shrAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "shrAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  const int mask =
      dstexpOrig->getLastConcreteValue ().getSize () > 32 ? 0x3f : 0x1f;
  srcexp->bitwiseAnd (mask);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->shiftToRight (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::ShiftRightOperationGroup
       (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sarAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sarAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->arithmeticShiftToRight (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags (new edu::sharif::twinner::operationgroup
                   ::ShiftArithmeticRightOperationGroup (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sarAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sarAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->arithmeticShiftToRight (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags (new edu::sharif::twinner::operationgroup
                   ::ShiftArithmeticRightOperationGroup (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sarAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sarAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->arithmeticShiftToRight (srcexp);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags (new edu::sharif::twinner::operationgroup
                   ::ShiftArithmeticRightOperationGroup (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::sarAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "sarAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tshifting operation...";
  dstexp->arithmeticShiftToRight (srcexp);
  setRegExpression (dstReg, trace, dstexp);
  eflags.setFlags (new edu::sharif::twinner::operationgroup
                   ::ShiftArithmeticRightOperationGroup (dstexpOrig, srcexp));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rorAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *lsb = dstexp->clone ();
  lsb->truncate (1);
  // TODO: set lsb as the carry flag (CF) value
  delete lsb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-right operation...";
  dstexp->rotateToRight (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rorAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *lsb = dstexp->clone ();
  lsb->truncate (1);
  // TODO: set lsb as the carry flag (CF) value
  delete lsb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-right operation...";
  dstexp->rotateToRight (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rorAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *lsb = dstexp->clone ();
  lsb->truncate (1);
  // TODO: set lsb as the carry flag (CF) value
  delete lsb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-right operation...";
  dstexp->rotateToRight (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rorAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *lsb = dstexp->clone ();
  lsb->truncate (1);
  // TODO: set lsb as the carry flag (CF) value
  delete lsb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-right operation...";
  dstexp->rotateToRight (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rolAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rolAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *msb = dstexp->clone ();
  msb->shiftToRight (dstexp->getLastConcreteValue ().getSize () - 1);
  msb->truncate (1);
  // TODO: set msb as the carry flag (CF) value
  delete msb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-left operation...";
  dstexp->rotateToLeft (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rolAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rolAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *msb = dstexp->clone ();
  msb->shiftToRight (dstexp->getLastConcreteValue ().getSize () - 1);
  msb->truncate (1);
  // TODO: set msb as the carry flag (CF) value
  delete msb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-left operation...";
  dstexp->rotateToLeft (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rolAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rolAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *msb = dstexp->clone ();
  msb->shiftToRight (dstexp->getLastConcreteValue ().getSize () - 1);
  msb->truncate (1);
  // TODO: set msb as the carry flag (CF) value
  delete msb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-left operation...";
  dstexp->rotateToLeft (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rolAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rolAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::trace::Expression *msb = dstexp->clone ();
  msb->shiftToRight (dstexp->getLastConcreteValue ().getSize () - 1);
  msb->truncate (1);
  // TODO: set msb as the carry flag (CF) value
  delete msb;
  edu::sharif::twinner::util::Logger::loquacious () << "\trotating-left operation...";
  dstexp->rotateToLeft (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::andAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "andAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::andAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "andAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcImmediateValue.clone ());
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::andAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "andAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::andAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "andAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::andAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "andAnalysisRoutine(...)\n";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::orAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "orAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::orAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "orAnalysisRoutine(...)\n";
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseOr (srcImmediateValue.clone ());
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::orAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "orAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::orAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "orAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::orAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "orAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xorAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseXor (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xorAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xorAnalysisRoutine(...)\n";
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseXor (srcImmediateValue.clone ());
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xorAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseXor (srcexp);
  delete srcexp;
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xorAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseXor (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::xorAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "xorAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseXor (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp, false);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::testAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "testAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcexp);
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::testAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "testAnalysisRoutine(...)\n";
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcImmediateValue.clone ());
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::testAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "testAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcexp);
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::testAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "testAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tbinary operation...";
  dstexp->bitwiseAnd (srcexp);
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::BitwiseAndOperationGroup
       (dstexp));
  eflags.setOverflowFlag (false);
  eflags.setCarryFlag (false);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  offsetexp->bitwiseAnd (memReadBytes * 8 - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  delete offsetexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  offsetexp->bitwiseAnd ((REG_Size (dstReg) * 8) - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  delete offsetexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  offsetexp->bitwiseAnd (memReadBytes * 8 - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  delete offsetexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  offsetexp->bitwiseAnd ((REG_Size (dstReg) * 8) - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  delete offsetexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btrAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstMemSrcImd (dstMemoryEa, memReadBytes, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btrAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      bitstringexpOrig->clone ();
  offsetexp->bitwiseAnd (memReadBytes * 8 - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tresetting selected bit...";
  edu::sharif::twinner::trace::Expression *mask =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  mask->shiftToLeft (offsetexp);
  delete offsetexp;
  mask->bitwiseNegate ();
  bitstringexpOrig->bitwiseAnd (mask);
  delete mask;
  setMemExpression (dstMemoryEa, memReadBytes, trace, bitstringexpOrig);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btrAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    const ConcreteValue &srcImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcImd (dstReg, dstRegVal, srcImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btrAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      new edu::sharif::twinner::trace::ExpressionImp (srcImmediateValue);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      bitstringexpOrig->clone ();
  offsetexp->bitwiseAnd ((REG_Size (dstReg) * 8) - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tresetting selected bit...";
  edu::sharif::twinner::trace::Expression *mask =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  mask->shiftToLeft (offsetexp);
  delete offsetexp;
  mask->bitwiseNegate ();
  bitstringexpOrig->bitwiseAnd (mask);
  delete mask;
  setRegExpression (dstReg, trace, bitstringexpOrig);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btrAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstMemSrcReg (dstMemoryEa, memReadBytes, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btrAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      bitstringexpOrig->clone ();
  offsetexp->bitwiseAnd (memReadBytes * 8 - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tresetting selected bit...";
  edu::sharif::twinner::trace::Expression *mask =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  mask->shiftToLeft (offsetexp);
  delete offsetexp;
  mask->bitwiseNegate ();
  bitstringexpOrig->bitwiseAnd (mask);
  delete mask;
  setMemExpression (dstMemoryEa, memReadBytes, trace, bitstringexpOrig);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::btrAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "btrAnalysisRoutine(...)\n"
      << "\tgetting offset exp...";
  edu::sharif::twinner::trace::Expression *offsetexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting bitstring exp...";
  edu::sharif::twinner::trace::Expression *bitstringexpOrig =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tfinding requested bit...";
  edu::sharif::twinner::trace::Expression *bitstringexp =
      bitstringexpOrig->clone ();
  offsetexp->bitwiseAnd ((REG_Size (dstReg) * 8) - 1);
  bitstringexp->shiftToRight (offsetexp);
  bitstringexp->bitwiseAnd (0x1);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting EFLAGS...";
  eflags.setCarryFlag (bitstringexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tresetting selected bit...";
  edu::sharif::twinner::trace::Expression *mask =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  mask->shiftToLeft (offsetexp);
  delete offsetexp;
  mask->bitwiseNegate ();
  bitstringexpOrig->bitwiseAnd (mask);
  delete mask;
  setRegExpression (dstReg, trace, bitstringexpOrig);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pmovmskbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pmovmskbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tpreparing mask-byte(src)...";
  edu::sharif::twinner::trace::Expression *maskbyte =
      new edu::sharif::twinner::trace::ExpressionImp (); // zero-filled
  // src is a reg and is mutable
  const int size = REG_Size (srcReg) * 8;
  for (int i = 7, loc = 0; i < size; i += 8) {
    edu::sharif::twinner::trace::Expression *ithBit = srcexp->clone ();
    ithBit->shiftToRight (i - loc); // it is (i+1)-th bit in 1-counting mode
    ithBit->bitwiseAnd (1 << loc); // i-th bit in 0-counting
    loc++;
    maskbyte->bitwiseOr (ithBit);
    delete ithBit;
  }
  delete srcexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, maskbyte);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pcmpeqbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pcmpeqbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tcomparing...";
  const int size = REG_Size (dstReg) * 8;
  ConcreteValue *result = dstexp->getLastConcreteValue ().clone ();
  *result = 0;
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  bool equal;
  for (int i = 0; i < size; i += 8) {
    edu::sharif::twinner::trace::Expression *ithByteSrc = srcexp->clone ();
    edu::sharif::twinner::trace::Expression *ithByteDst = dstexp->clone ();
    ithByteSrc->shiftToRight (i);
    ithByteSrc->bitwiseAnd (0xFF);
    ithByteDst->shiftToRight (i);
    ithByteDst->bitwiseAnd (0xFF);
    //    edu::sharif::twinner::util::Logger::warning () << "byte: " << i
    //        << " from src: " << ithByteSrc << " and from dst: " << ithByteDst << "\n";
    ithByteSrc->minus (ithByteDst);
    edu::sharif::twinner::trace::Constraint *ithBytesAreEqualConstraint =
        edu::sharif::twinner::trace::Constraint::instantiateEqualConstraint
        (equal, ithByteSrc, disassembledInstruction);
    cc.push_back (ithBytesAreEqualConstraint);
    ConcreteValue *c = dstexp->getLastConcreteValue ().clone ();
    *c = equal ? 0xFF : 0x00;
    delete ithByteSrc;
    delete ithByteDst;
    (*c) <<= i;
    (*result) |= (*c);
    delete c;
  }
  trace->addPathConstraints (cc);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *resexp =
      new edu::sharif::twinner::trace::ExpressionImp (result);
  setRegExpression (dstReg, trace, resexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pcmpeqbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pcmpeqbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tcomparing...";
  const int size = REG_Size (dstReg) * 8;
  ConcreteValue *result = dstexp->getLastConcreteValue ().clone ();
  *result = 0;
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  bool equal;
  for (int i = 0; i < size; i += 8) {
    edu::sharif::twinner::trace::Expression *ithByteSrc = srcexp->clone ();
    edu::sharif::twinner::trace::Expression *ithByteDst = dstexp->clone ();
    ithByteSrc->shiftToRight (i);
    ithByteSrc->bitwiseAnd (0xFF);
    ithByteDst->shiftToRight (i);
    ithByteDst->bitwiseAnd (0xFF);
    ithByteSrc->minus (ithByteDst);
    edu::sharif::twinner::trace::Constraint *ithBytesAreEqualConstraint =
        edu::sharif::twinner::trace::Constraint::instantiateEqualConstraint
        (equal, ithByteSrc, disassembledInstruction);
    cc.push_back (ithBytesAreEqualConstraint);
    ConcreteValue *c = dstexp->getLastConcreteValue ().clone ();
    *c = equal ? 0xFF : 0x00;
    delete ithByteSrc;
    delete ithByteDst;
    (*c) <<= i;
    (*result) |= (*c);
    delete c;
  }
  trace->addPathConstraints (cc);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *resexp =
      new edu::sharif::twinner::trace::ExpressionImp (result);
  setRegExpression (dstReg, trace, resexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pcmpgtbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "pcmpgtbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tcomparing...";
  const int size = REG_Size (dstReg) * 8;
  ConcreteValue *result = dstexp->getLastConcreteValue ().clone ();
  *result = 0;
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  for (int i = 0; i < size; i += 8) {
    edu::sharif::twinner::trace::Expression *ithByteSrc = srcexp->clone ();
    edu::sharif::twinner::trace::Expression *ithByteDst = dstexp->clone ();
    ithByteSrc->shiftToRight (i);
    ithByteSrc->bitwiseAnd (0xFF);
    ithByteDst->shiftToRight (i);
    ithByteDst->bitwiseAnd (0xFF);
    bool lessOrEqual;
    edu::sharif::twinner::trace::Constraint *ithDstByteIsGreaterThanSrc =
        edu::sharif::twinner::trace::Constraint::instantiateLessOrEqualConstraint
        (lessOrEqual, ithByteDst, ithByteSrc, disassembledInstruction);
    cc.push_back (ithDstByteIsGreaterThanSrc);
    ConcreteValue *c = dstexp->getLastConcreteValue ().clone ();
    *c = lessOrEqual ? 0x00 : 0xFF;
    delete ithByteSrc;
    delete ithByteDst;
    (*c) <<= i;
    (*result) |= (*c);
    delete c;
  }
  trace->addPathConstraints (cc);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *resexp =
      new edu::sharif::twinner::trace::ExpressionImp (result);
  setRegExpression (dstReg, trace, resexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pcmpgtbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "pcmpgtbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tcomparing...";
  const int size = REG_Size (dstReg) * 8;
  ConcreteValue *result = dstexp->getLastConcreteValue ().clone ();
  *result = 0;
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  for (int i = 0; i < size; i += 8) {
    edu::sharif::twinner::trace::Expression *ithByteSrc = srcexp->clone ();
    edu::sharif::twinner::trace::Expression *ithByteDst = dstexp->clone ();
    ithByteSrc->shiftToRight (i);
    ithByteSrc->bitwiseAnd (0xFF);
    ithByteDst->shiftToRight (i);
    ithByteDst->bitwiseAnd (0xFF);
    bool lessOrEqual;
    edu::sharif::twinner::trace::Constraint *ithDstByteIsGreaterThanSrc =
        edu::sharif::twinner::trace::Constraint::instantiateLessOrEqualConstraint
        (lessOrEqual, ithByteDst, ithByteSrc, disassembledInstruction);
    cc.push_back (ithDstByteIsGreaterThanSrc);
    ConcreteValue *c = dstexp->getLastConcreteValue ().clone ();
    *c = lessOrEqual ? 0x00 : 0xFF;
    delete ithByteSrc;
    delete ithByteDst;
    (*c) <<= i;
    (*result) |= (*c);
    delete c;
  }
  trace->addPathConstraints (cc);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *resexp =
      new edu::sharif::twinner::trace::ExpressionImp (result);
  setRegExpression (dstReg, trace, resexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pminubAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pminubAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tcalculating the minimum...";
  const int size = REG_Size (dstReg) * 8;
  ConcreteValue *mask = dstexp->getLastConcreteValue ().clone ();
  *mask = 0;
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  bool below;
  for (int i = 0; i < size; i += 8) {
    edu::sharif::twinner::trace::Expression *ithByteSrc = srcexp->clone ();
    edu::sharif::twinner::trace::Expression *ithByteDst = dstexp->clone ();
    ithByteSrc->shiftToRight (i);
    ithByteSrc->bitwiseAnd (0xFF);
    ithByteDst->shiftToRight (i);
    ithByteDst->bitwiseAnd (0xFF);
    edu::sharif::twinner::trace::Constraint *srcIsBelowDstConstraint =
        edu::sharif::twinner::trace::Constraint::instantiateBelowConstraint
        (below, ithByteSrc, ithByteDst, disassembledInstruction);
    cc.push_back (srcIsBelowDstConstraint);
    if (below) {
      ConcreteValue *c = dstexp->getLastConcreteValue ().clone ();
      *c = 0xFF;
      (*c) <<= i;
      (*mask) |= (*c);
      delete c;
    }
    delete ithByteSrc;
    delete ithByteDst;
  }
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\ttransferring (mask & src) to (dst) for mask=" << (*mask);
  dstexp->bitwiseAnd (mask->bitwiseNegated ());
  srcexp->bitwiseAnd (mask);
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::pminubAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "pminubAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tcalculating the minimum...";
  const int size = REG_Size (dstReg) * 8;
  ConcreteValue *mask = dstexp->getLastConcreteValue ().clone ();
  *mask = 0;
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  bool below;
  for (int i = 0; i < size; i += 8) {
    edu::sharif::twinner::trace::Expression *ithByteSrc = srcexp->clone ();
    edu::sharif::twinner::trace::Expression *ithByteDst = dstexp->clone ();
    ithByteSrc->shiftToRight (i);
    ithByteSrc->bitwiseAnd (0xFF);
    ithByteDst->shiftToRight (i);
    ithByteDst->bitwiseAnd (0xFF);
    edu::sharif::twinner::trace::Constraint *srcIsBelowDstConstraint =
        edu::sharif::twinner::trace::Constraint::instantiateBelowConstraint
        (below, ithByteSrc, ithByteDst, disassembledInstruction);
    cc.push_back (srcIsBelowDstConstraint);
    if (below) {
      ConcreteValue *c = dstexp->getLastConcreteValue ().clone ();
      *c = 0xFF;
      (*c) <<= i;
      (*mask) |= (*c);
      delete c;
    }
    delete ithByteSrc;
    delete ithByteDst;
  }
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\ttransferring (mask & src) to (dst) for mask=" << (*mask);
  dstexp->bitwiseAnd (mask->bitwiseNegated ());
  srcexp->bitwiseAnd (mask);
  dstexp->bitwiseOr (srcexp);
  delete srcexp;
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::psubbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "psubbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tsubtracting byte-by-byte...";
  edu::sharif::twinner::trace::Expression *res = 0;
  const int bytesNumber = size / 8;
  ConcreteValue *mask = dstexp->getLastConcreteValue ().clone ();
  (*mask) = 0xFF;
  for (int i = 0; i < bytesNumber; ++i) {
    edu::sharif::twinner::trace::Expression *nextDstByte = dstexp->clone (size);
    edu::sharif::twinner::trace::Expression *nextSrcByte = srcexp->clone (size);
    nextDstByte->bitwiseAnd (mask->clone ());
    nextSrcByte->bitwiseAnd (mask->clone ());
    nextDstByte->minus (nextSrcByte);
    delete nextSrcByte;
    nextDstByte->bitwiseAnd (mask->clone ());
    if (res == 0) {
      res = nextDstByte;
    } else {
      res->bitwiseOr (nextDstByte);
      delete nextDstByte;
    }
    (*mask) <<= 8;
  }
  delete mask;
  setRegExpression (dstReg, trace, res);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::psubbAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "psubbAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tsubtracting byte-by-byte...";
  edu::sharif::twinner::trace::Expression *res = 0;
  const int bytesNumber = size / 8;
  ConcreteValue *mask = dstexp->getLastConcreteValue ().clone ();
  (*mask) = 0xFF;
  for (int i = 0; i < bytesNumber; ++i) {
    edu::sharif::twinner::trace::Expression *nextDstByte = dstexp->clone (size);
    edu::sharif::twinner::trace::Expression *nextSrcByte = srcexp->clone (size);
    nextDstByte->bitwiseAnd (mask->clone ());
    nextSrcByte->bitwiseAnd (mask->clone ());
    nextDstByte->minus (nextSrcByte);
    delete nextSrcByte;
    nextDstByte->bitwiseAnd (mask->clone ());
    if (res == 0) {
      res = nextDstByte;
    } else {
      res->bitwiseOr (nextDstByte);
      delete nextDstByte;
    }
    (*mask) <<= 8;
  }
  delete mask;
  setRegExpression (dstReg, trace, res);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::punpcklbwAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "punpcklbwAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tunpacking and interleaving low-data byte-to-word...";
  edu::sharif::twinner::trace::Expression *res = dstexp->clone ();
  res->truncate (8);
  // dst: d3 d2 d1 d0 | src: s3 s2 s1 s0
  // res: s3 d3 s2 d2 s1 d1 s0 d0
  UINT64 byteMask = 0xFF;
  const edu::sharif::twinner::trace::Expression *operand = srcexp;
  int bytesNumber = size / 16;
  for (int k = 0; k < 2; ++k) {
    for (int i = 0; i < bytesNumber; ++i) {
      const int shift = (i + 1) * 8;
      edu::sharif::twinner::trace::Expression *nextByte = operand->clone (size);
      nextByte->bitwiseAnd (byteMask);
      nextByte->shiftToLeft (shift);
      res->bitwiseOr (nextByte);
      delete nextByte;
      byteMask <<= 8;
    }
    byteMask = 0xFF00;
    operand = dstexp;
    --bytesNumber;
  }
  setRegExpression (dstReg, trace, res);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::punpcklbwAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "punpcklbwAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tunpacking and interleaving low-data byte-to-word...";
  edu::sharif::twinner::trace::Expression *res = dstexp->clone ();
  res->truncate (8);
  // dst: d3 d2 d1 d0 | src: s3 s2 s1 s0
  // res: s3 d3 s2 d2 s1 d1 s0 d0
  UINT64 byteMask = 0xFF;
  const edu::sharif::twinner::trace::Expression *operand = srcexp;
  int bytesNumber = size / 16;
  for (int k = 0; k < 2; ++k) {
    for (int i = 0; i < bytesNumber; ++i) {
      const int shift = (i + 1) * 8;
      edu::sharif::twinner::trace::Expression *nextByte = operand->clone (size);
      nextByte->bitwiseAnd (byteMask);
      nextByte->shiftToLeft (shift);
      res->bitwiseOr (nextByte);
      delete nextByte;
      byteMask <<= 8;
    }
    byteMask = 0xFF00;
    operand = dstexp;
    --bytesNumber;
  }
  setRegExpression (dstReg, trace, res);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::punpcklwdAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "punpcklwdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tunpacking and interleaving low-data word-to-double-word...";
  edu::sharif::twinner::trace::Expression *res = dstexp->clone ();
  res->truncate (16);
  // dst: d3 d2 d1 d0 | src: s3 s2 s1 s0 (di and si are 16-bits/word)
  // res: s3 d3 s2 d2 s1 d1 s0 d0
  UINT64 wordMask = 0xFFFF;
  const edu::sharif::twinner::trace::Expression *operand = srcexp;
  int wordsNumber = size / 32;
  for (int k = 0; k < 2; ++k) {
    for (int i = 0; i < wordsNumber; ++i) {
      const int shift = (i + 1) * 16;
      edu::sharif::twinner::trace::Expression *nextWord = operand->clone (size);
      nextWord->bitwiseAnd (wordMask);
      nextWord->shiftToLeft (shift);
      res->bitwiseOr (nextWord);
      delete nextWord;
      wordMask <<= 16;
    }
    wordMask = 0xFFFF0000;
    operand = dstexp;
    --wordsNumber;
  }
  setRegExpression (dstReg, trace, res);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::punpcklwdAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "punpcklwdAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tunpacking and interleaving low-data word-to-double-word...";
  edu::sharif::twinner::trace::Expression *res = dstexp->clone ();
  res->truncate (16);
  // dst: d3 d2 d1 d0 | src: s3 s2 s1 s0 (di and si are 16-bits/word)
  // res: s3 d3 s2 d2 s1 d1 s0 d0
  UINT64 wordMask = 0xFFFF;
  const edu::sharif::twinner::trace::Expression *operand = srcexp;
  int wordsNumber = size / 32;
  for (int k = 0; k < 2; ++k) {
    for (int i = 0; i < wordsNumber; ++i) {
      const int shift = (i + 1) * 16;
      edu::sharif::twinner::trace::Expression *nextWord = operand->clone (size);
      nextWord->bitwiseAnd (wordMask);
      nextWord->shiftToLeft (shift);
      res->bitwiseOr (nextWord);
      delete nextWord;
      wordMask <<= 16;
    }
    wordMask = 0xFFFF0000;
    operand = dstexp;
    --wordsNumber;
  }
  setRegExpression (dstReg, trace, res);
  delete srcexp;
  delete dstexp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::bsfAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "bsfAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  const edu::sharif::twinner::trace::cv::ConcreteValue &cv = srcexp->getLastConcreteValue ();
  UINT64 i = 0;
  for (unsigned int s = cv.getSize (); i < s; ++i) {
    edu::sharif::twinner::trace::cv::ConcreteValue *bit = cv.clone ();
    (*bit) >>= i;
    (*bit) &= 1;
    if ((*bit) == 1) {
      delete bit;
      break;
    }
    delete bit;
  }
  edu::sharif::twinner::trace::Expression *indexexp =
      new edu::sharif::twinner::trace::ExpressionImp (i);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, indexexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  edu::sharif::twinner::trace::Expression *conditionExp = srcexp;
  edu::sharif::twinner::trace::cv::ConcreteValue *bit = cv.clone ();
  (*bit) = 1;
  (*bit) <<= i;
  conditionExp->truncate (i + 1);
  conditionExp->minus (bit); // takes ownership of bit
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  edu::sharif::twinner::trace::Constraint *bsfConstraint =
      new edu::sharif::twinner::trace::Constraint
      (conditionExp, edu::sharif::twinner::trace::Constraint::ZERO,
       disassembledInstruction, false);
  cc.push_back (bsfConstraint);
  delete conditionExp;
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::bsfAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "bsfAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  const edu::sharif::twinner::trace::cv::ConcreteValue &cv = srcexp->getLastConcreteValue ();
  UINT64 i = 0;
  for (unsigned int s = cv.getSize (); i < s; ++i) {
    edu::sharif::twinner::trace::cv::ConcreteValue *bit = cv.clone ();
    (*bit) >>= i;
    (*bit) &= 1;
    if ((*bit) == 1) {
      delete bit;
      break;
    }
    delete bit;
  }
  edu::sharif::twinner::trace::Expression *indexexp =
      new edu::sharif::twinner::trace::ExpressionImp (i);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (dstReg, trace, indexexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  edu::sharif::twinner::trace::Expression *conditionExp = srcexp;
  edu::sharif::twinner::trace::cv::ConcreteValue *bit = cv.clone ();
  (*bit) = 1;
  (*bit) <<= i;
  conditionExp->truncate (i + 1);
  conditionExp->minus (bit); // takes ownership of bit
  std::list <edu::sharif::twinner::trace::Constraint *> cc;
  edu::sharif::twinner::trace::Constraint *bsfConstraint =
      new edu::sharif::twinner::trace::Constraint
      (conditionExp, edu::sharif::twinner::trace::Constraint::ZERO,
       disassembledInstruction, false);
  cc.push_back (bsfConstraint);
  delete conditionExp;
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::divAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcMem (dstLeftReg, dstLeftRegVal, dstRightReg, dstRightRegVal,
                              srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "divAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting left dst exp...";
  edu::sharif::twinner::trace::Expression *leftDstExp =
      getRegExpression (dstLeftReg, dstLeftRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tpreparing left-right in both dst regs...";
  operandSize = REG_Size (dstLeftReg) * 8;
  leftDstExp->shiftToLeft (operandSize);
  leftDstExp->bitwiseOr (rightDstExp);
  delete rightDstExp;
  rightDstExp = leftDstExp->clone ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tcalculating quotient (right) and remainder (left) of division...";
  leftDstExp->remainder (srcexp);
  rightDstExp->divide (srcexp);
  delete srcexp;
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic quotient and remainder are calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::divAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcReg (dstLeftReg, dstLeftRegVal, dstRightReg, dstLeftRegVal,
                              srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "divAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting left dst exp...";
  edu::sharif::twinner::trace::Expression *leftDstExp =
      getRegExpression (dstLeftReg, dstLeftRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tpreparing left-right in both dst regs...";
  operandSize = REG_Size (dstLeftReg) * 8;
  leftDstExp->shiftToLeft (operandSize);
  leftDstExp->bitwiseOr (rightDstExp);
  delete rightDstExp;
  rightDstExp = leftDstExp->clone ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tcalculating quotient (right) and remainder (left) of division...";
  leftDstExp->remainder (srcexp);
  rightDstExp->divide (srcexp);
  delete srcexp;
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic quotient and remainder are calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::idivAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcMem (dstLeftReg, dstLeftRegVal, dstRightReg, dstRightRegVal,
                              srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "idivAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting left dst exp...";
  edu::sharif::twinner::trace::Expression *leftDstExp =
      getRegExpression (dstLeftReg, dstLeftRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tpreparing left-right in both dst regs...";
  operandSize = REG_Size (dstLeftReg) * 8;
  leftDstExp->shiftToLeft (operandSize);
  leftDstExp->bitwiseOr (rightDstExp);
  delete rightDstExp;
  rightDstExp = leftDstExp->clone ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tcalculating quotient (right)"
      " and remainder (left) of signed division...";
  leftDstExp->signedRemainder (srcexp);
  rightDstExp->signedDivide (srcexp);
  delete srcexp;
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic quotient and remainder are calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::idivAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcReg (dstLeftReg, dstLeftRegVal, dstRightReg, dstLeftRegVal,
                              srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "idivAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting left dst exp...";
  edu::sharif::twinner::trace::Expression *leftDstExp =
      getRegExpression (dstLeftReg, dstLeftRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tpreparing left-right in both dst regs...";
  operandSize = REG_Size (dstLeftReg) * 8;
  leftDstExp->shiftToLeft (operandSize);
  leftDstExp->bitwiseOr (rightDstExp);
  delete rightDstExp;
  rightDstExp = leftDstExp->clone ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tcalculating quotient (right)"
      " and remainder (left) of signed division...";
  leftDstExp->signedRemainder (srcexp);
  rightDstExp->signedDivide (srcexp);
  delete srcexp;
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic quotient and remainder are calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands (
    const CONTEXT *context, const ConcreteValue &operandSize) {
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "adjustDivisionMultiplicationOperands(...) hook...";
  const edu::sharif::twinner::trace::cv::ConcreteValue64Bits os = operandSize;
  const UINT64 osval = os.toUint64 ();
  REG leftReg, rightReg;
  switch (osval) {
  case 8:
    leftReg = REG_AH;
    rightReg = REG_AL;
    break;
  case 16:
    leftReg = REG_DX;
    rightReg = REG_AX;
    break;
  case 32:
    leftReg = REG_EDX;
    rightReg = REG_EAX;
    break;
#ifdef TARGET_IA32E
  case 64:
    leftReg = REG_RDX;
    rightReg = REG_RAX;
    break;
#endif
  default:
    edu::sharif::twinner::util::Logger::error ()
        << "adjustDivisionMultiplicationOperands(...) hook: "
        "unsupported operand size: " << operandSize << '\n';
    abort ();
  }
  ConcreteValue *leftVal =
      edu::sharif::twinner::util::readRegisterContent (context, leftReg);
  ConcreteValue *rightVal =
      edu::sharif::twinner::util::readRegisterContent (context, rightReg);
  edu::sharif::twinner::trace::Expression *leftExp =
      trace->getSymbolicExpressionByRegister (osval, leftReg);
  edu::sharif::twinner::trace::Expression *rightExp =
      trace->getSymbolicExpressionByRegister (osval, rightReg);
  leftExp->setLastConcreteValue (leftVal);
  rightExp->setLastConcreteValue (rightVal);
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tconcrete values are adjusted...";
  if (osval == 8) { // AX == AH:AL
    leftExp->shiftToLeft (8);
    leftExp->bitwiseOr (rightExp);
    setRegExpression (REG_AX, trace, leftExp, false); // this deletes unused expressions by itself
  } else {
    edu::sharif::twinner::trace::StateSummary state;
    registerValueIsChanged (leftReg, trace, *leftExp, state);
    if (state.isWrongState ()) {
      edu::sharif::twinner::util::Logger::error () << state.getMessage () << '\n';
      abort ();
    }
    registerValueIsChanged (rightReg, trace, *rightExp, state);
    if (state.isWrongState ()) {
      edu::sharif::twinner::util::Logger::error () << state.getMessage () << '\n';
      abort ();
    }
  }
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\toverlapping registers are updated.\n";
}

void InstructionSymbolicExecuter::mulAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcMem (dstLeftReg, dstLeftRegVal, dstRightReg, dstRightRegVal,
                              srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "mulAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *leftDstExp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  operandSize = REG_Size (dstLeftReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmultiplying (left-right = right * src; size=0x"
      << std::hex << operandSize << ")...";
  rightDstExp->multiply (srcexp);
  delete srcexp;
  leftDstExp = rightDstExp->clone ();
  leftDstExp->shiftToRight (operandSize);
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic multiplication result is calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::mulAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcReg (dstLeftReg, dstLeftRegVal, dstRightReg, dstLeftRegVal,
                              srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "mulAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::trace::Expression *leftDstExp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  operandSize = REG_Size (dstLeftReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmultiplying (left-right = right * src; size=0x"
      << std::hex << operandSize << ")...";
  rightDstExp->multiply (srcexp);
  delete srcexp;
  leftDstExp = rightDstExp->clone ();
  leftDstExp->shiftToRight (operandSize);
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic multiplication result is calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::imulAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcMem (dstLeftReg, dstLeftRegVal, dstRightReg, dstRightRegVal,
                              srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  operandSize = REG_Size (dstLeftReg) * 8;
  const int doubleSize = operandSize * 2;
  /*
   * Operation: (leftDst-rightDst) = rightDst <signed-multiply> src
   * Signed and unsigned multiplications are equivalent iff result is truncated
   * to size of operands. So we should first sign-extend operands to double-size
   * and then do unsigned multiplication.
   */
  edu::sharif::twinner::util::Logger::loquacious () << "imulAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *signExtendedExp =
      srcexp->signExtended (doubleSize);
  delete srcexp;
  srcexp = signExtendedExp;
  edu::sharif::twinner::trace::Expression *leftDstExp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  signExtendedExp = rightDstExp->signExtended (doubleSize);
  delete rightDstExp;
  rightDstExp = signExtendedExp;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tsigned multiplying (left-right = right * src; size=0x"
      << std::hex << operandSize << ")...";
  rightDstExp->multiply (srcexp);
  delete srcexp;
  leftDstExp = rightDstExp->clone ();
  leftDstExp->shiftToRight (operandSize);
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic multiplication result is calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::imulAnalysisRoutine (
    REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
    REG dstRightReg, const ConcreteValue &dstRightRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcReg (dstLeftReg, dstLeftRegVal, dstRightReg, dstLeftRegVal,
                              srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  operandSize = REG_Size (dstLeftReg) * 8;
  const int doubleSize = operandSize * 2;
  /*
   * Operation: (leftDst-rightDst) = rightDst <signed-multiply> src
   * Signed and unsigned multiplications are equivalent iff result is truncated
   * to size of operands. So we should first sign-extend operands to double-size
   * and then do unsigned multiplication.
   */
  edu::sharif::twinner::util::Logger::loquacious () << "imulAnalysisRoutine(...)\n"
      << "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::trace::Expression *signExtendedExp =
      srcexp->signExtended (doubleSize);
  delete srcexp;
  srcexp = signExtendedExp;
  edu::sharif::twinner::trace::Expression *leftDstExp;
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting right dst exp...";
  edu::sharif::twinner::trace::Expression *rightDstExp =
      getRegExpression (dstRightReg, dstRightRegVal, trace);
  signExtendedExp = rightDstExp->signExtended (doubleSize);
  delete rightDstExp;
  rightDstExp = signExtendedExp;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tsigned multiplying (left-right = right * src; size=0x"
      << std::hex << operandSize << ")...";
  rightDstExp->multiply (srcexp);
  delete srcexp;
  leftDstExp = rightDstExp->clone ();
  leftDstExp->shiftToRight (operandSize);
  setRegExpressionWithoutChangeNotification (dstLeftReg, trace, leftDstExp);
  setRegExpressionWithoutChangeNotification (dstRightReg, trace, rightDstExp);
  // At this point, symbolic multiplication result is calculated correctly.
  // but concrete values are not! So we need to register a hook to synchronize concrete
  // values too (we can also calculate them in assembly, but it's not required).

  hook = &InstructionSymbolicExecuter::adjustDivisionMultiplicationOperands;
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::imulAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstRegSrcMem (dstReg, dstRegVal, srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "imulAnalysisRoutine(...): "
      "two-operands-mode\n"
      "\tgetting src exp...";
  const edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmultiplying (dst = dst * src; size=0x" << std::hex << size << ")...";
  dstexp->multiply (srcexp);
  delete srcexp;
  dstexp->truncate (size);
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::imulAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcReg (dstReg, dstRegVal, srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "imulAnalysisRoutine(...): "
      "two-operands-mode\n"
      "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (dstReg, dstRegVal, trace);
  const int size = REG_Size (dstReg) * 8;
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmultiplying (dst = dst * src; size=0x" << std::hex << size << ")...";
  dstexp->multiply (srcexp);
  delete srcexp;
  dstexp->truncate (size);
  setRegExpression (dstReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::imulAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    const ConcreteValue &auxImmediateValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcMemAuxImd (dstReg, dstRegVal, srcMemoryEa, memReadBytes,
                              auxImmediateValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "imulAnalysisRoutine(...): "
      "three-operands-mode\n"
      "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting imd exp...";
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmultiplying (dst = src * imd)...";
  srcexp->multiply (auxImmediateValue.clone ());
  setRegExpression (dstReg, trace, srcexp); // sets and truncates expression
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::imulAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    const ConcreteValue &imdValue,
    UINT32 insAssembly) {
  if (!logDstRegSrcRegAuxImd (dstReg, dstRegVal, srcReg, srcRegVal, imdValue, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "imulAnalysisRoutine(...): "
      "three-operands-mode\n"
      "\tgetting src exp...";
  edu::sharif::twinner::trace::Expression *srcexp =
      getRegExpression (srcReg, srcRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tgetting imd exp...";
  edu::sharif::twinner::util::Logger::loquacious ()
      << "\tmultiplying (dst = src * imd)...";
  srcexp->multiply (imdValue.clone ());
  setRegExpression (dstReg, trace, srcexp); // sets and truncates expression
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::scasAnalysisRoutine (
    REG dstReg, const ConcreteValue &dstRegVal,
    REG rdiReg, const ConcreteValue &rdiRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcMem (dstReg, dstRegVal, rdiReg, rdiRegVal,
                              srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "scasAnalysisRoutine(...)\n";
  cmpAnalysisRoutine (dstReg, dstRegVal, srcMemoryEa, memReadBytes); // comparing AL/AX/EAX/RAX with memory
  edu::sharif::twinner::trace::Expression *exp =
      getRegExpression (rdiReg, rdiRegVal, trace);
  if (eflags.getDirectionFlag ()) { // DF == 1
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tdecrementing index register...";
    exp->minus (REG_Size (dstReg));
  } else { // DF == 0
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tincrementing index register...";
    exp->add (REG_Size (dstReg));
  }
  setRegExpression (rdiReg, trace, exp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tchecking eflags...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> ccList =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  trace->addPathConstraints (ccList);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::stosAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    REG rdiReg, const ConcreteValue &rdiRegVal,
    REG srcReg, const ConcreteValue &srcRegVal,
    UINT32 insAssembly) {
  if (!logOneMemTwoReg (dstMemoryEa, memReadBytes, rdiReg, rdiRegVal,
                        srcReg, srcRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "stosAnalysisRoutine(...)\n";
  movAnalysisRoutine (dstMemoryEa, memReadBytes, srcReg, srcRegVal);
  edu::sharif::twinner::trace::Expression *rdiexp =
      getRegExpression (rdiReg, rdiRegVal, trace);
  if (eflags.getDirectionFlag ()) { // DF == 1
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tdecrementing index register...";
    rdiexp->minus (memReadBytes);
  } else { // DF == 0
    edu::sharif::twinner::util::Logger::loquacious ()
        << "\tincrementing index register...";
    rdiexp->add (memReadBytes);
  }
  setRegExpression (rdiReg, trace, rdiexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::leaveAnalysisRoutine (
    REG fpReg, const ConcreteValue &fpRegVal,
    REG spReg, const ConcreteValue &spRegVal,
    ADDRINT srcMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logTwoDstRegOneSrcMem (fpReg, fpRegVal, spReg, spRegVal,
                              srcMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "leaveAnalysisRoutine(...)\n"
      << "\tgetting frame pointer (to be set in stack pointer)...";
  edu::sharif::twinner::trace::Expression *rsp =
      getRegExpression (fpReg, fpRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tpopping frame pointer...";
  edu::sharif::twinner::trace::Expression *memexp =
      getMemExpression (srcMemoryEa, memReadBytes, trace);
  setRegExpression (fpReg, trace, memexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadjusting rsp...";
  rsp->add (STACK_OPERATION_UNIT_SIZE);
  setRegExpression (spReg, trace, rsp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::rdtscAnalysisRoutine (const CONTEXT *context,
    UINT32 insAssembly) {
  if (!logAfterOperandLessInstruction (context, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "rdtscAnalysisRoutine(...)\n";
  /**
   * Now, we are right after the RDTSC instruction and time-stamp is loaded in
   * the edx:eax registers. These registers should be loaded as immediate values
   * in symbolic expressions.
   */
  // FIXME: This code doesn't preserve time-stamp and is vulnerable to time bombs
  ConcreteValue *edxVal =
      edu::sharif::twinner::util::readRegisterContent (context, REG_EDX);
  ConcreteValue *eaxVal =
      edu::sharif::twinner::util::readRegisterContent (context, REG_EAX);
  edu::sharif::twinner::trace::Expression *edxNewExp =
      new edu::sharif::twinner::trace::ExpressionImp (edxVal);
  edu::sharif::twinner::trace::Expression *eaxNewExp =
      new edu::sharif::twinner::trace::ExpressionImp (eaxVal);

  setRegExpression (REG_EDX, trace, edxNewExp);
  setRegExpression (REG_EAX, trace, eaxNewExp);
}

void InstructionSymbolicExecuter::cldAnalysisRoutine (const CONTEXT *context,
    UINT32 insAssembly) {
  if (!logAfterOperandLessInstruction (context, insAssembly)) {
    return;
  }
  edu::sharif::twinner::util::Logger::loquacious () << "cldAnalysisRoutine(...)\n";
  /**
   * Now, we are right after the CLD instruction. This is a decision to match with other
   * operand-less instructions. Anyway, our implementation for CLD works independent of
   * being executed before or after the CLD instruction itself.
   */
  eflags.setCarryFlag (false);
}

void InstructionSymbolicExecuter::cpuidAnalysisRoutine (const CONTEXT *context,
    UINT32 insAssembly) {
  if (!logAfterOperandLessInstruction (context, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "cpuidAnalysisRoutine(...)\n";
  /*
   * CPUID instruction will read EAX and ECX and based on their values, sets 4 registers
   * deterministically. Now, we are after the CPUID and can set those registers.
   */
  // FIXME: Two constraints must be created to state previous values of EAX and ECX
  ConcreteValue *eaxVal =
      edu::sharif::twinner::util::readRegisterContent (context, REG_EAX);
  ConcreteValue *ebxVal =
      edu::sharif::twinner::util::readRegisterContent (context, REG_EBX);
  ConcreteValue *ecxVal =
      edu::sharif::twinner::util::readRegisterContent (context, REG_ECX);
  ConcreteValue *edxVal =
      edu::sharif::twinner::util::readRegisterContent (context, REG_EDX);
  edu::sharif::twinner::trace::Expression *eaxNewExp =
      new edu::sharif::twinner::trace::ExpressionImp (eaxVal);
  edu::sharif::twinner::trace::Expression *ebxNewExp =
      new edu::sharif::twinner::trace::ExpressionImp (ebxVal);
  edu::sharif::twinner::trace::Expression *ecxNewExp =
      new edu::sharif::twinner::trace::ExpressionImp (ecxVal);
  edu::sharif::twinner::trace::Expression *edxNewExp =
      new edu::sharif::twinner::trace::ExpressionImp (edxVal);

  setRegExpression (REG_EAX, trace, eaxNewExp);
  setRegExpression (REG_EBX, trace, ebxNewExp);
  setRegExpression (REG_ECX, trace, ecxNewExp);
  setRegExpression (REG_EDX, trace, edxNewExp);
}

void InstructionSymbolicExecuter::incAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "incAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tincrementing...";
  dstexp->add (1);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  const edu::sharif::twinner::trace::Expression *one =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AdditionOperationGroup
       (dstexpOrig, one));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::incAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "incAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (oprReg, oprRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tincrementing...";
  dstexp->add (1);
  setRegExpression (oprReg, trace, dstexp);
  const edu::sharif::twinner::trace::Expression *one =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::AdditionOperationGroup
       (dstexpOrig, one));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::decAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "decAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tdecrementing...";
  dstexp->minus (1);
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  const edu::sharif::twinner::trace::Expression *one =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexpOrig, one));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::decAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "decAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (oprReg, oprRegVal, trace);
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->clone ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tdecrementing...";
  dstexp->minus (1);
  setRegExpression (oprReg, trace, dstexp);
  const edu::sharif::twinner::trace::Expression *one =
      new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (dstexpOrig, one));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::negAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "negAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\ttwo's complementing...";
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->twosComplement ();
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0)), dstexpOrig));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::negAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "negAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  const edu::sharif::twinner::trace::Expression *dstexpOrig =
      getRegExpression (oprReg, oprRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\ttwo's complementing...";
  edu::sharif::twinner::trace::Expression *dstexp = dstexpOrig->twosComplement ();
  setRegExpression (oprReg, trace, dstexp);
  eflags.setFlags
      (new edu::sharif::twinner::operationgroup::SubtractOperationGroup
       (new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0)), dstexpOrig));
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setoAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "setoAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool overflow;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForOverflowCase (overflow, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (overflow) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setoAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "setoAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool overflow;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForOverflowCase (overflow, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (overflow) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setpAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setpAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool parity;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForParityCase (parity, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (parity) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setpAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setpAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool parity;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForParityCase (parity, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (parity) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnpAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnpAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool parity;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForParityCase (parity, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!parity) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnpAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnpAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool parity;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForParityCase (parity, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!parity) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnsAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnsAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool sign;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForSignCase (sign, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!sign) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnsAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnsAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool sign;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForSignCase (sign, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!sign) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnzAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnzAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!zero) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnzAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnzAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!zero) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setzAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setzAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (zero) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setzAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setzAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool zero;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForZeroCase (zero, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (zero) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setleAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setleAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool lessOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessOrEqualCase
      (lessOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (lessOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setleAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setleAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool lessOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessOrEqualCase
      (lessOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (lessOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnleAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnleAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool lessOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessOrEqualCase
      (lessOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!lessOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnleAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnleAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool lessOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessOrEqualCase
      (lessOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!lessOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setlAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setlAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool less;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessCase (less, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (less) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setlAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setlAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool less;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessCase (less, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (less) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setbeAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setbeAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool belowOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowOrEqualCase
      (belowOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (belowOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setbeAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setbeAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool belowOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowOrEqualCase
      (belowOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (belowOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnbeAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnbeAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool belowOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowOrEqualCase
      (belowOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!belowOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnbeAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnbeAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool belowOrEqual;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowOrEqualCase
      (belowOrEqual, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (!belowOrEqual) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setbAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setbAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool below;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowCase (below, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (below) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setbAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setbAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool below;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowCase (below, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (below) {
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  } else { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnlAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "setnlAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool less;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessCase (less, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (less) { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  } else { // NL; set to one
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnlAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious ()
      << "setnlAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool less;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForLessCase (less, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (less) { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  } else { // NL; set to one
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnbAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnbAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool below;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowCase
      (below, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (below) { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  } else { // NB; set to one
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  }
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::setnbAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "setnbAnalysisRoutine(...)\n"
      << "\tinstantiating constraint...";
  bool below;
  std::list <edu::sharif::twinner::trace::Constraint *> cc =
      eflags.instantiateConstraintForBelowCase
      (below, disassembledInstruction);
  edu::sharif::twinner::util::Logger::loquacious () << "\tadding constraint...";
  trace->addPathConstraints (cc);
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp;
  if (below) { // shouldSetToZero
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (0));
  } else { // NB; set to one
    dstexp = new edu::sharif::twinner::trace::ExpressionImp (UINT64 (1));
  }
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::notAnalysisRoutine (
    ADDRINT dstMemoryEa, int memReadBytes,
    UINT32 insAssembly) {
  if (!logDstMemSrcImplicit (dstMemoryEa, memReadBytes, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "notAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getMemExpression (dstMemoryEa, memReadBytes, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tnegating...";
  dstexp->bitwiseNegate ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setMemExpression (dstMemoryEa, memReadBytes, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

void InstructionSymbolicExecuter::notAnalysisRoutine (
    REG oprReg, const ConcreteValue &oprRegVal,
    UINT32 insAssembly) {
  if (!logDstRegSrcImplicit (oprReg, oprRegVal, insAssembly)) {
    return;
  }
  edu::sharif::twinner::trace::Trace *trace = getTrace ();
  edu::sharif::twinner::util::Logger::loquacious () << "notAnalysisRoutine(...)\n"
      << "\tgetting dst exp...";
  edu::sharif::twinner::trace::Expression *dstexp =
      getRegExpression (oprReg, oprRegVal, trace);
  edu::sharif::twinner::util::Logger::loquacious () << "\tnegating...";
  dstexp->bitwiseNegate ();
  edu::sharif::twinner::util::Logger::loquacious () << "\tsetting dst exp...";
  setRegExpression (oprReg, trace, dstexp);
  edu::sharif::twinner::util::Logger::loquacious () << "\tdone\n";
}

InstructionSymbolicExecuter::SuddenlyChangedRegAnalysisRoutine
InstructionSymbolicExecuter::convertOpcodeToSuddenlyChangedRegAnalysisRoutine (
    OPCODE op) const {
  switch (op) {
  case XED_ICLASS_CALL_FAR:
  case XED_ICLASS_CALL_NEAR:
    return &InstructionSymbolicExecuter::callAnalysisRoutine;
  case XED_ICLASS_RET_FAR:
  case XED_ICLASS_RET_NEAR:
    return &InstructionSymbolicExecuter::retAnalysisRoutine;
  case XED_ICLASS_JMP_FAR:
  case XED_ICLASS_JMP:
    return &InstructionSymbolicExecuter::jmpAnalysisRoutine;
  default:
    edu::sharif::twinner::util::Logger::error () << "Analysis routine: "
        "Suddenly Changed Register: Unknown opcode: " << OPCODE_StringShort (op) << '\n';
    abort ();
  }
}

InstructionSymbolicExecuter::SuddenlyChangedRegWithArgAnalysisRoutine
InstructionSymbolicExecuter::convertOpcodeToSuddenlyChangedRegWithArgAnalysisRoutine (
    OPCODE op) const {
  switch (op) {
  case XED_ICLASS_RET_NEAR:
    return &InstructionSymbolicExecuter::retWithArgAnalysisRoutine;
  default:
    edu::sharif::twinner::util::Logger::error () << "Analysis routine: "
        "Suddenly Changed Register (with arg): Unknown opcode: "
        << OPCODE_StringShort (op) << '\n';
    abort ();
  }
}

VOID analysisRoutineSyscall (VOID *iseptr,
    ADDRINT syscallNumber,
    ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3,
    ADDRINT arg4, ADDRINT arg5,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->analysisRoutineSyscall
      (syscallNumber, arg0, arg1, arg2, arg3, arg4, arg5, insAssembly);
}

VOID analysisRoutineDstRegSrcRegMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegMovsx (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movsxAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegCdq (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cdqAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegShl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegShr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegSar (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegRor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegRol (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegTest (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegBt (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegBtr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pmovmskbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpeqbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpgtbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegPminub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pminubAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegPsubb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->psubbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklbwAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklwdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegBsf (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->bsfAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegXchg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xchgAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegXadd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xaddAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAuxRegCmpxchg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpxchgAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAuxRegShld (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shldAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegMovsx (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movsxAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegCdq (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cdqAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegShl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegShr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegSar (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegRor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegRol (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegTest (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegBt (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegBtr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pmovmskbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpeqbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpgtbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegPminub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pminubAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegPsubb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->psubbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklbwAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklwdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegBsf (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->bsfAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegXchg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xchgAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcLargeRegXadd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xaddAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegMovsx (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movsxAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegCdq (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cdqAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegShl (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegShr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegSar (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegRor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegRol (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegTest (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegBt (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegBtr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pmovmskbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpeqbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpgtbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegPminub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pminubAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegPsubb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->psubbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklbwAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklwdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegBsf (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->bsfAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegXchg (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xchgAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcRegXadd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xaddAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegMovsx (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movsxAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegCdq (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cdqAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegShl (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegShr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegSar (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegRor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegRol (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegTest (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegBt (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegBtr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pmovmskbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpeqbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpgtbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegPminub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pminubAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegPsubb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->psubbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklbwAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklwdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegBsf (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->bsfAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegXchg (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xchgAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegXadd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xaddAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->palignrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pshufdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdShld (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shldAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAuxImdImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->palignrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pshufdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcRegAuxImdShld (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shldAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemMovlpd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movlpdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemMovhpd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movhpdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemMovsx (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movsxAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemPcmpeqb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpeqbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemPcmpgtb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpgtbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemPminub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pminubAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemPsubb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->psubbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemPunpcklbw (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklbwAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemPunpcklwd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklwdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemBsf (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->bsfAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemAuxImdImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->palignrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcMemAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pshufdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       srcMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAuxImdImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->palignrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pshufdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemMovlpd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movlpdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemMovhpd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movhpdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemMovsx (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movsxAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemPcmpeqb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpeqbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemPcmpgtb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pcmpgtbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemPminub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pminubAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemPsubb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->psubbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemPunpcklbw (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklbwAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemPunpcklwd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->punpcklwdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemBsf (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->bsfAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAuxRegPop (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->popAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcMemAuxRegLodsd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->lodsdAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       srcMemoryEa, memReadBytes,
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdPslldq (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pslldqAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdShl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdShr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdSar (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdRor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdRol (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdTest (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdBt (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImdBtr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdPslldq (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pslldqAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdShl (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdShr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdSar (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdRor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdRol (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdTest (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdBt (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstLargeRegSrcImdBtr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegMov (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegMovlpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movlpdAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegMovhpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movhpdAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAdd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAdc (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegSub (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegSbb (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegCmp (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegShl (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegShr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegSar (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegRor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegRol (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAnd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegOr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegXor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegTest (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegBt (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegBtr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegXchg (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xchgAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegXadd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xaddAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAuxRegCmpxchg (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpxchgAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAuxRegPushfd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pushfdAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAuxRegPush (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pushAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAuxRegShld (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shldAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcRegAuxImdShld (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shldAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegMov (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegMovlpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movlpdAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegMovhpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movhpdAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegAdd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegAdc (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegSub (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegSbb (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegCmp (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegShl (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegShr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegSar (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegRor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegRol (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegAnd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegOr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegXor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegTest (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegBt (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcLargeRegBtr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) srcReg, edu::sharif::twinner::trace::cv::ConcreteValue128Bits (*srcRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdMov (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdAdd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->addAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdAdc (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->adcAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdSub (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->subAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdSbb (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sbbAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdCmp (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdShl (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shlAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdShr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->shrAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdSar (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->sarAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdRor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rorAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdRol (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rolAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdAnd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->andAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdOr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->orAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdXor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->xorAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdTest (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->testAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdBt (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdBtr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->btrAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImdAuxRegPush (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pushAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcImmediateValue),
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcMemAuxRegPush (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->pushAnalysisRoutine
      (dstMemoryEa,
       srcMemoryEa, memReadBytes,
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcMemAuxRegPop (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->popAnalysisRoutine
      (dstMemoryEa,
       srcMemoryEa, memReadBytes,
       (REG) auxReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (auxRegVal),
       insAssembly);
}

VOID analysisRoutineConditionalBranchJnz (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jnzAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJz (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jzAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJle (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jleAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJnle (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jnleAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJl (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jlAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJnl (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jnlAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJbe (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jbeAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJnbe (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jnbeAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJnb (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jnbAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJb (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jbAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJo (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->joAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJp (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jpAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJnp (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jnpAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJs (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jsAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineConditionalBranchJns (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->jnsAnalysisRoutine
      (branchTaken,
       insAssembly);
}

VOID analysisRoutineDstRegSrcAdgLea (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->leaAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineBeforeChangeOfReg (VOID *iseptr, UINT32 opcode,
    UINT32 reg,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->analysisRoutineBeforeChangeOfReg
      (ise->convertOpcodeToSuddenlyChangedRegAnalysisRoutine ((OPCODE) opcode),
       (REG) reg,
       insAssembly);
  if (opcode == XED_ICLASS_RET_NEAR || opcode == XED_ICLASS_RET_FAR) {
#ifdef TARGET_IA32E
    ise->analysisRoutineBeforeRet (REG_RIP);
#else
    ise->analysisRoutineBeforeRet (REG_EIP);
#endif
  }
}

VOID analysisRoutineBeforeChangeOfRegWithArg (VOID *iseptr, UINT32 opcode,
    UINT32 reg, ADDRINT argImmediateValue,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->analysisRoutineBeforeChangeOfRegWithArg
      (ise->convertOpcodeToSuddenlyChangedRegWithArgAnalysisRoutine ((OPCODE) opcode),
       (REG) reg, argImmediateValue,
       insAssembly);
  if (opcode == XED_ICLASS_RET_NEAR || opcode == XED_ICLASS_RET_FAR) {
#ifdef TARGET_IA32E
    ise->analysisRoutineBeforeRet (REG_RIP);
#else
    ise->analysisRoutineBeforeRet (REG_EIP);
#endif
  }
}

VOID analysisRoutineTwoDstRegOneSrcRegDiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->divAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       (REG) srcReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcRegIdiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->idivAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       (REG) srcReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcRegMul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->mulAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       (REG) srcReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcRegImul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       (REG) srcReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcMemDiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->divAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcMemIdiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->idivAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcMemMul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->mulAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcMemImul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->imulAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcMemScas (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->scasAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineTwoDstRegOneSrcMemLeave (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->leaveAnalysisRoutine
      ((REG) dstLeftReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstLeftRegVal),
       (REG) dstRightReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRightRegVal),
       srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineAfterOperandLessRdtsc (VOID *iseptr,
    const CONTEXT *context,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->rdtscAnalysisRoutine
      (context,
       insAssembly);
}

VOID analysisRoutineAfterOperandLessCld (VOID *iseptr,
    const CONTEXT *context,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cldAnalysisRoutine
      (context,
       insAssembly);
}

VOID analysisRoutineAfterOperandLessCpuid (VOID *iseptr,
    const CONTEXT *context,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cpuidAnalysisRoutine
      (context,
       insAssembly);
}

VOID analysisRoutineRunHooks (VOID *iseptr, const CONTEXT *context) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->analysisRoutineRunHooks (context);
}

VOID analysisRoutineDstRegSrcImplicitInc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->incAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitDec (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->decAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitNeg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->negAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSeto (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setoAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetnp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnpAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetns (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnsAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetnz (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnzAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetz (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setzAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetle (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setleAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetnle (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnleAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setlAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetnl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnlAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetbe (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setbeAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetnbe (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnbeAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitSetnb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnbAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstRegSrcImplicitNot (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->notAnalysisRoutine
      ((REG) dstReg, edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitInc (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->incAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitDec (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->decAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitNeg (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->negAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSeto (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setoAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetp (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setpAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetnp (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnpAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetns (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnsAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetnz (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnzAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetz (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setzAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetle (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setleAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetnle (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnleAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetl (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setlAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetnl (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnlAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetb (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setbAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetbe (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setbeAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetnbe (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnbeAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitSetnb (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->setnbAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineDstMemSrcImplicitNot (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->notAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineInitializeRegisters (VOID *iseptr, CONTEXT *context) {
  static bool executed = false;
  if (executed) {
    return;
  }
  executed = true;
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->analysisRoutineInitializeRegisters (context);
}

VOID analysisRoutineStrOpMemRegStos (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->stosAnalysisRoutine
      (dstMemoryEa, memReadBytes,
       (REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       insAssembly);
}

VOID analysisRoutineStrOpMemMemMovs (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT srcMemoryEa,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->movsAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       dstMemoryEa, srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineStrOpMemMemCmps (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT srcMemoryEa,
    UINT32 memReadBytes,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->cmpsAnalysisRoutine
      ((REG) dstReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (dstRegVal),
       (REG) srcReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (srcRegVal),
       dstMemoryEa, srcMemoryEa, memReadBytes,
       insAssembly);
}

VOID analysisRoutineRepPrefix (VOID *iseptr, UINT32 opcode,
    UINT32 repReg, ADDRINT repRegVal,
    UINT32 executing, UINT32 repEqual,
    UINT32 insAssembly) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->analysisRoutineRepEqualOrRepNotEqualPrefix
      ((REG) repReg,
       edu::sharif::twinner::trace::cv::ConcreteValue64Bits (repRegVal),
       executing, repEqual,
       insAssembly);
}

VOID analysisRoutinePrefetchMem (VOID *iseptr,
    ADDRINT memoryEa, UINT32 memReadBytes) {
  InstructionSymbolicExecuter *ise = (InstructionSymbolicExecuter *) iseptr;
  ise->analysisRoutinePrefetchMem (memoryEa, memReadBytes);
}

}
}
}
}
