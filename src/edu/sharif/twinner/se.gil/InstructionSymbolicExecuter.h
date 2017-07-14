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

#ifndef INSTRUCTION_SYMBOLIC_EXECUTER_H
#define INSTRUCTION_SYMBOLIC_EXECUTER_H

#include "edu/sharif/twinner/pin-wrapper.h"

#include "edu/sharif/twinner/operationgroup/Flags.h"

#include <sstream>
#include <map>

namespace edu {
namespace sharif {
namespace twinner {
namespace util {

class MemoryManager;
}
namespace trace {

class Trace;
class FunctionInfo;
class FunctionInvocation;
class StateSummary;

namespace syscall {

class Syscall;
}
namespace cv {

class ConcreteValue;
}
}
namespace twintool {

class Instrumenter;

class InstructionSymbolicExecuter {
private:
  typedef edu::sharif::twinner::trace::cv::ConcreteValue ConcreteValue;

  typedef void (InstructionSymbolicExecuter::*Hook) (const CONTEXT *context,
      const ConcreteValue &value);
  typedef Hook SuddenlyChangedRegAnalysisRoutine;
  typedef void (InstructionSymbolicExecuter::*HookWithArg) (
      const CONTEXT *context, const ConcreteValue &value, ADDRINT arg);
  typedef HookWithArg SuddenlyChangedRegWithArgAnalysisRoutine;

  typedef edu::sharif::twinner::trace::FunctionInfo FunctionInfo;

  Instrumenter *im;
  edu::sharif::twinner::trace::Trace *lazyTrace;
  edu::sharif::twinner::util::MemoryManager *memoryManager;
  edu::sharif::twinner::operationgroup::Flags eflags;

  REG trackedReg;
  int operandSize;
  Hook hook;

  ADDRINT arg;
  HookWithArg hookWithArg;

  UINT32 disassembledInstruction;

  bool disabled;
  const bool measureMode;

  UINT64 numberOfExecutedInstructions; // used in measure mode

  ADDRINT endOfSafeFuncRetAddress;
  bool withinSafeFunc;

public:
  InstructionSymbolicExecuter (Instrumenter *im,
      bool disabled, bool _measureMode);

  edu::sharif::twinner::trace::Trace *getTrace ();
  const edu::sharif::twinner::trace::Trace *getTrace () const;

  void disable ();
  void enable ();

  void syscallInvoked (const CONTEXT *context,
      edu::sharif::twinner::trace::syscall::Syscall s);
  void startNewTraceSegment (CONTEXT *context) const;

  edu::sharif::twinner::util::MemoryManager *getTraceMemoryManager () const;

public:
  void analysisRoutineBeforeCallingSafeFunction (ADDRINT retAddress,
      const FunctionInfo &fi, UINT32 insAssembly, const CONTEXT *context);

  void analysisRoutineSyscall (ADDRINT syscallNumber,
      ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3,
      ADDRINT arg4, ADDRINT arg5,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcReg (OPCODE opcode,
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcRegAuxReg (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcRegAuxImd (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &auxImmediateValue,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcMem (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcMemAuxReg (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcMemAuxImd (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      const ConcreteValue &auxImmediateValue,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcImd (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcReg (OPCODE op,
      ADDRINT dstMemoryEa,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcMutableReg (OPCODE op,
      ADDRINT dstMemoryEa,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcRegAuxReg (OPCODE op,
      ADDRINT dstMemoryEa,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcRegAuxImd (OPCODE op,
      ADDRINT dstMemoryEa,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &auxImmediateValue,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcImd (OPCODE op,
      ADDRINT dstMemoryEa,
      const ConcreteValue &srcImmediateValue,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcImdAuxReg (OPCODE op,
      ADDRINT dstMemoryEa,
      const ConcreteValue &srcImmediateValue,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcMem (OPCODE op,
      ADDRINT dstMemoryEa,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcMemAuxReg (OPCODE op,
      ADDRINT dstMemoryEa,
      ADDRINT srcMemoryEa,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineConditionalBranch (OPCODE op,
      BOOL branchTaken,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcAdg (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      UINT32 insAssembly);
  void analysisRoutineBeforeRet (REG reg);
  void analysisRoutineBeforeChangeOfReg (SuddenlyChangedRegAnalysisRoutine routine,
      REG reg,
      UINT32 insAssembly);
  void analysisRoutineBeforeChangeOfRegWithArg (
      SuddenlyChangedRegWithArgAnalysisRoutine routine,
      REG reg, ADDRINT argImmediateValue,
      UINT32 insAssembly);
  void analysisRoutineTwoDstRegOneSrcReg (OPCODE op,
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void analysisRoutineTwoDstRegOneSrcMem (OPCODE op,
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineOneMemTwoReg (OPCODE op,
      ADDRINT dstMemoryEa,
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 memReadBytes, UINT32 insAssembly);
  void analysisRoutineTwoRegTwoMem (OPCODE op,
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT dstMemoryEa, ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineAfterOperandLessInstruction (OPCODE op,
      const CONTEXT *context,
      UINT32 insAssembly);
  void analysisRoutineDstRegSrcImplicit (OPCODE op,
      REG dstReg, const ConcreteValue &dstRegVal,
      UINT32 insAssembly);
  void analysisRoutineDstMemSrcImplicit (OPCODE op,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  void analysisRoutineRunHooks (const CONTEXT *context);
  /// This call does not return to caller
  void analysisRoutineInitializeRegisters (CONTEXT *context) const;
  void analysisRoutineRepEqualOrRepNotEqualPrefix (REG repReg,
      const ConcreteValue &repRegVal, BOOL executing, BOOL repEqual,
      UINT32 insAssembly);
  void analysisRoutinePrefetchMem (ADDRINT memoryEa, UINT32 memReadBytes);

private:
  const edu::sharif::twinner::trace::Expression *
  setMemExpressionWithoutChangeNotification (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::Expression *exp,
      bool &shouldDeleteExp) const;
  const edu::sharif::twinner::trace::Expression *setAlignedMemExpression (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::Expression *exp) const;
  const edu::sharif::twinner::trace::Expression *setUnalignedMemExpression (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::Expression *exp) const;

  void memoryValueIsChanged (ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      const edu::sharif::twinner::trace::Expression &changedExp,
      edu::sharif::twinner::trace::StateSummary &state) const;

  void alignedCheckForOverwritingMemory (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace) const;

  edu::sharif::twinner::trace::Expression *getMemExpression (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace) const;
  edu::sharif::twinner::trace::Expression *getMemExpression (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::StateSummary &state) const;
  edu::sharif::twinner::trace::Expression *getAlignedMemExpression (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::StateSummary &state) const;
  edu::sharif::twinner::trace::Expression *getUnalignedMemExpression (
      ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::StateSummary &state) const;
  void setMemExpression (ADDRINT memoryEa, int memReadBytes,
      edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::Expression *exp,
      bool shouldDeleteExp = true) const;

  /// temporary cache of any used exp during change propagation in valueIsChanged ()
  typedef std::map < std::pair < ADDRINT, int >,
  std::pair < const edu::sharif::twinner::trace::Expression *, bool > >
  AddrSizeToExpMap; // (addr, size) -> (exp*, owned?)
  mutable AddrSizeToExpMap expCache;
  void propagateChangeDownwards (int size, ADDRINT memoryEa,
      edu::sharif::twinner::trace::Trace *trace,
      const edu::sharif::twinner::trace::Expression &changedExp,
      bool ownExp) const;
  void actualPropagateChangeDownwards (int size,
      ADDRINT memoryEa,
      edu::sharif::twinner::trace::Trace *trace,
      const edu::sharif::twinner::trace::Expression *exp) const;
  void propagateChangeUpwards (int size,
      ADDRINT memoryEa, edu::sharif::twinner::trace::Trace *trace,
      const edu::sharif::twinner::trace::Expression &changedExp,
      edu::sharif::twinner::trace::StateSummary &state) const;
  const edu::sharif::twinner::trace::Expression *getNeighborExpression (
      int size, ADDRINT address, edu::sharif::twinner::trace::Trace *trace,
      bool &readFromCache,
      edu::sharif::twinner::trace::StateSummary &state) const;
  void emptyExpressionCache () const;

  edu::sharif::twinner::trace::Expression *getRegExpression (
      REG reg, const ConcreteValue &regVal,
      edu::sharif::twinner::trace::Trace *trace) const;
  void setRegExpression (REG reg, edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::Expression *exp,
      bool shouldDeleteExp = true) const;
  const edu::sharif::twinner::trace::Expression *
  setRegExpressionWithoutChangeNotification (
      REG reg, edu::sharif::twinner::trace::Trace *trace,
      edu::sharif::twinner::trace::Expression *exp,
      bool shouldDeleteExp = true) const;

  void registerValueIsChanged (
      REG reg,
      edu::sharif::twinner::trace::Trace *trace,
      const edu::sharif::twinner::trace::Expression &changedExp,
      edu::sharif::twinner::trace::StateSummary &state) const;
  void putExpressionInLeastSignificantBitsOfRegister (
      edu::sharif::twinner::trace::Trace *trace, int rsize, REG r, int bits,
      const edu::sharif::twinner::trace::Expression *exp) const;

  /**
   * Run hooks from last instruction (if any) and reset them afterwards.
   */
  void runHooks (const CONTEXT *context);

  /**
   * Register the safe function as a segment terminator in the trace
   */
  void registerSafeFunction (const FunctionInfo &fi, const CONTEXT *context);

  edu::sharif::twinner::trace::FunctionInvocation *
  instantiateFunctionInvocation (const FunctionInfo &fi,
      edu::sharif::twinner::trace::Trace *trace, const CONTEXT *context) const;

  /**
   * Called before invocation of every syscall and before the syscallInvoked ().
   */
  void syscallAnalysisRoutine (
      edu::sharif::twinner::trace::syscall::Syscall const &syscall);

  /**
   * accumulator := RAX | EAX | AX | AL
   * if (dst == accumulator)
   *  dst <- src
   * else
   *  accumulator <- dst
   */
  void cmpxchgAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG auxReg, const ConcreteValue &auxRegVal);
  void cmpxchgAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG auxReg, const ConcreteValue &auxRegVal);

  /**
   * PALIGNR is packed align right. The dst and src are first concatenated
   * and then shifted to right as many bytes as indicated in the shift argument
   * and then stored in the dst reg.
   */
  void palignrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      const ConcreteValue &shiftImmediateValue);
  void palignrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &shiftImmediateValue);

  /**
   * PSHUFD is packed shuffle for double words. The 8-bits order argument is consisted
   * of 4 parts of 2-bits index numbers. Each index indicates that which double word
   * from the src operand should be placed in the next double word place of the dst.
   */
  void pshufdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      const ConcreteValue &orderImmediateValue);
  void pshufdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &orderImmediateValue);

  /**
   * SHLD shifts (dst,src) to left as much as (shift) and stores it in (dst).
   * That is, the (dst) is shifted left by (shift) and its lower order bits
   * are filled with the shifted (src) instead of zero.
   * The last bit which goes out of (dst) is stored in CF.
   */
  void shldAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &shiftImmediateValue);
  void shldAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG shiftReg, const ConcreteValue &shiftRegVal);
  void shldAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &shiftImmediateValue);
  void shldAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG shiftReg, const ConcreteValue &shiftRegVal);

  /**
   * XCHG instruction exchanges values of dst (r/m) and src (r) atomically
   */
  void xchgAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void xchgAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * XADD instruction exchanges values of dst (r/m) and src (r) and
   * loads sum of two operands in the dst atomically
   */
  void xaddAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void xaddAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * MOVLPD moves 64-bits from mem src to low packed double-precision
   * (the lower 64-bits) of dst xmm reg or vice versa.
   */
  void movlpdAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void movlpdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);

  /**
   * MOVHPD moves 64-bits from mem src to high packed double-precision
   * (the upper 64-bits) of dst xmm reg or vice versa.
   */
  void movhpdAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void movhpdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);

  /**
   * MOV has 5 models
   * r <- r/m/i
   * m <- r/i
   */
  void movAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void movAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * MOV with Sign extension
   * r <- sign-extend (r/m)
   */
  void movsxAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void movsxAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * Sign extends the (src) into (dst:src). That is, fills (dst) with
   * the sign bit of the (src).
   */
  void cdqAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * MOV String to String reads from [rsi]/srcMem and moves to [rdi]/dstMem and
   * increments/decrements rdi/rsi registers
   */
  void movsAnalysisRoutine (
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG rsiReg, const ConcreteValue &rsiRegVal,
      ADDRINT dstMemoryEa, ADDRINT srcMemoryEa,
      UINT32 memReadBytes);

  /**
   * CMPSB / CMPSW / CMPSD / CMPSQ compare string with 1/2/4/8 bytes sizes.
   * Operands are read from [rsi]/srcMem and [rdi]/dstMem and
   * increments/decrements rdi/rsi registers.
   */
  void cmpsAnalysisRoutine (
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG rsiReg, const ConcreteValue &rsiRegVal,
      ADDRINT dstMemoryEa, ADDRINT srcMemoryEa,
      UINT32 memReadBytes);

  /**
   * PUSHFD pushes FLAGS onto stack.
   */
  void pushfdAnalysisRoutine (
      ADDRINT stackMemoryEa, int stackReadBytes,
      REG flagsReg, const ConcreteValue &flagsRegVal,
      REG rspReg, const ConcreteValue &rspRegVal);

  /**
   * PUSH has 3 models
   * m <- r/m/i
   */
  void pushAnalysisRoutine (
      ADDRINT dstMemoryEa,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rspReg, const ConcreteValue &rspRegVal);
  void pushAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      REG rspReg, const ConcreteValue &rspRegVal);
  void pushAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG rspReg, const ConcreteValue &rspRegVal);

  /**
   * POP has 2 models
   * r/m <- m
   */
  void popAnalysisRoutine (
      ADDRINT dstMemoryEa,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rspReg, const ConcreteValue &rspRegVal);
  void popAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rspReg, const ConcreteValue &rspRegVal);

  /**
   * LODSD is load string double word
   * eax/dst-reg <- [rsi]
   */
  void lodsdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rsiReg, const ConcreteValue &rsiRegVal);

  /**
   * ADD has 5 models
   * r += r/m/i
   * m += r/i
   */
  void addAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void addAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void addAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void addAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void addAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * ADC has 5 models. It is Add with carry.
   * r += r/m/i
   * m += r/i
   */
  void adcAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void adcAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void adcAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void adcAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void adcAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * SUB has 5 models
   * r -= r/m/i
   * m -= r/i
   */
  void subAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void subAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void subAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void subAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void subAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * SBB is subtract with borrow
   * dst = dst - (src + CF) where CF is the carry of the previous operation
   */
  void sbbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void sbbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void sbbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void sbbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void sbbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * CMP is same as SUB else of not modifying dst operand's value
   */
  void cmpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void cmpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void cmpAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void cmpAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void cmpAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * LEA loads an address into a register. This analysis routine is called after execution
   * of the instruction. The dst parameter should be set, without getting its value, since
   * value of register has been changed by the instruction and we must synch its symbolic
   * value (as a constant value) now.
   */
  void leaAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcAdgVal);

  /**
   * JNZ jumps if ZF=0 which means that corresponding expression was not zero
   */
  void jnzAnalysisRoutine (bool branchTaken);

  /**
   * JZ jumps if ZF=1 which means that corresponding expression was zero
   */
  void jzAnalysisRoutine (bool branchTaken);

  /**
   * JLE jumps if ZF=1 or SF!=OF which means that corresponding expression was <= 0
   */
  void jleAnalysisRoutine (bool branchTaken);

  /**
   * JNLE jumps if ZF=0 and SF=OF which means that corresponding expression was > 0
   */
  void jnleAnalysisRoutine (bool branchTaken);

  /**
   * JL jumps if SF!=OF which means that corresponding expression was < 0
   */
  void jlAnalysisRoutine (bool branchTaken);

  /**
   * JNL jumps if SF=OF which means that corresponding expression was > 0
   */
  void jnlAnalysisRoutine (bool branchTaken);

  /**
   * JBE jumps if ZF=1 or CF=1 which means that corresponding expression was <= 0
   */
  void jbeAnalysisRoutine (bool branchTaken);

  /**
   * JNBE jumps if ZF=0 and CF=0 which means that corresponding expression was > 0
   */
  void jnbeAnalysisRoutine (bool branchTaken);

  /**
   * JNB jumps if CF=0 which means that corresponding expression was > 0
   */
  void jnbAnalysisRoutine (bool branchTaken);

  /**
   * JB jumps if CF=1 (jump below)
   */
  void jbAnalysisRoutine (bool branchTaken);

  /**
   * JO jumps if OF=1 which means that last operation caused a signed overflow
   */
  void joAnalysisRoutine (bool branchTaken);

  /**
   * JP jumps if PF=1 (even parity)
   */
  void jpAnalysisRoutine (bool branchTaken);

  /**
   * JNP jumps if PF=0 (odd parity)
   */
  void jnpAnalysisRoutine (bool branchTaken);

  /**
   * JS jumps if SF=1 which means that corresponding expression was < 0
   */
  void jsAnalysisRoutine (bool branchTaken);

  /**
   * JNS jumps if SF=0 which means that corresponding expression was >= 0
   */
  void jnsAnalysisRoutine (bool branchTaken);

  /**
   * CALL instruction is executed and RSP is changed. This method will synchronize its
   * symbolic value with its concrete value.
   */
  void callAnalysisRoutine (const CONTEXT *context, const ConcreteValue &rspRegVal);

  void checkForEndOfSafeFunc (const CONTEXT *context, const ConcreteValue &ripRegVal);

  /**
   * RET instruction is executed and RSP is changed. This method will synchronize its
   * symbolic value with its concrete value.
   */
  void retAnalysisRoutine (const CONTEXT *context, const ConcreteValue &rspRegVal);

  /**
   * RET arg instruction is executed and RSP is changed.
   * This method will synchronize its symbolic value with its concrete value.
   */
  void retWithArgAnalysisRoutine (const CONTEXT *context,
      const ConcreteValue &rspRegVal, ADDRINT arg);

  /**
   * JMP instruction performs an unconditional jump.
   * Normally we do not need to track jumps. However due to a bug in PIN, some
   * instructions coming after some JMP instructions are not get instrumented.
   * So JMP may change value of RSP without any notice.
   * This hook is for maintaining the value of RSP.
   */
  void jmpAnalysisRoutine (const CONTEXT *context, const ConcreteValue &rspRegVal);

  void repAnalysisRoutine (
      REG repReg, const ConcreteValue &repRegVal,
      bool executing, bool repEqual);

  /**
   * PSLLDQ is packed shift to left logically for double quadword
   * which shifts dst to left as many bytes as indicated by src.
   */
  void pslldqAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);

  /**
   * SHL shifts dst to left as much as indicated by src.
   */
  void shlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void shlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void shlAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void shlAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * SHR shifts dst to right as much as indicated by src.
   */
  void shrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void shrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void shrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void shrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * SAR arithmetic shifts dst to right as much as indicated by src (signed division).
   */
  void sarAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void sarAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void sarAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void sarAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * ROR rotates right the dst as much as indicated by src.
   * Also the LSB of src (which will be moved to the new MSB) will be set in CF.
   */
  void rorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void rorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void rorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void rorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * ROL rotates left the dst as much as indicated by src.
   * Also the MSB of src (which will be moved to the new LSB) will be set in CF.
   */
  void rolAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void rolAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void rolAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void rolAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * AND bitwise ands dst with src as its mask.
   */
  void andAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void andAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void andAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void andAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void andAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * OR bitwise ores dst with src as its complement.
   */
  void orAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void orAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void orAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void orAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void orAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * XOR calculates exclusive or of dst with src.
   */
  void xorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void xorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void xorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void xorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void xorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * TEST performs AND between arguments, temporarily, and sets ZF, SF, and PF based
   * on result. Also CF and OF are set to zero. AF is undefined.
   */
  void testAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void testAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void testAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void testAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * BT is bit test instruction. It finds the bitoffset-th bit from the bitstring and
   * set it as the CF.
   */
  void btAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void btAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void btAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void btAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * BTR is bit test and reset instruction. It acts like BT and also
   * resets the selected bit to zero.
   */
  void btrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void btrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue);
  void btrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue);
  void btrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * PMOVMSKB is a packed-move instruction which moves the mask-byte of
   * the src reg to the dst reg.
   * Mask-byte: read MSB of each byte of a reg and put those bits together.
   * A 128-bits reg has 16 bytes and its mask-byte has 16-bits or 2 bytes.
   * Remaining bits in left-side of the dst reg will be filled with zero.
   * TODO: Currently only 128-bit XMM registers are supported which should be expanded with proxy objects
   */
  void pmovmskbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * PCMPEQB is a packed compare equality check which works byte-wise.
   * The src and dst are compared together byte-by-byte and those bytes
   * which are/aren't equal will be filed with 1 (0xFF) / 0 (0x00) in
   * the dst reg.
   */
  void pcmpeqbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void pcmpeqbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * PCMPGTB is a packed compare greater-than check which works byte-wise.
   * The src and dst are compared together byte-by-byte and those dst bytes
   * which are/aren't greater-than src will be filed with 1 (0xFF) / 0 (0x00) in
   * the dst reg.
   */
  void pcmpgtbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void pcmpgtbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * PMINUB is a packed minimum finding for unsigned bytes.
   * Packed unsigned bytes which are stored in dst and src wil be compared to find their
   * minimum values. Minimum values will be stored in the dst.
   */
  void pminubAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void pminubAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * PSUBB is a packed subtract instruction which subtracts src individual bytes
   * from dst individual bytes and stores the results in dst bytes.
   * Overflows are not reported in EFLAGS.
   */
  void psubbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void psubbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * PUNPCKLBW is a packed operation which "unpacks" low-data from src-dst and interleaves
   * them and put the result in the dst.
   *  -- byte to word
   */
  void punpcklbwAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void punpcklbwAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * PUNPCKLWD is a packed operation which "unpacks" low-data from src-dst and interleaves
   * them and put the result in the dst.
   *  -- word to double-word
   */
  void punpcklwdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void punpcklwdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * BSF is bit scan forward instruction which searches for the least significant 1 bit
   * in the src and sets its index in the dst. The index is placed as a constant in dst
   * and a constraint is added to indicate that the noted bit was set.
   */
  void bsfAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void bsfAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * DIV unsigned divide left-right regs by src reg putting quotient in right, remainder
   * in left. This method only calculates symbolic values of operands (concrete values
   * will be wrong) and also ignores propagating new values to overlapping registers.
   * Instead, it registers a hook to adjust concrete values and propagate to overlapping
   * registers at the beginning of next executed instruction.
   */
  void divAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void divAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * IDIV signed divide the left-right regs by src reg/mem and puts the
   * quotient in right and remainder in left dst.
   * This method only calculates symbolic values of operands (concrete values
   * will be wrong) and also ignores propagating new values to overlapping
   * registers. Instead, it registers a hook to adjust concrete values and
   * propagates to overlapping registers at the beginning of
   * next executed instruction.
   */
  void idivAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void idivAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * MUL unsigned multiply right reg by src and puts result in left-right regs.
   * This method only calculates symbolic values of operands (concrete values
   * will be wrong) and also ignores propagating new values to overlapping registers.
   * Instead, it registers a hook to adjust concrete values and propagate to overlapping
   * registers at the beginning of next executed instruction.
   */
  void mulAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void mulAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * IMUL is signed multiply and has three models.
   * This method implements the one operand model.
   */
  void imulAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void imulAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * IMUL is signed multiply and has three models.
   * This method implements the two operands model.
   */
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * IMUL is signed multiply and has three models.
   * This method implements the three operands model.
   */
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &imdValue);
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      const ConcreteValue &auxImmediateValue);

  /**
   * SCAS instruction compares AL/AX/EAX/RAX (the dstReg) and a given srcMem value
   * which is pointed to by the DI/EDI/RDI and sets the EFLAGS based on
   * the comparison result.
   */
  void scasAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG rdiReg, const ConcreteValue &rdiRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);

  /**
   * Store String stores the srcReg into dstMem==[rdi] location and moves rdi accordingly.
   */
  void stosAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * LEAVE instruction:
   *   spReg <- fpReg
   *   fpReg <- pop-from-stack
   */
  void leaveAnalysisRoutine (
      REG fpReg, const ConcreteValue &fpRegVal,
      REG spReg, const ConcreteValue &spRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);

  /**
   * This hook adjusts concrete values of division/multiplication operands
   * and also propagates their values to overlapping registers.
   */
  void adjustDivisionMultiplicationOperands (const CONTEXT *context,
      const ConcreteValue &operandSize);

  /**
   * read time-stamp counter and put it in EDX:EAX
   */
  void rdtscAnalysisRoutine (const CONTEXT *context);

  /**
   * Clears the direction flags (DF)
   */
  void cldAnalysisRoutine (const CONTEXT *context);

  /**
   * CPUID == CPU Identification
   */
  void cpuidAnalysisRoutine (const CONTEXT *context);

  /**
   * INC increments the opr reg/mem operand.
   */
  void incAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void incAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * DEC decrements the opr reg/mem operand.
   */
  void decAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void decAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * NEG two's complements the opr (which is reg or mem).
   */
  void negAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void negAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETO sets opr to 1 iff OF=1 (and sets it to 0 otherwise).
   */
  void setoAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setoAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETP sets opr to 1 iff PF=1 (and sets it to 0 otherwise).
   */
  void setpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setpAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETNP sets opr to 1 iff PF=0 (and sets it to 0 otherwise).
   */
  void setnpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setnpAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETNS sets opr to 1 iff SF=0 (and sets it to 0 otherwise).
   */
  void setnsAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setnsAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETNZ sets opr to 1 iff ZF=0 (and sets it to 0 otherwise).
   */
  void setnzAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setnzAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETZ sets opr to 1 iff ZF=1 (and sets it to 0 otherwise).
   */
  void setzAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setzAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETLE sets opr to 1 iff ZF=1 or SF != OF (and sets it to 0 otherwise).
   */
  void setleAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setleAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETNLE sets opr to 1 iff ZF=0 and SF == OF (and sets it to 0 otherwise).
   */
  void setnleAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setnleAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETL sets opr to 1 iff SF != OF (and sets it to 0 otherwise).
   */
  void setlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setlAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETNL sets opr to 1 iff SF == OF (and sets it to 0 otherwise).
   */
  void setnlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setnlAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETB sets opr to 1 iff CF=1 (and sets it to 0 otherwise).
   */
  void setbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setbAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETBE sets opr to 1 iff ZF=1 or CF=1 (and sets it to 0 otherwise).
   */
  void setbeAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setbeAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETNBE sets opr to 1 iff ZF=0 and CF=0 (and sets it to 0 otherwise).
   */
  void setnbeAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setnbeAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * SETNB sets opr to 1 iff CF=0 (and sets it to 0 otherwise).
   */
  void setnbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void setnbAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  /**
   * NOT one's complements the opr.
   * opr <- NOT(opr)
   */
  void notAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes);
  void notAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal);

  void adjustRsiRdiRegisters (int size,
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG rsiReg, const ConcreteValue &rsiRegVal);

public:
  SuddenlyChangedRegAnalysisRoutine convertOpcodeToSuddenlyChangedRegAnalysisRoutine (
      OPCODE op) const;
  SuddenlyChangedRegWithArgAnalysisRoutine
  convertOpcodeToSuddenlyChangedRegWithArgAnalysisRoutine (OPCODE op) const;
};

VOID analysisRoutineSyscall (VOID *iseptr,
    ADDRINT syscallNumber,
    ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3,
    ADDRINT arg4, ADDRINT arg5,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMutableReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAuxReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegAuxImd (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAuxImd (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMem (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImd (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemAuxImd (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAuxImd (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMem (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAuxReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImd (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcReg (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcMutableReg (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAuxReg (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAuxImd (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeReg (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImd (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdAuxReg (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcMem (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcMemAuxReg (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranch (VOID *iseptr, UINT32 opcode,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcAdg (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineBeforeChangeOfReg (VOID *iseptr, UINT32 opcode,
    UINT32 reg,
    UINT32 insAssembly);
VOID analysisRoutineBeforeChangeOfRegWithArg (VOID *iseptr, UINT32 opcode,
    UINT32 reg, ADDRINT argImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcReg (VOID *iseptr, UINT32 opcode,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcMem (VOID *iseptr, UINT32 opcode,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineAfterOperandLess (VOID *iseptr, UINT32 opcode,
    const CONTEXT *context,
    UINT32 insAssembly);
VOID analysisRoutineRunHooks (VOID *iseptr, const CONTEXT *context);
VOID analysisRoutineDstRegSrcImplicit (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicit (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineInitializeRegisters (VOID *iseptr, CONTEXT *context);
VOID analysisRoutineStrOpRegMem (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineStrOpMemReg (VOID *iseptr, UINT32 opcode,
    ADDRINT dstMemoryEa,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineStrOpMemMem (VOID *iseptr, UINT32 opcode,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT srcMemoryEa,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineRepPrefix (VOID *iseptr, UINT32 opcode,
    UINT32 repReg, ADDRINT repRegVal,
    UINT32 executing, UINT32 repEqual,
    UINT32 insAssembly);
VOID analysisRoutinePrefetchMem (VOID *iseptr,
    ADDRINT memoryEa, UINT32 memReadBytes);

}
}
}
}

#endif /* InstructionSymbolicExecuter.h */
