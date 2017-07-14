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
  bool logDstRegSrcReg (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  bool logDstRegSrcRegAuxReg (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);
  bool logDstRegSrcRegAuxImd (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &auxImmediateValue,
      UINT32 insAssembly);
  bool logDstRegSrcMem (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  bool logDstRegSrcMemAuxReg (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);
  bool logDstRegSrcMemAuxImd (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      const ConcreteValue &auxImmediateValue,
      UINT32 insAssembly);
  bool logDstRegSrcImd (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  bool logDstMemSrcReg (
      ADDRINT dstMemoryEa, UINT32 memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  bool logDstMemSrcRegAuxReg (
      ADDRINT dstMemoryEa, UINT32 memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);
  bool logDstMemSrcRegAuxImd (
      ADDRINT dstMemoryEa, UINT32 memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &auxImmediateValue,
      UINT32 insAssembly);
  bool logDstMemSrcImd (
      ADDRINT dstMemoryEa, UINT32 memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  bool logDstMemSrcImdAuxReg (
      ADDRINT dstMemoryEa, UINT32 memReadBytes,
      const ConcreteValue &srcImmediateValue,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);
  bool logDstMemSrcMemAuxReg (
      ADDRINT dstMemoryEa,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);
  bool logConditionalBranch (
      BOOL branchTaken,
      UINT32 insAssembly);
  bool logDstRegSrcAdg (
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
  bool logTwoDstRegOneSrcReg (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  bool logTwoDstRegOneSrcMem (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  bool logOneMemTwoReg (
      ADDRINT dstMemoryEa, UINT32 memReadBytes,
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  bool logTwoRegTwoMem (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT dstMemoryEa, ADDRINT srcMemoryEa, UINT32 memReadBytes,
      UINT32 insAssembly);
  bool logAfterOperandLessInstruction (
      const CONTEXT *context,
      UINT32 insAssembly);
  bool logDstRegSrcImplicit (
      REG dstReg, const ConcreteValue &dstRegVal,
      UINT32 insAssembly);
  bool logDstMemSrcImplicit (
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

public:
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
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);
  void cmpxchgAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG auxReg, const ConcreteValue &auxRegVal,
      UINT32 insAssembly);

  /**
   * PALIGNR is packed align right. The dst and src are first concatenated
   * and then shifted to right as many bytes as indicated in the shift argument
   * and then stored in the dst reg.
   */
  void palignrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      const ConcreteValue &shiftImmediateValue,
      UINT32 insAssembly);
  void palignrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &shiftImmediateValue,
      UINT32 insAssembly);

  /**
   * PSHUFD is packed shuffle for double words. The 8-bits order argument is consisted
   * of 4 parts of 2-bits index numbers. Each index indicates that which double word
   * from the src operand should be placed in the next double word place of the dst.
   */
  void pshufdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      const ConcreteValue &orderImmediateValue,
      UINT32 insAssembly);
  void pshufdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &orderImmediateValue,
      UINT32 insAssembly);

  /**
   * SHLD shifts (dst,src) to left as much as (shift) and stores it in (dst).
   * That is, the (dst) is shifted left by (shift) and its lower order bits
   * are filled with the shifted (src) instead of zero.
   * The last bit which goes out of (dst) is stored in CF.
   */
  void shldAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &shiftImmediateValue,
      UINT32 insAssembly);
  void shldAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG shiftReg, const ConcreteValue &shiftRegVal,
      UINT32 insAssembly);
  void shldAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &shiftImmediateValue,
      UINT32 insAssembly);
  void shldAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG shiftReg, const ConcreteValue &shiftRegVal,
      UINT32 insAssembly);

  /**
   * XCHG instruction exchanges values of dst (r/m) and src (r) atomically
   */
  void xchgAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void xchgAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * XADD instruction exchanges values of dst (r/m) and src (r) and
   * loads sum of two operands in the dst atomically
   */
  void xaddAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void xaddAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * MOVLPD moves 64-bits from mem src to low packed double-precision
   * (the lower 64-bits) of dst xmm reg or vice versa.
   */
  void movlpdAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void movlpdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);

  /**
   * MOVHPD moves 64-bits from mem src to high packed double-precision
   * (the upper 64-bits) of dst xmm reg or vice versa.
   */
  void movhpdAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void movhpdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);

  /**
   * MOV has 5 models
   * r <- r/m/i
   * m <- r/i
   */
  void movAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void movAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal);
  void movAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void movAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal);

  /**
   * MOV with Sign extension
   * r <- sign-extend (r/m)
   */
  void movsxAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void movsxAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * Sign extends the (src) into (dst:src). That is, fills (dst) with
   * the sign bit of the (src).
   */
  void cdqAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * MOV String to String reads from [rsi]/srcMem and moves to [rdi]/dstMem and
   * increments/decrements rdi/rsi registers
   */
  void movsAnalysisRoutine (
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG rsiReg, const ConcreteValue &rsiRegVal,
      ADDRINT dstMemoryEa, ADDRINT srcMemoryEa,
      UINT32 memReadBytes,
      UINT32 insAssembly);

  /**
   * CMPSB / CMPSW / CMPSD / CMPSQ compare string with 1/2/4/8 bytes sizes.
   * Operands are read from [rsi]/srcMem and [rdi]/dstMem and
   * increments/decrements rdi/rsi registers.
   */
  void cmpsAnalysisRoutine (
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG rsiReg, const ConcreteValue &rsiRegVal,
      ADDRINT dstMemoryEa, ADDRINT srcMemoryEa,
      UINT32 memReadBytes,
      UINT32 insAssembly);

  /**
   * PUSHFD pushes FLAGS onto stack.
   */
  void pushfdAnalysisRoutine (
      ADDRINT stackMemoryEa, int stackReadBytes,
      REG flagsReg, const ConcreteValue &flagsRegVal,
      REG rspReg, const ConcreteValue &rspRegVal,
      UINT32 insAssembly);

  /**
   * PUSH has 3 models
   * m <- r/m/i
   */
  void pushAnalysisRoutine (
      ADDRINT dstMemoryEa,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rspReg, const ConcreteValue &rspRegVal,
      UINT32 insAssembly);
  void pushAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      REG rspReg, const ConcreteValue &rspRegVal,
      UINT32 insAssembly);
  void pushAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      REG rspReg, const ConcreteValue &rspRegVal,
      UINT32 insAssembly);

  /**
   * POP has 2 models
   * r/m <- m
   */
  void popAnalysisRoutine (
      ADDRINT dstMemoryEa,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rspReg, const ConcreteValue &rspRegVal,
      UINT32 insAssembly);
  void popAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rspReg, const ConcreteValue &rspRegVal,
      UINT32 insAssembly);

  /**
   * LODSD is load string double word
   * eax/dst-reg <- [rsi]
   */
  void lodsdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      REG rsiReg, const ConcreteValue &rsiRegVal,
      UINT32 insAssembly);

  /**
   * ADD has 5 models
   * r += r/m/i
   * m += r/i
   */
  void addAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void addAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void addAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void addAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void addAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * ADC has 5 models. It is Add with carry.
   * r += r/m/i
   * m += r/i
   */
  void adcAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void adcAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void adcAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void adcAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void adcAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * SUB has 5 models
   * r -= r/m/i
   * m -= r/i
   */
  void subAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void subAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void subAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void subAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void subAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * SBB is subtract with borrow
   * dst = dst - (src + CF) where CF is the carry of the previous operation
   */
  void sbbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void sbbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void sbbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void sbbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void sbbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * CMP is same as SUB else of not modifying dst operand's value
   */
  void cmpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void cmpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void cmpAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void cmpAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void cmpAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes);
  void cmpAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
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
      const ConcreteValue &srcAdgVal,
      UINT32 insAssembly);

  /**
   * JNZ jumps if ZF=0 which means that corresponding expression was not zero
   */
  void jnzAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JZ jumps if ZF=1 which means that corresponding expression was zero
   */
  void jzAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JLE jumps if ZF=1 or SF!=OF which means that corresponding expression was <= 0
   */
  void jleAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JNLE jumps if ZF=0 and SF=OF which means that corresponding expression was > 0
   */
  void jnleAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JL jumps if SF!=OF which means that corresponding expression was < 0
   */
  void jlAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JNL jumps if SF=OF which means that corresponding expression was > 0
   */
  void jnlAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JBE jumps if ZF=1 or CF=1 which means that corresponding expression was <= 0
   */
  void jbeAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JNBE jumps if ZF=0 and CF=0 which means that corresponding expression was > 0
   */
  void jnbeAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JNB jumps if CF=0 which means that corresponding expression was > 0
   */
  void jnbAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JB jumps if CF=1 (jump below)
   */
  void jbAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JO jumps if OF=1 which means that last operation caused a signed overflow
   */
  void joAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JP jumps if PF=1 (even parity)
   */
  void jpAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JNP jumps if PF=0 (odd parity)
   */
  void jnpAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JS jumps if SF=1 which means that corresponding expression was < 0
   */
  void jsAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

  /**
   * JNS jumps if SF=0 which means that corresponding expression was >= 0
   */
  void jnsAnalysisRoutine (bool branchTaken, UINT32 insAssembly);

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
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);

  /**
   * SHL shifts dst to left as much as indicated by src.
   */
  void shlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void shlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void shlAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void shlAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * SHR shifts dst to right as much as indicated by src.
   */
  void shrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void shrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void shrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void shrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * SAR arithmetic shifts dst to right as much as indicated by src (signed division).
   */
  void sarAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void sarAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void sarAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void sarAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * ROR rotates right the dst as much as indicated by src.
   * Also the LSB of src (which will be moved to the new MSB) will be set in CF.
   */
  void rorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void rorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void rorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void rorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * ROL rotates left the dst as much as indicated by src.
   * Also the MSB of src (which will be moved to the new LSB) will be set in CF.
   */
  void rolAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void rolAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void rolAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void rolAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * AND bitwise ands dst with src as its mask.
   */
  void andAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void andAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void andAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void andAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void andAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * OR bitwise ores dst with src as its complement.
   */
  void orAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void orAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void orAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void orAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void orAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * XOR calculates exclusive or of dst with src.
   */
  void xorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void xorAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void xorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void xorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void xorAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * TEST performs AND between arguments, temporarily, and sets ZF, SF, and PF based
   * on result. Also CF and OF are set to zero. AF is undefined.
   */
  void testAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void testAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void testAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void testAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * BT is bit test instruction. It finds the bitoffset-th bit from the bitstring and
   * set it as the CF.
   */
  void btAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void btAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void btAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void btAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * BTR is bit test and reset instruction. It acts like BT and also
   * resets the selected bit to zero.
   */
  void btrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);
  void btrAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void btrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      const ConcreteValue &srcImmediateValue,
      UINT32 insAssembly);
  void btrAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

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
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * PCMPEQB is a packed compare equality check which works byte-wise.
   * The src and dst are compared together byte-by-byte and those bytes
   * which are/aren't equal will be filed with 1 (0xFF) / 0 (0x00) in
   * the dst reg.
   */
  void pcmpeqbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void pcmpeqbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * PCMPGTB is a packed compare greater-than check which works byte-wise.
   * The src and dst are compared together byte-by-byte and those dst bytes
   * which are/aren't greater-than src will be filed with 1 (0xFF) / 0 (0x00) in
   * the dst reg.
   */
  void pcmpgtbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void pcmpgtbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * PMINUB is a packed minimum finding for unsigned bytes.
   * Packed unsigned bytes which are stored in dst and src wil be compared to find their
   * minimum values. Minimum values will be stored in the dst.
   */
  void pminubAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void pminubAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * PSUBB is a packed subtract instruction which subtracts src individual bytes
   * from dst individual bytes and stores the results in dst bytes.
   * Overflows are not reported in EFLAGS.
   */
  void psubbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void psubbAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * PUNPCKLBW is a packed operation which "unpacks" low-data from src-dst and interleaves
   * them and put the result in the dst.
   *  -- byte to word
   */
  void punpcklbwAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void punpcklbwAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * PUNPCKLWD is a packed operation which "unpacks" low-data from src-dst and interleaves
   * them and put the result in the dst.
   *  -- word to double-word
   */
  void punpcklwdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void punpcklwdAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * BSF is bit scan forward instruction which searches for the least significant 1 bit
   * in the src and sets its index in the dst. The index is placed as a constant in dst
   * and a constraint is added to indicate that the noted bit was set.
   */
  void bsfAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void bsfAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

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
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void divAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

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
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void idivAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

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
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void mulAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * IMUL is signed multiply and has three models.
   * This method implements the one operand model.
   */
  void imulAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void imulAnalysisRoutine (
      REG dstLeftReg, const ConcreteValue &dstLeftRegVal,
      REG dstRightReg, const ConcreteValue &dstRightRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * IMUL is signed multiply and has three models.
   * This method implements the two operands model.
   */
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * IMUL is signed multiply and has three models.
   * This method implements the three operands model.
   */
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      const ConcreteValue &imdValue,
      UINT32 insAssembly);
  void imulAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      const ConcreteValue &auxImmediateValue,
      UINT32 insAssembly);

  /**
   * SCAS instruction compares AL/AX/EAX/RAX (the dstReg) and a given srcMem value
   * which is pointed to by the DI/EDI/RDI and sets the EFLAGS based on
   * the comparison result.
   */
  void scasAnalysisRoutine (
      REG dstReg, const ConcreteValue &dstRegVal,
      REG rdiReg, const ConcreteValue &rdiRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);

  /**
   * Store String stores the srcReg into dstMem==[rdi] location and moves rdi accordingly.
   */
  void stosAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG srcReg, const ConcreteValue &srcRegVal,
      UINT32 insAssembly);

  /**
   * LEAVE instruction:
   *   spReg <- fpReg
   *   fpReg <- pop-from-stack
   */
  void leaveAnalysisRoutine (
      REG fpReg, const ConcreteValue &fpRegVal,
      REG spReg, const ConcreteValue &spRegVal,
      ADDRINT srcMemoryEa, int memReadBytes,
      UINT32 insAssembly);

  /**
   * This hook adjusts concrete values of division/multiplication operands
   * and also propagates their values to overlapping registers.
   */
  void adjustDivisionMultiplicationOperands (const CONTEXT *context,
      const ConcreteValue &operandSize);

  /**
   * read time-stamp counter and put it in EDX:EAX
   */
  void rdtscAnalysisRoutine (const CONTEXT *context,
      UINT32 insAssembly);

  /**
   * Clears the direction flags (DF)
   */
  void cldAnalysisRoutine (const CONTEXT *context,
      UINT32 insAssembly);

  /**
   * CPUID == CPU Identification
   */
  void cpuidAnalysisRoutine (const CONTEXT *context,
      UINT32 insAssembly);

  /**
   * INC increments the opr reg/mem operand.
   */
  void incAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void incAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * DEC decrements the opr reg/mem operand.
   */
  void decAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void decAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * NEG two's complements the opr (which is reg or mem).
   */
  void negAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void negAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETO sets opr to 1 iff OF=1 (and sets it to 0 otherwise).
   */
  void setoAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setoAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETP sets opr to 1 iff PF=1 (and sets it to 0 otherwise).
   */
  void setpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setpAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETNP sets opr to 1 iff PF=0 (and sets it to 0 otherwise).
   */
  void setnpAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setnpAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETNS sets opr to 1 iff SF=0 (and sets it to 0 otherwise).
   */
  void setnsAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setnsAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETNZ sets opr to 1 iff ZF=0 (and sets it to 0 otherwise).
   */
  void setnzAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setnzAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETZ sets opr to 1 iff ZF=1 (and sets it to 0 otherwise).
   */
  void setzAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setzAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETLE sets opr to 1 iff ZF=1 or SF != OF (and sets it to 0 otherwise).
   */
  void setleAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setleAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETNLE sets opr to 1 iff ZF=0 and SF == OF (and sets it to 0 otherwise).
   */
  void setnleAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setnleAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETL sets opr to 1 iff SF != OF (and sets it to 0 otherwise).
   */
  void setlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setlAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETNL sets opr to 1 iff SF == OF (and sets it to 0 otherwise).
   */
  void setnlAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setnlAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETB sets opr to 1 iff CF=1 (and sets it to 0 otherwise).
   */
  void setbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setbAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETBE sets opr to 1 iff ZF=1 or CF=1 (and sets it to 0 otherwise).
   */
  void setbeAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setbeAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETNBE sets opr to 1 iff ZF=0 and CF=0 (and sets it to 0 otherwise).
   */
  void setnbeAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setnbeAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * SETNB sets opr to 1 iff CF=0 (and sets it to 0 otherwise).
   */
  void setnbAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void setnbAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  /**
   * NOT one's complements the opr.
   * opr <- NOT(opr)
   */
  void notAnalysisRoutine (
      ADDRINT dstMemoryEa, int memReadBytes,
      UINT32 insAssembly);
  void notAnalysisRoutine (
      REG oprReg, const ConcreteValue &oprRegVal,
      UINT32 insAssembly);

  void adjustRsiRdiRegisters (int size,
      REG rdiReg, const ConcreteValue &rdiRegVal,
      REG rsiReg, const ConcreteValue &rsiRegVal);

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

VOID analysisRoutineDstRegSrcRegMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegMovsx (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegCdq (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegShl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegShr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegSar (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegRor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegRol (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegTest (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegBt (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegBtr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegPminub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegPsubb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegBsf (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegXchg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegXadd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcLargeRegMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegMovsx (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegCdq (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegShl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegShr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegSar (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegRor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegRol (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegTest (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegBt (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegBtr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegPminub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegPsubb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegBsf (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegXchg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcLargeRegXadd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);

VOID analysisRoutineDstLargeRegSrcRegMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegMovsx (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegCdq (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegShl (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegShr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegSar (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegRor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegRol (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegTest (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegBt (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegBtr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegPminub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegPsubb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegBsf (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegXchg (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcRegXadd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);

VOID analysisRoutineDstLargeRegSrcLargeRegMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegMovsx (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegCdq (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegShl (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegShr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegSar (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegRor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegRol (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegTest (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegBt (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegBtr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegPmovmskb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegPcmpeqb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegPcmpgtb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegPminub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegPsubb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegPunpcklbw (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegPunpcklwd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegBsf (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegXchg (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegXadd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcRegAuxRegCmpxchg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAuxRegShld (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcRegAuxImdImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcRegAuxImdShld (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);

VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcLargeRegAuxImdShld (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);

VOID analysisRoutineDstLargeRegSrcMemMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemMovlpd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemMovhpd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemMovsx (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemPcmpeqb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemPcmpgtb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemPminub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemPsubb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemPunpcklbw (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemPunpcklwd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemBsf (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcMemAuxImdImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);

VOID analysisRoutineDstLargeRegSrcMemAuxImdImul (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemAuxImdPalignr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcMemAuxImdPshufd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    ADDRINT auxImmediateValue,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcMemMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemMovlpd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemMovhpd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemImul (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemMovsx (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemPcmpeqb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemPcmpgtb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemPminub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemPsubb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemPunpcklbw (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemPunpcklwd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemBsf (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcMemAuxRegPop (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcMemAuxRegLodsd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcImdMov (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdAdd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdAdc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdSub (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdSbb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdCmp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdPslldq (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdShl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdShr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdSar (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdRor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdRol (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdAnd (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdOr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdXor (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdTest (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdBt (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImdBtr (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);

VOID analysisRoutineDstLargeRegSrcImdMov (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdAdd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdAdc (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdSub (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdSbb (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdCmp (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdPslldq (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdShl (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdShr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdSar (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdRor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdRol (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdAnd (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdOr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdXor (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdTest (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdBt (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);
VOID analysisRoutineDstLargeRegSrcImdBtr (VOID *iseptr,
    UINT32 dstReg, const PIN_REGISTER *dstRegVal,
    ADDRINT srcImmediateValue,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcRegMov (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegMovlpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegMovhpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAdd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAdc (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegSub (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegSbb (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegCmp (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegShl (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegShr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegSar (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegRor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegRol (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAnd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegOr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegXor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegTest (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegBt (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegBtr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegXchg (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegXadd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcRegAuxRegCmpxchg (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAuxRegPushfd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAuxRegPush (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcRegAuxRegShld (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcRegAuxImdShld (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT auxImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcLargeRegMov (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegMovlpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegMovhpd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegAdd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegAdc (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegSub (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegSbb (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegCmp (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegShl (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegShr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegSar (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegRor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegRol (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegAnd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegOr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegXor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegTest (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegBt (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcLargeRegBtr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, const PIN_REGISTER *srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcImdMov (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdAdd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdAdc (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdSub (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdSbb (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdCmp (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdShl (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdShr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdSar (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdRor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdRol (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdAnd (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdOr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdXor (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdTest (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdBt (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImdBtr (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcImdAuxRegPush (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcImmediateValue,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcMemAuxRegPush (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcMemAuxRegPop (VOID *iseptr,
    ADDRINT dstMemoryEa,
    ADDRINT srcMemoryEa,
    UINT32 auxReg, ADDRINT auxRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineConditionalBranchJnz (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJz (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJle (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJnle (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJl (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJnl (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJbe (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJnbe (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJnb (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJb (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJo (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJp (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJnp (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJs (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);
VOID analysisRoutineConditionalBranchJns (VOID *iseptr,
    BOOL branchTaken,
    UINT32 insAssembly);

VOID analysisRoutineDstRegSrcAdgLea (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineBeforeChangeOfReg (VOID *iseptr, UINT32 opcode,
    UINT32 reg,
    UINT32 insAssembly);
VOID analysisRoutineBeforeChangeOfRegWithArg (VOID *iseptr, UINT32 opcode,
    UINT32 reg, ADDRINT argImmediateValue,
    UINT32 insAssembly);

VOID analysisRoutineTwoDstRegOneSrcRegDiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcRegIdiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcRegMul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcRegImul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 insAssembly);

VOID analysisRoutineTwoDstRegOneSrcMemDiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcMemIdiv (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcMemMul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcMemImul (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcMemScas (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineTwoDstRegOneSrcMemLeave (VOID *iseptr,
    UINT32 dstLeftReg, ADDRINT dstLeftRegVal,
    UINT32 dstRightReg, ADDRINT dstRightRegVal,
    ADDRINT srcMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineAfterOperandLessRdtsc (VOID *iseptr,
    const CONTEXT *context,
    UINT32 insAssembly);
VOID analysisRoutineAfterOperandLessCld (VOID *iseptr,
    const CONTEXT *context,
    UINT32 insAssembly);
VOID analysisRoutineAfterOperandLessCpuid (VOID *iseptr,
    const CONTEXT *context,
    UINT32 insAssembly);

VOID analysisRoutineRunHooks (VOID *iseptr, const CONTEXT *context);

VOID analysisRoutineDstRegSrcImplicitInc (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitDec (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitNeg (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSeto (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetnp (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetns (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetnz (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetz (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetle (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetnle (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetnl (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetbe (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetnbe (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitSetnb (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);
VOID analysisRoutineDstRegSrcImplicitNot (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 insAssembly);

VOID analysisRoutineDstMemSrcImplicitInc (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitDec (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitNeg (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSeto (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetp (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetnp (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetns (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetnz (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetz (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetle (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetnle (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetl (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetnl (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetb (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetbe (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetnbe (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitSetnb (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineDstMemSrcImplicitNot (VOID *iseptr,
    ADDRINT dstMemoryEa, UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineInitializeRegisters (VOID *iseptr, CONTEXT *context);

VOID analysisRoutineStrOpMemRegStos (VOID *iseptr,
    ADDRINT dstMemoryEa,
    UINT32 dstReg, ADDRINT dstRegVal,
    UINT32 srcReg, ADDRINT srcRegVal,
    UINT32 memReadBytes,
    UINT32 insAssembly);

VOID analysisRoutineStrOpMemMemMovs (VOID *iseptr,
    UINT32 dstReg, ADDRINT dstRegVal,
    ADDRINT dstMemoryEa,
    UINT32 srcReg, ADDRINT srcRegVal,
    ADDRINT srcMemoryEa,
    UINT32 memReadBytes,
    UINT32 insAssembly);
VOID analysisRoutineStrOpMemMemCmps (VOID *iseptr,
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
