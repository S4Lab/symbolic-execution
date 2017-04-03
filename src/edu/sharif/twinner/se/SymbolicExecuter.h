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

#ifndef TWIN_TOOL_H
#define TWIN_TOOL_H

#include "edu/sharif/twinner/pin-wrapper.h"

#include <set>

namespace edu {
namespace sharif {
namespace twinner {
namespace twintool {

class Instrumenter;

class SymbolicExecuter {
private:

  /**
   * This enum must be kept in synch with Executer::ExecutionMode from Twinner.
   * We can not use the same enum, as SymbolicExecuter is supposed to be independent of Twinner's
   * binary and object codes.
   */
  enum ExecutionMode {
    NORMAL_MODE = 0x1,
    INITIAL_STATE_DETECTION_MODE = 0x4,
  };

  Instrumenter *im;
  bool justAnalyzeMainRoutine;

public:
  SymbolicExecuter ();
  ~SymbolicExecuter ();

  INT32 run (int argc, char *argv[]);

private:
  template < typename T >
  INT32 printError (const T &msg) const;
  INT32 printUsage () const;

  bool parseArgumentsAndInitializeTool ();
};

}
}
}
}

#endif /* SymbolicExecuter.h */
