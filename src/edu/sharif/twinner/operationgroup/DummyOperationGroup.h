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

#ifndef DUMMY_OPERATION_GROUP_H
#define DUMMY_OPERATION_GROUP_H

#include "OperationGroup.h"
#include <string>

namespace edu {
namespace sharif {
namespace twinner {
namespace operationgroup {

class DummyOperationGroup : public NaryOperationGroup<0> {
private:
  const std::string name;

public:
  DummyOperationGroup (const char *name);

  virtual ExpressionPtr getCarryExpression () const;

  virtual std::list <ConstraintPtr> instantiateConstraintForOverflowCase (
      bool &overflow, uint32_t instruction) const;
  virtual std::list <ConstraintPtr> instantiateConstraintForZeroCase (bool &zero,
      uint32_t instruction) const;
  virtual std::list <ConstraintPtr> instantiateConstraintForLessCase (bool &less,
      uint32_t instruction) const;
  virtual std::list <ConstraintPtr> instantiateConstraintForLessOrEqualCase (
      bool &lessOrEqual, uint32_t instruction) const;
  virtual std::list <ConstraintPtr> instantiateConstraintForBelowCase (bool &below,
      uint32_t instruction) const;
  virtual std::list <ConstraintPtr> instantiateConstraintForBelowOrEqualCase (
      bool &belowOrEqual, uint32_t instruction) const;

  virtual std::list <ConstraintPtr> operationResultIsLessOrEqualWithZero (
      bool &lessOrEqual, uint32_t instruction) const;
  virtual std::list <ConstraintPtr> operationResultIsLessThanZero (bool &lessOrEqual,
      uint32_t instruction) const;
  virtual ExpressionPtr getOperationResult () const;
};

}
}
}
}

#endif /* DummyOperationGroup.h */
