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

#ifndef XOR_OPERATOR_H
#define XOR_OPERATOR_H

#include "Operator.h"

namespace edu {
namespace sharif {
namespace twinner {
namespace trace {
namespace exptoken {

class XorOperator : public Operator {

public:
  XorOperator ();
  XorOperator (const XorOperator &ao);
  virtual ~XorOperator ();

  virtual XorOperator *clone () const;

  virtual bool doesSupportSimplification () const;
  virtual bool isCommutable () const;
  virtual bool apply (edu::sharif::twinner::trace::cv::ConcreteValue &dst,
      const edu::sharif::twinner::trace::cv::ConcreteValue &src) const;

  virtual std::string toString () const;
  virtual bool operator== (const ExpressionToken &token) const;

private:
  void initializeSimplificationRules ();
};

}
}
}
}
}

#endif	/* XorOperator.h */
