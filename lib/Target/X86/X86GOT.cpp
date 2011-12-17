//===- impl.cpp -----------------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include "X86GOT.h"
#include <mcld/LD/LDFileFormat.h>

using namespace mcld;

//==========================
// X86GOT
X86GOT::X86GOT(const std::string pSectionName)
  : GOT(pSectionName)
{
}

X86GOT::~X86GOT()
{
}
