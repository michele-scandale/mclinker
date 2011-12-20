//===- MCLinker.h -------------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides a number of APIs used by SectLinker.
// These APIs do the things which a linker should do.
//
//===----------------------------------------------------------------------===//
#ifndef MCLD_MCLINKER_H
#define MCLD_MCLINKER_H
#ifdef ENABLE_UNITTEST
#include <gtest.h>
#endif

#include <vector>
#include <string>
#include <llvm/MC/MCAssembler.h>
#include <mcld/LD/StrSymPool.h>
#include <mcld/LD/StaticResolver.h>
#include <mcld/LD/SectionFactory.h>
#include <mcld/LD/LDFileFormat.h>
#include <mcld/LD/LDContext.h>
#include <mcld/Support/GCFactory.h>

namespace mcld {

class Input;
class Layout;
class TargetLDBackend;
class MCLDInfo;
class LDSection;
class SectionFactory;

/** \class MCLinker
 *  \brief MCLinker provides a pass to link object files.
 */
class MCLinker
{
public:
  typedef SectionFactory::iterator sect_iterator;
  typedef SectionFactory::const_iterator const_sect_iterator;

public:
  MCLinker(TargetLDBackend& pBackend,
           MCLDInfo& pLDInfo,
           LDContext& pContext,
           const Resolver& pResolver = StaticResolver());
  ~MCLinker();

  // ----- about symbols  ----- //
  /// addGlobalSymbol - add a symbol and resolve it immediately
  LDSymbol* addGlobalSymbol(const llvm::StringRef& pName,
                            bool pIsDyn,
                            ResolveInfo::Desc pDesc,
                            ResolveInfo::Binding pBinding,
                            ResolveInfo::ValueType pValue,
                            ResolveInfo::SizeType pSize,
                            ResolveInfo::Visibility pVisibility = ResolveInfo::Default);

  /// addLocalSymbol - create a local symbol and add it into the output.
  LDSymbol* addLocalSymbol(const llvm::StringRef& pName,
                           ResolveInfo::Desc pDesc,
                           ResolveInfo::ValueType pValue,
                           ResolveInfo::SizeType pSize,
                           ResolveInfo::Visibility pVisibility = ResolveInfo::Default);

  /// mergeSymbolTable - merge the symbol table and resolve symbols.
  ///   Since in current design, MCLinker resolves symbols when reading symbol
  ///   tables, this function do nothing.
  bool mergeSymbolTable(Input& pInput)
  { return true; }

  // -----  sections  ----- //
  /// getSectionMap - getSectionMap to change the behavior of SectionMerger
  /// SectionMap& getSectionMap()
  /// { return m_SectionMap; }

  /// getSectFactory - getSectFactory to create LDSection
  SectionFactory& getSectFactory()
  { return m_SectionFactory; }

  const LDSection* getOrCreateSection(const std::string& pName,
                                LDFileFormat::Kind pKind,
                                uint32_t pType,
                                uint32_t pFlag);

  // -----  capacity  ----- //
  MCLDInfo& getLDInfo()
  { return m_Info; }

  const MCLDInfo& getLDInfo() const
  { return m_Info; }

private:
  typedef GCFactory<LDSymbol, 0> LDSymbolFactory;

private:
  TargetLDBackend& m_Backend;
  MCLDInfo& m_Info;
  LDContext& m_Output;
  StrSymPool m_StrSymPool;
  LDSymbolFactory m_LDSymbolFactory;
  SectionFactory m_SectionFactory;
  // SectionMap& m_SectionMap;
};

} // namespace of mcld

#endif

