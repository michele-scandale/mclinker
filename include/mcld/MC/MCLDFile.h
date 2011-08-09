/*****************************************************************************
 *   The MCLinker Project, Copyright (C), 2011 -                             *
 *   Embedded and Web Computing Lab, National Taiwan University              *
 *   MediaTek, Inc.                                                          *
 *                                                                           *
 *   Duo <pinronglu@gmail.com>                                               *
 ****************************************************************************/
#ifndef MCLD_LDFILE_H
#define MCLD_LDFILE_H
#ifdef ENABLE_UNITTEST
#include <gtest.h>
#endif

#include <llvm/ADT/StringRef.h>
#include <mcld/MC/MCLDContext.h>
#include <mcld/Support/FileSystem.h>
#include <mcld/ADT/GCFactory.h>
#include <string>

#include "mcld/MC/MCLDContext.h"

namespace mcld
{
class MCContext;
class MCLDContext;

/** \class MCLDFile
 *  \brief MCLDFile represents the file being linked or produced.
 *
 *  MCLDFile is the storage of name, path and type
 *  A MCLDFile just refers to MCLDContext, not owns it.
 *
 *  @see mcld::sys::fs::Path MCLDContext
 */
class MCLDFile
{
public:
  enum Type {
    Archive,
    Object,
    DynObj,
    Exec,
    Script,
    Unknown
  };

public:
  MCLDFile();
  MCLDFile(llvm::StringRef pName,
           const sys::fs::Path& pPath,
           unsigned int pType = Unknown);

  ~MCLDFile();

  // -----  modifiers  ----- //
  void setType(Type pType)
  { m_Type = pType; }

  // -----  observers  ----- //
  bool isRecognized() const
  { return (m_Type != Unknown); }

  unsigned int type() const
  { return m_Type; }

  llvm::StringRef name() const;

  const sys::fs::Path& path() const
  { return m_Path; }

  void setContext(MCLDContext& pContext)
  { m_pContext = &pContext; }

  bool hasContext() const
  { return (0 == m_pContext); }

  MCLDContext* context()
  { return m_pContext; }

  const MCLDContext* context() const
  { return m_pContext; }

private:
  sys::fs::Path m_Path;
  std::string m_InputName;
  MCLDContext   *m_pContext;
  MCAttribute *m_pAttribute;
  unsigned int m_Type;
};

/** \class MCLDFileFactory
 *  \brief MCLDFileFactory controls the production and destruction of
 *  MCLDFiles.
 *
 *  All MCLDFiles created by MCLDFileFactory are guaranteed to be destructed
 *  while MCLDFileFactory is destructed.
 *
 *  MCLDFileFactory also provides the MCLCContextFactory to MCLDFile.
 *  MCLDFile is responsed for the life of MCLDContext, therefore, the best
 *  idea is let MCLDFile control the life of MCLDContext. Since SectLinker
 *  has the need to count the number of MCLDContext, we give a central factory
 *  for MCLDContext.
 *
 *  \see llvm::sys::Path
 */
template<size_t NUM>
class MCLDFileFactory : public GCFactory<MCLDFile, NUM>
{
public:
  typedef GCFactory<MCLDFile, NUM> Alloc;

public:
  // -----  production  ----- //
  MCLDFile* produce(llvm::StringRef pName,
                    const sys::fs::Path& pPath,
                    unsigned int pType = MCLDFile::Unknown);
  
  MCLDFile* produce();
};

} // namespace of mcld

//===----------------------------------------------------------------------===//
// MCLDFileFactory
template<size_t NUM>
mcld::MCLDFile* mcld::MCLDFileFactory<NUM>::produce(llvm::StringRef pName,
                                   const mcld::sys::fs::Path& pPath,
                                   unsigned int pType)
{
    mcld::MCLDFile* result = Alloc::allocate();
    new (result) mcld::MCLDFile(pName, pPath, pType);
    return result;
}

template<size_t NUM>
mcld::MCLDFile* mcld::MCLDFileFactory<NUM>::produce()
{
    mcld::MCLDFile* result = Alloc::allocate();
    new (result) mcld::MCLDFile();
    return result;
}

#endif

