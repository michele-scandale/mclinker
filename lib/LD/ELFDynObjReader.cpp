//===- ELFDynObjReader.cpp ------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include <mcld/LD/ELFDynObjReader.h>

#include <mcld/LinkerConfig.h>
#include <mcld/IRBuilder.h>
#include <mcld/LD/DiagnosticInfos.h>
#include <mcld/LD/ELFReaderWriter.h>
#include <mcld/LD/LDContext.h>
#include <mcld/MC/Input.h>
#include <mcld/Support/MemoryArea.h>
#include <mcld/Support/MsgHandling.h>

#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/Twine.h>
#include <llvm/Support/ErrorHandling.h>

#include <string>

using namespace mcld;

//===----------------------------------------------------------------------===//
// ELFDynObjReader
//===----------------------------------------------------------------------===//
ELFDynObjReader::ELFDynObjReader(const GenericELFReaderWriter& pELFReaderWriter,
                                 const LinkerConfig& pConfig,
                                 IRBuilder& pBuilder)
  : DynObjReader(),
    m_ELFReaderWriter(pELFReaderWriter),
    m_Builder(pBuilder) {}

ELFDynObjReader::~ELFDynObjReader() {}

/// isMyFormat
bool ELFDynObjReader::isMyFormat(Input& pInput, bool &pContinue) const
{
  assert(pInput.hasMemArea());

  // Don't warning about the frequently requests.
  // MemoryArea has a list of cache to handle this.
  size_t hdr_size = m_ELFReaderWriter.getHeaderSize();
  if (pInput.memArea()->size() < hdr_size)
    return false;

  llvm::StringRef region = pInput.memArea()->request(pInput.fileOffset(),
                                                     hdr_size);

  const char* ELF_hdr = region.begin();

  pContinue = true;
  if (!m_ELFReaderWriter.isELF(ELF_hdr))
    return false;

  if (m_ELFReaderWriter.fileType(ELF_hdr) != Input::DynObj)
    return false;

  pContinue = false;
  if (!m_ELFReaderWriter.isMyEndian(ELF_hdr))
    return false;

  if (!m_ELFReaderWriter.isMyMachine(ELF_hdr))
    return false;

  return true;
}

/// readHeader
bool ELFDynObjReader::readHeader(Input& pInput)
{
  assert(pInput.hasMemArea());

  size_t hdr_size = m_ELFReaderWriter.getHeaderSize();
  llvm::StringRef region = pInput.memArea()->request(pInput.fileOffset(),
                                                     hdr_size);
  const char* ELF_hdr = region.begin();

  bool shdr_result = m_ELFReaderWriter.readSectionHeaders(ELF_hdr, pInput);

  // read .dynamic to get the correct SONAME
  bool dyn_result = m_ELFReaderWriter.readDynamic(pInput);

  return (shdr_result && dyn_result);
}

/// readSymbols
bool ELFDynObjReader::readSymbols(Input& pInput)
{
  assert(pInput.hasMemArea());

  LDSection* symtab_shdr = pInput.context()->getSection(".dynsym");
  if (NULL == symtab_shdr) {
    note(diag::note_has_no_symtab) << pInput.name()
                                   << pInput.path()
                                   << ".dynsym";
    return true;
  }

  LDSection* strtab_shdr = symtab_shdr->getLink();
  if (NULL == strtab_shdr) {
    fatal(diag::fatal_cannot_read_strtab) << pInput.name()
                                          << pInput.path()
                                          << ".dynstr";
    return false;
  }

  llvm::StringRef symtab_region = pInput.memArea()->request(
      pInput.fileOffset() + symtab_shdr->offset(), symtab_shdr->size());

  llvm::StringRef strtab_region = pInput.memArea()->request(
      pInput.fileOffset() + strtab_shdr->offset(), strtab_shdr->size());
  const char* strtab = strtab_region.begin();
  bool result = m_ELFReaderWriter.readSymbols(symtab_region, strtab,
                                              pInput, m_Builder);
  return result;
}

