//===- ELFObjectWriter.cpp ------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include <mcld/LD/ELFObjectWriter.h>

#include <mcld/ADT/SizeTraits.h>
#include <mcld/Fragment/AlignFragment.h>
#include <mcld/Fragment/FillFragment.h>
#include <mcld/Fragment/RegionFragment.h>
#include <mcld/Fragment/Stub.h>
#include <mcld/Fragment/NullFragment.h>
#include <mcld/LD/EhFrame.h>
#include <mcld/LD/ELFFileFormat.h>
#include <mcld/LD/LDSymbol.h>
#include <mcld/LD/LDSection.h>
#include <mcld/LD/SectionData.h>
#include <mcld/LD/ELFSegment.h>
#include <mcld/LD/ELFSegmentFactory.h>
#include <mcld/LD/RelocData.h>
#include <mcld/LinkerConfig.h>
#include <mcld/LinkerScript.h>
#include <mcld/Module.h>
#include <mcld/Support/MsgHandling.h>
#include <mcld/Target/GNUInfo.h>
#include <mcld/Target/GNULDBackend.h>

#include <llvm/Support/Errc.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/ELF.h>
#include <llvm/Support/Casting.h>

using namespace llvm;
using namespace llvm::ELF;
using namespace mcld;

//===----------------------------------------------------------------------===//
// ELFObjectWriter
//===----------------------------------------------------------------------===//
ELFObjectWriter::ELFObjectWriter(const GenericELFReaderWriter& pELFReaderWriter)
 : ObjectWriter(), m_ELFReaderWriter(pELFReaderWriter) {}

ELFObjectWriter::~ELFObjectWriter() {}

std::error_code ELFObjectWriter::writeObject(Module& pModule,
                                             FileOutputBuffer& pOutput) {
  const LinkerConfig &config = m_ELFReaderWriter.config();
  bool IsDynObj = config.codeGenType() == LinkerConfig::DynObj;
  bool IsExec = config.codeGenType() == LinkerConfig::Exec;
  bool IsBinary = config.codeGenType() == LinkerConfig::Binary;
  bool IsObject = config.codeGenType() == LinkerConfig::Object;

  assert(IsDynObj || IsExec || IsBinary || IsObject);

  if (IsBinary) {
    // Iterate over the loadable segments and write the corresponding sections
    const ELFSegmentFactory& SegmentTable =
      m_ELFReaderWriter.target().elfSegmentTable();
    for (ELFSegmentFactory::const_iterator I = SegmentTable.begin(),
         E = SegmentTable.end(); I != E; ++I) {
      const ELFSegment& Seg = **I;
      if (Seg.type() == llvm::ELF::PT_LOAD) {
        for (ELFSegment::const_iterator SI = Seg.begin(),
             SE = Seg.end(); SI != SE; ++SI)
          m_ELFReaderWriter.writeSection(pModule, **SI, pOutput);
      }
    }

    return std::error_code();
  }


  if (IsDynObj || IsExec) {
    // Allow backend to sort symbols before emitting
    m_ELFReaderWriter.target().orderSymbolTable(pModule);

    // Write out the interpreter section: .interp
    m_ELFReaderWriter.writeInterp(pOutput);

    // Write out name pool sections: .dynsym, .dynstr, .hash
    m_ELFReaderWriter.writeDynamicNamePools(pModule, pOutput);
  }

  if (IsObject || IsDynObj || IsExec) {
    // Write out name pool sections: .symtab, .strtab
    m_ELFReaderWriter.writeRegularNamePools(pModule, pOutput);
  }

  // Write out regular ELF sections
  for (Module::iterator SI = pModule.begin(),
       SE = pModule.end(); SI != SE; ++SI)
    m_ELFReaderWriter.writeSection(pModule, **SI, pOutput);

  m_ELFReaderWriter.writeShStrTab(pModule, pOutput);

  m_ELFReaderWriter.writeELFHeader(pModule, pOutput);

  if (IsDynObj || IsExec)
    m_ELFReaderWriter.writeProgramHeaders(pOutput);

  m_ELFReaderWriter.writeSectionHeaders(pModule, pOutput);

  return std::error_code();
}

// getOutputSize - count the final output size
size_t ELFObjectWriter::getOutputSize(const Module& pModule) const {
  return m_ELFReaderWriter.getOutputSize(pModule);
}
