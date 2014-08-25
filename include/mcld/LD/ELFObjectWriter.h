//===- ELFObjectWriter.h --------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#ifndef MCLD_LD_ELFOBJWRITER_H
#define MCLD_LD_ELFOBJWRITER_H

#include <mcld/LD/ObjectWriter.h>
#include <mcld/LD/ELFReaderWriter.h>

namespace mcld {

class FileOutputBuffer;
class Module;

/** \class ELFObjectWriter
 *  \brief ELFObjectWriter writes the target-independent parts of object files.
 *  ELFObjectWriter reads a MCLDFile and writes into raw_ostream
 *
 */
class ELFObjectWriter : public ObjectWriter
{
public:
  ELFObjectWriter(const GenericELFReaderWriter &pELFWriter);

  ~ELFObjectWriter();

  std::error_code writeObject(Module &pModule, FileOutputBuffer &pOutput);

  size_t getOutputSize(const Module &pModule) const;

private:
  const GenericELFReaderWriter &m_ELFReaderWriter;
};

} // namespace of mcld

#endif

