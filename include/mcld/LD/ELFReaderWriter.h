//===- ELFReaderWriter.h --------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#ifndef MCLD_LD_ELFREADERWRITER_H
#define MCLD_LD_ELFREADERWRITER_H

#include <mcld/LD/ResolveInfo.h>
#include <mcld/LD/LDSymbol.h>
#include <mcld/MC/Input.h>
#include <mcld/Support/MemoryRegion.h>

#include <llvm/ADT/StringRef.h>
#include <llvm/Support/Endian.h>

namespace mcld {

class EhFrame;
class FileOutputBuffer;
class GNULDBackend;
class IRBuilder;
class LDSection;
class Module;
class RelocData;
class SectionData;

class GenericELFReaderWriter {
public:
  virtual ~GenericELFReaderWriter() {}

  GNULDBackend& target() const { return m_Backend; }
  const LinkerConfig &config() const { return m_Config; }

  size_t getHeaderSize() const { return HeaderSize; }
  size_t getProgramHeaderSize() const { return ProgramHeaderSize; }
  size_t getSectionHeaderSize() const { return SectionHeaderSize; }
  size_t getRelaSize() const { return RelaSize; }
  size_t getRelSize() const { return RelSize; }

  size_t sectionStartOffset() const;
  size_t getOutputSize(const Module &pModule) const;

  /// Check this is a ELF file
  virtual bool isELF(const void *pELFHeader) const = 0;

  /// Check the data storage flag matches the expected endianness.
  virtual bool isMyEndian(const void *pELFHeader) const = 0;

  /// Check the machine identifier matches is correct.
  virtual bool isMyMachine(const void *pELFHeader) const = 0;

  /// Retrieve the eobject file type.
  virtual Input::Type fileType(const void *pELFHeader) const = 0;

  /// Read section headers and create the corresponding LDSection objects.
  virtual bool readSectionHeaders(const void *pELFHeader,
                                  Input &pInput) const = 0;

  /// Read the content of regular sections and create the corresponding
  /// Fragment objects.
  bool readRegularSection(Input &pInput, SectionData &pSD) const;

  /// Read ELF symbols and create the corresponding LDSymbol objects.
  virtual bool readSymbols(llvm::StringRef pRegion, const char *pStrTab,
                           Input &pInput, IRBuilder &pBuilder) const = 0;

  /// Read a symbol from the given Input and index in the given symtab section.
  /// This is used to get the signature of a group section.
  virtual ResolveInfo* readSignature(Input &pInput,
                                     LDSection &pSymTab,
                                     uint32_t pSymIdx) const = 0;

  /// Read .dynamic section of a dynamic object.
  virtual bool readDynamic(Input &pInput) const = 0;

  /// Read relocations from a given section.
  bool readRelocation(llvm::StringRef pRegion, Input &pInput,
                      LDSection &pSection) const;

  /// Write the ELF header for a given Module.
  virtual void writeELFHeader(const Module &pModule,
                              FileOutputBuffer &pOutput) const = 0;

  /// Write the ELF section headers for a given Module.
  virtual void writeSectionHeaders(const Module &pModule,
                                   FileOutputBuffer &pOutput) const = 0;

  /// Write the ELF program headers.
  virtual void writeProgramHeaders(FileOutputBuffer &pOutput) const = 0;

  /// Write a symbol table entry for a given LDSymbol.
  virtual void writeSymbol(const LDSymbol &pSym, void *pSymTab, size_t pSymIdx,
                           char *pStrTab, size_t pStrTabOffset) const = 0;

  /// Write .symtab and .strtab sections.
  void writeRegularNamePools(const Module &pModule,
                             FileOutputBuffer &pOutput) const;

  /// Write .dynsym .dynstr .dynamic sections.
  void writeDynamicNamePools(const Module &pModule,
                             FileOutputBuffer &pOutput) const;

  /// Write .interp section.
  void writeInterp(FileOutputBuffer &pOutput) const;

  /// Write .shstrtab section
  void writeShStrTab(const Module &pModule, FileOutputBuffer &pOutput) const;

  /// Write the section content for a given LDSection.
  void writeSection(const Module &pModule, LDSection &pSection,
                    FileOutputBuffer &pOutput) const;

  /// Write .eh_frame section.
  virtual void writeEhFrame(const Module &pModule, const EhFrame &pFrame,
                            MemoryRegion pRegion) const = 0;

  /// Write relocations for a given LDSection.
  void writeRelocation(const LDSection &pSection, MemoryRegion pRegion) const;

  /// Static constructor: it creates an instance of GenericELFReaderWriter
  /// for the given target architecture.
  static GenericELFReaderWriter *create(GNULDBackend &pBackend,
                                        const LinkerConfig &pConfig);

protected:
  struct AliasInfo {
    LDSymbol *PotentialAlias;
    uint64_t RelValue;
    ResolveInfo::Binding Binding;

    AliasInfo(LDSymbol *pSym, uint64_t pRelValue,
              ResolveInfo::Binding pBinding)
     : PotentialAlias(pSym), RelValue(pRelValue), Binding(pBinding) {}

    /// comparison function to sort symbols for analyzing weak alias.
    /// sort symbols by symbol value and then weak before strong.
    /// ref. to gold symtabl.cc 1595
    bool operator<(const AliasInfo &AI) const {
      if (RelValue != AI.RelValue)
        return RelValue < AI.RelValue;

      if (Binding != AI.Binding) {
        if (Binding == ResolveInfo::Weak)
          return true;
        if (AI.Binding == ResolveInfo::Weak)
          return false;
      }

      return PotentialAlias->str() < AI.PotentialAlias->str();
    }
  };

  struct LinkInfo {
    LDSection *Section;
    uint32_t Link;
    uint32_t Info;

    LinkInfo() : Section(nullptr) {}
    LinkInfo(LDSection *pSection, uint32_t pLink, uint32_t pInfo)
     : Section(pSection), Link(pLink), Info(pInfo) {}
  };

  typedef std::vector<LinkInfo> LinkInfoList;

protected:
  GenericELFReaderWriter(GNULDBackend& pBackend,
                         const LinkerConfig &config)
   : m_Backend(pBackend), m_Config(config) {}

protected:
  /// Read 'rela' section related to a given section and create corresponding
  /// Relocation objects.
  virtual bool readRela(llvm::StringRef pRegion, Input &pInput,
                        LDSection &pSection) const = 0;

  /// Read 'rel' section related to a given section and create corresponding
  /// Relocation objects.
  virtual bool readRel(llvm::StringRef pRegion, Input& pInput,
                       LDSection &pSection) const = 0;

  /// Compute the symbol type.
  ResolveInfo::Type getSymbolType(uint8_t pInfo, uint16_t pShndx) const;

  /// Compute the symbol desc.
  ResolveInfo::Desc getSymbolDesc(uint16_t pShndx, const Input &pInput) const;

  /// Compute the symbol binding.
  ResolveInfo::Binding getSymbolBinding(uint8_t pBinding,
                                        uint16_t pShndx,
                                        uint8_t pVisibility) const;

  /// Compute the symbol value.
  uint64_t getSymbolValue(uint64_t pValue,
                          uint16_t pShndx,
                          const Input& pInput) const;

  /// Compute the symbol fragment ref.
  FragmentRef *getSymbolFragmentRef(Input& pInput,
                                    uint16_t pShndx,
                                    uint32_t pOffset) const;

  /// Compute the symbol visibility.
  ResolveInfo::Visibility getSymbolVisibility(uint8_t pVis) const;

protected:
  /// Return the last start offset available.
  uint64_t getLastStartOffset(const Module &pModule) const;

  /// Return the offset of the program headers.
  uint64_t getProgramHeadersOffset() const;

  /// Return the entry point address for the given Module.
  uint64_t getEntryPoint(const Module &pModule) const;

  /// Return the section header table index link for the given LDSection.
  uint64_t getSectionLink(const LDSection &pSection) const;

  /// Return the section extra information for a given LDSection.
  uint64_t getSectionInfo(const LDSection &pSection) const;

  /// Return the ELF output object type value.
  uint16_t getOutputObjectType() const;

  /// Write section data in a given mapped output region.
  void writeSectionData(const SectionData &pSD, MemoryRegion pRegion) const;

  /// Write a 'rela' section.
  virtual void writeRela(const RelocData &pRelocData,
                         MemoryRegion &pRegion) const = 0;

  /// Write a 'rel' section.
  virtual void writeRel(const RelocData &pRelocData,
                        MemoryRegion &pRegion) const = 0;

  uint8_t getSymbolInfoEncoding(const LDSymbol &pSymbol) const;
  uint16_t getSymbolShndxEncoding(const LDSymbol &pSymbol) const;
  uint64_t getSymbolSize(const LDSymbol &pSymbol) const;
  uint64_t getSymbolValue(const LDSymbol &pSymbol) const;

protected:
  GNULDBackend &m_Backend;
  const LinkerConfig &m_Config;

  size_t HeaderSize;
  size_t ProgramHeaderSize;
  size_t SectionHeaderSize;
  size_t RelaSize;
  size_t RelSize;
};

template<size_t BIT, llvm::support::endianness endian>
class ELFReaderWriter : public GenericELFReaderWriter {
public:
  ELFReaderWriter(GNULDBackend &pBackend, const LinkerConfig &pConfig);

  ~ELFReaderWriter();

  bool isELF(const void *pELFHeader) const;

  bool isMyEndian(const void *pELFHeader) const;

  bool isMyMachine(const void *pELFHeader) const;

  Input::Type fileType(const void *pELFHeader) const;

  bool readSectionHeaders(const void *pELFHeader, Input &pInput) const;

  bool readSymbols(llvm::StringRef pRegion, const char *pStrTab,
                   Input &pInput, IRBuilder &pBuilder) const;

  ResolveInfo* readSignature(Input &pInput, LDSection& pSymTab,
                             uint32_t pSymIdx) const;

  bool readRela(llvm::StringRef pRegion, Input& pInput,
                LDSection& pSection) const;

  bool readRel(llvm::StringRef pRegion, Input &pInput,
               LDSection& pSection) const;

  bool readDynamic(Input &pInput) const;

  void writeELFHeader(const Module &pModule, FileOutputBuffer &pOutput) const;

  void writeProgramHeaders(FileOutputBuffer &pOutput) const;

  void writeSectionHeaders(const Module &pModule,
                           FileOutputBuffer &pOutput) const;

  void writeEhFrame(const Module &pModule, const EhFrame &pFrame,
                    MemoryRegion pRegion) const;

  void writeSymbol(const LDSymbol &pSym, void *pSymTab, size_t pSymIdx,
                   char *pStrTab, size_t pStrTabOffset) const;

protected:
  void writeRela(const RelocData &pRelocData, MemoryRegion &pRegion) const;

  void writeRel(const RelocData &pRelocData, MemoryRegion &pRegion) const;

private:
  template<typename T>
  T toNative(T n) const {
    return llvm::support::endian::byte_swap<T, endian>(n);
  }
  uint64_t getSectionEntrySize(const LDSection &pSection) const;
};

#ifdef __GNUC__
__extension__ extern template class ELFReaderWriter<32, llvm::support::big>;
__extension__ extern template class ELFReaderWriter<64, llvm::support::big>;
__extension__ extern template class ELFReaderWriter<32, llvm::support::little>;
__extension__ extern template class ELFReaderWriter<64, llvm::support::little>;
#endif

} // namespace of mcld

#endif

