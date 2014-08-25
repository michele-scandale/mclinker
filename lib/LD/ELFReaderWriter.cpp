//===- ELFReaderWriter.cpp ------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <mcld/LD/ELFReaderWriterImpl.h>

#include <mcld/Fragment/AlignFragment.h>
#include <mcld/Fragment/FillFragment.h>
#include <mcld/Fragment/RegionFragment.h>
#include <mcld/Fragment/Stub.h>
#include <mcld/LD/ELFFileFormat.h>
#include <mcld/LinkerScript.h>
#include <mcld/Target/ELFDynamic.h>

using namespace mcld;

template class mcld::ELFReaderWriter<32, llvm::support::big>;
template class mcld::ELFReaderWriter<64, llvm::support::big>;
template class mcld::ELFReaderWriter<32, llvm::support::little>;
template class mcld::ELFReaderWriter<64, llvm::support::little>;

size_t GenericELFReaderWriter::sectionStartOffset() const {
  if (config().codeGenType() == LinkerConfig::Binary)
    return 0;

  return HeaderSize + target().elfSegmentTable().size() * ProgramHeaderSize;
}

uint64_t GenericELFReaderWriter::
getLastStartOffset(const Module &pModule) const {
  const LDSection *S = pModule.back();
  assert(S);
  size_t BitSize = config().targets().bitclass();
  assert((BitSize & (BitSize-1)) == 0);
  return (S->offset() + S->size() + BitSize - 1) & -BitSize;
}

uint64_t GenericELFReaderWriter::getProgramHeadersOffset() const {
  if (config().codeGenType() != LinkerConfig::Object)
    return HeaderSize;

  return 0;
}

size_t GenericELFReaderWriter::getOutputSize(const Module &pModule) const {
  return getLastStartOffset(pModule) + pModule.size() * SectionHeaderSize;
}

ResolveInfo::Type GenericELFReaderWriter::
getSymbolType(uint8_t pInfo, uint16_t pShndx) const {
  ResolveInfo::Type result = static_cast<ResolveInfo::Type>(pInfo & 0xF);
  if (llvm::ELF::SHN_ABS == pShndx && ResolveInfo::Section == result) {
    // In Mips, __gp_disp is a special section symbol. Its name comes from
    // .strtab, not .shstrtab. However, it is unique. Only it is also a ABS
    // symbol. So here is a tricky to identify __gp_disp and convert it to
    // Object symbol.
    return ResolveInfo::Object;
  }

  return result;
}

ResolveInfo::Desc GenericELFReaderWriter::
getSymbolDesc(uint16_t pShndx, const Input& pInput) const {
  if (pShndx == llvm::ELF::SHN_UNDEF)
    return ResolveInfo::Undefined;

  if (pShndx < llvm::ELF::SHN_LORESERVE) {
    // an ELF symbol defined in a section which we are not including
    // must be treated as an Undefined.
    // @ref Google gold linker: symtab.cc: 1086
    if (NULL == pInput.context()->getSection(pShndx) ||
        LDFileFormat::Ignore == pInput.context()->getSection(pShndx)->kind())
      return ResolveInfo::Undefined;
    return ResolveInfo::Define;
  }

  if (pShndx == llvm::ELF::SHN_ABS)
    return ResolveInfo::Define;

  if (pShndx == llvm::ELF::SHN_COMMON)
    return ResolveInfo::Common;

  if (pShndx >= llvm::ELF::SHN_LOPROC &&
      pShndx <= llvm::ELF::SHN_HIPROC)
    return target().getSymDesc(pShndx);

  // FIXME: ELF weak alias should be ResolveInfo::Indirect
  return ResolveInfo::NoneDesc;
}

ResolveInfo::Binding GenericELFReaderWriter::
getSymbolBinding(uint8_t pBinding, uint16_t pShndx, uint8_t pVis) const {

  // TODO:
  // if --just-symbols option is enabled, the symbol must covert to Absolute

  switch(pBinding) {
  case llvm::ELF::STB_LOCAL:
    return ResolveInfo::Local;
  case llvm::ELF::STB_GLOBAL:
    if (pShndx == llvm::ELF::SHN_ABS)
      return ResolveInfo::Absolute;
    return ResolveInfo::Global;
  case llvm::ELF::STB_WEAK:
    return ResolveInfo::Weak;
  }

  return ResolveInfo::NoneBinding;
}

FragmentRef *GenericELFReaderWriter::
getSymbolFragmentRef(Input& pInput, uint16_t pShndx, uint32_t pOffset) const {

  if (Input::DynObj == pInput.type())
    return FragmentRef::Null();

  if (pShndx == llvm::ELF::SHN_UNDEF)
    return FragmentRef::Null();

  if (pShndx >= llvm::ELF::SHN_LORESERVE) // including ABS and COMMON
    return FragmentRef::Null();

  LDSection* sect_hdr = pInput.context()->getSection(pShndx);

  if (NULL == sect_hdr)
    unreachable(diag::unreachable_invalid_section_idx) << pShndx
                                                       << pInput.path().native();

  if (LDFileFormat::Ignore == sect_hdr->kind())
    return FragmentRef::Null();

  if (LDFileFormat::Group == sect_hdr->kind())
    return FragmentRef::Null();

  return FragmentRef::Create(*sect_hdr, pOffset);
}

ResolveInfo::Visibility
GenericELFReaderWriter::getSymbolVisibility(uint8_t pVis) const {
  return static_cast<ResolveInfo::Visibility>(pVis);
}

uint64_t GenericELFReaderWriter::
getSymbolValue(uint64_t pValue, uint16_t pShndx, const Input& pInput) const {
  if (Input::Object == pInput.type()) {
    // In relocatable files, st_value holds alignment constraints for a symbol
    // whose section index is SHN_COMMON
    if (pShndx == llvm::ELF::SHN_COMMON || pShndx == llvm::ELF::SHN_ABS) {
      return pValue;
    }

    // In relocatable files, st_value holds a section offset for a defined symbol.
    // TODO:
    // if --just-symbols option are enabled, convert the value from section offset
    // to virtual address by adding input section's virtual address.
    // The section's virtual address in relocatable files is normally zero, but
    // people can use link script to change it.
    return pValue;
  }

  // In executable and shared object files, st_value holds a virtual address.
  // the virtual address is needed for alias identification.
  return pValue;
}

uint64_t GenericELFReaderWriter::getEntryPoint(const Module &pModule) const {
  llvm::StringRef Name = target().getEntry(pModule);

  bool IssueWarning = (pModule.getScript().hasEntry() &&
                       LinkerConfig::Object != config().codeGenType() &&
                       LinkerConfig::DynObj != config().codeGenType());

  const LDSymbol *Sym = pModule.getNamePool().findSymbol(Name);

  if (!Sym) {
    char *End;
    uint64_t Value = strtoull(Name.data(), &End, 0);
    if (*End != '\0' && IssueWarning)
      llvm::errs() << "cannot find entry symbol '" << Name << "'.\n";

    return *End != '\0' ? 0 : Value;
  }

  if (Sym->desc() != ResolveInfo::Define && IssueWarning) {
    llvm::errs() << "WARNNG: entry symbol '" << Sym->name()
                 << "' exists but is not defined.\n";
  }

  return Sym->value();
}

uint64_t GenericELFReaderWriter::
getSectionLink(const LDSection &pSection) const {
  const ELFFileFormat &Fmt = *target().getOutputFormat();
  switch (pSection.type()) {
  case llvm::ELF::SHT_SYMTAB:
    return Fmt.getStrTab().index();
  case llvm::ELF::SHT_DYNSYM:
    return Fmt.getDynStrTab().index();
  case llvm::ELF::SHT_DYNAMIC:
    return Fmt.getDynStrTab().index();
  case llvm::ELF::SHT_HASH:
  case llvm::ELF::SHT_GNU_HASH:
    return Fmt.getDynSymTab().index();
  case llvm::ELF::SHT_REL:
  case llvm::ELF::SHT_RELA:
    if (LinkerConfig::Object == config().codeGenType())
      return Fmt.getSymTab().index();

    return Fmt.getDynSymTab().index();
  case llvm::ELF::SHT_ARM_EXIDX:
    // FIXME: currently we link ARM_EXIDX section to output text section here
    return Fmt.getText().index();
  default:
    return llvm::ELF::SHN_UNDEF;
  }
}

uint64_t GenericELFReaderWriter::
getSectionInfo(const LDSection &pSection) const {
  switch (pSection.type()) {
  case llvm::ELF::SHT_SYMTAB:
  case llvm::ELF::SHT_DYNSYM:
    return pSection.getInfo();
  case llvm::ELF::SHT_REL:
  case llvm::ELF::SHT_RELA:
    if (const LDSection *InfoLink = pSection.getLink())
      return InfoLink->index();
    return 0;
  default: return 0;
  }
}

uint16_t GenericELFReaderWriter::getOutputObjectType() const {
  switch (config().codeGenType()) {
  case LinkerConfig::Object:
    return llvm::ELF::ET_REL;
  case LinkerConfig::DynObj:
    return llvm::ELF::ET_DYN;
  case LinkerConfig::Exec:
    return llvm::ELF::ET_EXEC;
  default:
    llvm::errs() << "unsupported output file type: "
                 << config().codeGenType() << ".\n";
    return llvm::ELF::ET_NONE;
  }
}

void GenericELFReaderWriter::
writeRegularNamePools(const Module &pModule, FileOutputBuffer &pOutput) const {
  ELFFileFormat *Fmt = target().getOutputFormat();

  if (!Fmt->hasSymTab())
    return;

  const LDSection &SymTab = Fmt->getSymTab();
  const LDSection &StrTab = Fmt->getStrTab();

  MemoryRegion SymTabRegion = pOutput.request(SymTab.offset(), SymTab.size());
  MemoryRegion StrTabRegion = pOutput.request(StrTab.offset(), StrTab.size());

  void *SymTabEntry = SymTabRegion.begin();
  char *StrTabEntry = reinterpret_cast<char*>(StrTabRegion.begin());

  const LDSymbol *NullSym = LDSymbol::Null();
  writeSymbol(*NullSym, SymTabEntry, 0, StrTabEntry, 0);
  target().mapSymbol(NullSym, 0);

  size_t SymIdx = 1;
  size_t StrTabSize = 1;

  const Module::SymbolTable &Symbols = pModule.getSymbolTable();
  for (Module::const_sym_iterator I = Symbols.begin(),
       E = Symbols.end(); I != E; ++I) {
    const LDSymbol &Sym = **I;
    target().mapSymbol(&Sym, SymIdx);
    writeSymbol(Sym, SymTabEntry, SymIdx, StrTabEntry, StrTabSize);

    ++SymIdx;
    if (target().hasEntryInStrTab(Sym))
      StrTabSize += Sym.nameSize() + 1;
  }
}

void GenericELFReaderWriter::
writeDynamicNamePools(const Module &pModule, FileOutputBuffer &pOutput) const {
  ELFFileFormat *Fmt = target().getOutputFormat();

  if (!Fmt->hasDynSymTab() ||
      !Fmt->hasDynStrTab() ||
      !Fmt->hasDynamic())
    return;

  const LDSection &DynSymTab = Fmt->getDynSymTab();
  const LDSection &DynStrTab = Fmt->getDynStrTab();
  const LDSection &Dynamic = Fmt->getDynamic();

  MemoryRegion DynSymTabRegion = pOutput.request(DynSymTab.offset(),
                                                 DynSymTab.size());
  MemoryRegion DynStrTabRegion = pOutput.request(DynStrTab.offset(),
                                                 DynStrTab.size());
  MemoryRegion DynamicRegion = pOutput.request(Dynamic.offset(),
                                               Dynamic.size());

  void *DynSymTabEntry = DynSymTabRegion.begin();
  char *DynStrTabEntry = reinterpret_cast<char*>(DynStrTabRegion.begin());

  writeSymbol(*LDSymbol::Null(), DynSymTabEntry, 0, DynStrTabEntry, 0);

  const Module::SymbolTable &Symbols = pModule.getSymbolTable();

  // emit .gnu.hash
  if (GeneralOptions::GNU  == config().options().getHashStyle() ||
      GeneralOptions::Both == config().options().getHashStyle())
    // FIXME: should it be target independent?
    target().emitGNUHashTab(const_cast<Module::SymbolTable&>(Symbols), pOutput);

  // emit .hash
  if (GeneralOptions::SystemV == config().options().getHashStyle() ||
      GeneralOptions::Both == config().options().getHashStyle())
    // FIXME: should it be target independent?
    target().emitELFHashTab(const_cast<Module::SymbolTable&>(Symbols), pOutput);

  size_t SymIdx = 1;
  size_t StrTabSize = 1;

  for (Module::const_sym_iterator I = Symbols.localDynBegin(),
       E = Symbols.dynamicEnd(); I != E; ++I) {
    const LDSymbol &Sym = **I;
    target().mapDynamicSymbol(&Sym, SymIdx);
    writeSymbol(Sym, DynSymTabEntry, SymIdx, DynStrTabEntry, StrTabSize);

    ++SymIdx;
    if (target().hasEntryInStrTab(Sym))
      StrTabSize += Sym.nameSize() + 1;
  }

  ELFDynamic::iterator dt_need = target().dynamic().needBegin();
  for (Module::const_lib_iterator I = pModule.lib_begin(),
       E = pModule.lib_end(); I != E; ++I) {
    const Input *CurLib = *I;
    if (!CurLib->attribute()->isAsNeeded() || CurLib->isNeeded()) {
      elf_dynamic::EntryIF *DynEntry = *dt_need++;
      strcpy(DynStrTabEntry + StrTabSize, CurLib->name().c_str());
      DynEntry->setValue(llvm::ELF::DT_NEEDED, StrTabSize);
      StrTabSize += CurLib->name().size() + 1;
    }
  }

  const GeneralOptions &Opts = config().options();
  if (!Opts.getRpathList().empty()) {
    elf_dynamic::EntryIF *DynEntry = *dt_need++;
    uint64_t DTag = Opts.hasNewDTags() ? llvm::ELF::DT_RUNPATH
                                       : llvm::ELF::DT_RPATH;
    DynEntry->setValue(DTag, StrTabSize);

    for (GeneralOptions::const_rpath_iterator I = Opts.rpath_begin(),
         E = Opts.rpath_end(); I != E; ++I) {
      memcpy(DynStrTabEntry + StrTabSize, I->data(), I->size());
      StrTabSize += I->size();
      DynStrTabEntry[StrTabSize++] = (std::next(I) == E ? '\0' : ':');
    }
  }

  // Emit .dynamic section
  if (config().codeGenType() == LinkerConfig::DynObj) {
    target().dynamic().applySoname(StrTabSize);
    strcpy(DynStrTabEntry + StrTabSize, Opts.soname().c_str());
    StrTabSize += Opts.soname().size() + 1;
  }

  target().dynamic().applyEntries(*Fmt);
  target().dynamic().emit(Dynamic, DynamicRegion);
}

void GenericELFReaderWriter::writeInterp(FileOutputBuffer &pOutput) const {
  if (!target().getOutputFormat()->hasInterp())
    return;

  const LDSection &Interp = target().getOutputFormat()->getInterp();
  MemoryRegion InterpRegion = pOutput.request(Interp.offset(), Interp.size());

  const GeneralOptions &Opts = config().options();
  const char *DyldName = Opts.hasDyld() ? Opts.dyld().c_str()
                                        : target().getInfo().dyld();
  memcpy(InterpRegion.begin(), DyldName, Interp.size());
}

void GenericELFReaderWriter::
writeShStrTab(const Module &pModule, FileOutputBuffer &pOutput)  const {

  const LDSection &ShStrTab = target().getOutputFormat()->getShStrTab();
  MemoryRegion ShStrTabRegion = pOutput.request(ShStrTab.offset(),
                                                ShStrTab.size());

  char *ShStrTabEntry = reinterpret_cast<char*>(ShStrTabRegion.begin());
  size_t ShStrSize = 0;
  for (Module::const_iterator I = pModule.begin(),
       E = pModule.end(); I != E; ++I) {
    const LDSection &S = **I;
    strcpy(ShStrTabEntry + ShStrSize, S.name().data());
    ShStrSize += S.name().size() + 1;
  }
}

static MemoryRegion getMemoryRegionForSection(const LDSection &pSection,
                                              FileOutputBuffer &pOutput) {
  switch (pSection.kind()) {
  case LDFileFormat::Note:
    if (!pSection.getSectionData())
      return MemoryRegion();
    // fallthrough
  case LDFileFormat::TEXT:
  case LDFileFormat::DATA:
  case LDFileFormat::Relocation:
  case LDFileFormat::Target:
  case LDFileFormat::Debug:
  case LDFileFormat::GCCExceptTable:
  case LDFileFormat::EhFrame:
    if (pSection.size())
      return pOutput.request(pSection.offset(), pSection.size());
    return MemoryRegion();
  default:
    llvm::errs() << "WARNING: unsupported section kind: "
                 << pSection.kind()
                 << " of section "
                 << pSection.name()
                 << ".\n";
    // fallthrough
  case LDFileFormat::Null:
  case LDFileFormat::NamePool:
  case LDFileFormat::BSS:
  case LDFileFormat::MetaData:
  case LDFileFormat::Version:
  case LDFileFormat::EhFrameHdr:
  case LDFileFormat::StackNote:
    // Ignore these sections
    return MemoryRegion();
  }
}

void GenericELFReaderWriter::writeSection(const Module &pModule,
                                          LDSection &pSection,
                                          FileOutputBuffer &pOutput) const {
  MemoryRegion Region = getMemoryRegionForSection(pSection, pOutput);
  if (!Region.data()) 
    return;

  switch (pSection.kind()) {
  case LDFileFormat::GCCExceptTable:
  case LDFileFormat::TEXT:
  case LDFileFormat::DATA:
  case LDFileFormat::Debug:
  case LDFileFormat::Note:
    assert(pSection.hasSectionData());
    writeSectionData(*pSection.getSectionData(), Region);
    break;
  case LDFileFormat::EhFrame:
    writeEhFrame(pModule, *pSection.getEhFrame(), Region);
    break;
  case LDFileFormat::Relocation:
    // sort relocation for the benefit of the dynamic linker.
    target().sortRelocation(pSection);
    writeRelocation(pSection, Region);
    break;
  case LDFileFormat::Target:
    target().emitSectionData(pSection, Region);
    break;
  default:
    llvm_unreachable("invalid section kind");
  }
}

void GenericELFReaderWriter::writeSectionData(const SectionData &pSD,
                                              MemoryRegion pRegion) const {
  char *Base = reinterpret_cast<char*>(pRegion.begin());
  size_t Offset = 0;
  for (SectionData::const_iterator I = pSD.begin(),
       E = pSD.end(); I != E; ++I) {
    size_t Size = I->size();

    switch (I->getKind()) {
    case Fragment::Region: {
      const RegionFragment &RF = llvm::cast<RegionFragment>(*I);
      memcpy(Base + Offset, RF.getRegion().begin(), Size);
      break;
    }
    case Fragment::Alignment: {
      const AlignFragment &AF = llvm::cast<AlignFragment>(*I);
      uint64_t Count = Size / AF.getValueSize();
      switch (AF.getValueSize()) {
      case 1:
        std::memset(Base + Offset, AF.getValue(), Count);
        break;
      default:
        llvm::report_fatal_error("unsupported value size for align fragment "
                                 "emission yet.\n");
        break;
      }
      break;
    }
    case Fragment::Fillment: {
      const FillFragment &FF = llvm::cast<FillFragment>(*I);
      if (Size != 0 && FF.getValueSize() != 0 && FF.size() != 0) {
        size_t NumTiles = FF.size() / FF.getValueSize();
        for (size_t i = 0; i != NumTiles; ++i)
          memset(Base + Offset, FF.getValue(), FF.getValueSize());
      }
      break;
    }
    case Fragment::Stub: {
      const Stub &SF = llvm::cast<Stub>(*I);
      memcpy(Base + Offset, SF.getContent(), Size);
      break;
    }
    case Fragment::Null:
      assert(Size == 0);
      break;
    case Fragment::Target:
      llvm::report_fatal_error("target fragment should not be "
                               "in regular section.\n");
      break;
    default:
      llvm::report_fatal_error("invalid fragment should not be "
                               "in regular section.\n");
      break;
    }

    Offset += Size;
  }
}

bool GenericELFReaderWriter::readRelocation(llvm::StringRef pRegion,
                                            Input &pInput,
                                            LDSection &pSection) const {
  switch (pSection.type()) {
  case llvm::ELF::SHT_RELA:
    return readRela(pRegion, pInput, pSection);
  case llvm::ELF::SHT_REL:
    return readRel(pRegion, pInput, pSection);
  default:
    return false;
  }
}

void GenericELFReaderWriter::writeRelocation(const LDSection &pSection,
                                             MemoryRegion pRegion) const {
  const RelocData &Data = *pSection.getRelocData();

  switch (pSection.type()) {
  case llvm::ELF::SHT_REL:
    writeRel(Data, pRegion);
    break;
  case llvm::ELF::SHT_RELA:
    writeRela(Data, pRegion);
    break;
  default:
    llvm::report_fatal_error("unsupported relocation section type!");
  }
}

uint64_t GenericELFReaderWriter::getSymbolSize(const LDSymbol& pSymbol) const {
  // @ref Google gold linker: symtab.cc: 2780
  // undefined and dynamic symbols should have zero size.
  if (pSymbol.isDyn() || pSymbol.desc() == ResolveInfo::Undefined)
    return 0;

  return pSymbol.resolveInfo()->size();
}

static uint8_t getSymbolBindEncoding(const LDSymbol &pSymbol,
                                     const LinkerConfig &pConfig) {
  uint8_t Visibility = pSymbol.visibility();
  if (pConfig.codeGenType() != LinkerConfig::Object &&
      (Visibility == llvm::ELF::STV_INTERNAL ||
       Visibility == llvm::ELF::STV_HIDDEN))
    return llvm::ELF::STB_LOCAL;

  const ResolveInfo &RI = *pSymbol.resolveInfo();

  if (RI.isLocal())
    return llvm::ELF::STB_LOCAL;

  if (RI.isGlobal())
    return llvm::ELF::STB_GLOBAL;

  if (RI.isWeak())
    return llvm::ELF::STB_WEAK;

  if (RI.isAbsolute())
    // (Luba) Is a absolute but not global (weak or local) symbol meaningful?
    return llvm::ELF::STB_GLOBAL;

  return 0;
}

uint8_t
GenericELFReaderWriter::getSymbolInfoEncoding(const LDSymbol &pSymbol) const {
  uint8_t bind = getSymbolBindEncoding(pSymbol, config());
  uint8_t type = pSymbol.resolveInfo()->type();
  // if the IndirectFunc symbol (i.e., STT_GNU_IFUNC) is from dynobj, change
  // its type to Function
  if (type == ResolveInfo::IndirectFunc && pSymbol.isDyn())
    type = ResolveInfo::Function;
  return (type | (bind << 4));
}

uint64_t
GenericELFReaderWriter::getSymbolValue(const LDSymbol& pSymbol) const {
  return pSymbol.isDyn() ? 0 : pSymbol.value();
}

uint16_t
GenericELFReaderWriter::getSymbolShndxEncoding(const LDSymbol& pSymbol) const {
  const ResolveInfo &RI = *pSymbol.resolveInfo();

  if (RI.isAbsolute())
    return llvm::ELF::SHN_ABS;
  if (RI.isCommon())
    return llvm::ELF::SHN_COMMON;
  if (RI.isUndef() || pSymbol.isDyn())
    return llvm::ELF::SHN_UNDEF;

  if (pSymbol.resolveInfo()->isDefine() && !pSymbol.hasFragRef())
    return llvm::ELF::SHN_ABS;

  assert(pSymbol.hasFragRef() &&
         "symbols must have fragment reference to get its index");
  return pSymbol.fragRef()->frag()->getParent()->getSection().index();
}

GenericELFReaderWriter *
GenericELFReaderWriter::create(GNULDBackend &pBackend,
                               const LinkerConfig &pConfig) {
  if (pConfig.targets().is32Bits()) {
    if (pConfig.targets().isLittleEndian())
      return new ELFReaderWriter<32, llvm::support::little>(pBackend, pConfig);

    if (pConfig.targets().isBigEndian())
      return new ELFReaderWriter<32, llvm::support::big>(pBackend, pConfig);

    llvm_unreachable("unsupported endinanness!");
  }
  if (pConfig.targets().is64Bits()) {
    if (pConfig.targets().isLittleEndian())
      return new ELFReaderWriter<64, llvm::support::little>(pBackend, pConfig);

    if (pConfig.targets().isBigEndian())
      return new ELFReaderWriter<64, llvm::support::big>(pBackend, pConfig);

    llvm_unreachable("unsupported endinanness!");
  }
  llvm_unreachable("unsupported bitclass architecture!");
}
