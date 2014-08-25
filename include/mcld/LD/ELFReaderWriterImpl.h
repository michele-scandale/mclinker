//===- ELFReaderWriterImpl.h ----------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef MCLD_LD_ELFREADERIMPL_H
#define MCLD_LD_ELFREADERIMPL_H

#include <mcld/LD/ELFReaderWriter.h>

#include <mcld/IRBuilder.h>
#include <mcld/Fragment/FillFragment.h>
#include <mcld/LD/EhFrame.h>
#include <mcld/LD/ELFSegment.h>
#include <mcld/LD/ELFSegmentFactory.h>
#include <mcld/LD/LDContext.h>
#include <mcld/LD/RelocData.h>
#include <mcld/LD/SectionData.h>
#include <mcld/LinkerConfig.h>
#include <mcld/Object/ObjectBuilder.h>
#include <mcld/Support/FileOutputBuffer.h>
#include <mcld/Support/MsgHandling.h>
#include <mcld/Support/MemoryArea.h>
#include <mcld/Target/GNULDBackend.h>
#include <mcld/Target/GNUInfo.h>

#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/Twine.h>
#include <llvm/Support/ELF.h>
#include <llvm/Support/Host.h>

#include <cstring>
#include <iostream>

namespace mcld {

template<size_t BIT, llvm::support::endianness endian>
ELFReaderWriter<BIT, endian>::ELFReaderWriter(GNULDBackend &pBackend,
                                              const LinkerConfig &pConfig)
 : GenericELFReaderWriter(pBackend, pConfig) {
  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;
  typedef typename ELFSizeTraits<BIT>::Phdr ElfN_Phdr;
  typedef typename ELFSizeTraits<BIT>::Shdr ElfN_Shdr;
  typedef typename ELFSizeTraits<BIT>::Rela ElfN_Rela;
  typedef typename ELFSizeTraits<BIT>::Rel ElfN_Rel;

  HeaderSize = sizeof(ElfN_Ehdr);
  ProgramHeaderSize = sizeof(ElfN_Phdr);
  SectionHeaderSize = sizeof(ElfN_Shdr);
  RelaSize = sizeof(ElfN_Rela);
  RelSize = sizeof(ElfN_Rel);
}

template<size_t BIT, llvm::support::endianness endian>
ELFReaderWriter<BIT, endian>::~ELFReaderWriter() {}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::isELF(const void *pELFHeader) const {
  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;

  const ElfN_Ehdr *Hdr = reinterpret_cast<const ElfN_Ehdr*>(pELFHeader);
  return memcmp(llvm::ELF::ElfMagic, Hdr->e_ident, 4) == 0;
}

bool GenericELFReaderWriter::readRegularSection(Input &pInput,
                                                SectionData &pSD) const {
  uint32_t Offset = pInput.fileOffset() + pSD.getSection().offset();
  uint32_t Size = pSD.getSection().size();

  Fragment *frag = IRBuilder::CreateRegion(pInput, Offset, Size);
  ObjectBuilder::AppendFragment(*frag, pSD);
  return true;
}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::readSymbols(llvm::StringRef pRegion,
                                               const char *pStrTab,
                                               Input &pInput,
                                               IRBuilder &pBuilder) const {
  typedef typename ELFSizeTraits<BIT>::Sym ElfN_Sym;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename SizeTraits<BIT>::Word Word;

  bool IsDynObj = pInput.type() == Input::DynObj;

  size_t NumEntries = pRegion.size() / sizeof(ElfN_Sym);
  const ElfN_Sym *SymTab = reinterpret_cast<const ElfN_Sym*>(pRegion.begin());

  // Handle explicitly NULL symbol.
  pInput.context()->addSymbol(LDSymbol::Null());

  std::set<AliasInfo> PotentialAliases;
  for (size_t Idx = 1; Idx < NumEntries; ++Idx) {
    uint32_t NameIdx  = toNative<uint32_t>(SymTab[Idx].st_name);
    ElfN_Addr Value = toNative<ElfN_Addr>(SymTab[Idx].st_value);
    Word Size  = toNative<Word>(SymTab[Idx].st_size);
    uint8_t Info  = SymTab[Idx].st_info;
    uint8_t Other = SymTab[Idx].st_other;
    uint16_t ShIdx = toNative<uint16_t>(SymTab[Idx].st_shndx);

    // If the section should not be included, set the st_shndx SHN_UNDEF
    // - A section in interrelated groups are not included.
    if (pInput.type() == Input::Object &&
        ShIdx < llvm::ELF::SHN_LORESERVE &&
        ShIdx != llvm::ELF::SHN_UNDEF &&
        pInput.context()->getSection(ShIdx) == NULL)
      ShIdx = llvm::ELF::SHN_UNDEF;

    ResolveInfo::Type Type = getSymbolType(Info, ShIdx);
    ResolveInfo::Desc Desc = getSymbolDesc(ShIdx, pInput);
    ResolveInfo::Binding Binding = getSymbolBinding((Info >> 4), ShIdx, Other);
    uint64_t RelValue = getSymbolValue(Value, ShIdx, pInput);
    ResolveInfo::Visibility Visibility = getSymbolVisibility(Other);

    LDSection *Section = ShIdx < llvm::ELF::SHN_LORESERVE
                           ? Section = pInput.context()->getSection(ShIdx)
                           : NULL;

    std::string Name = Type == ResolveInfo::Section
                         ? Section->name()
                         : std::string(pStrTab + NameIdx);

    LDSymbol *Sym = pBuilder.AddSymbol(pInput, Name, Type, Desc, Binding, Size,
                                       RelValue, Section, Visibility);

    if (IsDynObj && Sym && Desc != ResolveInfo::Undefined &&
        Type == ResolveInfo::Object &&
        (Binding == ResolveInfo::Global ||
         Binding == ResolveInfo::Weak))
      PotentialAliases.insert(AliasInfo(Sym, RelValue, Binding));
  }

  // analyze weak alias
  // FIXME: it is better to let IRBuilder handle alias anlysis.
  //        1. eliminate code duplication
  //        2. easy to know if a symbol is from .so
  //           (so that it may be a potential alias)
  if (IsDynObj) {
    // for each weak symbol, find out all its aliases, and
    // then link them as a circular list in Module
    for (std::set<AliasInfo>::const_iterator I = PotentialAliases.begin(),
         E = PotentialAliases.end(); I != E;) {
      if (I->Binding != ResolveInfo::Weak) {
        ++I;
        continue;
      }

      Module &Mod = pBuilder.getModule();
      const AliasInfo &FirstWeak = *I++;

      // If we have more than one weak alias, create the alias list.
      if (FirstWeak.RelValue == I->RelValue) {
        Mod.CreateAliasList(*FirstWeak.PotentialAlias->resolveInfo());

        // Add other weak alias to the alias list.
        for (; I != E && FirstWeak.RelValue == I->RelValue; ++I)
          Mod.addAlias(*I->PotentialAlias->resolveInfo());
      }
    }
  }

  return true;
}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::readRela(llvm::StringRef pRegion,
                                            Input &pInput,
                                            LDSection &pSection) const {
  typedef typename ELFSizeTraits<BIT>::Rela ElfN_Rela;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename SizeTraits<BIT>::Word Word;
  typedef typename SizeTraits<BIT>::Word SWord;

  size_t NumEntries = pRegion.size() / sizeof(ElfN_Rela);
  const ElfN_Rela *Relocs = reinterpret_cast<const ElfN_Rela*>(pRegion.begin());

  for (size_t Idx = 0; Idx != NumEntries; ++Idx) {
    ElfN_Addr Offset = toNative<ElfN_Addr>(Relocs[Idx].r_offset);
    Word Info = toNative<Word>(Relocs[Idx].r_info);
    SWord Addend = toNative<SWord>(Relocs[Idx].r_addend);

    Relocation::Type Type;
    uint32_t SymIdx;
    if (!target().decodeRelocationInfo(Info, Type, SymIdx))
      return false;

    LDSymbol *Sym = pInput.context()->getSymbol(SymIdx);
    if (!Sym)
      fatal(diag::err_cannot_read_symbol) << Sym << pInput.path();

    IRBuilder::AddRelocation(pSection, Type, *Sym, Offset, Addend);
  }
  return true;
}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::readRel(llvm::StringRef pRegion,
                                           Input &pInput,
                                           LDSection &pSection) const {
  typedef typename ELFSizeTraits<BIT>::Rel ElfN_Rel;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename SizeTraits<BIT>::Word Word;

  size_t NumEntries = pRegion.size() / sizeof(ElfN_Rel);
  const ElfN_Rel *Relocs = reinterpret_cast<const ElfN_Rel*>(pRegion.begin());

  for (size_t Idx = 0; Idx != NumEntries; ++Idx) {
    ElfN_Addr Offset = toNative<ElfN_Addr>(Relocs[Idx].r_offset);
    Word Info = toNative<Word>(Relocs[Idx].r_info);

    Relocation::Type Type;
    uint32_t SymIdx;
    if (!target().decodeRelocationInfo(Info, Type, SymIdx))
      return false;

    LDSymbol *Sym = pInput.context()->getSymbol(SymIdx);
    if (!Sym)
      fatal(diag::err_cannot_read_symbol) << Sym << pInput.path();

    IRBuilder::AddRelocation(pSection, Type, *Sym, Offset);
  }
  return true;
}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::isMyEndian(const void *pELFHeader) const {
  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;

  const ElfN_Ehdr *Hdr = reinterpret_cast<const ElfN_Ehdr*>(pELFHeader);

  unsigned TargetEndiannes = endian == llvm::support::little
                              ? llvm::ELF::ELFDATA2LSB
                              : llvm::ELF::ELFDATA2MSB;

  return Hdr->e_ident[llvm::ELF::EI_DATA] == TargetEndiannes;
}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::isMyMachine(const void *pELFHeader) const {
  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;

  const ElfN_Ehdr *Hdr = reinterpret_cast<const ElfN_Ehdr*>(pELFHeader);

  return toNative<uint16_t>(Hdr->e_machine) == target().getInfo().machine();
}

template<size_t BIT, llvm::support::endianness endian>
Input::Type ELFReaderWriter<BIT, endian>::
fileType(const void *pELFHeader) const {
  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;

  const ElfN_Ehdr *Hdr = reinterpret_cast<const ElfN_Ehdr*>(pELFHeader);

  switch (toNative<uint16_t>(Hdr->e_type)) {
  case llvm::ELF::ET_REL:
    return Input::Object;
  case llvm::ELF::ET_EXEC:
    return Input::Exec;
  case llvm::ELF::ET_DYN:
    return Input::DynObj;
  case llvm::ELF::ET_CORE:
    return Input::CoreFile;
  case llvm::ELF::ET_NONE:
  default:
    return Input::Unknown;
  }
}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::readSectionHeaders(const void *pELFHeader,
                                                      Input &pInput) const {
  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;
  typedef typename ELFSizeTraits<BIT>::Shdr ElfN_Shdr;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename ELFSizeTraits<BIT>::Off ElfN_Off;
  typedef typename SizeTraits<BIT>::Word Word;

  const ElfN_Ehdr *Ehdr = reinterpret_cast<const ElfN_Ehdr*>(pELFHeader);

  ElfN_Off ShOffset = toNative<ElfN_Off>(Ehdr->e_shoff);
  uint16_t ShEntSize = toNative<uint16_t>(Ehdr->e_shentsize);
  Word ShNum = toNative<uint16_t>(Ehdr->e_shnum);
  uint32_t ShStrIdx = toNative<uint16_t>(Ehdr->e_shstrndx);

  // ShOffset == 0 implies no section header.
  if (ShOffset == 0)
    return true;

  llvm::StringRef Region;
  if (ShNum == llvm::ELF::SHN_UNDEF || ShStrIdx == llvm::ELF::SHN_XINDEX) {
    Region = pInput.memArea()->request(pInput.fileOffset() + ShOffset,
                                       ShEntSize);

    const ElfN_Shdr *Shdr = reinterpret_cast<const ElfN_Shdr*>(Region.begin());

    if (ShNum == llvm::ELF::SHN_UNDEF)
      ShNum = toNative<Word>(Shdr->sh_size);

    if (ShStrIdx == llvm::ELF::SHN_XINDEX)
      ShStrIdx = toNative<uint32_t>(Shdr->sh_link);
 
    // Skip the extra section header.
    ShOffset += ShEntSize;
  }

  Region = pInput.memArea()->request(pInput.fileOffset() + ShOffset,
                                     ShNum * ShEntSize);
  const ElfN_Shdr *ShdrTab = reinterpret_cast<const ElfN_Shdr*>(Region.begin());

  ElfN_Off ShStrTabOffset = toNative<ElfN_Off>(ShdrTab[ShStrIdx].sh_offset);
  Word ShStrTabSize = toNative<ElfN_Off>(ShdrTab[ShStrIdx].sh_size);
  llvm::StringRef SectNameRegion =
    pInput.memArea()->request(pInput.fileOffset() + ShStrTabOffset,
                              ShStrTabSize);
  const char *SectNames = SectNameRegion.begin();
  LinkInfoList Links;

  for (size_t Idx = 0; Idx != ShNum; ++Idx) {
    uint32_t NameIdx = toNative<uint32_t>(ShdrTab[Idx].sh_name);
    uint32_t Type = toNative<uint32_t>(ShdrTab[Idx].sh_type);
    Word Flags = toNative<Word>(ShdrTab[Idx].sh_flags);
    ElfN_Off Offset = toNative<ElfN_Off>(ShdrTab[Idx].sh_offset);
    Word Size = toNative<Word>(ShdrTab[Idx].sh_size);
    uint32_t Link = toNative<uint32_t>(ShdrTab[Idx].sh_link);
    uint32_t Info = toNative<uint32_t>(ShdrTab[Idx].sh_info);
    Word AddrAlign = toNative<Word>(ShdrTab[Idx].sh_addralign);
    Word EntSize = toNative<Word>(ShdrTab[Idx].sh_entsize);

    LDSection *Sect = IRBuilder::CreateELFHeader(pInput, SectNames + NameIdx,
                                                 Type, Flags, AddrAlign);
    Sect->setSize(Size);
    Sect->setOffset(Offset);
    Sect->setInfo(Info);

    if (Link != 0 || Info != 0)
      Links.push_back(LinkInfo(Sect, Link, Info));
  }

  for (LinkInfoList::const_iterator I = Links.begin(),
       E = Links.end(); I != E; ++I) {
    if (I->Section->kind() == LDFileFormat::Relocation)
      I->Section->setLink(pInput.context()->getSection(I->Info));
    else
      I->Section->setLink(pInput.context()->getSection(I->Link));
  }

  return true;
}

template<size_t BIT, llvm::support::endianness endian>
ResolveInfo *ELFReaderWriter<BIT, endian>::
readSignature(Input &pInput, LDSection &pSymTab, uint32_t pSymIdx) const {
  typedef typename ELFSizeTraits<BIT>::Sym ElfN_Sym;
  LDSection *StrTab = pSymTab.getLink();
  assert(StrTab != NULL);

  uint32_t Offset = pInput.fileOffset() + pSymTab.offset() +
                    sizeof(ElfN_Sym) * pSymIdx;

  llvm::StringRef SymsRegion =
    pInput.memArea()->request(Offset, sizeof(ElfN_Sym));
  const ElfN_Sym *Entry = reinterpret_cast<const ElfN_Sym*>(SymsRegion.begin());

  uint32_t NameIdx = toNative<uint32_t>(Entry->st_name);
  uint8_t Info = Entry->st_info;
  uint8_t Other = Entry->st_other;
  uint16_t ShIdx = toNative<uint16_t>(Entry->st_shndx);

  llvm::StringRef StrTabRegion =
    pInput.memArea()->request(pInput.fileOffset() + StrTab->offset(),
                              StrTab->size());

  llvm::StringRef Name(StrTabRegion.begin() + NameIdx);
  ResolveInfo *Result = ResolveInfo::Create(Name);
  Result->setSource(pInput.type() == Input::DynObj);
  Result->setType(static_cast<ResolveInfo::Type>(Info & 0xF));
  Result->setDesc(getSymbolDesc(ShIdx, pInput));
  Result->setBinding(getSymbolBinding((Info >> 4), ShIdx, Other));
  Result->setVisibility(getSymbolVisibility(Other));

  return Result;
}

template<size_t BIT, llvm::support::endianness endian>
bool ELFReaderWriter<BIT, endian>::readDynamic(Input& pInput) const {
  typedef typename ELFSizeTraits<BIT>::Dyn ElfN_Dyn;
  typedef typename ELFSizeTraits<BIT>::Word ElfN_Word;
  typedef typename ELFSizeTraits<BIT>::Sword ElfN_Sword;

  assert(pInput.type() == Input::DynObj);

  const LDSection *DynamicSect = pInput.context()->getSection(".dynamic");
  if (!DynamicSect)
    fatal(diag::err_cannot_read_section) << ".dynamic";

  const LDSection *DynStrSect = DynamicSect->getLink();
  if (!DynStrSect)
    fatal(diag::err_cannot_read_section) << ".dynstr";

  llvm::StringRef DynamicRegion =
    pInput.memArea()->request(pInput.fileOffset() + DynamicSect->offset(),
                              DynamicSect->size());

  llvm::StringRef DynStrRegion =
    pInput.memArea()->request(pInput.fileOffset() + DynStrSect->offset(),
                              DynStrSect->size());

  const ElfN_Dyn *Dynamic =
    reinterpret_cast<const ElfN_Dyn*>(DynamicRegion.begin());
  const char *DynStr = DynStrRegion.begin();
  size_t NumEntries = DynamicSect->size() / sizeof(ElfN_Dyn);

  bool HasSOName = false;
  for (size_t Idx = 0; Idx != NumEntries; ++Idx) {
    ElfN_Sword DTag = toNative<ElfN_Sword>(Dynamic[Idx].d_tag);
    ElfN_Word DVal = toNative<ElfN_Word>(Dynamic[Idx].d_un.d_val);

    switch (DTag) {
    case llvm::ELF::DT_SONAME:
      assert(DVal < DynStrSect->size());
      pInput.setName(sys::fs::Path(DynStr + DVal).filename().native());
      HasSOName = true;
      break;
    case llvm::ELF::DT_NEEDED:
      // TODO: what should be done here?!
      break;
    case llvm::ELF::DT_NULL:
    default:
      break;
    }
  }

  if (!HasSOName)
    pInput.setName(pInput.path().filename().native());

  return true;
}

template<size_t BIT, llvm::support::endianness endian>
void ELFReaderWriter<BIT, endian>::
writeELFHeader(const Module &pModule, FileOutputBuffer &pOutput) const {
  using namespace llvm::ELF;

  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;
  typedef typename ELFSizeTraits<BIT>::Shdr ElfN_Shdr;
  typedef typename ELFSizeTraits<BIT>::Phdr ElfN_Phdr;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename ELFSizeTraits<BIT>::Off ElfN_Off;

  const GNUInfo &Info = target().getInfo();
  const LDSection *ShStrTab = pModule.getSection(".shstrtab");

  // ELF header must start from 0x0
  MemoryRegion Region = pOutput.request(0, sizeof(ElfN_Ehdr));
  ElfN_Ehdr *Hdr = reinterpret_cast<ElfN_Ehdr*>(Region.begin());

  Hdr->e_ident[EI_MAG0] = ElfMagic[0];
  Hdr->e_ident[EI_MAG1] = ElfMagic[1];
  Hdr->e_ident[EI_MAG2] = ElfMagic[2];
  Hdr->e_ident[EI_MAG3] = ElfMagic[3];

  Hdr->e_ident[EI_CLASS] = (BIT == 32) ? ELFCLASS32 : ELFCLASS64;
  Hdr->e_ident[EI_DATA] = endian == llvm::support::little
                           ? ELFDATA2LSB : ELFDATA2MSB;

  Hdr->e_ident[EI_VERSION] = Info.ELFVersion();
  Hdr->e_ident[EI_OSABI] = Info.OSABI();
  Hdr->e_ident[EI_ABIVERSION] = Info.ABIVersion();

  Hdr->e_type = toNative<uint16_t>(getOutputObjectType());
  Hdr->e_machine = toNative<uint16_t>(target().getInfo().machine());
  Hdr->e_version = toNative<uint32_t>(Hdr->e_ident[EI_VERSION]);

  Hdr->e_entry = toNative<ElfN_Addr>(getEntryPoint(pModule));
  Hdr->e_phoff = toNative<ElfN_Off>(getProgramHeadersOffset());
  Hdr->e_shoff = toNative<ElfN_Off>(getLastStartOffset(pModule));

  Hdr->e_flags = toNative<uint32_t>(target().getInfo().flags());
  Hdr->e_ehsize = toNative<uint16_t>(sizeof(ElfN_Ehdr));
  Hdr->e_phentsize = toNative<uint16_t>(sizeof(ElfN_Phdr));
  Hdr->e_phnum = toNative<uint16_t>(target().elfSegmentTable().size());
  Hdr->e_shentsize = toNative<uint16_t>(sizeof(ElfN_Shdr));
  Hdr->e_shnum = toNative<uint16_t>(pModule.size());
  Hdr->e_shstrndx = toNative<uint16_t>(ShStrTab->index());
}

template<size_t BIT, llvm::support::endianness endian>
void ELFReaderWriter<BIT, endian>::
writeProgramHeaders(FileOutputBuffer &pOutput) const {
  typedef typename ELFSizeTraits<BIT>::Ehdr ElfN_Ehdr;
  typedef typename ELFSizeTraits<BIT>::Phdr ElfN_Phdr;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename ELFSizeTraits<BIT>::Off ElfN_Off;
  typedef typename SizeTraits<BIT>::Word Word;

  const ELFSegmentFactory &SegmentTable = target().elfSegmentTable();
  size_t StartOffset = sizeof(ElfN_Ehdr);
  size_t Size = SegmentTable.size() * sizeof(ElfN_Phdr);
  MemoryRegion Region = pOutput.request(StartOffset, Size);

  ElfN_Phdr *Phdr = reinterpret_cast<ElfN_Phdr*>(Region.begin());

  size_t Idx = 0;
  for (ELFSegmentFactory::const_iterator I = SegmentTable.begin(),
       E = SegmentTable.end(); I != E; ++I, ++Idx) {
    const ELFSegment &S = **I;
    Phdr[Idx].p_type = toNative<uint32_t>(S.type());
    Phdr[Idx].p_flags = toNative<uint32_t>(S.flag());
    Phdr[Idx].p_offset = toNative<ElfN_Off>(S.offset());
    Phdr[Idx].p_vaddr = toNative<ElfN_Addr>(S.vaddr());
    Phdr[Idx].p_paddr = toNative<ElfN_Addr>(S.paddr());
    Phdr[Idx].p_filesz = toNative<Word>(S.filesz());
    Phdr[Idx].p_memsz = toNative<Word>(S.memsz());
    Phdr[Idx].p_align = toNative<Word>(S.align());
  }
}

template<size_t BIT, llvm::support::endianness endian>
void ELFReaderWriter<BIT, endian>::
writeSectionHeaders(const Module &pModule, FileOutputBuffer &pOutput) const {
  typedef typename ELFSizeTraits<BIT>::Shdr ElfN_Shdr;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename ELFSizeTraits<BIT>::Off ElfN_Off;
  typedef typename SizeTraits<BIT>::Word Word;

  // emit section header
  unsigned SectNum = pModule.size();
  unsigned HeaderSize = sizeof(ElfN_Shdr) * SectNum;
  size_t StartOffset = getLastStartOffset(pModule);
  MemoryRegion Region = pOutput.request(StartOffset, HeaderSize);
  ElfN_Shdr *Shdr = reinterpret_cast<ElfN_Shdr*>(Region.begin());

  const LDContext::SectionTable &SectTable = pModule.getSectionTable();
  unsigned int ShStrIdx = 0; // NULL section has empty name
  for (unsigned SectIdx = 0; SectIdx < SectNum; ++SectIdx) {
    const LDSection &S = *SectTable.at(SectIdx);
    Shdr[SectIdx].sh_name = toNative<uint32_t>(ShStrIdx);
    Shdr[SectIdx].sh_type = toNative<uint32_t>(S.type());
    Shdr[SectIdx].sh_flags = toNative<Word>(S.flag());
    Shdr[SectIdx].sh_addr = toNative<ElfN_Addr>(S.addr());
    Shdr[SectIdx].sh_offset = toNative<ElfN_Off>(S.offset());
    Shdr[SectIdx].sh_size = toNative<Word>(S.size());
    Shdr[SectIdx].sh_link = toNative<uint32_t>(getSectionLink(S));
    Shdr[SectIdx].sh_info = toNative<uint32_t>(getSectionInfo(S));
    Shdr[SectIdx].sh_addralign = toNative<Word>(S.align());
    Shdr[SectIdx].sh_entsize = toNative<Word>(getSectionEntrySize(S));

    // adjust strshidx
    ShStrIdx += S.name().size() + 1;
  }
}

template<size_t BIT, llvm::support::endianness endian>
void ELFReaderWriter<BIT, endian>::writeRela(const RelocData &pRelocData,
                                             MemoryRegion &pRegion) const {
  typedef typename ELFSizeTraits<BIT>::Rela ElfN_Rela;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename SizeTraits<BIT>::Word Word;
  typedef typename SizeTraits<BIT>::SWord SWord;

  ElfN_Rela *Rela = reinterpret_cast<ElfN_Rela*>(pRegion.begin());

  for (RelocData::const_iterator I = pRelocData.begin(),
       E = pRelocData.end(); I != E; ++I, ++Rela) {
    const FragmentRef &FragRef = I->targetRef();
    uint64_t Offset = FragRef.getOutputOffset();

    if (config().codeGenType() == LinkerConfig::DynObj ||
        config().codeGenType() == LinkerConfig::Exec)
      Offset += FragRef.frag()->getParent()->getSection().addr();

    const ResolveInfo *SymInfo = I->symInfo();
    uint32_t SymIdx = SymInfo ? target().getSymbolIdx(SymInfo->outSymbol())
                              : 0;
    Word RelInfo = 0;
    target().encodeRelocationInfo(I->type(), SymIdx, RelInfo);

    Rela->r_info = toNative<Word>(RelInfo);
    Rela->r_offset = toNative<ElfN_Addr>(Offset);
    Rela->r_addend = toNative<SWord>(I->addend());
  }
}

template<size_t BIT, llvm::support::endianness endian>
void ELFReaderWriter<BIT, endian>::writeRel(const RelocData &pRelocData,
                                             MemoryRegion &pRegion) const {
  typedef typename ELFSizeTraits<BIT>::Rel ElfN_Rel;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename SizeTraits<BIT>::Word Word;

  ElfN_Rel *Rel = reinterpret_cast<ElfN_Rel*>(pRegion.begin());

  for (RelocData::const_iterator I = pRelocData.begin(),
       E = pRelocData.end(); I != E; ++I, ++Rel) {
    const FragmentRef &FragRef = I->targetRef();
    uint64_t Offset = FragRef.getOutputOffset();

    if (config().codeGenType() == LinkerConfig::DynObj ||
        config().codeGenType() == LinkerConfig::Exec)
      Offset += FragRef.frag()->getParent()->getSection().addr();

    const ResolveInfo *SymInfo = I->symInfo();
    uint32_t SymIdx = SymInfo ? target().getSymbolIdx(SymInfo->outSymbol())
                              : 0;
    Word RelInfo = 0;
    target().encodeRelocationInfo(I->type(), SymIdx, RelInfo);

    Rel->r_info = toNative<Word>(RelInfo);
    Rel->r_offset = toNative<ElfN_Addr>(Offset);
  }
}

template<size_t BIT, llvm::support::endianness endian>
void ELFReaderWriter<BIT, endian>::writeEhFrame(const Module &pModule,
                                                const EhFrame &pFrame,
                                                MemoryRegion pRegion) const {
  writeSectionData(*pFrame.getSectionData(), pRegion);

  for (EhFrame::const_cie_iterator I = pFrame.cie_begin(),
       E = pFrame.cie_end(); I != E; ++I) {
    const EhFrame::CIE &CIE = **I;
    for (EhFrame::const_fde_iterator FI = CIE.begin(),
         FE = CIE.end(); FI != FE; ++FI) {
      const EhFrame::FDE &FDE = **FI;

      if (FDE.getRecordType() == EhFrame::RECORD_GENERATED) {
        const LDSection *PLT = pModule.getSection(".plt");
        assert(PLT && "We have no plt but have corresponding eh_frame?");
        size_t RelOffset = FDE.getOffset() + EhFrame::getDataStartOffset<32>();

        uint64_t PLTOffset = PLT->offset();
        uint64_t FDEOffset = pFrame.getSection().offset() + RelOffset;
        int32_t Offset = PLTOffset < FDEOffset ? PLTOffset - FDEOffset
                                               : FDEOffset - PLTOffset;
        uint32_t WrOffset = toNative<uint32_t>(Offset);
        uint32_t WrSize = toNative<uint32_t>(PLT->size());
        memcpy(pRegion.begin() + RelOffset, &WrOffset, 4);
        memcpy(pRegion.begin() + RelOffset + 4, &WrSize, 4);
      }

      uint64_t FDECIEPtrOffset = FDE.getOffset() +
                                 EhFrame::getDataStartOffset<32>() - 4;
      uint64_t CIEStartOffset = CIE.getOffset();

      int32_t Offset = FDECIEPtrOffset < CIEStartOffset
                        ? CIEStartOffset - FDECIEPtrOffset
                        : FDECIEPtrOffset - CIEStartOffset;

      uint32_t WrOffset = toNative<uint32_t>(Offset);
      memcpy(pRegion.begin() + FDECIEPtrOffset, &WrOffset, 4);
    }
  }
}

template<size_t BIT, llvm::support::endianness endian>
uint64_t ELFReaderWriter<BIT, endian>::
getSectionEntrySize(const LDSection &pSection) const {
  typedef typename ELFSizeTraits<BIT>::Word ElfN_Word;
  typedef typename ELFSizeTraits<BIT>::Sym ElfN_Sym;
  typedef typename ELFSizeTraits<BIT>::Rel ElfN_Rel;
  typedef typename ELFSizeTraits<BIT>::Rela ElfN_Rela;
  typedef typename ELFSizeTraits<BIT>::Dyn ElfN_Dyn;

  switch (pSection.type()) {
  case llvm::ELF::SHT_DYNSYM:
  case llvm::ELF::SHT_SYMTAB:
    return sizeof(ElfN_Sym);
  case llvm::ELF::SHT_REL:
    return sizeof(ElfN_Rel);
  case llvm::ELF::SHT_RELA:
    return sizeof(ElfN_Rela);
  case llvm::ELF::SHT_HASH:
  case llvm::ELF::SHT_GNU_HASH:
    return sizeof(ElfN_Word);
  case llvm::ELF::SHT_DYNAMIC:
    return sizeof(ElfN_Dyn);
  default: break;
  }

  // FIXME: We should get the entsize from input since the size of each
  // character is specified in the section header's sh_entsize field.
  // For example, traditional string is 0x1, UCS-2 is 0x2, ... and so on.
  // Ref: http://www.sco.com/developers/gabi/2003-12-17/ch4.sheader.html
  if (pSection.flag() & llvm::ELF::SHF_STRINGS)
    return 0x1;

  return 0x0;
}

template<size_t BIT, llvm::support::endianness endian>
void ELFReaderWriter<BIT, endian>::
writeSymbol(const LDSymbol &pSym, void *pSymTab, size_t pSymIdx,
            char *pStrTab, size_t pStrTabOffset) const {
  typedef typename ELFSizeTraits<BIT>::Sym ElfN_Sym;
  typedef typename ELFSizeTraits<BIT>::Addr ElfN_Addr;
  typedef typename SizeTraits<BIT>::Word Word;

  ElfN_Sym *SymTab = reinterpret_cast<ElfN_Sym*>(pSymTab);

  if (target().hasEntryInStrTab(pSym)) {
    SymTab[pSymIdx].st_name  = toNative<uint32_t>(pStrTabOffset);
    strcpy(pStrTab + pStrTabOffset, pSym.name());
  } else {
    SymTab[pSymIdx].st_name  = 0;
  }
  SymTab[pSymIdx].st_value = toNative<ElfN_Addr>(pSym.value());
  SymTab[pSymIdx].st_size = toNative<Word>(getSymbolSize(pSym));
  SymTab[pSymIdx].st_info = getSymbolInfoEncoding(pSym);
  SymTab[pSymIdx].st_other = pSym.visibility();
  SymTab[pSymIdx].st_shndx = toNative<uint16_t>(getSymbolShndxEncoding(pSym));
}

}
#endif
