//===- ELFObjectReader.cpp ------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include <mcld/LD/ELFObjectReader.h>

#include <string>
#include <cassert>

#include <llvm/Support/ELF.h>
#include <llvm/ADT/Twine.h>

#include <mcld/MC/MCLDInput.h>
#include <mcld/Fragment/FragmentLinker.h>
#include <mcld/LD/ELFReader.h>
#include <mcld/LD/EhFrameReader.h>
#include <mcld/LD/EhFrame.h>
#include <mcld/Target/GNULDBackend.h>
#include <mcld/Support/MsgHandling.h>

using namespace mcld;

//===----------------------------------------------------------------------===//
// ELFObjectReader
//===----------------------------------------------------------------------===//
/// constructor
ELFObjectReader::ELFObjectReader(GNULDBackend& pBackend, FragmentLinker& pLinker)
  : ObjectReader(),
    m_pELFReader(NULL),
    m_pEhFrameReader(NULL),
    m_Linker(pLinker),
    m_ReadFlag(ParseEhFrame),
    m_Backend(pBackend) {
  if (32 == pBackend.bitclass() && pBackend.isLittleEndian()) {
    m_pELFReader = new ELFReader<32, true>(pBackend);
  }

  m_pEhFrameReader = new EhFrameReader();
}

/// destructor
ELFObjectReader::~ELFObjectReader()
{
  delete m_pELFReader;
  delete m_pEhFrameReader;
}

/// isMyFormat
bool ELFObjectReader::isMyFormat(Input &pInput) const
{
  assert(pInput.hasMemArea());

  // Don't warning about the frequently requests.
  // MemoryArea has a list of cache to handle this.
  size_t hdr_size = m_pELFReader->getELFHeaderSize();
  MemoryRegion* region = pInput.memArea()->request(pInput.fileOffset(),
                                                     hdr_size);

  uint8_t* ELF_hdr = region->start();
  bool result = true;
  if (!m_pELFReader->isELF(ELF_hdr))
    result = false;
  else if (!m_pELFReader->isMyEndian(ELF_hdr))
    result = false;
  else if (!m_pELFReader->isMyMachine(ELF_hdr))
    result = false;
  else if (Input::Object != m_pELFReader->fileType(ELF_hdr))
    result = false;
  pInput.memArea()->release(region);
  return result;
}

/// readHeader - read section header and create LDSections.
bool ELFObjectReader::readHeader(Input& pInput)
{
  assert(pInput.hasMemArea());

  size_t hdr_size = m_pELFReader->getELFHeaderSize();
  MemoryRegion* region = pInput.memArea()->request(pInput.fileOffset(),
                                                     hdr_size);
  uint8_t* ELF_hdr = region->start();
  bool result = m_pELFReader->readSectionHeaders(pInput, m_Linker, ELF_hdr);
  pInput.memArea()->release(region);
  return result;
}

/// readSections - read all regular sections.
bool ELFObjectReader::readSections(Input& pInput)
{
  // handle sections
  LDContext::sect_iterator section, sectEnd = pInput.context()->sectEnd();
  for (section = pInput.context()->sectBegin(); section != sectEnd; ++section) {
    // ignore the section if the LDSection* in input context is NULL
    if (NULL == *section)
        continue;

    switch((*section)->kind()) {
      /** group sections **/
      case LDFileFormat::Group: {
        assert(NULL != (*section)->getLink());
        ResolveInfo* signature =
              m_pELFReader->readSignature(pInput,
                                          *(*section)->getLink(),
                                          (*section)->getInfo());

        bool exist = false;
        if (0 == signature->nameSize() &&
            ResolveInfo::Section == signature->type()) {
          // if the signature is a section symbol in input object, we use the
          // section name as group signature.
          signatures().insert((*section)->name(), exist);
        } else {
          signatures().insert(signature->name(), exist);
        }

        if (exist) {
          // if this is not the first time we see this group signature, then
          // ignore all the members in this group (set NULL)
          MemoryRegion* region = pInput.memArea()->request(
               pInput.fileOffset() + (*section)->offset(), (*section)->size());
          llvm::ELF::Elf32_Word* value =
                     reinterpret_cast<llvm::ELF::Elf32_Word*>(region->start());

          size_t size = region->size() / sizeof(llvm::ELF::Elf32_Word);
          if (llvm::ELF::GRP_COMDAT == *value) {
            for (size_t index = 1; index < size; ++index) {
              pInput.context()->getSection(value[index])->setKind(LDFileFormat::Ignore);
            }
          }
          pInput.memArea()->release(region);
        }
        break;
      }
      /** relocation sections **/
      case LDFileFormat::Relocation: {
        assert(NULL != (*section)->getLink());
        size_t link_index = (*section)->getLink()->index();
        LDSection* link_sect = pInput.context()->getSection(link_index);
        if (NULL == link_sect || LDFileFormat::Ignore == link_sect->kind()) {
          // Relocation sections of group members should also be part of the
          // group. Thus, if the associated member sections are ignored, the
          // related relocations should be also ignored.
          (*section)->setKind(LDFileFormat::Ignore);
        }
        break;
      }
      /** normal sections **/
      // FIXME: support Version Kinds
      case LDFileFormat::Version:
      /** Fall through **/
      case LDFileFormat::Regular:
      case LDFileFormat::Note:
      case LDFileFormat::MetaData: {
        if (!m_pELFReader->readRegularSection(pInput, m_Linker, **section))
          fatal(diag::err_cannot_read_section) << (*section)->name();
        break;
      }
      case LDFileFormat::Debug: {
        if (m_Linker.getLDInfo().options().stripDebug()) {
          (*section)->setKind(LDFileFormat::Ignore);
        }
        else if (!m_pELFReader->readRegularSection(pInput, m_Linker, **section))
          fatal(diag::err_cannot_read_section) << (*section)->name();
        break;
      }
      case LDFileFormat::EhFrame: {
        if (m_Linker.getLDInfo().options().hasEhFrameHdr() &&
            (m_ReadFlag & ParseEhFrame)) {

          // set up input's section data.
          SectionData* sect_data = m_Backend.getEhFrame()->getSection().getSectionData();

          (*section)->setSectionData(sect_data);
          m_Linker.getLayout().addInputRange(*sect_data, **section);

          // if --eh-frame-hdr option is given, parse .eh_frame.
          if (!m_pEhFrameReader->read<32, true>(pInput,
                                                **section,
                                                *m_Backend.getEhFrame())) {
            // if we failed to parse a .eh_frame, we should not parse the rest
            // .eh_frame.
            m_ReadFlag ^= ParseEhFrame;
          }
        }
        else {
          if (!m_pELFReader->readRegularSection(pInput, m_Linker, **section)) {
            fatal(diag::err_cannot_read_section) << (*section)->name();
          }
        }
        break;
      }
      case LDFileFormat::GCCExceptTable: {
        //if (!m_pELFReader->readExceptionSection(pInput, m_Linker, **section))
        if (!m_pELFReader->readRegularSection(pInput, m_Linker, **section))
          fatal(diag::err_cannot_read_section) << (*section)->name();
        break;
      }
      /** target dependent sections **/
      case LDFileFormat::Target: {
        if (!m_pELFReader->readTargetSection(pInput, m_Linker, **section))
          fatal(diag::err_cannot_read_target_section) << (*section)->name();
        break;
      }
      /** BSS sections **/
      case LDFileFormat::BSS: {
        SectionData& sect_data = m_Linker.CreateInputSectData(**section);
                                            /*  value, valsize, size*/
        FillFragment* frag = new FillFragment(0x0,   1,       (*section)->size());

        uint64_t size = m_Linker.getLayout().appendFragment(*frag,
                                                            sect_data,
                                                            (*section)->align());

        LDSection& output_bss = sect_data.getSection();
        output_bss.setSize(output_bss.size() + size);
        break;
      }
      // ignore
      case LDFileFormat::Null:
      case LDFileFormat::NamePool:
      case LDFileFormat::Ignore:
      case LDFileFormat::StackNote:
        continue;
      // warning
      case LDFileFormat::EhFrameHdr:
      default: {
        warning(diag::warn_illegal_input_section) << (*section)->name()
                                                  << pInput.name()
                                                  << pInput.path();
        break;
      }
    }
  } // end of for all sections

  return true;
}

/// readSymbols - read symbols into FragmentLinker from the input relocatable object.
bool ELFObjectReader::readSymbols(Input& pInput)
{
  assert(pInput.hasMemArea());

  LDSection* symtab_shdr = pInput.context()->getSection(".symtab");
  if (NULL == symtab_shdr) {
    note(diag::note_has_no_symtab) << pInput.name()
                                   << pInput.path()
                                   << ".symtab";
    return true;
  }

  LDSection* strtab_shdr = symtab_shdr->getLink();
  if (NULL == strtab_shdr) {
    fatal(diag::fatal_cannot_read_strtab) << pInput.name()
                                          << pInput.path()
                                          << ".symtab";
    return false;
  }

  MemoryRegion* symtab_region = pInput.memArea()->request(
             pInput.fileOffset() + symtab_shdr->offset(), symtab_shdr->size());
  MemoryRegion* strtab_region = pInput.memArea()->request(
             pInput.fileOffset() + strtab_shdr->offset(), strtab_shdr->size());
  char* strtab = reinterpret_cast<char*>(strtab_region->start());
  bool result = m_pELFReader->readSymbols(pInput,
                                          m_Linker,
                                          *symtab_region,
                                          strtab);
  pInput.memArea()->release(symtab_region);
  pInput.memArea()->release(strtab_region);
  return result;
}

bool ELFObjectReader::readRelocations(Input& pInput)
{
  assert(pInput.hasMemArea());

  MemoryArea* mem = pInput.memArea();
  LDContext::sect_iterator section, sectEnd = pInput.context()->sectEnd();
  for (section = pInput.context()->sectBegin(); section != sectEnd; ++section) {
    // ignore the section if the LDSection* in input context is NULL
    if (NULL == *section)
        continue;

    if ((*section)->type() == llvm::ELF::SHT_RELA &&
        (*section)->kind() == LDFileFormat::Relocation) {
      MemoryRegion* region = mem->request(
               pInput.fileOffset() + (*section)->offset(), (*section)->size());
      bool result = m_pELFReader->readRela(pInput, m_Linker, **section,
                                           *region);
      mem->release(region);
      if (!result)
        return false;
    }
    else if ((*section)->type() == llvm::ELF::SHT_REL &&
             (*section)->kind() == LDFileFormat::Relocation) {
      MemoryRegion* region = mem->request(
               pInput.fileOffset() + (*section)->offset(), (*section)->size());
      bool result = m_pELFReader->readRel(pInput, m_Linker, **section, *region);
      mem->release(region);
      if (!result)
        return false;
    }
  }
  return true;
}

