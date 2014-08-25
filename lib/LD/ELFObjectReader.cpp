//===- ELFObjectReader.cpp ------------------------------------------------===//
//
//                     The MCLinker Project
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include <mcld/LD/ELFObjectReader.h>

#include <mcld/IRBuilder.h>
#include <mcld/MC/Input.h>
#include <mcld/LD/EhFrame.h>
#include <mcld/LD/EhFrameReader.h>
#include <mcld/LD/ELFReaderWriter.h>
#include <mcld/LD/LDContext.h>
#include <mcld/LinkerConfig.h>
#include <mcld/Target/GNULDBackend.h>
#include <mcld/Support/MsgHandling.h>
#include <mcld/Support/MemoryArea.h>
#include <mcld/Object/ObjectBuilder.h>

#include <llvm/Support/ELF.h>
#include <llvm/ADT/Twine.h>
#include <llvm/ADT/StringRef.h>

#include <string>
#include <cassert>

using namespace mcld;

//===----------------------------------------------------------------------===//
// ELFObjectReader
//===----------------------------------------------------------------------===//
/// constructor
ELFObjectReader::ELFObjectReader(const GenericELFReaderWriter &pELFReaderWriter,
                                 const LinkerConfig &pConfig,
                                 IRBuilder& pBuilder)
 : ObjectReader(),
   m_ELFReaderWriter(pELFReaderWriter),
   m_pEhFrameReader(new EhFrameReader()),
   m_Builder(pBuilder),
   m_ReadFlag(ParseEhFrame),
   m_Config(pConfig) {}

/// destructor
ELFObjectReader::~ELFObjectReader() {
  delete m_pEhFrameReader;
}

/// isMyFormat
bool ELFObjectReader::isMyFormat(Input &pInput, bool &pContinue) const {
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

  if (m_ELFReaderWriter.fileType(ELF_hdr) != Input::Object)
    return false;

  pContinue = false;
  if (!m_ELFReaderWriter.isMyEndian(ELF_hdr))
    return false;

  if (!m_ELFReaderWriter.isMyMachine(ELF_hdr))
    return false;

  return true;
}

/// readHeader - read section header and create LDSections.
bool ELFObjectReader::readHeader(Input& pInput)
{
  assert(pInput.hasMemArea());

  size_t hdr_size = m_ELFReaderWriter.getHeaderSize();
  if (pInput.memArea()->size() < hdr_size)
    return false;

  llvm::StringRef region = pInput.memArea()->request(pInput.fileOffset(),
                                                     hdr_size);
  const char* ELF_hdr = region.begin();
  return m_ELFReaderWriter.readSectionHeaders(ELF_hdr, pInput);
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
            m_ELFReaderWriter.readSignature(pInput,
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
          // ignore all the members in this group (set Ignore)
          llvm::StringRef region = pInput.memArea()->request(
               pInput.fileOffset() + (*section)->offset(), (*section)->size());
          const llvm::ELF::Elf32_Word* value =
              reinterpret_cast<const llvm::ELF::Elf32_Word*>(region.begin());

          size_t size = region.size() / sizeof(llvm::ELF::Elf32_Word);
          if (llvm::ELF::GRP_COMDAT == *value) {
            for (size_t index = 1; index < size; ++index) {
              pInput.context()->getSection(value[index])->setKind(LDFileFormat::Ignore);
            }
          }
        }
        ResolveInfo::Destroy(signature);
        break;
      }
      /** linkonce sections **/
      case LDFileFormat::LinkOnce: {
        bool exist = false;
        // .gnu.linkonce + "." + type + "." + name
        llvm::StringRef name(llvm::StringRef((*section)->name()).drop_front(14));
        signatures().insert(name.split(".").second, exist);
        if (!exist) {
          if (name.startswith("wi")) {
            (*section)->setKind(LDFileFormat::Debug);
            if (m_Config.options().stripDebug())
              (*section)->setKind(LDFileFormat::Ignore);
            else {
              SectionData* sd = IRBuilder::CreateSectionData(**section);
              if (!m_ELFReaderWriter.readRegularSection(pInput, *sd))
                fatal(diag::err_cannot_read_section) << (*section)->name();
            }
          } else {
            if (((*section)->flag() & llvm::ELF::SHF_EXECINSTR) != 0)
              (*section)->setKind(LDFileFormat::TEXT);
            else
              (*section)->setKind(LDFileFormat::DATA);
            SectionData* sd = IRBuilder::CreateSectionData(**section);
            if (!m_ELFReaderWriter.readRegularSection(pInput, *sd))
              fatal(diag::err_cannot_read_section) << (*section)->name();
          }
        } else {
          (*section)->setKind(LDFileFormat::Ignore);
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
      // FIXME: support Version Kind
      case LDFileFormat::Version:
      // FIXME: support GCCExceptTable Kind
      case LDFileFormat::GCCExceptTable:
      /** Fall through **/
      case LDFileFormat::TEXT:
      case LDFileFormat::DATA:
      case LDFileFormat::Note:
      case LDFileFormat::MetaData: {
        SectionData* sd = IRBuilder::CreateSectionData(**section);
        if (!m_ELFReaderWriter.readRegularSection(pInput, *sd))
          fatal(diag::err_cannot_read_section) << (*section)->name();
        break;
      }
      case LDFileFormat::Debug: {
        if (m_Config.options().stripDebug()) {
          (*section)->setKind(LDFileFormat::Ignore);
        }
        else {
          SectionData* sd = IRBuilder::CreateSectionData(**section);
          if (!m_ELFReaderWriter.readRegularSection(pInput, *sd)) {
            fatal(diag::err_cannot_read_section) << (*section)->name();
          }
        }
        break;
      }
      case LDFileFormat::EhFrame: {
        EhFrame* eh_frame = IRBuilder::CreateEhFrame(**section);

        // We don't really parse EhFrame if this is a partial linking
        if ((m_Config.codeGenType() != LinkerConfig::Object) &&
            (m_ReadFlag & ParseEhFrame)) {
          if (!m_pEhFrameReader->read<32, true>(pInput, *eh_frame)) {
            // if we failed to parse a .eh_frame, we should not parse the rest
            // .eh_frame.
            m_ReadFlag ^= ParseEhFrame;
          }
        }
        else {
          if (!m_ELFReaderWriter.readRegularSection(pInput,
                                                *eh_frame->getSectionData())) {
            fatal(diag::err_cannot_read_section) << (*section)->name();
          }
        }
        break;
      }
      /** target dependent sections **/
      case LDFileFormat::Target: {
        SectionData* sd = IRBuilder::CreateSectionData(**section);
        if (!m_ELFReaderWriter.target().readSection(pInput, *sd)) {
          fatal(diag::err_cannot_read_target_section) << (*section)->name();
        }
        break;
      }
      /** BSS sections **/
      case LDFileFormat::BSS: {
        IRBuilder::CreateBSS(**section);
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

/// readSymbols - read symbols from the input relocatable object.
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

  llvm::StringRef symtab_region = pInput.memArea()->request(
      pInput.fileOffset() + symtab_shdr->offset(), symtab_shdr->size());
  llvm::StringRef strtab_region = pInput.memArea()->request(
      pInput.fileOffset() + strtab_shdr->offset(), strtab_shdr->size());
  const char* strtab = strtab_region.begin();
  bool result = m_ELFReaderWriter.readSymbols(symtab_region, strtab,
                                              pInput, m_Builder);
  return result;
}

bool ELFObjectReader::readRelocations(Input& pInput)
{
  assert(pInput.hasMemArea());

  MemoryArea* mem = pInput.memArea();
  LDContext::sect_iterator rs, rsEnd = pInput.context()->relocSectEnd();
  for (rs = pInput.context()->relocSectBegin(); rs != rsEnd; ++rs) {
    if (LDFileFormat::Ignore == (*rs)->kind())
      continue;

    uint32_t offset = pInput.fileOffset() + (*rs)->offset();
    uint32_t size = (*rs)->size();
    llvm::StringRef region = mem->request(offset, size);
    IRBuilder::CreateRelocData(**rs); ///< create relocation data for the header

    if (!m_ELFReaderWriter.readRelocation(region, pInput, **rs))
      return false;

  } // end of for all relocation data

  return true;
}

