/*****************************************************************************
 *   The MCLinker Project, Copyright (C), 2011 -                             *
 *   Embedded and Web Computing Lab, National Taiwan University              *
 *   MediaTek, Inc.                                                          *
 *                                                                           *
 *   Luba Tang <lubatang@mediatek.com>                                       *
 ****************************************************************************/
#include <mcld/Support/MemoryArea.h>
#include <mcld/Support/MemoryRegion.h>
#include <mcld/Support/FileSystem.h>
#include <llvm/Support/ErrorHandling.h>
#include <fcntl.h>
#include <cerrno>
#include <sstream>

using namespace mcld;

//===--------------------------------------------------------------------===//
// MemoryArea
MemoryArea::MemoryArea(const sys::fs::Path& pPath)
  : m_FilePath(pPath), m_FileDescriptor(-1) {
}

MemoryArea::~MemoryArea()
{
  if (isGood())
    close();
}

void MemoryArea::open(const sys::fs::Path& pPath, int pFlags)
{
  m_FileDescriptor = ::open(pPath.c_str(), pFlags);
}

void MemoryArea::open(const sys::fs::Path& pPath, int pFlags, int pMode)
{
  m_FileDescriptor = ::open(pPath.c_str(), pFlags, pMode);
}

void MemoryArea::close()
{
  ::close(m_FileDescriptor);
  m_FileDescriptor = -1;  
}

bool MemoryArea::isGood() const
{
  return (-1 == m_FileDescriptor);
}

MemoryRegion* MemoryArea::request(off_t pOffset, size_t pLength)
{
  Space* space = find(pOffset, pLength);
  MemoryArea::Address vma_start = 0;
  if (0 == space) { // not found
    space = new Space();
    m_SpaceList.push_back(space);
    switch(space->type = policy(pOffset, pLength)) {
      case Space::MMAPED: {
        // FIXME: implement memory mapped I/O 
        // compute correct vma_start
        break;
      }
      case Space::ALLOCATED_ARRAY: {
        space->file_offset = pOffset;
        space->size = pLength;
        space->data = new unsigned char[pLength];
        size_t read_bytes = sys::fs::detail::pread(m_FileDescriptor,
                                          space->data,
                                          space->size,
                                          space->file_offset);
        if (read_bytes == pLength) {
          vma_start = space->data;
          break;
        }
        else {
          std::stringstream error_mesg;
          error_mesg << m_FilePath.native();
          if (read_bytes < 0) {
            error_mesg << ":pread failed: ";
            error_mesg << sys::fs::detail::strerror(errno) << '\n';
          }
          else if (read_bytes < pLength) {
            error_mesg << ": file too short: read only ";
            error_mesg << read_bytes << " of " << space->size << " bytes at ";
            error_mesg << space->file_offset << std::endl;
          }
          else {
            error_mesg << ": implementation of detail::pread reads exceeding bytes.\n";
            error_mesg << "pread( " << m_FilePath.native() << ", buf, "
                       << space->size << ", " << space->file_offset << '\n';
          }
          llvm::report_fatal_error(error_mesg.str());
        }
      } // case
    } // switch
  }

  // now, we have a legal space to hold the new MemoryRegion
  MemoryRegion* result = new MemoryRegion(*space, vma_start, pLength);
  ++space->region_counter;
  return result;
}

void MemoryArea::release(MemoryRegion* pRegion)
{
}

void MemoryArea::clean()
{
}

MemoryArea::Space* MemoryArea::find(off_t pOffset, size_t pLength)
{
}

void MemoryArea::release(MemoryArea::Space* pSpace)
{
}

MemoryArea::Space::Type MemoryArea::policy(off_t pOffset, size_t pLength)
{
  // FIXME: implement memory mapped I/O
  return Space::ALLOCATED_ARRAY;
}

