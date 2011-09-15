/*****************************************************************************
 *   The MCLinker Project, Copyright (C), 2011 -                             *
 *   Embedded and Web Computing Lab, National Taiwan University              *
 *   MediaTek, Inc.                                                          *
 *                                                                           *
 *   Luba Tang <lubatang@mediatek.com>                                       *
 ****************************************************************************/
#include <mcld/Support/MemoryRegion.h>

using namespace mcld;

//==========================
// MemoryRegion
MemoryRegion::MemoryRegion(MemoryArea::Space& pParent, 
                           const Address pVMAStart,
                           size_t pSize)
  : m_Parent(pParent), m_VMAStart(pVMAStart), m_Length(pSize) {
}

MemoryRegion::~MemoryRegion()
{
  --m_Parent.region_counter;
}

