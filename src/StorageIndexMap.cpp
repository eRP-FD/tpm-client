#include "StorageIndexMap.h"

#include "Exception.h"

#include <algorithm>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const tpmclient::StorageIndexMap& tpmclient::StorageIndexMap::GetInstance()
{
    static const StorageIndexMap instance{};
    return instance;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const tpmclient::StorageIndex& tpmclient::StorageIndexMap::getIndex(StorageIndexKey::PredefinedKeys key) const
{
    const auto findItr = std::find_if(mMap.cbegin(),
                                      mMap.cend(),
                                      [&key](const auto& entry)
                                      {
                                          return entry.first == key;
                                      });

    if (findItr == mMap.cend())
    {
        throw Exception{"Unable to get storage index: key not found"};
    }

    return findItr->second;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const tpmclient::StorageIndex& tpmclient::StorageIndexMap::operator[](StorageIndexKey::PredefinedKeys key) const
{
    return getIndex(key);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

tpmclient::StorageIndexMap::StorageIndexMap()
: mMap{}
{
    auto writeItr = mMap.begin();

    #ifdef HARDWARE_TPM
        insertEntry(writeItr,
                    std::make_pair(StorageIndexKey::PredefinedKeys::EK_CERTIFICATE, StorageIndex{0x01c0000a}));
        insertEntry(writeItr,
                    std::make_pair(StorageIndexKey::PredefinedKeys::EK_NONCE, StorageIndex{0x01c0000b}));
        insertEntry(writeItr,
                    std::make_pair(StorageIndexKey::PredefinedKeys::EK_TEMPLATE, StorageIndex{0x01c0000c}));
    #else
        insertEntry(writeItr,
                    std::make_pair(StorageIndexKey::PredefinedKeys::EK_CERTIFICATE, StorageIndex{0x01c0000a}));
        insertEntry(writeItr,
                    std::make_pair(StorageIndexKey::PredefinedKeys::EK_NONCE, StorageIndex{0x01c0000b}));
        insertEntry(writeItr,
                    std::make_pair(StorageIndexKey::PredefinedKeys::EK_TEMPLATE, StorageIndex{0x01c0000c}));
    #endif
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void tpmclient::StorageIndexMap::insertEntry(Map::iterator& writeItr, Entry entry)
{
    if (writeItr == mMap.end())
    {
        throw Exception{"Unable to insert entry: map storage is full"};
    }

    *writeItr++ = std::move(entry);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
