#ifndef TPM_CLIENT_STORAGEINDEXMAP_H
#define TPM_CLIENT_STORAGEINDEXMAP_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "StorageIndex.h"
#include "StorageIndexKey.h"

#include <array>
#include <utility>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace tpmclient
{

/**
 * TODO TSB
 */
class StorageIndexMap
{
public:
    StorageIndexMap(const StorageIndexMap&) = delete;
    StorageIndexMap(StorageIndexMap&&) = delete;
    StorageIndexMap& operator=(const StorageIndexMap&) = delete;
    StorageIndexMap& operator=(StorageIndexMap&&) = delete;

    /**
     * TODO TSB
     */
    static const StorageIndexMap& GetInstance();

    /**
     * TODO TSB
     */
    const StorageIndex& getIndex(StorageIndexKey::PredefinedKeys key) const;

    /**
     * TODO TSB
     */
    const StorageIndex& operator[](StorageIndexKey::PredefinedKeys key) const;

private:
    using Entry = std::pair<StorageIndexKey::PredefinedKeys, StorageIndex>;
    using Map = std::array<Entry, StorageIndexKey::PredefinedKeysCount>;

    Map mMap;

    StorageIndexMap();

    void insertEntry(Map::iterator& writeItr, Entry entry);
};

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
