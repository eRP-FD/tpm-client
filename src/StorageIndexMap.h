/*
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
 * Singleton that acts as a means of converting from a storage key to a storage index.
 */
class StorageIndexMap
{
public:
    StorageIndexMap(const StorageIndexMap&) = delete;
    StorageIndexMap(StorageIndexMap&&) = delete;
    StorageIndexMap& operator=(const StorageIndexMap&) = delete;
    StorageIndexMap& operator=(StorageIndexMap&&) = delete;

    /**
     * Returns the singleton instance.
     */
    static const StorageIndexMap& GetInstance();

    /**
     * Retrieves the storage index for the given storage key. Throws if there is no index at given key.
     */
    const StorageIndex& getIndex(StorageIndexKey::PredefinedKeys key) const;

    /**
     * Retrieves the storage index for the given storage key. Throws if there is no index at given key.
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
