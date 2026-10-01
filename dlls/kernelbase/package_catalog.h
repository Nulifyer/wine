/* Private catalog snapshots. Strings and entries are owned until free.
 * This research reader uses the selected native StateRepository cache.
 * It does not deploy packages or infer identity from executable paths. */
#ifndef __WINE_PACKAGE_CATALOG_H
#define __WINE_PACKAGE_CATALOG_H

struct package_catalog_entry
{
    struct package_catalog_entry *next;
    WCHAR *full_name, *family_name, *path, *publisher;
    UINT64 type;
};

HRESULT package_catalog_family(const WCHAR *family_name, struct package_catalog_entry **result);
void package_catalog_free(struct package_catalog_entry *entry);

#endif
