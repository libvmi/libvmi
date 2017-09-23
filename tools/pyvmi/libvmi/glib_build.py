#!/usr/bin/env python3


from cffi import FFI
import pkgconfig

cdef = """
typedef int    gint;
typedef gint   gboolean;
typedef void* gpointer;
typedef const void *gconstpointer;
typedef unsigned int    guint;
typedef struct _GHashTable  GHashTable;

typedef guint (*GHashFunc)(gconstpointer key);
typedef gboolean (*GEqualFunc)(gconstpointer a, gconstpointer b);

GHashTable* g_hash_table_new               (GHashFunc       hash_func,
                                            GEqualFunc      key_equal_func);

gboolean    g_hash_table_insert            (GHashTable     *hash_table,
                                            gpointer        key,
                                            gpointer        value);

void        g_hash_table_destroy           (GHashTable     *hash_table);

guint    g_str_hash     (gconstpointer  v);
gboolean g_str_equal    (gconstpointer  v1, gconstpointer  v1);
"""


ffi = FFI()
includes = pkgconfig.cflags('glib-2.0')
if not includes:
    raise RuntimeError('Unable to find pkgconfig for glib-2.0')
includes = includes.replace('-I', '').split(' ')

# set source
ffi.set_source("_glib",
    """
    #include <glib.h>
    """,
    libraries=['glib-2.0'], include_dirs=includes)

ffi.cdef(cdef)

if __name__ == "__main__":
    ffi.compile(verbose=True)
