#include <stdbool.h>

#include "private.h"
#include "json_profiles.h"

typedef enum json_profile_type {
    JPT_INVALID,
    JPT_REKALL_PROFILE,
    JPT_VOLATILITY_IST
} json_profile_type_t;

bool json_profile_init(vmi_instance_t vmi, const char* path)
{
    json_interface_t *json = &vmi->json;

    if ( json->path ) {
        errprint("Duplicate JSON profile detected: %s\n", path);
        return false;
    }

    json->path = g_strdup(path);
    json->root = json_object_from_file(json->path);

    if (!json->root) {
        errprint("JSON at %s couldn't be opened!\n", path);
        g_free((char*)json->path);
        json->path = NULL;
        return false;
    }

    json_object *metadata = NULL;
    json_profile_type_t type = JPT_INVALID;

    if (json_object_object_get_ex(vmi->json.root, "metadata", &metadata))
        type = JPT_VOLATILITY_IST;
    else if (json_object_object_get_ex(vmi->json.root, "$METADATA", &metadata))
        type = JPT_REKALL_PROFILE;

    switch ( type ) {
        case JPT_VOLATILITY_IST:
            json->handler = volatility_ist_symbol_to_rva;
            json->get_os_type = volatility_get_os_type;
            break;
        case JPT_REKALL_PROFILE:
            json->handler = rekall_profile_symbol_to_rva;
            json->get_os_type = rekall_get_os_type;
            break;
        default:
            return false;
    };

    return true;
}
