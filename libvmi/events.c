/* The LibVMI Library is an introspection library that simplifies access to 
 * memory in a target virtual machine or in a file containing a dump of 
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Nasser Salim (njsalim@sandia.gov)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "libvmi.h"
#include "private.h"
#include "driver/interface.h"

#define _GNU_SOURCE
#include <glib.h>

/* XXX This is likely not be the best data structure arrangement to
   keep track of events and callback registrations.  Namely,

   1. There really can only be 1 event registration per page or register.
      This data structure allows multiple registrations and at the moment,
      a new registration simply stomps on the low level settings.
   2. It is probably better to keep a seperate structure per event type.

   Right now I am just trying to get something out the door.
 
 */

//----------------------------------------------------------------------------
//  General event callback management.

static void event_entry_free (gpointer key)
{
    vmi_event_t * entry = (vmi_event_t*) key;
    if (entry) free(entry);
}

void events_init (vmi_instance_t vmi)
{
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return;
    }

    vmi->event_handlers = g_hash_table_new_full(
            g_int_hash, g_int_equal, event_entry_free, NULL);
}

void event_handler_clear (vmi_instance_t vmi)
{
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return;
    }

    event_iter_t i;
    vmi_event_t *stored_event;
    event_callback_t stored_callback;
    GSList *to_delete = NULL;

    for_each_event(vmi, i, stored_event, stored_callback){
        to_delete=g_slist_append(to_delete, (gpointer)stored_event);
    }

    while(to_delete != NULL) {
        vmi_clear_event(vmi, *(vmi_event_t *)(to_delete->data) );

        GSList *temp = to_delete->next;
        g_slist_free(to_delete);
        to_delete = temp;
    }
}

void events_destroy (vmi_instance_t vmi)
{
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return;
    }

    event_handler_clear(vmi);
    g_hash_table_destroy(vmi->event_handlers);
}

void event_handler_set (vmi_instance_t vmi, vmi_event_t event, event_callback_t cb)
{
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return;
    }

    vmi_event_t * pe = safe_malloc(sizeof(vmi_event_t));
    *pe = event;
    g_hash_table_insert(vmi->event_handlers, pe, cb);
}

status_t event_handler_del (vmi_instance_t vmi, gpointer key)
{
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return VMI_FAILURE;
    }

    if (g_hash_table_remove(vmi->event_handlers, key))
        return VMI_SUCCESS;
    return VMI_FAILURE;
}

//----------------------------------------------------------------------------
// Public event functions.

status_t vmi_handle_event (vmi_instance_t vmi, 
                           vmi_event_t event,
                           event_callback_t callback)
{
    status_t rc = VMI_FAILURE;
    
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return VMI_FAILURE;
    }

    switch(event.type){
        case VMI_REGISTER_EVENT:
            dbprint("Enabling register event on reg: %d\n",
                event.reg_event.reg);
            rc = driver_set_reg_access(vmi, event.reg_event);
            break;
        case VMI_MEMORY_EVENT:
            dbprint("Enabling memory event on pages: %llx + %d\n",
                event.mem_event.page, event.mem_event.npages);
            rc = driver_set_mem_access(vmi, event.mem_event);
            break;
        default:
            errprint("Unknown event type: %d\n", event.type);
    }

    if(rc == VMI_SUCCESS)
        event_handler_set(vmi, event, callback);
    return rc;
}

status_t vmi_clear_event (vmi_instance_t vmi, 
                          vmi_event_t event)
{
    status_t rc = VMI_FAILURE;
    event_iter_t i;
    vmi_event_t *stored_event, *todelete = NULL;
    event_callback_t stored_callback;
    
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return VMI_FAILURE;
    }

    for_each_event(vmi, i, stored_event, stored_callback){
        if(stored_event->type == event.type){
            switch(event.type){
                case VMI_REGISTER_EVENT:
                    if(stored_event->type == VMI_REGISTER_EVENT){
                        if(stored_event->reg_event.reg == event.reg_event.reg){
                            dbprint("Disabling register event on reg: %d\n",
                                    event.reg_event.reg);
                            todelete = stored_event;
                            todelete->reg_event.in_access = VMI_REG_N;
                            rc = driver_set_reg_access(vmi, todelete->reg_event);
                        }
                    }
                    break;
                case VMI_MEMORY_EVENT:
                    if(stored_event->type == VMI_MEMORY_EVENT){
                        if(stored_event->mem_event.page == event.mem_event.page){
                            dbprint("Disabling memory event on page: %llu\n",
                                    event.mem_event.page);
                            todelete = stored_event;
                            todelete->mem_event.in_access = VMI_MEM_N;
                            rc = driver_set_mem_access(vmi, todelete->mem_event);
                        }
                    }
                    break;
                default:
                    errprint("Cannot clear unknown event: %d\n", event.type);
                    return VMI_FAILURE;
            }
        }
    }

    if(!todelete){
        warnprint("Could not find event to delete!\n");
        return VMI_FAILURE;
    }

    if(rc != VMI_SUCCESS){
        errprint("Could not disable event!\n");
        return rc;
    }

    return event_handler_del(vmi, todelete);
}

status_t vmi_events_listen(vmi_instance_t vmi, uint32_t timeout){
    
    if(!(vmi->init_mode & VMI_INIT_EVENTS)){
        return VMI_FAILURE;
    }

    return driver_events_listen(vmi, timeout);
}
