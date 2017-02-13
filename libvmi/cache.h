/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Tamas K Lengyel <tamas.lengyel@zentific.com>
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

#ifndef CACHE_H
#define CACHE_H

#define NOOP

/* Custom 128-bit key functions */
struct key_128 {
    uint64_t low;
    uint64_t high;
};
typedef struct key_128 *key_128_t;

uint64_t hash128to64(uint64_t low, uint64_t high);
guint64 key_128_hash(gconstpointer key);
gboolean key_128_equals(gconstpointer key1, gconstpointer key2);
void key_128_init(vmi_instance_t vmi, key_128_t key, uint64_t low, uint64_t high);
key_128_t key_128_build (vmi_instance_t vmi, uint64_t low, uint64_t high);

#if ENABLE_ADDRESS_CACHE == 1

void pid_cache_init(vmi_instance_t vmi);
void pid_cache_destroy(vmi_instance_t vmi);
void pid_cache_set(vmi_instance_t vmi, vmi_pid_t pid, addr_t dtb);
void pid_cache_flush(vmi_instance_t vmi);
status_t pid_cache_get(vmi_instance_t vmi, vmi_pid_t pid, addr_t *dtb);
status_t pid_cache_del(vmi_instance_t vmi, vmi_pid_t pid);

void sym_cache_init(vmi_instance_t vmi);
void sym_cache_destroy(vmi_instance_t vmi);
void sym_cache_set(vmi_instance_t vmi, addr_t base_addr, vmi_pid_t pid, const char *sym, addr_t va);
void sym_cache_flush(vmi_instance_t vmi);
status_t sym_cache_get(vmi_instance_t vmi, addr_t base_addr, vmi_pid_t pid, const char *sym, addr_t *va);
status_t sym_cache_del(vmi_instance_t vmi, addr_t base_addr, vmi_pid_t pid, char *sym);

void rva_cache_init(vmi_instance_t vmi);
void rva_cache_destroy(vmi_instance_t vmi);
void rva_cache_set(vmi_instance_t vmi, addr_t base_addr, addr_t dtb, addr_t rva, char *sym);
void rva_cache_flush(vmi_instance_t vmi);
status_t rva_cache_get(vmi_instance_t vmi, addr_t base_addr, addr_t dtb, addr_t rva, char **sym);
status_t rva_cache_del(vmi_instance_t vmi, addr_t base_addr, addr_t dtb, addr_t rva);

void v2p_cache_init(vmi_instance_t vmi);
void v2p_cache_destroy(vmi_instance_t vmi);
void v2p_cache_set(vmi_instance_t vmi, addr_t va, addr_t dtb, addr_t pa);
void v2p_cache_flush(vmi_instance_t vmi, addr_t dtb);
status_t v2p_cache_get(vmi_instance_t vmi, addr_t va, addr_t dtb, addr_t *pa);
status_t v2p_cache_del(vmi_instance_t vmi, addr_t va, addr_t dtb);

#else

#define pid_cache_init(...)     NOOP
#define pid_cache_destroy(...)  NOOP
#define pid_cache_set(...)      NOOP
#define pid_cache_flush(...)    NOOP
#define pid_cache_get(...) VMI_FAILURE
#define pid_cache_del(...) VMI_FAILURE

#define sym_cache_init(...)     NOOP
#define sym_cache_destroy(...)  NOOP
#define sym_cache_set(...)      NOOP
#define sym_cache_flush(...)    NOOP
#define sym_cache_get(...) VMI_FAILURE
#define sym_cache_del(...) VMI_FAILURE

#define rva_cache_init(...)     NOOP
#define rva_cache_destroy(...)  NOOP
#define rva_cache_set(...)      NOOP
#define rva_cache_flush(...)    NOOP
#define rva_cache_get(...) VMI_FAILURE
#define rva_cache_del(...) VMI_FAILURE

#define v2p_cache_init(...)     NOOP
#define v2p_cache_destroy(...)  NOOP
#define v2p_cache_set(...)      NOOP
#define v2p_cache_flush(...)    NOOP
#define v2p_cache_get(...) VMI_FAILURE
#define v2p_cache_del(...) VMI_FAILURE

#endif

#if ENABLE_SHM_SNAPSHOT == 1 && ENABLE_ADDRESS_CACHE == 1

void v2m_cache_init(vmi_instance_t vmi);
void v2m_cache_destroy(vmi_instance_t vmi);
void v2m_cache_set(vmi_instance_t vmi, addr_t va, pid_t pid, addr_t ma, uint64_t length);
void v2m_cache_flush(vmi_instance_t vmi);
status_t v2m_cache_get(vmi_instance_t vmi, addr_t va, pid_t pid, addr_t *ma, uint64_t *length);
status_t v2m_cache_del(vmi_instance_t vmi, addr_t va, pid_t pid);

#else

#define v2m_cache_init(...)     NOOP
#define v2m_cache_destroy(...)  NOOP
#define v2m_cache_set(...)      NOOP
#define v2m_cache_flush(...)    NOOP
#define v2m_cache_get(...) VMI_FAILURE
#define v2m_cache_del(...) VMI_FAILURE

#endif

#endif /* CACHE_H */
