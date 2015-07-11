/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
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

/**
 * @file events.h
 * @brief The LibVMI VM Event API is defined here.
 *
 * More detailed description can go here.
 */
#ifndef LIBVMI_EVENTS_H
#define LIBVMI_EVENTS_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

#include <stdbool.h>

/*---------------------------------------------------------
 * Event management
 */

/**
 * The types of events that can be requested of hypervisors with requisite
 *  features.
 */
typedef enum {
    VMI_EVENT_INVALID,
    VMI_EVENT_MEMORY,       /**< Read/write/execute on a region of memory */
    VMI_EVENT_REGISTER,     /**< Read/write of a specific register */
    VMI_EVENT_SINGLESTEP,   /**< Instructions being executed on a set of VCPUs */
    VMI_EVENT_INTERRUPT,    /**< Interrupts being delivered */

    __VMI_EVENT_MAX
} vmi_event_type_t;

/**
 * Max number of vcpus we can set single step on at one time for a domain
 */
#define MAX_SINGLESTEP_VCPUS 32

/**
 * Register operations used both for configuring type of register operations to
 *  monitor and also to determine the type of access causing an event to be
 *  recorded.
 */
typedef enum {
    VMI_REGACCESS_INVALID = 0,
    VMI_REGACCESS_N = (1 << 0),
    VMI_REGACCESS_R = (1 << 1),
    VMI_REGACCESS_W = (1 << 2),
    VMI_REGACCESS_RW = (VMI_REGACCESS_R | VMI_REGACCESS_W),

    __VMI_REGACCESS_MAX
} vmi_reg_access_t;

/**
 * Page permissions used both for configuring type of memory operations to
 *  monitor and also to determine the type of access causing an event to be
 *  recorded.
 */
typedef enum {
    VMI_MEMACCESS_INVALID    = 0,
    VMI_MEMACCESS_N          = (1 << 0),
    VMI_MEMACCESS_R          = (1 << 1),
    VMI_MEMACCESS_W          = (1 << 2),
    VMI_MEMACCESS_X          = (1 << 3),
    VMI_MEMACCESS_RW         = (VMI_MEMACCESS_R | VMI_MEMACCESS_W),
    VMI_MEMACCESS_RX         = (VMI_MEMACCESS_R | VMI_MEMACCESS_X),
    VMI_MEMACCESS_WX         = (VMI_MEMACCESS_W | VMI_MEMACCESS_X),
    VMI_MEMACCESS_RWX        = (VMI_MEMACCESS_R | VMI_MEMACCESS_W | VMI_MEMACCESS_X),

    // Special cases
    VMI_MEMACCESS_W2X        = (1 << 4),
    VMI_MEMACCESS_RWX2N      = (1 << 5),

    __VMI_MEMACCESS_MAX
} vmi_mem_access_t;

/**
 * The level of granularity used in the configuration of a memory event.
 *  VMI_MEMEVENT_PAGE granularity delivers an event for any operation
 *   matching the access permission on the relevant page.
 *  VMI_MEMEVENT_BYTE granularity is more specific, deliving an event
 *   if an operation occurs involving the specific byte within a page
 */
typedef enum {
    VMI_MEMEVENT_INVALID,
    VMI_MEMEVENT_BYTE,
    VMI_MEMEVENT_PAGE,

    __VMI_MEMEVENT_MAX
} vmi_memevent_granularity_t;

typedef struct x86_regs {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t dr7;
    uint64_t rip;
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t msr_efer;
    uint64_t msr_star;
    uint64_t msr_lstar;
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t cs_arbytes;
    uint32_t _pad;
} x86_registers_t;

typedef struct {
    /**
     * Register for which write event is configured.
     * Hypervisors offering register events tend to
     *  have a limited number available for monitoring.
     * These registers tend to be those defined as
     * 'sensitive register instructions' by Popek and
     *  Goldberg, meaning that the registers trigger
     *  a VMEXIT, trap, or equivalent.
     */
    registers_t reg;

    /**
     * Reserved
     */
    reg_t mask;

    /**
     * Event filter: callback triggers IFF register==<equal>
     */
    reg_t equal;

    /**
     * IFF set to 1, events are delivered asynchronously and
     *  without pausing the originating VCPU
     * Default : 0. (i.e., VCPU is paused at time of event delivery).
     */
    bool async;

    /**
     * IFF set to 1, events are only delivered if the written
     *  value differs from the previously held value.
     * Default : 0. (i.e., All write events are delivered).
     */
    bool onchange;

    /**
     * IFF set to 1, an extended set of MSR events are going to be delivered
     * Only available on Xen with 4.5 and onwards
     */
    bool extended_msr;

    /**
     * Type of register event being monitored.
     * Hypervisors offering register events do so only for those that trigger a
     *  VMEXIT or similar trap. This predominantly means that only write events
     *  are supported by the corresponding LibVMI driver
     */
    vmi_reg_access_t in_access;

    /**
     * MSR register operations only: holds the specific MSR for which the event occurred.
     * Unused for other register event types.
     */
    reg_t context;

    /**
     * Register value read or written
     */
    reg_t value;

    /**
     * Previous value of register (only for CR0/CR3/CR4)
     */
    reg_t previous;

    /**
     * Type of register access that triggered the event
     */
    vmi_reg_access_t out_access;
} reg_event_t;

typedef struct {
    /**
     * IN: Specify if using VMI_MEMEVENT_BYTE/PAGE
     */
    vmi_memevent_granularity_t granularity;

    /**
     * IN: Physical address to set event on.
     * With granularity of
     *  VMI_MEMEVENT_PAGE, this can any
     *  byte on the target page.
     */
    addr_t physical_address;

    /**
     * Reserved.
     */
    uint64_t npages;

    /**
     * IN: Page permissions used to trigger memory events. See enum definition
     * for valid values.
     */
    vmi_mem_access_t in_access;

    /**
     * OUT: Specific virtual address at which event occurred.
     */
    addr_t gla;

    /**
     * OUT: Page number at which event occurred
     */
    addr_t gfn;

    /**
     * OUT: Offset in bytes (relative to page base) at which the event occurred
     */
    uint64_t offset;

    /**
     * OUT: Type of page access that caused event to be triggered.
     * Typically a subset of in_access
     */
    vmi_mem_access_t out_access;
} mem_access_event_t;

typedef enum {
    INT_INVALID,
    INT3                /**< Software breakpoint (INT3/0xCC) */
} interrupts_t;

typedef struct {
    addr_t gla;         /**< (Global Linear Address) == RIP of the trapped instruction */
    addr_t gfn;         /**< (Guest Frame Number) == 'physical' page where trap occurred */
    addr_t offset;      /**< Offset in bytes (relative to GFN) */
    interrupts_t intr;  /**< Specific interrupt intended to trigger the event */

    /**
     * Toggle, controls whether interrupt is re-injected after callback.
     *   Set reinject to 1 to deliver it to guest ("pass through" mode)
     *   Set reinject to 0 to swallow it silently without
     */
    int reinject;
} interrupt_event_t;

typedef struct {
    addr_t gla;         /**< The IP of the current instruction */
    addr_t gfn;         /**< The physical page of the current instruction */
    addr_t offset;      /**< Offset in bytes (relative to GFN) */
    uint32_t vcpus;     /**< A bitfield corresponding to VCPU IDs. */
    bool enable;        /**< Set to true to immediately turn vCPU to singlestep. */
} single_step_event_t;

struct vmi_event;
typedef struct vmi_event vmi_event_t;

/**
 * Callbacks can flip the corresponding bits on event_response_t to trigger
 * the following behaviors.
 */
typedef enum {
    VMI_EVENT_RESPONSE_NONE,
    VMI_EVENT_RESPONSE_EMULATE,
    VMI_EVENT_RESPONSE_EMULATE_NOWRITE,
    VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP,
    __VMI_EVENT_RESPONSE_MAX
} event_response_flags_t;

/**
 * Bitmap holding event_reponse_flags_t values returned by callback
 */
typedef uint32_t event_response_t;

/**
 * Event callback function prototype, taking two parameters:
 * The vmi_instance_t passed by the library itself, and the vmi_event_t
 *   object provided by the library user.
 */
typedef event_response_t (*event_callback_t)(vmi_instance_t vmi, vmi_event_t *event);

/**
 * The event structure used during configuration of events and their delivery.
 */
struct vmi_event {
    vmi_event_type_t type;  /**< The specific type of event */

    /**
     *  The specific event type structure (per event type above)
     *  "IN" members of the *_event_t are set by the library user during event
     *      registration to configure LibVMI and the hypervisor.
     *  "OUT" members are set by LibVMI upon observation of an event with
     *      contextual information helpful to the callback.
     */
    union {
        reg_event_t reg_event;
        mem_access_event_t mem_event;
        single_step_event_t ss_event;
        interrupt_event_t interrupt_event;
    };

    uint32_t vcpu_id; /**< The VCPU relative to which the event occurred. */

   /**
    * An open-ended mechanism allowing a library user to
    *  associate external data to the event.
    * Metadata assigned to this pointer at any time (prior to
    *  or following registration) is delivered to the callback,
    *  for each matching event. The callback is also free to
    *  modify in any way. The library user assumes all memory
    *  management for this referenced data.
    */
    void * data;

  /**
   * The callback function that is invoked when the relevant is observed.
   */
    event_callback_t callback;

    /**
     * Snapshot of some VCPU registers when the event occurred
     */
    union {
        x86_registers_t *x86;
    } regs;
};

/**
 * Enables the correct bit for the given vcpu number x
 */
#define SET_VCPU_SINGLESTEP(ss_event, x) \
        do { (ss_event).vcpus |= (1 << x); } while (0)

/**
 * Disables the correct bit for a given vcpu number x
 */
#define UNSET_VCPU_SINGLESTEP(ss_event, x) \
        do { (ss_event).vcpus &= ~(1 << x); } while (0)

/**
 * Check to see if a vcpu number has single step enabled
 */
#define CHECK_VCPU_SINGLESTEP(ss_event, x) \
        (((ss_event).vcpus) & (1 << x))

/**
 * Convenience macro to setup a singlestep event
 */
#define SETUP_SINGLESTEP_EVENT(_event, _vcpu_mask, _callback, _enable) \
        do { \
            (_event)->type = VMI_EVENT_SINGLESTEP; \
            (_event)->ss_event.vcpus = _vcpu_mask; \
            (_event)->ss_event.enable = _enable; \
            (_event)->callback = _callback; \
        } while(0)

/**
 * Convenience macro to setup a memory event
 */
#define SETUP_MEM_EVENT(_event, _addr, _granularity, _access, _callback) \
        do { \
            (_event)->type = VMI_EVENT_MEMORY; \
            (_event)->mem_event.physical_address = _addr; \
            (_event)->mem_event.granularity = _granularity; \
            (_event)->mem_event.in_access = _access; \
            (_event)->mem_event.npages = 1; \
            (_event)->callback = _callback; \
        } while(0)

/**
 * Convenience macro to setup a register event
 */
#define SETUP_REG_EVENT(_event, _reg, _access, _equal, _callback) \
        do { \
            (_event)->type = VMI_EVENT_REGISTER; \
            (_event)->reg_event.reg = _reg; \
            (_event)->reg_event.in_access = _access; \
            (_event)->reg_event.equal = _equal; \
            (_event)->callback = _callback; \
        } while(0)

/**
 * Convenience macro to setup a interrupt event
 */
#define SETUP_INTERRUPT_EVENT(_event, _reinject, _callback) \
        do { \
            (_event)->type = VMI_EVENT_INTERRUPT; \
            (_event)->interrupt_event.reinject = _reinject; \
            (_event)->callback = _callback; \
        } while(0)

/**
 * Register to handle the event specified by the vmi_event object.
 *
 * Callback receives one event as input.
 * Callback is invoked while within the event listener loop, so
 *  actions taken by the callback must take into account that other
 *  events may have been delivered and not yet processed. This is
 *  especially important when events have been configured in an
 *  asyncronous manner (i.e., events delivered are not necessarily
 *  in lockstep with the VM state).
 *
 * Memory management of the vmi_event_t being registered remains the
 *  responsibility of the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] event Definition of event to monitor
 * @param[in] callback Function to call when the event occurs
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_register_event(
    vmi_instance_t vmi,
    vmi_event_t *event);

/**
 * Clear the event specified by the vmi_event_t object.
 *
 * For memory events, this operation resets page permissions so that
 *  execution relative to related page or pages can continue without
 *  further interaction.
 * For register and single-step events, this action disables monitoring
 *  of the given event type via the hypervisor driver.
 * In all cases, the event is removed from hashtables internal to LibVMI,
 *  but the memory related to the vmi_event_t is not freed. Memory management
 *  remains the responsibility of the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] event Definition of event to clear
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_clear_event(
    vmi_instance_t vmi,
    vmi_event_t *event);

/**
 * Return the pointer to the vmi_event_t if one is set on the given register.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] reg Register to check
 * @return vmi_event_t* or NULL if none found
 */
vmi_event_t *vmi_get_reg_event(
    vmi_instance_t vmi,
    registers_t reg);

/**
 * Return the pointer to the vmi_event_t if one is set on the given page.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] physical_address Physical address of byte/page to check
 * @param[in] granularity VMI_MEMEVENT_BYTE or VMI_MEMEVENT_PAGE
 * @return vmi_event_t* or NULL if none found
 */
vmi_event_t *vmi_get_mem_event(
    vmi_instance_t vmi,
    addr_t physical_address,
    vmi_memevent_granularity_t granularity);

/**
 * Setup single-stepping to register the given event
 * after the specified number of steps.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] event The event to register
 * @param[in] vcpu_id The vCPU ID to step the event on.
 * @param[in] steps The number of steps to take before registering the event
 * @param[in] cb Optional: A callback function to call after the specified number of steps.
 *                         If no callback is provided, the event will be re-registered
                           automatically. If a callback is provided, event re-registration
                           is not automatic, but can be done in the callback.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_step_event(
    vmi_instance_t vmi,
    vmi_event_t *event,
    uint32_t vcpu_id,
    uint64_t steps,
    event_callback_t cb);

/**
 * Listen for events until one occurs or a timeout.
 * If the timeout is given as 0, it will process leftover events
 * in the ring-buffer (if there are any).
 *
 * @param[in] vmi LibVMI instance
 * @param[in] timeout Number of ms.
 * @return VMI_FAILURE or VMI_SUCCESS (timeout w/ 0 events returns VMI_SUCCESS)
 */
status_t vmi_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout);

/**
 * Set wether to pause the domain if the event listener is no longer present.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] required Set to 0 if not required, 1 if required.
 * @return VMI_FAILURE or VMI_SUCCESS
 */
status_t vmi_event_listener_required(
    vmi_instance_t vmi,
    int required);

/**
 * Check if there are events pending to be processed.
 *
 * @param[in] vmi LibVMI instance
 * @return The number of pending events, or 0 if there are non, -1 on error.
 */
int vmi_are_events_pending(
    vmi_instance_t vmi);

/**
 * Return the pointer to the vmi_event_t if one is set on the given vcpu.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] vcpu the vcpu to check
 * @return VMI_SUCCESS or VMI_FAILURE
 */
vmi_event_t *vmi_get_singlestep_event (vmi_instance_t vmi,
    uint32_t vcpu);

/**
 * Disables the MTF single step flag from a vcpu as well as the
 * libvmi event object's bitfield position.
 * This does not disable single step for the whole domain.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] event the event to disable the vcpu on
 * @param[in] vcpu the vcpu to stop single stepping on
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_stop_single_step_vcpu(
    vmi_instance_t vmi,
    vmi_event_t* event,
    uint32_t vcpu);

/**
 * Cleans up any domain wide single step settings.
 * This should be called when the caller is completely
 * finished with single step, as it implicitly disables
 * single-step on all VM VCPUs.
 *
 * @param[in] vmi LibVMI instance
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_shutdown_single_step(
    vmi_instance_t);

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif /* LIBVMI_EVENTS_H */
