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

#define VMI_EVENTS_VERSION 0x00000005

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
typedef uint16_t vmi_event_type_t;

#define VMI_EVENT_INVALID           0
#define VMI_EVENT_MEMORY            1   /**< Read/write/execute on a region of memory */
#define VMI_EVENT_REGISTER          2   /**< Read/write of a specific register */
#define VMI_EVENT_SINGLESTEP        3   /**< Instructions being executed on a set of VCPUs */
#define VMI_EVENT_INTERRUPT         4   /**< Interrupts being delivered */
#define VMI_EVENT_GUEST_REQUEST     5   /**< Guest-requested event */
#define VMI_EVENT_CPUID             6   /**< CPUID event */
#define VMI_EVENT_DEBUG_EXCEPTION   7   /**< Debug exception event */
#define VMI_EVENT_PRIVILEGED_CALL   8   /**< Privileged call (ie. SMC on ARM) */
#define VMI_EVENT_DESCRIPTOR_ACCESS 9   /**< A descriptor table register was accessed */
#define VMI_EVENT_FAILED_EMULATION  10  /**< Emulation failed when requested by VMI_EVENT_RESPONSE_EMULATE */

/**
 * Max number of vcpus we can set single step on at one time for a domain
 */
#define MAX_SINGLESTEP_VCPUS 32

/**
 * Register operations used both for configuring type of register operations to
 *  monitor and also to determine the type of access causing an event to be
 *  recorded.
 */
typedef uint8_t vmi_reg_access_t;

#define VMI_REGACCESS_INVALID   0
#define VMI_REGACCESS_N         (1 << 0)
#define VMI_REGACCESS_R         (1 << 1)
#define VMI_REGACCESS_W         (1 << 2)
#define VMI_REGACCESS_RW        (VMI_REGACCESS_R | VMI_REGACCESS_W)

/**
 * Page permissions used both for configuring type of memory operations to
 *  monitor and also to determine the type of access causing an event to be
 *  recorded.
 */
typedef uint8_t vmi_mem_access_t;

#define VMI_MEMACCESS_INVALID     0
#define VMI_MEMACCESS_N           (1 << 0)
#define VMI_MEMACCESS_R           (1 << 1)
#define VMI_MEMACCESS_W           (1 << 2)
#define VMI_MEMACCESS_X           (1 << 3)
#define VMI_MEMACCESS_RW          (VMI_MEMACCESS_R | VMI_MEMACCESS_W)
#define VMI_MEMACCESS_RX          (VMI_MEMACCESS_R | VMI_MEMACCESS_X)
#define VMI_MEMACCESS_WX          (VMI_MEMACCESS_W | VMI_MEMACCESS_X)
#define VMI_MEMACCESS_RWX         (VMI_MEMACCESS_R | VMI_MEMACCESS_W | VMI_MEMACCESS_X)
#define VMI_MEMACCESS_W2X         (1 << 4)     // Special cases
#define VMI_MEMACCESS_RWX2N       (1 << 5)

typedef struct emul_read {
    uint32_t size;
    /* Tell LibVMI if it's not safe to free this structure once processed */
    uint8_t dont_free;
    uint8_t _pad[3];
    uint8_t data[256];
} emul_read_t;

typedef struct emul_insn {
    /* Tell LibVMI if it's not safe to free this structure once processed */
    uint8_t dont_free;
    uint8_t _pad[7];
    uint8_t data[16];
} emul_insn_t;

/**
 * The event structures used during configuration of events and their delivery.
 *  "IN" members of the structs are set by the user during event
 *      registration to configure LibVMI and the hypervisor.
 *  "OUT" members are set by LibVMI upon observation of an event with
 *      contextual information helpful to the callback.
 *  "RESPONSE" members can be set by the user at the end of the callback to signal
 *      to the hypervisor that a specific type of action should be performed.
 *  Note that IN and RESPONSE fields can overlap with OUT fields thus the user
 *      should NOT rely these fields remaining unchanged after event registration.
 *      IN fields that remain unchanged by LibVMI are marked CONST IN.
 */

typedef struct {
    /**
     * CONST IN
     *
     * Register for which write event is configured.
     * Hypervisors offering register events tend to
     *  have a limited number available for monitoring.
     * These registers tend to be those defined as
     * 'sensitive register instructions' by Popek and
     *  Goldberg, meaning that the registers trigger
     *  a VMEXIT, trap, or equivalent.
     *
     * Note for MSR events on Xen: up to Xen 4.7 only MSR_ALL is supported.
     *  Starting with Xen 4.8 the user has the option to subscribe to specific
     *  MSR events, or to continue using MSR_ALL. However, in this case MSR_ALL
     *  only corresponds to common MSRs that are defined by LibVMI in libvmi.h.
     *  To subscribe to MSR events that are NOT defined by LibVMI, the user can specify
     *  MSR_UNDEFINED here and then set the specific MSR index in the 'msr' field
     *  below.
     */
    reg_t reg;

    /**
     * CONST IN
     *
     * Event filter: callback triggers IFF register==<equal>
     */
    reg_t equal;

    /**
     * CONST IN
     *
     * IFF set to 1, events are delivered asynchronously and
     *  without pausing the originating VCPU
     * Default : 0. (i.e., VCPU is paused at time of event delivery).
     */
    uint8_t async;

    /**
     * CONST IN
     *
     * IFF set to 1, events are only delivered if the written
     *  value differs from the previously held value.
     * Default : 0. (i.e., All write events are delivered).
     */
    uint8_t onchange;

    /**
     * CONST IN
     *
     * Type of register event being monitored.
     * Hypervisors offering register events do so only for those that trigger a
     *  VMEXIT or similar trap. This predominantly means that only write events
     *  are supported by the corresponding LibVMI driver
     */
    vmi_reg_access_t in_access;

    /**
     * OUT
     *
     * Type of register access that triggered the event
     */
    vmi_reg_access_t out_access;

    uint32_t _pad;

    /**
     * OUT
     *
     * Register value read or written
     */
    reg_t value;

    /**
     * OUT
     *
     * Previous value of register (only for CR0/CR3/CR4/MSR)
     */
    reg_t previous;

    /**
     * CONST IN/OUT
     *
     * MSR register operations only
     *
     * CONST IN: Starting from Xen 4.8 the user can use this field to specify an
     *  MSR index to subscribe to when the MSR is not formally defined by LibVMI.
     *
     * OUT: holds the specific MSR for which the event occurred
     *  when the user registered with MSR_ALL.
     * Unused for other register event types.
     */
    uint32_t msr;
} reg_event_t;

typedef struct {
    /**
     * IN/OUT: Page number at which to set event (IN) or where event occurred (OUT)
     */
    addr_t gfn;

    /**
     * CONST IN: Generic access violation based event-handler.
     * The goal of generic mem_access events is to be a catch-all event, allowing the user to set
     * permissions with vmi_set_mem_event without having to create a separate vmi_event_t
     * structure for each page. The callback specified here will be then called for all gfn's where
     * a mem_access event is observed with a matching vmi_mem_access_t.
     * If this is set, gfn must be ~0UL.
     */
    uint8_t generic;

    /**
     * CONST IN: Page permissions used to trigger memory events. See definition
     * for valid values.
     */
    vmi_mem_access_t in_access;

    /**
     * OUT: Type of page access that caused event to be triggered.
     * Typically a subset of in_access
     */
    vmi_mem_access_t out_access;

    /**
     * OUT: Whether fault occured during a guest page-table walk.
     */
    uint8_t gptw;

    /**
     * OUT: Whether the value in gla is an actual virtual address
     */
    uint8_t gla_valid;

    uint8_t _pad[3];

    /**
     * OUT: Specific virtual address at which event occurred. If gptw is set, the fault occured
     * while trying to translate this virtual address.
     */
    addr_t gla;

    /**
     * OUT: Offset in bytes (relative to page base) at which the event occurred
     */
    addr_t offset;

} mem_access_event_t;

/*
 * Xen allows for subscribing to interrupt events in two ways as of Xen 4.9.
 * One method is to subscribe to specific interrupts, currently limited
 * to Int3. When such an interrupt is bound to be delivered to the guest,
 * Xen will instead notify the listener. It is the responsibility of the
 * subscriber to decide whether to reinject the interrupt to the guest or not.
 *
 * Another method is to request information about the next interrupt that
 * will be delivered to the guest, be it of any kind. This can only be
 * requested in the response of another type of event. The interrupt will
 * automatically going to be reinjected into the guest once the event is
 * processed, so it is not possible to block interrupts this way.
 *
 */
typedef uint8_t interrupts_t;

#define INT_INVALID     0
#define INT3            1   /**< Software breakpoint (INT3/0xCC) */
#define INT_NEXT        2   /**< Catch-all when next interrupt is reported */

typedef struct {
    /* CONST IN */
    interrupts_t intr;  /**< Specific interrupt intended to trigger the event */

    union {
        /* INT3 */
        struct {
            /* IN/OUT */
            uint32_t insn_length; /**< The instruction length to be used when reinjecting */

            /**
             * OUT
             *
             * Toggle, controls whether interrupt is re-injected after callback.
             *   Set reinject to 1 to deliver it to guest ("pass through" mode)
             *   Set reinject to 0 to swallow it silently without
             */
            int8_t reinject;

            uint16_t _pad1;
        };

        /* INT_NEXT */
        struct {
            /* OUT */
            uint32_t vector;
            uint32_t type;
            uint32_t error_code;
            uint32_t _pad2;
            uint64_t cr2;
        };
    };

    /* OUT */
    addr_t gla;         /**< (Global Linear Address) == RIP of the trapped instruction */
    addr_t gfn;         /**< (Guest Frame Number) == 'physical' page where trap occurred */
    addr_t offset;      /**< Offset in bytes (relative to GFN) */
} interrupt_event_t;

typedef struct {
    /* CONST IN */
    uint32_t vcpus;     /**< A bitfield corresponding to VCPU IDs. */
    uint8_t enable;     /**< Set to true to immediately turn vCPU to singlestep. */

    uint8_t _pad[3];

    /* OUT */
    addr_t gla;         /**< The IP of the current instruction */
    addr_t gfn;         /**< The physical page of the current instruction */
    addr_t offset;      /**< Offset in bytes (relative to GFN) */
} single_step_event_t;

typedef struct {
    addr_t gla;           /**< The IP of the current instruction */
    addr_t gfn;           /**< The physical page of the current instruction */
    addr_t offset;        /**< Offset in bytes (relative to GFN) */
    uint32_t insn_length; /**< Length of the reported instruction */

    /**
     * Intel VMX: {VM_ENTRY,VM_EXIT,IDT_VECTORING}_INTR_INFO[10:8]
     * AMD SVM: eventinj[10:8] and exitintinfo[10:8] (types 0-4 only)
     *
     * Matches HVMOP_TRAP_* on Xen.
     */
    uint8_t type;

    /**
     * Toggle, controls whether debug exception is re-injected after callback.
     *   Set reinject to 1 to deliver it to guest ("pass through" mode)
     *   Set reinject to 0 to swallow it silently without
     */
    int8_t reinject;

    uint16_t _pad;
} debug_event_t;

typedef struct {
    uint32_t insn_length; /**< Length of the reported instruction */
    uint32_t leaf;
    uint32_t subleaf;
    uint32_t _pad;
} cpuid_event_t;

#define VMI_DESCRIPTOR_IDTR           1
#define VMI_DESCRITPOR_GDTR           2
#define VMI_DESCRIPTOR_LDTR           3
#define VMI_DESCRIPTOR_TR             4

typedef struct desriptor_event {
    union {
        struct {
            uint32_t instr_info;         /* VMX: VMCS Instruction-Information */
            uint32_t _pad;
            uint64_t exit_qualification; /* VMX: VMCS Exit Qualification */
        };
        uint64_t exit_info;              /* SVM: VMCB EXITINFO */
    };
    uint8_t descriptor;                  /* VMI_DESCRIPTOR_* */
    uint8_t is_write;
    uint8_t _pad2[6];
} descriptor_event_t;

struct vmi_event;
typedef struct vmi_event vmi_event_t;

/**
 * Callbacks can flip the corresponding bits on event_response_t to trigger
 * the following behaviors.
 */
typedef uint32_t event_response_flags_t;

#define VMI_EVENT_RESPONSE_NONE                 0
#define VMI_EVENT_RESPONSE_EMULATE              (1u << 1)
#define VMI_EVENT_RESPONSE_EMULATE_NOWRITE      (1u << 2)
#define VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA   (1u << 3)
#define VMI_EVENT_RESPONSE_DENY                 (1u << 4)
#define VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP    (1u << 5)
#define VMI_EVENT_RESPONSE_SLAT_ID              (1u << 6)
#define VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID     VMI_EVENT_RESPONSE_SLAT_ID
#define VMI_EVENT_RESPONSE_SET_REGISTERS        (1u << 7)
#define VMI_EVENT_RESPONSE_SET_EMUL_INSN        (1u << 8)
#define VMI_EVENT_RESPONSE_GET_NEXT_INTERRUPT   (1u << 9)
#define __VMI_EVENT_RESPONSE_MAX                9

/**
 * Bitmap holding event_reponse_flags_t values returned by callback
 * (ie. 1u << VMI_EVENT_RESPONSE_*).
 */
typedef uint32_t event_response_t;

/**
 * Event callback function prototype, taking two parameters:
 * The vmi_instance_t passed by the library itself, and the vmi_event_t
 *   object provided by the library user.
 */
typedef event_response_t (*event_callback_t)(vmi_instance_t vmi, vmi_event_t *event);

/**
 * Function to be called when event has been successfully cleared after
 * calling vmi_clear_event.
 */
typedef void (*vmi_event_free_t)(vmi_event_t *event, status_t rc);

struct vmi_event {
    /* CONST IN */
    uint32_t version; /**< User should set it to VMI_EVENTS_VERSION */

    /* CONST IN */
    vmi_event_type_t type;  /**< The specific type of event */

    /**
     * IN/OUT/RESPONSE
     *
     * The VMM maintained SLAT ID. Can be specified when registering mem_event (IN).
     * On an event report (OUT) specifies the active SLAT ID on the vCPU.
     * Iff VMI_EVENT_RESPONSE_SLAT_ID is set (RESPONSE), switch the vCPU to this VMM pagetable ID.
     *
     * Note: on Xen this corresponds to the altp2m_idx.
     */
    uint16_t slat_id;

    /**
     * CONST IN
     *
     * An open-ended mechanism allowing a library user to
     *  associate external data to the event.
     * Metadata assigned to this pointer at any time (prior to
     *  or following registration) is delivered to the callback,
     *  for each matching event. The callback is also free to
     *  modify in any way. The library user assumes all memory
     *  management for this referenced data.
     */
    void *data;

    /**
     * CONST IN
     *
     * The callback function that is invoked when the relevant is observed.
     */
    event_callback_t callback;

    /* OUT */
    uint32_t vcpu_id; /**< The VCPU relative to which the event occurred. */

    /**
     * Reserved for future use
     */
    uint32_t _reserved[7];

    union {
        reg_event_t reg_event;
        mem_access_event_t mem_event;
        single_step_event_t ss_event;
        interrupt_event_t interrupt_event;
        cpuid_event_t cpuid_event;
        debug_event_t debug_event;
        descriptor_event_t descriptor_event;
    };

    /*
     * Note that the following pointers assume compiler compatibility
     * ie. if you compiled a 32-bit version of LibVMI it will be
     * incompatable with 64-bit tools and vice verse.
     */
    union {
        /**
         * OUT
         *
         * Snapshot of some VCPU registers when the event occurred
         */
        union {
            x86_registers_t *x86_regs;
            arm_registers_t *arm_regs;
        };

        /**
         * RESPONSE
         *
         * Read data to be sent back with VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA
         */
        emul_read_t *emul_read;

        /**
         * RESPONSE
         *
         * Instruction buffer to be sent back with VMI_EVENT_RESPONSE_SET_EMUL_INSN
         */
        emul_insn_t *emul_insn;
    };
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
            (_event)->version = VMI_EVENTS_VERSION; \
            (_event)->type = VMI_EVENT_SINGLESTEP; \
            (_event)->ss_event.vcpus = _vcpu_mask; \
            (_event)->ss_event.enable = _enable; \
            (_event)->callback = _callback; \
        } while(0)

/**
 * Convenience macro to setup a memory event
 */
#define SETUP_MEM_EVENT(_event, _gfn, _access, _callback, _generic) \
        do { \
            (_event)->version = VMI_EVENTS_VERSION; \
            (_event)->type = VMI_EVENT_MEMORY; \
            (_event)->mem_event.gfn = _generic ? ~0ULL :_gfn; \
            (_event)->mem_event.in_access = _access; \
            (_event)->mem_event.generic = _generic; \
            (_event)->callback = _callback; \
        } while(0)

/**
 * Convenience macro to setup a register event
 */
#define SETUP_REG_EVENT(_event, _reg, _access, _equal, _callback) \
        do { \
            (_event)->version = VMI_EVENTS_VERSION; \
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
            (_event)->version = VMI_EVENTS_VERSION; \
            (_event)->type = VMI_EVENT_INTERRUPT; \
            (_event)->interrupt_event.intr = INT3; \
            (_event)->interrupt_event.reinject = _reinject; \
            (_event)->callback = _callback; \
        } while(0)

/**
 * The maximum events version LibVMI supports.
 *
 * @return max supported events version
 */
uint32_t vmi_events_version();

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
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_register_event(
    vmi_instance_t vmi,
    vmi_event_t *event);

/**
 * Swap a registered event to another.
 *
 * This function is intended to be used when changing the MEMACCESS
 * page permissions on a page that already has been registered. This
 * function is safe to be called from event callbacks, as no pending
 * event will be left without a registered handler.
 *
 * Memory management of the vmi_event_t being registered remains the
 *  responsibility of the caller.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] swap_from A currently registered event
 * @param[in] swap_to The event to replace the currently registered one with
 * @param[in] free_routine Function to call when it is safe to free old event (swap_from).
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_swap_events(
    vmi_instance_t vmi,
    vmi_event_t *swap_from,
    vmi_event_t *swap_to,
    vmi_event_free_t free_routine);

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
 * @param[in] free_routine Function to call when it is safe to free event.
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_clear_event(
    vmi_instance_t vmi,
    vmi_event_t *event,
    vmi_event_free_t free_routine);

/**
 * Return the pointer to the vmi_event_t if one is set on the given register.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] reg Register to check
 * @return vmi_event_t* or NULL if none found
 */
vmi_event_t *vmi_get_reg_event(
    vmi_instance_t vmi,
    reg_t reg);

/**
 * Return the pointer to the vmi_event_t if one is set on the given page or
 * for a given access type.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] gfn Guest page-frame number to check
 * @param[in] access Access type to check
 * @return vmi_event_t* or NULL if none found
 */
vmi_event_t *vmi_get_mem_event(
    vmi_instance_t vmi,
    addr_t gfn,
    vmi_mem_access_t access);

/**
 * Set mem event on a page. Intended to be used when already registered a generic
 * violation-type based mem access event handlers.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] gfn Guest page-frame number to set event
 * @param[in] access Requested event type on the page
 * @param[in] vmm_pagetable_id The VMM pagetable ID in which to set the access
 * @return VMI_SUCCESS or VMI_FAILURE
 */
status_t vmi_set_mem_event(
    vmi_instance_t vmi,
    addr_t gfn,
    vmi_mem_access_t access,
    uint16_t vmm_pagetable_id);

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
 * Set whether to crash the domain if the event listener is no longer present.
 * By default Xen assumes the listener is not required.
 *
 * @param[in] vmi LibVMI instance
 * @param[in] required Set to false if not required, true if required.
 * @return VMI_FAILURE or VMI_SUCCESS
 */
status_t vmi_event_listener_required(
    vmi_instance_t vmi,
    bool required);

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
