#define VMI_EVENTS_VERSION 0x00000004

typedef uint16_t vmi_event_type_t;

#define VMI_EVENT_INVALID 0
#define VMI_EVENT_MEMORY 1
#define VMI_EVENT_REGISTER 2
#define VMI_EVENT_SINGLESTEP 3
#define VMI_EVENT_INTERRUPT 4
#define VMI_EVENT_GUEST_REQUEST 5
#define VMI_EVENT_CPUID 6
#define VMI_EVENT_DEBUG_EXCEPTION 7
#define VMI_EVENT_PRIVILEGED_CALL 8
#define VMI_EVENT_DESCRIPTOR_ACCESS 9

// reg_event_t
typedef struct {
    ...;
} reg_event_t;

typedef uint8_t vmi_mem_access_t;

#define VMI_MEMACCESS_INVALID     ...
#define VMI_MEMACCESS_N           ...
#define VMI_MEMACCESS_R           ...
#define VMI_MEMACCESS_W           ...
#define VMI_MEMACCESS_X           ...
#define VMI_MEMACCESS_RW          ...
#define VMI_MEMACCESS_RX          ...
#define VMI_MEMACCESS_WX          ...
#define VMI_MEMACCESS_RWX         ...
#define VMI_MEMACCESS_W2X         ...
#define VMI_MEMACCESS_RWX2N       ...

// mem_access_event_t
typedef struct {
    ...;
} mem_access_event_t;

// interrupt_event_t
typedef struct {
    ...;
} interrupt_event_t;

// single_step_event_t
typedef struct {
    uint32_t vcpus;
    uint8_t enable;
    ...;
} single_step_event_t;

// debug_event_t
typedef struct {
    ...;
} debug_event_t;

// cpuid_event_t
typedef struct {
    ...;
} cpuid_event_t;

// descriptor_event_t
typedef struct desriptor_event {
    ...;
} descriptor_event_t;

// vmi_event_t
struct vmi_event;
typedef struct vmi_event vmi_event_t;

typedef uint32_t event_response_flags_t;

#define VMI_EVENT_RESPONSE_NONE                 0
#define VMI_EVENT_RESPONSE_EMULATE              ...
#define VMI_EVENT_RESPONSE_EMULATE_NOWRITE      ...
#define VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA   ...
#define VMI_EVENT_RESPONSE_DENY                 ...
#define VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP    ...
#define VMI_EVENT_RESPONSE_SLAT_ID              ...
#define VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID     ...
#define VMI_EVENT_RESPONSE_SET_REGISTERS        ...
#define VMI_EVENT_RESPONSE_SET_EMUL_INSN        ...
#define VMI_EVENT_RESPONSE_GET_NEXT_INTERRUPT   ...
#define __VMI_EVENT_RESPONSE_MAX 9

typedef uint32_t event_response_t;

typedef event_response_t (*event_callback_t)(vmi_instance_t vmi, vmi_event_t *event);


// vmi_event
struct vmi_event {
    uint32_t version;
    vmi_event_type_t type;
    uint16_t slat_id;
    void *data;
    event_callback_t callback;
    uint32_t vcpu_id;
    ...;
    union {
        reg_event_t reg_event;
        mem_access_event_t mem_event;
        single_step_event_t ss_event;
        interrupt_event_t interrupt_event;
        cpuid_event_t cpuid_event;
        debug_event_t debug_event;
        descriptor_event_t descriptor_event;
    };
    union {
        union {
            x86_registers_t *x86_regs;
            arm_registers_t *arm_regs;
        };
        ...;
    };
};

// functions
status_t vmi_register_event(
    vmi_instance_t vmi,
    vmi_event_t *event);

status_t vmi_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout);

// our generic callback
extern "Python" event_response_t generic_event_callback(
    vmi_instance_t vmi,
    vmi_event_t *event);