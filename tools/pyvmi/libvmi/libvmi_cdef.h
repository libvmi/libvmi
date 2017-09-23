#define VMI_INIT_DOMAINNAME 1 /**< initialize using domain name */

#define VMI_INIT_DOMAINID 2 /**< initialize using domain id */

#define VMI_INIT_EVENTS 4 /**< initialize events */

#define VMI_INIT_SHM 8 /**< initialize SHM mode */

#define CR3 20

// vmi_instance_t
typedef struct vmi_instance *vmi_instance_t;

// addr_t
typedef uint64_t addr_t;

// vmi_pid_t
typedef int32_t vmi_pid_t;

// status_t
typedef enum status {

    VMI_SUCCESS,  /**< return value indicating success */

    VMI_FAILURE   /**< return value indicating failure */
} status_t;

// vmi_config
typedef enum vmi_config {

    VMI_CONFIG_GLOBAL_FILE_ENTRY, /**< config in file provided */

    VMI_CONFIG_STRING,            /**< config string provided */

    VMI_CONFIG_GHASHTABLE,        /**< config GHashTable provided */
} vmi_config_t;

// vmi_mode
typedef enum vmi_mode {

    VMI_XEN, /**< libvmi is monitoring a Xen VM */

    VMI_KVM, /**< libvmi is monitoring a KVM VM */

    VMI_FILE, /**< libvmi is viewing a file on disk */
} vmi_mode_t;

// vmi_init_error_t
typedef enum vmi_init_error {

    VMI_INIT_ERROR_NONE, /**< No error */

    VMI_INIT_ERROR_DRIVER_NOT_DETECTED, /**< Failed to auto-detect hypervisor */

    VMI_INIT_ERROR_DRIVER, /**< Failed to initialize hypervisor-driver */

    VMI_INIT_ERROR_VM_NOT_FOUND, /**< Failed to find the specified VM */

    VMI_INIT_ERROR_PAGING, /**< Failed to determine or initialize paging functions */

    VMI_INIT_ERROR_OS, /**< Failed to determine or initialize OS functions */

    VMI_INIT_ERROR_EVENTS, /**< Failed to initialize events */

    VMI_INIT_ERROR_SHM, /**< Failed to initialize SHM */

    VMI_INIT_ERROR_NO_CONFIG, /**< No configuration was found for OS initialization */

    VMI_INIT_ERROR_NO_CONFIG_ENTRY, /**< Configuration contained no valid entry for VM */
} vmi_init_error_t;

// os_t
typedef enum os {

    VMI_OS_UNKNOWN,  /**< OS type is unknown */

    VMI_OS_LINUX,    /**< OS type is Linux */

    VMI_OS_WINDOWS   /**< OS type is Windows */
} os_t;

/**
 * Windows version enumeration. The values of the enum
 * represent the size of KDBG structure up to Windows 8.
 * At Windows 10 the KDBG based scan is no longer supported
 * and thus at that point the value itself has no magic value.
 */
typedef enum win_ver {

    VMI_OS_WINDOWS_NONE,    /**< Not Windows */
    VMI_OS_WINDOWS_UNKNOWN, /**< Is Windows, not sure which */

    VMI_OS_WINDOWS_2000     = 0x0208, /**< Magic value for Windows 2000 */
    VMI_OS_WINDOWS_XP       = 0x0290, /**< Magic value for Windows XP */
    VMI_OS_WINDOWS_2003     = 0x0318, /**< Magic value for Windows 2003 */
    VMI_OS_WINDOWS_VISTA    = 0x0328, /**< Magic value for Windows Vista */
    VMI_OS_WINDOWS_2008     = 0x0330, /**< Magic value for Windows 2008 */
    VMI_OS_WINDOWS_7        = 0x0340, /**< Magic value for Windows 7 */
    VMI_OS_WINDOWS_8        = 0x0360, /**< Magic value for Windows 8 */
    VMI_OS_WINDOWS_10,
} win_ver_t;

typedef enum page_mode {

    VMI_PM_UNKNOWN, /**< page mode unknown */

    VMI_PM_LEGACY,  /**< x86 32-bit paging */

    VMI_PM_PAE,     /**< x86 PAE paging */

    VMI_PM_IA32E,   /**< x86 IA-32e paging */

    VMI_PM_AARCH32, /**< ARM 32-bit paging */

    VMI_PM_AARCH64  /**< ARM 64-bit paging */
} page_mode_t;

typedef enum translation_mechanism {
    VMI_TM_INVALID,         /**< Invalid translation mechanism */
    VMI_TM_NONE,            /**< No translation is required, address is physical address */
    VMI_TM_PROCESS_DTB,     /**< Translate addr via specified directory table base. */
    VMI_TM_PROCESS_PID,     /**< Translate addr by finding process first to use its DTB. */
    VMI_TM_KERNEL_SYMBOL    /**< Find virtual address of kernel symbol and translate it via kernel DTB. */
} translation_mechanism_t;

// vmi_arch_t
typedef enum arch {
    VMI_ARCH_UNKNOWN,        /**< Unknown architecture */
    VMI_ARCH_X86,            /**< x86 32-bit architecture */
    VMI_ARCH_X86_64,         /**< x86 64-bit architecture */
    VMI_ARCH_ARM32,          /**< ARM 32-bit architecture */
    VMI_ARCH_ARM64           /**< ARM 64-bit architecture */
} vmi_arch_t;

// page_size_t
typedef enum page_size {

    VMI_PS_UNKNOWN  = 0,         /**< page size unknown */

    VMI_PS_1KB      = 0x400,     /**< 1KB */

    VMI_PS_4KB      = 0x1000,    /**< 4KB */

    VMI_PS_16KB     = 0x4000,    /**< 16KB */

    VMI_PS_64KB     = 0x10000,   /**< 64KB */

    VMI_PS_1MB      = 0x100000,  /**< 1MB */

    VMI_PS_2MB      = 0x200000,  /**< 2MB */

    VMI_PS_4MB      = 0x400000,  /**< 4MB */

    VMI_PS_16MB     = 0x1000000, /**< 16MB */

    VMI_PS_32MB     = 0x2000000, /**< 32MB */

    VMI_PS_512MB    = 0x2000000,  /**< 512MB */

    VMI_PS_1GB      = 0x4000000,  /**< 1GB */

} page_size_t;

typedef uint64_t reg_t;

/*
 * Commonly used x86 registers
 */
typedef struct x86_regs {
    ...;
} x86_registers_t;

typedef struct arm_registers {
    ...;
} arm_registers_t;

typedef struct registers {
    ...;
} registers_t;

// page_info_t
typedef struct page_info {
    ...;
} page_info_t;

// access_context_t
typedef struct {
    translation_mechanism_t translate_mechanism;

    addr_t addr;        /**< specify iff using VMI_TM_NONE, VMI_TM_PROCESS_DTB or VMI_TM_PROCESS_PID */
    const char *ksym;   /**< specify iff using VMI_TM_KERNEL_SYMBOL */
    addr_t dtb;         /**< specify iff using VMI_TM_PROCESS_DTB */
    vmi_pid_t pid;      /**< specify iff using VMI_TM_PROCESS_PID */
} access_context_t;

typedef struct _ustring {
    size_t length;         /**< byte count of contents */

    uint8_t *contents;     /**< pointer to byte array holding string */

    const char *encoding;  /**< holds iconv-compatible encoding of contents; do not free */

} unicode_string_t;

// functions
status_t vmi_init(
    vmi_instance_t *vmi,
    vmi_mode_t mode,
    void* domain,
    uint64_t init_flags,
    void *init_data,
    vmi_init_error_t *error);

status_t vmi_init_complete(
    vmi_instance_t *vmi,
    void *domain,
    uint64_t init_flags,
    void *init_data,
    vmi_config_t config_mode,
    void *config,
    vmi_init_error_t *error);

page_mode_t vmi_init_paging(
    vmi_instance_t vmi,
    uint64_t flags);

os_t vmi_init_os(
    vmi_instance_t vmi,
    vmi_config_t config_mode,
    void *config,
    vmi_init_error_t *error);

status_t vmi_destroy(
    vmi_instance_t vmi);

vmi_arch_t vmi_get_library_arch();

const char *vmi_get_rekall_path(
    vmi_instance_t vmi);

// memory translations
status_t vmi_translate_kv2p(
    vmi_instance_t vmi,
    addr_t vaddr,
    addr_t *paddr);

status_t vmi_translate_uv2p(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t *paddr);

status_t vmi_translate_ksym2v(
    vmi_instance_t vmi,
    const char *symbol,
    addr_t *vaddr);

status_t vmi_translate_sym2v(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    const char *symbol,
    addr_t *vaddr);

const char* vmi_translate_v2sym(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t rva);

const char* vmi_translate_v2ksym(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t va);

status_t vmi_pid_to_dtb(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t *dtb);

status_t vmi_dtb_to_pid(
    vmi_instance_t vmi,
    addr_t dtb,
    vmi_pid_t *pid);

status_t vmi_pagetable_lookup(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    addr_t *paddr);

status_t vmi_pagetable_lookup_extended(
    vmi_instance_t vmi,
    addr_t dtb,
    addr_t vaddr,
    page_info_t *info);

status_t vmi_read(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t count,
    void *buf,
    size_t *bytes_read);

status_t vmi_read_8(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t * value);

status_t vmi_read_16(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint16_t * value);

status_t vmi_read_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value);

status_t vmi_read_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value);

status_t vmi_read_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t *value);

char *vmi_read_str(
    vmi_instance_t vmi,
    const access_context_t *ctx);

unicode_string_t *vmi_read_unicode_str(
    vmi_instance_t vmi,
    const access_context_t *ctx);

status_t vmi_read_ksym(
    vmi_instance_t vmi,
    const char *sym,
    size_t count,
    void *buf,
    size_t *bytes_read
);

status_t vmi_read_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_read
);

status_t vmi_read_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t count,
    void *buf,
    size_t *bytes_read
);

status_t vmi_read_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value);

status_t vmi_read_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value);

status_t vmi_read_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value);

status_t vmi_read_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value);

status_t vmi_read_addr_ksym(
    vmi_instance_t vmi,
    char *sym,
    addr_t *value);

char *vmi_read_str_ksym(
    vmi_instance_t vmi,
    char *sym);

status_t vmi_read_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint8_t * value);

status_t vmi_read_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint16_t * value);

status_t vmi_read_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint32_t * value);

status_t vmi_read_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint64_t * value);

status_t vmi_read_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t *value);

char *vmi_read_str_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid);

unicode_string_t *vmi_read_unicode_str_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid);

status_t vmi_convert_str_encoding(
    const unicode_string_t *in,
    unicode_string_t *out,
    const char *outencoding);

void vmi_free_unicode_str(
    unicode_string_t *p_us);

status_t vmi_read_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value);

status_t vmi_read_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value);

status_t vmi_read_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value);

status_t vmi_read_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value);

status_t vmi_read_addr_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    addr_t *value);

char *vmi_read_str_pa(
    vmi_instance_t vmi,
    addr_t paddr);

// write
status_t vmi_write(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    size_t count,
    void *buf,
    size_t *bytes_written);

status_t vmi_write_ksym(
    vmi_instance_t vmi,
    char *sym,
    size_t count,
    void *buf,
    size_t *bytes_written);

status_t vmi_write_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t count,
    void *buf,
    size_t *bytes_written);

status_t vmi_write_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t count,
    void *buf,
    size_t *bytes_written);

status_t vmi_write_8(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint8_t * value);

status_t vmi_write_16(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint16_t * value);

status_t vmi_write_32(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint32_t * value);

status_t vmi_write_64(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    uint64_t * value);

status_t vmi_write_addr(
    vmi_instance_t vmi,
    const access_context_t *ctx,
    addr_t * value);

status_t vmi_write_8_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint8_t * value);

status_t vmi_write_16_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint16_t * value);

status_t vmi_write_32_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint32_t * value);

status_t vmi_write_64_ksym(
    vmi_instance_t vmi,
    char *sym,
    uint64_t * value);

status_t vmi_write_addr_ksym(
    vmi_instance_t vmi,
    char *sym,
    addr_t * value);

status_t vmi_write_8_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint8_t * value);

status_t vmi_write_16_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint16_t * value);

status_t vmi_write_32_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint32_t * value);

status_t vmi_write_64_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    uint64_t * value);

status_t vmi_write_addr_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    addr_t * value);

status_t vmi_write_8_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint8_t * value);

status_t vmi_write_16_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint16_t * value);

status_t vmi_write_32_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint32_t * value);

status_t vmi_write_64_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    uint64_t * value);

status_t vmi_write_addr_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    addr_t * value);

// print util functions
void vmi_print_hex(
    unsigned char *data,
    unsigned long length);

void vmi_print_hex_ksym(
    vmi_instance_t vmi,
    char *sym,
    size_t length);

void vmi_print_hex_va(
    vmi_instance_t vmi,
    addr_t vaddr,
    vmi_pid_t pid,
    size_t length);

void vmi_print_hex_pa(
    vmi_instance_t vmi,
    addr_t paddr,
    size_t length);

// get functions
char *vmi_get_name(
    vmi_instance_t vmi);

uint64_t vmi_get_vmid(
    vmi_instance_t vmi);

status_t vmi_get_access_mode(
    vmi_instance_t vmi,
    void *domain,
    uint64_t init_flags,
    void* init_data,
    vmi_mode_t *mode);

page_mode_t vmi_get_page_mode(
    vmi_instance_t vmi,
    unsigned long vcpu);

uint8_t vmi_get_address_width(
    vmi_instance_t vmi);

os_t vmi_get_ostype(
    vmi_instance_t vmi);

win_ver_t vmi_get_winver(
    vmi_instance_t vmi);

const char *vmi_get_winver_str(
    vmi_instance_t vmi);

win_ver_t vmi_get_winver_manual(
    vmi_instance_t vmi,
    addr_t kdvb_pa);

status_t vmi_get_offset(
    vmi_instance_t vmi,
    const char *offset_name,
    addr_t *offset);

status_t vmi_get_kernel_struct_offset(
    vmi_instance_t vmi,
    const char* struct_name,
    const char* member,
    addr_t *addr);

uint64_t vmi_get_memsize(
    vmi_instance_t vmi);

addr_t vmi_get_max_physical_address(
    vmi_instance_t vmi);

unsigned int vmi_get_num_vcpus (
    vmi_instance_t vmi);

status_t vmi_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu);

status_t vmi_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);

status_t vmi_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu);

status_t vmi_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);

status_t vmi_pause_vm(
    vmi_instance_t vmi);

status_t vmi_resume_vm(
    vmi_instance_t vmi);

// cache functions
void vmi_v2pcache_flush(
    vmi_instance_t vmi,
    addr_t dtb);

void vmi_v2pcache_add(
    vmi_instance_t vmi,
    addr_t va,
    addr_t dtb,
    addr_t pa);

void vmi_symcache_flush(
    vmi_instance_t vmi);

void vmi_symcache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    char *sym,
    addr_t va);

void vmi_rvacache_flush(
    vmi_instance_t vmi);

void vmi_rvacache_add(
    vmi_instance_t vmi,
    addr_t base_addr,
    vmi_pid_t pid,
    addr_t rva,
    char *sym);

void vmi_pidcache_flush(
    vmi_instance_t vmi);

void vmi_pidcache_add(
    vmi_instance_t vmi,
    vmi_pid_t pid,
    addr_t dtb);
