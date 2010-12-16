#define ENABLE_XEN
#include <Python.h>
#include <sys/mman.h>
#include <xenaccess/xa_private.h>
#include <xenaccess/xenaccess.h>

#define pyxai(v)  (((pyxa_instance *)(v))->xai)
#define pyxamem(v)  (((pyxa_instance *)(v))->memory)

void print_debug(xa_instance_t xai) {
    printf("DEBUG: KPGD [%#x] CR3: [%#x] DomId: [%d] Version: [%d]\n"
           "       Memory size: [%d] OS Type: [%s]\n",

           xai.kpgd, xai.cr3, xai.m.xen.domain_id,
           xai.m.xen.xen_version, xai.m.xen.size,
           xai.os_type == XA_OS_LINUX ? "Linux" : "Windows");
}

// PyXa instance type fwdref
staticforward PyTypeObject pyxa_instance_Type;

typedef struct {
    PyObject_HEAD
    xa_instance_t xai;              // XenAccess instance
    char *memory;                   // Most recently used memory page
} pyxa_instance;

// Constructor & Destructor

static PyObject *
pyxa_instance_new(PyObject *self, PyObject *args) {
    uint32_t dom;
    pyxa_instance *object = NULL;
    
    object = PyObject_NEW(pyxa_instance, &pyxa_instance_Type);    

    if (!PyArg_ParseTuple(args, "I", &dom))
        return NULL;
    
    if (xa_init_vm_id_strict(dom, &(pyxai(object))) == XA_FAILURE) {
        PyErr_SetString(PyExc_ValueError,
            "Init failed for domain");
        return NULL;
    }

    //print_debug(pyxai(object));
    //printf("XAI instance is at %p\n", &pyxai(object));
    return (PyObject *) object;
}

static void
pyxa_instance_dealloc(PyObject *self) {
    //printf("About to destroy PyXa instance at %p\n", &(pyxai(self)));
    xa_destroy(&(pyxai(self)));
    if(pyxamem(self)) {
        //printf("About to unmap memory at %p\n", pyxamem(self));
        munmap(pyxamem(self), PAGE_SIZE);
    }
    //printf("About to call PyObject_DEL on self at %p\n", self);
    PyObject_DEL(self);
}

// Methods

static PyObject *
pyxa_read(PyObject *self, PyObject *args) {
    uint32_t pfn;
    uint32_t offset;
    char *returned_memory;

    if (!PyArg_ParseTuple(args, "I", &pfn))
        return NULL;
    
    if(pyxamem(self)) munmap(pyxamem(self), PAGE_SIZE);

    pyxamem(self) = xa_access_pa(&(pyxai(self)), pfn, &offset, PROT_READ);
    
    //printf("DEBUG: Offset within mapped region: %d\n", offset);

    if(!pyxamem(self)) {
        PyErr_SetString(PyExc_ValueError,
            "Unable to read memory at specified address");
        return NULL;
    }

    returned_memory = pyxamem(self) + offset;

    return Py_BuildValue("s#", returned_memory, PAGE_SIZE - offset);
}

/*
static PyObject *
pyxa_read_virt(PyObject *self, PyObject *args) {
    uint32_t pfn;
    uint32_t offset;
    unsigned char *memory = NULL;

    if (!PyArg_ParseTuple(args, "I", &pfn))
        return NULL;

    if(memory) munmap(memory, PAGE_SIZE);

    memory = xa_access_virtual_address(&xai, pfn, &offset);
    
    printf("DEBUG: Offset within mapped region: %d\n", offset);

    if(!memory) {
        PyErr_SetString(PyExc_ValueError,
            "Unable to read memory at specified address");
        return NULL;
    }

    return Py_BuildValue("s#", memory, 0x1000);
}

static PyObject *
pyxa_vtop(PyObject *self, PyObject *args) {
    uint32_t addr;
    uint32_t paddr;

    if (!PyArg_ParseTuple(args, "I", &addr))
        return NULL;

    paddr = xa_translate_kv2p(&xai, addr);

    if (!paddr) {
        PyErr_SetString(PyExc_ValueError,
            "Unable to translate specified address");
        return NULL;
    }

    return Py_BuildValue("I", paddr);
}
*/

static PyObject *
pyxa_get_cr3(PyObject *self, PyObject *args) {
    uint32_t cr3;
    
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    // This is cheesy, but xai.cr3 is wrong for some reason
    cr3 = pyxai(self).kpgd - pyxai(self).page_offset;
    
    return Py_BuildValue("I", cr3);
}

static PyObject *
pyxa_get_domain_id(PyObject *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ""))
        return NULL;
    return Py_BuildValue("I", pyxai(self).m.xen.domain_id);
}

static PyObject *
pyxa_get_size(PyObject *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ""))
        return NULL;
    return Py_BuildValue("I", pyxai(self).m.xen.size);
}

static PyObject *
pyxa_is_pae(PyObject *self, PyObject *args) {
    if(pyxai(self).pae)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static PyObject *
pyxa_is_pse(PyObject *self, PyObject *args) {
    if(pyxai(self).pse)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

/*
static PyObject *
pyxa_close(PyObject *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, ""))
        return NULL;

    if(memory) munmap(memory, PAGE_SIZE);
    xa_destroy(&xai);

    Py_RETURN_NONE;
}
*/

// pyxa_instance method table
static PyMethodDef pyxa_instance_methods[] = {
    {"read", pyxa_read, METH_VARARGS,
     "Read a page of physical memory"},
    {"get_cr3", pyxa_get_cr3, METH_VARARGS,
     "Get the current value of the CR3 register"},
    {"get_domain_id", pyxa_get_domain_id, METH_VARARGS,
     "Get the domain ID of this instance"},
    {"get_size", pyxa_get_size, METH_VARARGS,
     "Get the memory size (in bytes) of this instance"},
    {"is_pae", pyxa_is_pae, METH_VARARGS,
     "Returns True if the current domain has PAE enabled"},
    {"is_pse", pyxa_is_pse, METH_VARARGS,
     "Returns True if the current domain has PSE enabled"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

// python callbacks
static PyObject *
pyxa_instance_getattr(PyObject *self, char *attrname) {
    return Py_FindMethod(pyxa_instance_methods, self, attrname);
}

static PyObject *
pyxa_instance_repr(PyObject *self) {
    char buf[50];
    sprintf(buf, "<pyxa_instance for domain id %d>",
            pyxai(self).m.xen.domain_id);
    return PyString_FromString(buf);
}

// Type object itself
static PyTypeObject pyxa_instance_Type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,
    "pyxa_instance",          /* char *tp_name; */
    sizeof(pyxa_instance),    /* int tp_basicsize; */
    0,                        /* int tp_itemsize;        not used much */
    (destructor) pyxa_instance_dealloc,    /* destructor tp_dealloc; */
    0,                        /* printfunc  tp_print;   */
    (getattrfunc) pyxa_instance_getattr,    /* getattrfunc  tp_getattr;  __getattr__ */
    0,    /* setattrfunc  tp_setattr;  __setattr__ */
    0,                        /* cmpfunc  tp_compare;  __cmp__ */
    (reprfunc) pyxa_instance_repr,       /* reprfunc  tp_repr;    __repr__ */
    0,                        /* PyNumberMethods *tp_as_number; */
    0,                        /* PySequenceMethods *tp_as_sequence; */
    0,                        /* PyMappingMethods *tp_as_mapping; */
    0,                        /* hashfunc tp_hash;     __hash__ */
    0,                        /* ternaryfunc tp_call;  __call__ */
    0,                        /* reprfunc tp_str;      __str__ */
};

// module method table
static PyMethodDef PyXaMethods[] = {
    {"pyxa_instance", pyxa_instance_new, METH_VARARGS,
     "Create a new PyXa instance"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initpyxa(void) {
    (void) Py_InitModule("pyxa", PyXaMethods);
}

int main(int argc, char *argv[]) {
    /* Pass argv[0] to the Python interpreter */
    Py_SetProgramName(argv[0]);

    /* Initialize the Python interpreter.  Required. */
    Py_Initialize();

    /* Add a static module */
    initpyxa();

    return 0;
}
