#include <Python.h>
#include <structmember.h>
#if HAVE_BLUEZ
#include <bluetooth/bluetooth.h>
#endif
#include <openobex/obex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <execinfo.h>
#define MAX_BT_STACK 16

#define NDEBUG 1
#ifdef NDEBUG
#define debug(fmt, args...)
#else
#define debug(fmt, args...) fprintf(stderr, fmt, ## args);
#endif

/* for compatability with openobex 1.3 */
#ifndef OBEX_HDR_CREATOR
#define OBEX_HDR_CREATOR    0xcf /* indicates the creator of an object */
#endif

#ifndef OBEX_HDR_WANUUID
#define OBEX_HDR_WANUUID    0x50 /* uniquely identifies the network client
                    (OBEX server) */
#endif

#ifndef OBEX_HDR_OBJECTCLASS
#define OBEX_HDR_OBJECTCLASS    0x51 /* OBEX Object class of object */
#endif

#ifndef OBEX_HDR_SESSIONPARAM
#define OBEX_HDR_SESSIONPARAM    0x52 /* Parameters used in session
                    commands/responses */
#endif

#ifndef OBEX_HDR_SESSIONSEQ
#define OBEX_HDR_SESSIONSEQ    0x93 /* Sequence number used in each OBEX
                    packet for reliability */
#endif

#ifndef OBEX_CMD_SESSION
#define OBEX_CMD_SESSION    0x07 /* used for reliable session support */
#endif


static PyTypeObject PyObex_Type;
static PyTypeObject PyObexObject_Type;
static PyObject * PyObexIrdaInterface_Type;

typedef struct {
    PyObject_HEAD PyObject *inst_dict;
    int type;
    obex_t *obex;
} PyObex;

typedef struct {
    PyObject_HEAD PyObject *inst_dict;
    obex_object_t *object;
    PyObex *obex;
    int delete_explicit;
} PyObexObject;

typedef struct {
    PyObject *eventcb_dict;
    PyObject *user_data;
    PyObex *self;
} ObexUserData;

static PyObject *
pyobex_object_add_header(PyObexObject * self, PyObject * args);

static void print_backtrace()
{
#ifndef NDEBUG
    void *frame_addrs[MAX_BT_STACK];
    char **frame_strings;
    size_t backtrace_size;
    int i;
    backtrace_size = backtrace(frame_addrs, MAX_BT_STACK);
    frame_strings = backtrace_symbols(frame_addrs, backtrace_size);
    for (i = 0; i< backtrace_size; i++) {
        printf("%d: [%p] %s\n", i, frame_addrs[i], frame_strings[i]);
    }
    free(frame_strings);
#endif
}

static void
event_callback(obex_t * handle, obex_object_t * object,
           int mode, int event, int obex_cmd, int obex_rsp)
{
    PyObject *cb_dict, *_event, *cb_object, *cb_args, *self, *ret;
    ObexUserData *user_data = OBEX_GetUserData(handle);
    PyObexObject *obj;

    debug("%s:%d \t%s \t%p B\n", __FILE__, __LINE__, __func__, self);
    cb_dict = user_data->eventcb_dict;
    self = (PyObject *) user_data->self;
    _event = PyInt_FromLong(event);
    cb_object = PyObject_GetItem(cb_dict, _event);

    if(!cb_object) {
        debug("EVENT=%04x, CMD=%04x unhandled\n", event, obex_cmd);
        return;
    }else {
        debug( "EVENT=%04x, CMD=%04x handled\n", event, obex_cmd);
    }

    /* XXX */
    obj = (PyObexObject *) PyObexObject_Type.tp_new(&PyObexObject_Type, NULL,
        NULL);
    obj->inst_dict = NULL;
    obj->object = object;
    obj->obex = user_data->self;
    //Py_INCREF(self);

    cb_args = Py_BuildValue("(OOii)", self, obj, obex_cmd, obex_rsp);

    ret = PyEval_CallObject(cb_object, cb_args);

    if (!ret) {
        if (PyErr_ExceptionMatches(PyExc_KeyboardInterrupt)) {
            PyErr_Print();
            exit(0);
        }
        PyErr_Print();
    } else {
        Py_DECREF(ret);
    }
    Py_DECREF(cb_args);
    Py_DECREF(_event);
    debug("%s:%d \t%s \t%p E\n", __FILE__, __LINE__, __func__, self);
}


static int
pyobex_init(PyObex * self, PyObject * args, PyObject * kwds)
{
    int type, flags = 0;
    debug("%s:%d \t%s \t%p\n", __FILE__, __LINE__, __func__, self);
    print_backtrace();

    if (!PyArg_ParseTuple(args, "i|i:obex_new", &type, &flags)) {
        PyErr_SetString(PyExc_RuntimeError,
            "requires one or two integer arguments.");
        return -1;
    }
    self->inst_dict = NULL;

    ObexUserData *user_data = malloc(sizeof(ObexUserData));
    self->obex = OBEX_Init(type, event_callback, flags);
    debug("\t\tObex %p created\n", self->obex);
    if (self->obex <= 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        free(user_data);
        return -1;
    }
    self->type = type;
    user_data->self = self;
    //Py_INCREF(self);
    Py_INCREF(Py_None);
    user_data->user_data = Py_None;
    user_data->eventcb_dict = PyDict_New();
    OBEX_SetUserData(self->obex, user_data);
    return 0;
}

static void
pyobex_dealloc(PyObex * self)
{
    debug("%s:%d \t%s \t%p B\n", __FILE__, __LINE__, __func__, self);
    print_backtrace();
    ObexUserData *user_data =
    (ObexUserData *) OBEX_GetUserData(self->obex);
    if (user_data) {
        Py_DECREF(user_data->eventcb_dict);
        Py_DECREF(user_data->user_data);
        free(user_data);
    }

    debug("\t\tObex %p deleted\n", self->obex);
    OBEX_Cleanup(self->obex);
    if (self->inst_dict) {
        Py_DECREF(self->inst_dict);
        self->inst_dict = 0;
    }
    self->ob_type->tp_free((PyObject *) self);
    debug("%s:%d \t%s \t%p E\n", __FILE__, __LINE__, __func__, self);
}


static PyObject *
pyobex_setuserdata(PyObex * self, PyObject * new_user_data)
{
    ObexUserData *user_data =
    (ObexUserData *) OBEX_GetUserData(self->obex);
    Py_DECREF(user_data->user_data);
    Py_INCREF(new_user_data);
    user_data->user_data = new_user_data;
    Py_RETURN_NONE;
}

static PyObject *
pyobex_getuserdata(PyObex * self)
{
    PyObject *data;
    ObexUserData *user_data =
    (ObexUserData *) OBEX_GetUserData(self->obex);

    data = user_data->user_data;
    Py_INCREF(data);
    return data;
}

static PyObject *
pyobex_register_irda(PyObex * self, PyObject * args)
{
    char *service;
    int rc;
    if (!PyArg_ParseTuple(args, "s:obex_register_irda", &service)) {
        return NULL;
    }
    rc = IrOBEX_ServerRegister(self->obex, service);
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
pyobex_register_tcp(PyObex * self, PyObject * args)
{
    int rc;
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    rc = TcpOBEX_ServerRegister(self->obex, (struct sockaddr*) &address, sizeof(address));
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        return NULL;
    }
    Py_RETURN_NONE;
}

#if HAVE_BLUEZ
static PyObject *
pyobex_register_bluetooth(PyObex * self, PyObject * args)
{
    uint8_t service;
    int rc;
    if (!PyArg_ParseTuple(args, "B:obex_register_bluetooth", &service)) {
        return NULL;
    }

    rc = BtOBEX_ServerRegister(self->obex, BDADDR_ANY, service);
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        return NULL;
    }
    Py_RETURN_NONE;
}
#endif

static PyObject *
pyobex_register(PyObex * self, PyObject * args)
{
    switch (self->type) {
        case OBEX_TRANS_IRDA:
            return pyobex_register_irda(self, args);
#if HAVE_BLUEZ
        case OBEX_TRANS_BLUETOOTH:
            return pyobex_register_bluetooth(self, args);
#endif
        case OBEX_TRANS_INET:
            return pyobex_register_tcp(self, args);
    }
    PyErr_SetString(PyExc_RuntimeError, "Not Support Transport type");
    return NULL;
}

static PyObject *
pyobex_fileno(PyObex * self)
{
    int _fd = OBEX_GetFD(self->obex);
    PyObject *fd = PyInt_FromLong(_fd);
    return fd;
}

static PyObject *
pyobex_connect_irda(PyObex * self, PyObject * args)
{
    char *service;
    int rc;
    if (!PyArg_ParseTuple(args, "s:obex_connect_irda", &service)) {
        return NULL;
    }
    rc = IrOBEX_TransportConnect(self->obex, service);
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
pyobex_connect_tcp(PyObex * self, PyObject * args)
{
    char *addr;
    int rc;
    if (!PyArg_ParseTuple(args, "s:obex_connect_tcp", &addr)) {
        return NULL;
    }
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(addr);
    int len = sizeof(address);

    rc = TcpOBEX_TransportConnect(self->obex, (struct sockaddr *) &address,
                 len);
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        return NULL;
    }
    Py_RETURN_NONE;
}


#if HAVE_BLUEZ
static PyObject *
pyobex_connect_bluetooth(PyObex * self, PyObject * args)
{
    char *daddr;
    uint8_t channel;
    bdaddr_t bdaddr_dst;
    int rc;
    if (!PyArg_ParseTuple
            (args, "sB:obex_connect_bluetooth", &daddr, &channel)) {
        return NULL;
    }

    str2ba(daddr, &bdaddr_dst);

    rc = BtOBEX_TransportConnect(self->obex, BDADDR_ANY, &bdaddr_dst,
                 channel);
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        return NULL;
    }
    Py_RETURN_NONE;
}
#endif


static PyObject *
pyobex_transport_setup(PyObex *self, PyObject *args)
{
    int rfd, wfd, mtu, rc;
    rfd = wfd = -1;
    mtu = 0;
    if (!PyArg_ParseTuple(args, "i|ii:obex_transportsetup", &rfd, &wfd, &mtu)) {
        return NULL;
    }

    if (wfd == -1) wfd = rfd;

    rc = FdOBEX_TransportSetup(self->obex, rfd, wfd, mtu);
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        return NULL;
    }
    Py_RETURN_NONE;

}

static PyObject *
pyobex_connect(PyObex * self, PyObject * args)
{
    switch (self->type) {
        case OBEX_TRANS_IRDA:
            return pyobex_connect_irda(self, args);
#if HAVE_BLUEZ
        case OBEX_TRANS_BLUETOOTH:
            return pyobex_connect_bluetooth(self, args);
#endif
        case OBEX_TRANS_INET:
            return pyobex_connect_tcp(self, args);
        case OBEX_TRANS_FD:
            return pyobex_transport_setup(self, args);
    }
    PyErr_SetString(PyExc_RuntimeError, "Not Support Transport type");
    return NULL;
}

static PyObject *
pyobex_disconnect(PyObex * self)
{
    OBEX_TransportDisconnect(self->obex);
    Py_RETURN_NONE;
}


static PyObject *
pyobex_set_callbacks(PyObex * self, PyObject * args)
{
    if (!PyMapping_Check(args)) {
        PyErr_SetString(PyExc_RuntimeError, "only mapping types can be set");
        return NULL;
    }
    ObexUserData *user_data =
    (ObexUserData *) OBEX_GetUserData(self->obex);
    Py_DECREF(user_data->eventcb_dict);
    Py_INCREF(args);
    debug("\t\t obex = %p old callback = %p", self, user_data->eventcb_dict);
    user_data->eventcb_dict = args;

    debug("new  callback = %p \n", user_data->eventcb_dict);
    Py_RETURN_NONE;
}

static PyObject *
pyobex_accept(PyObex * self)
{
    ObexUserData *server_data, *user_data;
    PyObex *obj;
    user_data = malloc(sizeof(ObexUserData));
    server_data = (ObexUserData *) OBEX_GetUserData(self->obex);
    obex_t *obex =
    OBEX_ServerAccept(self->obex, event_callback, user_data);
    if (obex < 0) {
        PyErr_SetString(PyExc_OSError, strerror(errno));
        free(user_data);
        return NULL;
    }
    Py_INCREF(server_data->user_data);
    Py_INCREF(server_data->eventcb_dict);
    user_data->user_data = server_data->user_data;
    user_data->eventcb_dict = server_data->eventcb_dict;
    obj = (PyObex *) PyObex_Type.tp_new(&PyObex_Type, NULL, NULL);
    obj->type = self->type;
    obj->obex = obex;
    user_data->self = obj;
    Py_INCREF(obj);
    debug("%s:%d \t%s \t%p\n", __FILE__, __LINE__, __func__, obj);
    debug("\t\tObex %p created\n", obex);
    return (PyObject *) obj;

}

static PyObject *
pyobex_handle(PyObex * self, PyObject * args)
{
    int rc, timeout = 0;
    if (!PyArg_ParseTuple(args, "|i:obex_handle", &timeout)) {
        PyErr_SetString(PyExc_RuntimeError,
            "one integer argument required");
        return NULL;
    }
    rc = OBEX_HandleInput(self->obex, timeout);
    return PyInt_FromLong(rc);
}

static PyObject *
pyobex_repr(PyObex * self)
{
    return PyString_FromFormat("<Obex Object at %p>(obex = %p)", self,
                   self->obex);
}

static PyObject *
pyobex_request_object(PyObex *self, PyObject *args)
{
    PyObexObject *obj;
    obex_object_t *object;
    int command;
    PyObject *headers = NULL;
    int items_length = 0;
    int i;

    if (!PyArg_ParseTuple
            (args, "I|O:obex_request_object", &command, &headers)) {
        return NULL;
    }

    if (headers) {
        if (!PyList_Check(headers)) {
            PyErr_SetString(PyExc_RuntimeError, "second arg must list");
            return NULL;
        }
        items_length = PyList_Size(headers);
        for(i=0; i< items_length; i++)
        {
            uint8_t hdr_type;
            unsigned int flags = 0;
            PyObject *hdr_data;

            if (!PyArg_ParseTuple
                    (PyList_GetItem(headers, i), "BO|I", &hdr_type, &hdr_data,
                     &flags)) {
                PyErr_SetString(PyExc_RuntimeError, "arguments invalid");
            }
        }
    }

    object = OBEX_ObjectNew(self->obex, command);
    obj = (PyObexObject *) PyObexObject_Type.tp_new(&PyObexObject_Type, NULL,
        NULL);
    obj->inst_dict = NULL;
    obj->object = object;
    obj->obex = self;

    if (headers)
    {
        for(i = 0; i < items_length; i++) {
            PyObject *r = pyobex_object_add_header(obj, PyList_GetItem(headers, i));
            Py_XDECREF(r);
        }
    }

    i = OBEX_Request(self->obex, object);

    if (i)
    {
        PyErr_Format(PyExc_OSError, "OBEX request failed: %d", -i);
        Py_DECREF(obj);
        return NULL;
    }

    Py_INCREF(obj);
    return (PyObject *)obj;
}

static PyObject *
pyobex_set_mtu(PyObex * self, PyObject * args)
{
    uint16_t mtu_rx;
    uint16_t mtu_tx_max = 0;
    if (!PyArg_ParseTuple
            (args, "i|i:obex_set_mtu", &mtu_rx, &mtu_tx_max)) {
        return NULL;
    }

    if (mtu_tx_max == 0) {
        mtu_tx_max = OBEX_DEFAULT_MTU;
    }
    OBEX_SetTransportMTU(self->obex, mtu_rx, mtu_tx_max);
    Py_RETURN_NONE;
}

static PyObject *
pyobex_create_object(PyObex * self, PyObject * args)
{
    PyObexObject *obj;
    obex_object_t *object;
    debug("%s:%d \t%s \t%p B\n", __FILE__, __LINE__, __func__, obj);
    if (!PyInt_Check(args)) {
        PyErr_SetString(PyExc_RuntimeError, "only integer type allowed");
        return NULL;
    }
    object = OBEX_ObjectNew(self->obex, PyInt_AsLong(args));
    obj =
    (PyObexObject *) PyObexObject_Type.tp_new(&PyObexObject_Type, NULL,
                          NULL);
    obj->inst_dict = NULL;
    obj->object = object;
    Py_INCREF(self);
    obj->obex = self;
    obj->delete_explicit = 1;
    debug("%s:%d \t%s \t%p E\n", __FILE__, __LINE__, __func__, obj);
    debug("\t\tObex Object %p created\n", object);
    Py_INCREF(obj);
    return (PyObject *) obj;
}

static const char pyobex_enumerate_interfaces__doc__[] =
    "Enumerate the available interfaces/devices.\n"
    "\n"
    "Note that OpenOBEX calls devices 'interfaces' for unknown reasons.\n"
    "Use get_interface_by_index() to return the interface informations.\n"
    "\n"
    ":return: the number of interfaces found\n"
    ":rtype: int";

static PyObject *
pyobex_enumerate_interfaces(PyObex * self)
{
    int ret = OBEX_EnumerateInterfaces(self->obex);

    if (ret < 0) {
        PyErr_SetString(PyExc_RuntimeError, "EnumerateInterfaces failed");
        return NULL;
    }

    return PyInt_FromLong(ret);
}

/**
 * Wrap the given OpenOBEX IrDA interface into a Python structure.
 *
 * @return an IrdaInterface object.
**/
static PyObject *
wrap_irda_interface(PyObex * self, const obex_irda_intf_t *iface)
{
    return PyObject_CallFunction(
        PyObexIrdaInterface_Type,
        "kksbs#s",
        iface->local,
        iface->remote,
        iface->info,
        iface->charset,
        iface->hints, sizeof(iface->hints),
        iface->service);
}

static const char pyobex_get_interface_by_index__doc__[] =
    "Return information about an interface/device.\n"
    "\n"
    "enumerate_interfaces() returns the number of interfaces available.\n"
    "\n"
    ":param index: the interface index\n"
    ":type  index: int\n"
    ":return: an interface description object\n"
    ":rtype: IrdaInterface";

static PyObject *
pyobex_get_interface_by_index(PyObex * self, PyObject * args)
{
    int index;
    obex_interface_t * iface;

    if (!PyArg_ParseTuple(args, "i:get_interface_by_index", &index)) {
        return NULL;
    }

    iface = OBEX_GetInterfaceByIndex(self->obex, index);
    if (!iface) {
        PyErr_SetString(PyExc_RuntimeError, "GetInterfaceByIndex failed");
        return NULL;
    }

    switch (self->type) {
    case OBEX_TRANS_IRDA:
        return wrap_irda_interface(self, &iface->irda);
    default:
        PyErr_SetString(PyExc_TypeError, "unhandled transport type");
        return NULL;
    }
}

static const char pyobex_interface_connect__doc__[] =
    "Connect to a device using an interface index.\n"
    "\n"
    "The index should be the same used in get_interface_by_index()\n"
    "\n"
    ":param index: the interface index\n"
    ":type  index: int";

static PyObject *
pyobex_interface_connect(PyObex * self, PyObject * args)
{
    int index;
    obex_interface_t *iface;
    int rc;

    if (!PyArg_ParseTuple(args, "i:interface_connect", &index)) {
        return NULL;
    }

    iface = OBEX_GetInterfaceByIndex(self->obex, index);
    if (!iface) {
        PyErr_SetString(PyExc_ValueError, "invalid interface index");
        return NULL;
    }

    rc = OBEX_InterfaceConnect(self->obex, iface);
    if (rc < 0) {
        PyErr_SetString(PyExc_OSError, strerror(rc));
        return NULL;
    }

    Py_RETURN_NONE;
}

static const char pyobex_free_interfaces__doc__[] =
    "Free internal structures used for enumerating interfaces.\n"
    "\n"
    "This is not strictly necessary, but may be useful to free up some memory.";

static PyObject *
pyobex_free_interfaces(PyObex * self, PyObject * args)
{
    OBEX_FreeInterfaces(self->obex);
    Py_RETURN_NONE;
}

static int
pyobex_object_init(PyObexObject * self, PyObject * args, PyObject * kwds)
{
    PyObject *pyobex;
    PyObex *obex;
    int cmd;
    debug("%s:%d \t%s \t%p B\n", __FILE__, __LINE__, __func__, self);
    obex_object_t *object;
    if (!PyArg_ParseTuple(args, "Oi:obex_new", &pyobex, &cmd)) {
        PyErr_SetString(PyExc_RuntimeError, "two arguments required");
        return -1;
    }
    if (!PyObject_TypeCheck(pyobex, &PyObex_Type)) {
        PyErr_SetString(PyExc_RuntimeError,
            "first argument must be Obex type");
        return -1;
    }
    self->inst_dict = NULL;
    obex = (PyObex *) pyobex;
    object = OBEX_ObjectNew(obex->obex, cmd);
    self->object = object;
    Py_INCREF(obex);
    self->delete_explicit = 1;
    self->obex = obex;
    debug("\t\tObex Object %p created\n", object);
    debug("%s:%d \t%s \t%p E\n", __FILE__, __LINE__, __func__, self);
    return 0;
}

static void
pyobex_object_dealloc(PyObexObject * self)
{
    debug("%s:%d \t%s \t%p B\n", __FILE__, __LINE__, __func__, self);
    PyObex *obex = self->obex;
#if 0
    if (self->delete_explicit) {
    debug("\t\tObex Object %p deleted\n", self->object);
    OBEX_ObjectDelete(obex->obex, self->object);
    self->object = NULL;
    }
#endif
    Py_DECREF(obex);
    if (self->inst_dict) {
        Py_DECREF(self->inst_dict);
        self->inst_dict = 0;
    }
    self->ob_type->tp_free((PyObject *) self);
    debug("%s:%d \t%s \t%p E\n", __FILE__, __LINE__, __func__, self);
}

static PyObject *
pyobex_object_repr(PyObexObject * self)
{
    PyObex *obex = self->obex;
    return
    PyString_FromFormat
    ("<ObexObject object at %p>(obex = %p(%p), object = %p)", self,
     obex->obex, obex, self->object);
}


static PyObject *
pyobex_object_request(PyObexObject * self)
{
    PyObex *obex = self->obex;
    if (OBEX_Request(obex->obex, self->object) < 0) {
        Py_RETURN_FALSE;
    }
    Py_RETURN_TRUE;
}

static PyObject *
pyobex_object_cancel_request(PyObexObject * self, PyObject * args)
{
    PyObex *obex = self->obex;

    if (OBEX_CancelRequest(obex->obex, PyObject_IsTrue(args))) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}


static PyObject *
pyobex_object_add_header(PyObexObject * self, PyObject * args)
{
    uint8_t hdr_type;
    unsigned int flags = 0;
    Py_ssize_t hv_size = 0;
    obex_headerdata_t hv;
    PyObject *hdr_data, *null, *ucs2 = NULL;
    int size;


    if (!PyArg_ParseTuple
            (args, "BO|I:obex_object_add_header", &hdr_type, &hdr_data,
             &flags)) {
        PyErr_SetString(PyExc_RuntimeError, "arguments invalid");
        return NULL;
    }
    null = PyUnicode_FromOrdinal(0);

    switch (hdr_type & OBEX_HDR_TYPE_MASK) {
        case OBEX_HDR_TYPE_UINT32:
            if (PyInt_Check(hdr_data)) {
                hv.bq4 = (uint32_t) PyInt_AsLong(hdr_data);
                hv_size = 4;
            } else if (hdr_data == Py_None) {
                hv.bs = NULL;
                hv_size = 0;
            } else {

                Py_DECREF(null);
                PyErr_SetString(PyExc_RuntimeError,
                        "2nd argument must be integer.");
                return NULL;
            }
            break;
        case OBEX_HDR_TYPE_UINT8:
            if (PyString_Check(hdr_data)) {
                size = PyString_GET_SIZE(hdr_data);
                if (size == 1) {
                    hv.bq1 = (uint8_t) ((unsigned char)
                            *PyString_AS_STRING(hdr_data));
                    hv_size = 1;
                }
            } else if (PyUnicode_Check(hdr_data)) {
                size = PyUnicode_GET_SIZE(hdr_data);
                if (size == 1) {
                    hv.bq1 = (uint8_t) * PyUnicode_AS_UNICODE(hdr_data);
                    hv_size = 1;
                }
            } else if (PyInt_Check(hdr_data)) {
                hv.bq1 = (uint8_t) PyInt_AsLong(hdr_data);
                hv_size = 1;
            }
            if (!hv_size) {
                if (hdr_data == Py_None) {
                    hv.bs = NULL;
                } else {
                    Py_DECREF(null);
                    PyErr_SetString(PyExc_RuntimeError,
                        "2nd argument must be integer or character.");
                    return NULL;
                }
            }
            break;
        case OBEX_HDR_TYPE_BYTES:
            if (PyBuffer_Check(hdr_data)) {
                if (PyObject_AsReadBuffer
                        (hdr_data, (const void **) &hv.bs, &hv_size) < 0) {
                    Py_DECREF(null);
                    PyErr_SetString(PyExc_RuntimeError,
                        "only buffer type allowed");
                    return NULL;
                }
            } else if (PyString_Check(hdr_data)) {
                hv_size = PyString_GET_SIZE(hdr_data);
                if (hv_size) {
                    hv.bs = (uint8_t *) PyString_AS_STRING(hdr_data);
                } else
                    hv.bs = NULL;
            } else if (PyUnicode_Check(hdr_data)) {
                hv_size = PyUnicode_GET_SIZE(hdr_data);
                if (hv_size) {
                    hv.bs = (uint8_t *) PyUnicode_AS_UNICODE(hdr_data);
                } else
                    hv.bs = NULL;
            } else if (hdr_data == Py_None) {
                hv.bs = NULL;
                hv_size = 0;
            } else {
                Py_DECREF(null);
                PyErr_SetString(PyExc_RuntimeError,
                        "2nd argument must be string, unicode or buffer");
                return NULL;
            }
            break;
        case OBEX_HDR_TYPE_UNICODE:
            /* convert to UCS2 */
            if (hdr_data == Py_None) {
                hv.bs = NULL;
                hv_size = 0;
            } else if (PyUnicode_Check(hdr_data)) {
                PyObject *unicode = PySequence_Concat(hdr_data, null);
                /* must append null character */

                ucs2 = PyUnicode_AsEncodedString(unicode, "utf-16-be", NULL);
                hv.bs = (uint8_t *) PyString_AS_STRING(ucs2);
                hv_size = PyString_GET_SIZE(ucs2);

                Py_DECREF(unicode);
#ifndef NDEBUG
                int i;
                debug("code = ");
                for (i = 0; i < hv_size; i++) {
                    debug("0x%02x ", hv.bs[i]);
                }
                debug("\n");
#endif
            } else if (PyString_Check(hdr_data)) {
                PyObject *unicode = PyUnicode_FromObject(hdr_data);
                if (!unicode) {
                    Py_DECREF(null);
                    PyErr_SetString(PyExc_RuntimeError,
                        "can't convert string to unicode");
                    return NULL;
                }
                /* must append null character */
                unicode = PySequence_InPlaceConcat(unicode, null);

                ucs2 = PyUnicode_AsEncodedString(unicode, "utf-16-be", NULL);
                hv.bs = (uint8_t *) PyString_AS_STRING(ucs2);
                hv_size = PyString_GET_SIZE(ucs2);
                Py_DECREF(unicode);
#ifndef NDEBUG
                int i;
                debug("code = ");
                for (i = 0; i < hv_size; i++) {
                    debug("0x%02x ", hv.bs[i]);
                }
                debug("\n");
#endif
            } else {
                Py_DECREF(null);
                PyErr_SetString(PyExc_RuntimeError,
                        "2nd argument must be string or unicode");
                return NULL;
            }
            break;
        default:
            Py_DECREF(null);
            PyErr_SetString(PyExc_RuntimeError, "header type is invalid.");
            return NULL;
    }

    if (ucs2) {
        Py_DECREF(ucs2);
    }
    Py_DECREF(null);

    PyObex *obex = self->obex;
    if (OBEX_ObjectAddHeader
            (obex->obex, self->object, hdr_type, hv, hv_size, flags) < 0) {
        Py_RETURN_FALSE;
    }
    Py_RETURN_TRUE;
}

static PyObject *
pyobex_object_get_headers(PyObexObject * self)
{
    obex_headerdata_t hv;
    uint8_t hdr_type;
    Py_ssize_t hv_size;
    PyObject *object, *key, *dict;
    int r;

    PyObex *obex = self->obex;
    dict = PyDict_New();
    while ((r = OBEX_ObjectGetNextHeader
            (obex->obex, self->object, &hdr_type, &hv, (uint32_t *)&hv_size))) {
        if (r < 0) {
            Py_DECREF(dict);
            PyErr_SetString(PyExc_RuntimeError, "header is invalid.");
            return NULL;
        }
        int byteorder = 1;
        switch (hdr_type & OBEX_HDR_TYPE_MASK) {
            case OBEX_HDR_TYPE_UINT32:
                object = PyInt_FromLong(hv.bq4);
                break;
            case OBEX_HDR_TYPE_UINT8:
                object = PyInt_FromLong((long) hv.bq1);
                break;
            case OBEX_HDR_TYPE_BYTES:
                object = PyString_FromStringAndSize((void *) hv.bs, hv_size);
                break;
            case OBEX_HDR_TYPE_UNICODE:
                object =
                PyUnicode_DecodeUTF16((const char *) hv.bs, hv_size, NULL,
                              &byteorder);
                if (!object) {
                    Py_DECREF(dict);
                    PyErr_SetString(PyExc_RuntimeError, "invalid unicode.");
                    return NULL;
                }
                break;
            default:
                Py_DECREF(dict);
                PyErr_SetString(PyExc_RuntimeError, "header type is invalid.");
                return NULL;
        }
        key = PyInt_FromLong(hdr_type);
        PyDict_SetItem(dict, key, object);
        Py_DECREF(key);
        Py_DECREF(object);
    }
    return dict;
}

static PyObject *
pyobex_object_set_header_offset(PyObexObject * self, PyObject * args)
{
    unsigned int offset;
    if (!PyInt_Check(args)) {
        PyErr_SetString(PyExc_RuntimeError, "only integer type allowed");
        return NULL;
    }
    offset = PyInt_AsUnsignedLongMask(args);
    OBEX_ObjectSetHdrOffset(self->object, offset);
    Py_RETURN_NONE;
}

static PyObject *
pyobex_object_reparse_headers(PyObexObject * self)
{
    PyObex *obex = self->obex;
    if (OBEX_ObjectReParseHeaders(obex->obex, self->object)) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *
pyobex_object_start_read_stream(PyObexObject * self)
{
    PyObex *obex = self->obex;
    OBEX_ObjectReadStream(obex->obex, self->object, NULL);
    Py_RETURN_NONE;
}


static PyObject *
pyobex_object_read_stream(PyObexObject * self)
{
    PyObex *obex = self->obex;
    const uint8_t *buf;
    int len;
    len = OBEX_ObjectReadStream(obex->obex, self->object, &buf);
    if (len == 0) {
        Py_RETURN_NONE;
    } else if (len < 0) {
        PyErr_Format(PyExc_RuntimeError, "read failed: %d", len);
        return NULL;
    }
    return PyBuffer_FromMemory((void *) buf, len);
}

static PyObject *
pyobex_object_set_response(PyObexObject * self, PyObject * args)
{
    uint8_t rsp, lastrsp;
    if (!PyArg_ParseTuple
            (args, "BB:obex_object_set_response", &rsp, &lastrsp)) {
        PyErr_SetString(PyExc_RuntimeError,
            "two integer arguments required");
        return NULL;
    }
    OBEX_ObjectSetRsp(self->object, rsp, lastrsp);
    Py_RETURN_NONE;
}

static PyObject *
pyobex_object_get_data(PyObexObject * self)
{
    uint8_t *buf;
    int len;
    len = OBEX_ObjectGetNonHdrData(self->object, &buf);
    if (len == 0) {
        Py_RETURN_NONE;
    }
    return PyBuffer_FromMemory((void *) buf, len);
}

static PyObject *
pyobex_object_set_data(PyObexObject * self, PyObject * args)
{
    if (!PyBuffer_Check(args)) {
        PyErr_SetString(PyExc_RuntimeError, "only buffer type allowed");
        return NULL;
    }
    Py_ssize_t len;
    const uint8_t *buf;
    if (PyObject_AsReadBuffer(args, (const void **) &buf, &len) < 0) {
        PyErr_SetString(PyExc_RuntimeError, "invalid buffer");
    }

    if (OBEX_ObjectSetNonHdrData(self->object, buf, len) < 0) {
        Py_RETURN_FALSE;
    } else {
        Py_RETURN_TRUE;
    }
}

static PyObject *
pyobex_object_get_obex(PyObexObject * self)
{
    PyObex *obex = self->obex;
    Py_INCREF(obex);
    return (PyObject *) obex;
}



static PyMethodDef pyobex_methods[] = {
    {"register", (PyCFunction) pyobex_register, METH_VARARGS},
    {"get_userdata", (PyCFunction) pyobex_getuserdata, METH_NOARGS},
    {"set_userdata", (PyCFunction) pyobex_setuserdata, METH_O},
    {"fileno", (PyCFunction) pyobex_fileno, METH_NOARGS},
    {"connect", (PyCFunction) pyobex_connect, METH_VARARGS},
    {"disconnect", (PyCFunction) pyobex_disconnect, METH_NOARGS},
    {"accept", (PyCFunction) pyobex_accept, METH_NOARGS},
    {"set_callbacks", (PyCFunction) pyobex_set_callbacks, METH_O},
    {"handle", (PyCFunction) pyobex_handle, METH_VARARGS},
    {"create_object", (PyCFunction) pyobex_create_object, METH_O},
    {"request_object", (PyCFunction) pyobex_request_object, METH_VARARGS},
    {"set_mtu", (PyCFunction) pyobex_set_mtu, METH_VARARGS},
    {"enumerate_interfaces", (PyCFunction) pyobex_enumerate_interfaces, METH_NOARGS, pyobex_enumerate_interfaces__doc__},
    {"get_interface_by_index", (PyCFunction) pyobex_get_interface_by_index, METH_VARARGS, pyobex_get_interface_by_index__doc__},
    {"interface_connect", (PyCFunction) pyobex_interface_connect, METH_VARARGS, pyobex_interface_connect__doc__},
    {"free_interfaces", (PyCFunction) pyobex_free_interfaces, METH_NOARGS, pyobex_free_interfaces__doc__},
    {NULL, NULL},
};

static PyMethodDef pyobex_object_methods[] = {
    {"get_obex", (PyCFunction) pyobex_object_get_obex, METH_NOARGS},
    {"reparse", (PyCFunction) pyobex_object_reparse_headers,
         METH_NOARGS},
    {"start_read", (PyCFunction) pyobex_object_start_read_stream,
         METH_NOARGS},
    {"read", (PyCFunction) pyobex_object_read_stream, METH_NOARGS},
    {"request", (PyCFunction) pyobex_object_request, METH_NOARGS},
    {"cancel", (PyCFunction) pyobex_object_cancel_request, METH_O},
    {"set_response", (PyCFunction) pyobex_object_set_response,
         METH_VARARGS},
    {"get_data", (PyCFunction) pyobex_object_get_data, METH_NOARGS},
    {"set_data", (PyCFunction) pyobex_object_set_data, METH_O},
    {"set_header_offset",
         (PyCFunction) pyobex_object_set_header_offset,
         METH_O},
    {"add_header", (PyCFunction) pyobex_object_add_header,
         METH_VARARGS},
    {"get_headers", (PyCFunction) pyobex_object_get_headers,
         METH_NOARGS},
    {NULL, NULL},
};

static char PyObex_Type__doc__[] = "OBEX wrapper.";
static PyTypeObject PyObex_Type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,            /* ob_size */
    "Obex",            /* tp_name */
    sizeof(PyObex),        /* tp_basicsize */
    0,                /* tp_itemsize */
    (destructor) pyobex_dealloc,    /* tp_dealloc */
    (printfunc) 0,        /* tp_print */
    (getattrfunc) 0,        /* tp_getattr */
    (setattrfunc) 0,        /* tp_setattr */
    (cmpfunc) 0,        /* tp_compare */
    (reprfunc) pyobex_repr,    /* tp_repr */
    0,                /* tp_as_number */
    0,                /* tp_as_sequence */
    0,                /* tp_as_mapping */
    (hashfunc) 0,        /* tp_hash */
    (ternaryfunc) 0,        /* tp_call */
    (reprfunc) pyobex_repr,    /* tp_str */
    PyObject_GenericGetAttr,    /* tp_getattro */
    PyObject_GenericSetAttr,    /* tp_setattro */
    0L,                /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_CLASS | Py_TPFLAGS_BASETYPE,/* tp_flags */
    PyObex_Type__doc__,
    0,                /* tp_traverse */
    0,                /* tp_clear */
    0,                /* tp_richcompare */
    0,                /* tp_weaklistoffset */
    0,                /* tp_iter */
    0,                /* tp_iternext */
    pyobex_methods,        /* tp_methods */
    0,                /* tp_members */
    0,                /* tp_getset */
    0,                /* tp_base */
    0,                /* tp_dict */
    0,                /* tp_descr_get */
    0,                /* tp_descr_set */
    offsetof(PyObex, inst_dict),    /* tp_dictoffset */
    (initproc) pyobex_init,    /* tp_init */
    PyType_GenericAlloc,    /* tp_alloc */
    PyType_GenericNew,        /* tp_new */
    _PyObject_Del,        /* tp_free */
};

static char PyObexObject_Type__doc__[] = "OBEX Object wrapper.";
static PyTypeObject PyObexObject_Type = {
    PyObject_HEAD_INIT(&PyType_Type)
    0,            /* ob_size */
    "ObexObject",        /* tp_name */
    sizeof(PyObexObject),    /* tp_basicsize */
    0,                /* tp_itemsize */
    (destructor) pyobex_object_dealloc,    /* tp_dealloc */
    (printfunc) 0,        /* tp_print */
    (getattrfunc) 0,        /* tp_getattr */
    (setattrfunc) 0,        /* tp_setattr */
    (cmpfunc) 0,        /* tp_compare */
    (reprfunc) pyobex_object_repr,    /* tp_repr */
    0,                /* tp_as_number */
    0,                /* tp_as_sequence */
    0,                /* tp_as_mapping */
    (hashfunc) 0,        /* tp_hash */
    (ternaryfunc) 0,        /* tp_call */
    (reprfunc) pyobex_object_repr,    /* tp_str */
    PyObject_GenericGetAttr,    /* tp_getattro */
    PyObject_GenericSetAttr,    /* tp_setattro */
    0L,                /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_CLASS | Py_TPFLAGS_BASETYPE,/* tp_flags */
    PyObexObject_Type__doc__,
    0,                /* tp_traverse */
    0,                /* tp_clear */
    0,                /* tp_richcompare */
    0,                /* tp_weaklistoffset */
    0,                /* tp_iter */
    0,                /* tp_iternext */
    pyobex_object_methods,    /* tp_methods */
    0,                /* tp_members */
    0,                /* tp_getset */
    0,                /* tp_base */
    0,                /* tp_dict */
    0,                /* tp_descr_get */
    0,                /* tp_descr_set */
    offsetof(PyObexObject, inst_dict),    /* tp_dictoffset */
    (initproc) pyobex_object_init,    /* tp_init */
    PyType_GenericAlloc,    /* tp_alloc */
    PyType_GenericNew,        /* tp_new */
    _PyObject_Del,        /* tp_free */
};

/**
 * Create a Python type for the get_interface_by_index() return value.
 *
 * This uses a namedtuple to create something we can return to the user.
 *
 * @return a PyObject of a class type, or NULL on error.
**/
static PyObject *
pyobex_create_irda_interface_type(void)
{
    PyObject * collections = PyImport_ImportModule("collections");

    if (!collections)
        return NULL;

    PyObject * ret = PyObject_CallMethod(
        collections, "namedtuple",
        "s(ssssss)",
        "IrdaInterface",
        "local", "remote", "info", "charset", "hints", "services");

    Py_DECREF(collections);

    return ret;
}

static PyMethodDef _ObexMethods[] = {
    {NULL, NULL, 0, NULL}
};

void
init_obex()
{
    PyObject *m;
    PyObject *d;

    PyObexIrdaInterface_Type = pyobex_create_irda_interface_type();

    m = Py_InitModule("_obex", _ObexMethods);
    d = PyModule_GetDict(m);

    PyDict_SetItemString(d, "Obex", (PyObject *) & PyObex_Type);
    PyDict_SetItemString(d, "ObexObject",
             (PyObject *) & PyObexObject_Type);

    PyModule_AddIntConstant(m, "MODE_CLIENT", OBEX_MODE_CLIENT);
    PyModule_AddIntConstant(m, "MODE_SERVER", OBEX_MODE_SERVER);
    PyModule_AddIntConstant(m, "EV_PROGRESS", OBEX_EV_PROGRESS);
    PyModule_AddIntConstant(m, "EV_REQHINT", OBEX_EV_REQHINT);
    PyModule_AddIntConstant(m, "EV_REQ", OBEX_EV_REQ);
    PyModule_AddIntConstant(m, "EV_REQDONE", OBEX_EV_REQDONE);
    PyModule_AddIntConstant(m, "EV_LINKERR", OBEX_EV_LINKERR);
    PyModule_AddIntConstant(m, "EV_PARSEERR", OBEX_EV_PARSEERR);
    PyModule_AddIntConstant(m, "EV_ACCEPTHINT", OBEX_EV_ACCEPTHINT);
    PyModule_AddIntConstant(m, "EV_ABORT", OBEX_EV_ABORT);
    PyModule_AddIntConstant(m, "EV_STREAMEMPTY", OBEX_EV_STREAMEMPTY);
    PyModule_AddIntConstant(m, "EV_STREAMAVAIL", OBEX_EV_STREAMAVAIL);
    PyModule_AddIntConstant(m, "EV_UNEXPECTED", OBEX_EV_UNEXPECTED);
    PyModule_AddIntConstant(m, "EV_REQCHECK", OBEX_EV_REQCHECK);

    PyModule_AddIntConstant(m, "FL_KEEPSERVER", OBEX_FL_KEEPSERVER);
    PyModule_AddIntConstant(m, "FL_FILTERHINT", OBEX_FL_FILTERHINT);
    PyModule_AddIntConstant(m, "FL_FILTERIAS", OBEX_FL_FILTERIAS);

    PyModule_AddIntConstant(m, "FL_FIT_ONE_PACKET",
                OBEX_FL_FIT_ONE_PACKET);
    PyModule_AddIntConstant(m, "FL_STREAM_START", OBEX_FL_STREAM_START);
    PyModule_AddIntConstant(m, "FL_STREAM_DATA", OBEX_FL_STREAM_DATA);
    PyModule_AddIntConstant(m, "FL_STREAM_DATAEND",
                OBEX_FL_STREAM_DATAEND);

    PyModule_AddIntConstant(m, "TRANS_IRDA", OBEX_TRANS_IRDA);
    PyModule_AddIntConstant(m, "TRANS_INET", OBEX_TRANS_INET);
    PyModule_AddIntConstant(m, "TRANS_BLUETOOTH", OBEX_TRANS_BLUETOOTH);
    PyModule_AddIntConstant(m, "TRANS_FD", OBEX_TRANS_FD);

    PyModule_AddIntConstant(m, "HDR_COUNT", OBEX_HDR_COUNT);
    PyModule_AddIntConstant(m, "HDR_NAME", OBEX_HDR_NAME);
    PyModule_AddIntConstant(m, "HDR_TYPE", OBEX_HDR_TYPE);
    PyModule_AddIntConstant(m, "HDR_TIME", OBEX_HDR_TIME);
    PyModule_AddIntConstant(m, "HDR_TIME2", OBEX_HDR_TIME2);
    PyModule_AddIntConstant(m, "HDR_LENGTH", OBEX_HDR_LENGTH);
    PyModule_AddIntConstant(m, "HDR_DESCRIPTION", OBEX_HDR_DESCRIPTION);
    PyModule_AddIntConstant(m, "HDR_TARGET", OBEX_HDR_TARGET);
    PyModule_AddIntConstant(m, "HDR_BODY", OBEX_HDR_BODY);
    PyModule_AddIntConstant(m, "HDR_BODY_END", OBEX_HDR_BODY_END);
    PyModule_AddIntConstant(m, "HDR_WHO", OBEX_HDR_WHO);
    PyModule_AddIntConstant(m, "HDR_APPARAM", OBEX_HDR_APPARAM);
    PyModule_AddIntConstant(m, "HDR_AUTHCHAL", OBEX_HDR_AUTHCHAL);
    PyModule_AddIntConstant(m, "HDR_AUTHRESP", OBEX_HDR_AUTHRESP);
    PyModule_AddIntConstant(m, "HDR_CONNECTION", OBEX_HDR_CONNECTION);
    PyModule_AddIntConstant(m, "HDR_CREATOR", OBEX_HDR_CREATOR);
    PyModule_AddIntConstant(m, "HDR_WANUUID", OBEX_HDR_WANUUID);
    PyModule_AddIntConstant(m, "HDR_OBJECTCLASS", OBEX_HDR_OBJECTCLASS);
    PyModule_AddIntConstant(m, "HDR_SESSIONPARAM", OBEX_HDR_SESSIONPARAM);
    PyModule_AddIntConstant(m, "HDR_SESSIONSEQ", OBEX_HDR_SESSIONSEQ);

    PyModule_AddIntConstant(m, "CMD_CONNECT", OBEX_CMD_CONNECT);
    PyModule_AddIntConstant(m, "CMD_DISCONNECT", OBEX_CMD_DISCONNECT);
    PyModule_AddIntConstant(m, "CMD_PUT", OBEX_CMD_PUT);
    PyModule_AddIntConstant(m, "CMD_GET", OBEX_CMD_GET);
    PyModule_AddIntConstant(m, "CMD_SETPATH", OBEX_CMD_SETPATH);
    PyModule_AddIntConstant(m, "CMD_SESSION", OBEX_CMD_SESSION);
    PyModule_AddIntConstant(m, "CMD_ABORT", OBEX_CMD_ABORT);
    PyModule_AddIntConstant(m, "FINAL", OBEX_FINAL);

    PyModule_AddIntConstant(m, "RSP_CONTINUE", OBEX_RSP_CONTINUE);
    PyModule_AddIntConstant(m, "RSP_SWITCH_PRO", OBEX_RSP_SWITCH_PRO);
    PyModule_AddIntConstant(m, "RSP_SUCCESS", OBEX_RSP_SUCCESS);
    PyModule_AddIntConstant(m, "RSP_CREATED", OBEX_RSP_CREATED);
    PyModule_AddIntConstant(m, "RSP_ACCEPTED", OBEX_RSP_ACCEPTED);
    PyModule_AddIntConstant(m, "RSP_NO_CONTENT", OBEX_RSP_NO_CONTENT);
    PyModule_AddIntConstant(m, "RSP_BAD_REQUEST", OBEX_RSP_BAD_REQUEST);
    PyModule_AddIntConstant(m, "RSP_UNAUTHORIZED", OBEX_RSP_UNAUTHORIZED);
    PyModule_AddIntConstant(m, "RSP_PAYMENT_REQUIRED",
                OBEX_RSP_PAYMENT_REQUIRED);
    PyModule_AddIntConstant(m, "RSP_FORBIDDEN", OBEX_RSP_FORBIDDEN);
    PyModule_AddIntConstant(m, "RSP_NOT_FOUND", OBEX_RSP_NOT_FOUND);
    PyModule_AddIntConstant(m, "RSP_METHOD_NOT_ALLOWED",
                OBEX_RSP_METHOD_NOT_ALLOWED);
    PyModule_AddIntConstant(m, "RSP_CONFLICT", OBEX_RSP_CONFLICT);
    PyModule_AddIntConstant(m, "RSP_INTERNAL_SERVER_ERROR",
                OBEX_RSP_INTERNAL_SERVER_ERROR);
    PyModule_AddIntConstant(m, "RSP_NOT_IMPLEMENTED",
                OBEX_RSP_NOT_IMPLEMENTED);
    PyModule_AddIntConstant(m, "RSP_DATABASE_FULL",
                OBEX_RSP_DATABASE_FULL);
    PyModule_AddIntConstant(m, "RSP_DATABASE_LOCKED",
                OBEX_RSP_DATABASE_LOCKED);

    PyModule_AddIntConstant(m, "DEFAULT_MTU", OBEX_DEFAULT_MTU);
    PyModule_AddIntConstant(m, "MINIMUM_MTU", OBEX_MINIMUM_MTU);
    PyModule_AddIntConstant(m, "MAXIMUM_MTU", OBEX_MAXIMUM_MTU);
    PyModule_AddIntConstant(m, "IRDA_OPT_MTU", OBEX_IRDA_OPT_MTU);
}
