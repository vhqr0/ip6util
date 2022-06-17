/* The missing bindings for socket options. */

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <netinet/icmp6.h>

static PyObject *icmp6setfilter(PyObject *self, PyObject *args) {
  int sockfd, icmp6type;
  struct icmp6_filter filter;

  if (!PyArg_ParseTuple(args, "II", &sockfd, &icmp6type))
    return NULL;

  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS(icmp6type, &filter);
  if (setsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                 sizeof(filter)) < 0)
    return PyErr_SetFromErrno(PyExc_OSError);

  Py_RETURN_NONE;
}

static PyMethodDef icmp6filter_Methods[] = {
    {"icmp6setfilter", icmp6setfilter, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}};

static PyModuleDef icmp6filter_Module = {
    PyModuleDef_HEAD_INIT, "icmp6filter_pym", NULL, -1, icmp6filter_Methods};

PyMODINIT_FUNC PyInit_icmp6filter_pym() {
  return PyModule_Create(&icmp6filter_Module);
}
