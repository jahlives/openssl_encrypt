#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <Python.h>

/* FFI wrapper for mobile crypto functions */

// Global Python module reference
static PyObject *crypto_module = NULL;

// Initialize Python and import our crypto module
int init_crypto_ffi() {
    if (Py_IsInitialized()) {
        return 1; // Already initialized
    }
    
    // Save and redirect stderr before Python initialization
    int stderr_fd = dup(STDERR_FILENO);
    int null_fd = open("/dev/null", O_WRONLY);
    dup2(null_fd, STDERR_FILENO);
    close(null_fd);
    
    // Force environment variables before Python init
    putenv("PYTHONWARNINGS=ignore");
    putenv("PYTHONNOUSERSITE=1");
    
    Py_Initialize();
    
    // Restore stderr
    dup2(stderr_fd, STDERR_FILENO);
    close(stderr_fd);
    
    if (!Py_IsInitialized()) {
        return 0;
    }
    
    // Suppress any remaining warnings at Python level
    PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");
    PyRun_SimpleString("import logging; logging.disable(logging.WARNING)");
    
    // Add current directory to Python path
    PyRun_SimpleString("import sys\nsys.path.append('.')");
    
    // Import our mobile crypto module
    crypto_module = PyImport_ImportModule("mobile_crypto_core");
    if (!crypto_module) {
        PyErr_Print();
        return 0;
    }
    
    return 1;
}

// Cleanup Python
void cleanup_crypto_ffi() {
    if (crypto_module) {
        Py_DECREF(crypto_module);
        crypto_module = NULL;
    }
    if (Py_IsInitialized()) {
        Py_Finalize();
    }
}

// Helper function to call Python function and return string result
char* call_python_function(const char* func_name, const char* arg1, const char* arg2) {
    if (!crypto_module) {
        return strdup("ERROR: Crypto module not initialized");
    }
    
    PyObject *func = PyObject_GetAttrString(crypto_module, func_name);
    if (!func || !PyCallable_Check(func)) {
        Py_XDECREF(func);
        return strdup("ERROR: Function not found or not callable");
    }
    
    PyObject *args = NULL;
    PyObject *arg1_obj = NULL;
    PyObject *arg2_obj = NULL;
    
    if (arg2) {
        arg1_obj = PyUnicode_FromString(arg1);
        arg2_obj = PyUnicode_FromString(arg2);
        args = PyTuple_Pack(2, arg1_obj, arg2_obj);
        Py_DECREF(arg1_obj);
        Py_DECREF(arg2_obj);
    } else if (arg1) {
        arg1_obj = PyUnicode_FromString(arg1);
        args = PyTuple_Pack(1, arg1_obj);
        Py_DECREF(arg1_obj);
    } else {
        args = PyTuple_New(0);
    }
    
    PyObject *result = PyObject_CallObject(func, args);
    Py_DECREF(args);
    Py_DECREF(func);
    
    if (!result) {
        PyErr_Print();
        return strdup("ERROR: Function call failed");
    }
    
    const char *result_str = PyUnicode_AsUTF8(result);
    if (!result_str) {
        Py_DECREF(result);
        return strdup("ERROR: Failed to convert result to string");
    }
    
    char *copy = strdup(result_str);
    Py_DECREF(result);
    
    return copy;
}

// FFI functions for Flutter

char* mobile_crypto_encrypt_text(const char* text, const char* password) {
    return call_python_function("mobile_encrypt_text", text, password);
}

char* mobile_crypto_decrypt_text(const char* encrypted_json, const char* password) {
    return call_python_function("mobile_decrypt_text", encrypted_json, password);
}

char* mobile_crypto_get_algorithms() {
    return call_python_function("mobile_get_algorithms", NULL, NULL);
}

// Free memory allocated by this library
void free_crypto_string(char* str) {
    if (str) {
        free(str);
    }
}