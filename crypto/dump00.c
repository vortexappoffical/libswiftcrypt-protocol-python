#include <Python.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16

// Function to generate a 256-bit AES key
static PyObject* generate_key(PyObject* self, PyObject* args) {
    unsigned char key[AES_KEY_SIZE / 8];
    if (!RAND_bytes(key, sizeof(key))) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to generate key");
        return NULL;
    }
    return PyBytes_FromStringAndSize((char*)key, sizeof(key));
}

// Function to encrypt text using AES IGE
static PyObject* encrypt_text(PyObject* self, PyObject* args) {
    const char* plaintext;
    const char* key;
    const char* iv;
    int plaintext_len, key_len, iv_len;

    if (!PyArg_ParseTuple(args, "y#y#y#", &plaintext, &plaintext_len, &key, &key_len, &iv, &iv_len)) {
        return NULL;
    }

    if (key_len != AES_KEY_SIZE / 8 || iv_len != AES_BLOCK_SIZE * 2) {
        PyErr_SetString(PyExc_ValueError, "Invalid key or IV size");
        return NULL;
    }

    int ciphertext_len = ((plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    if (!ciphertext) {
        PyErr_SetString(PyExc_RuntimeError, "Memory allocation error");
        return NULL;
    }
    
    AES_KEY aes_key;
    AES_set_encrypt_key((const unsigned char*)key, AES_KEY_SIZE, &aes_key);
    unsigned char iv_copy[AES_BLOCK_SIZE * 2];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE * 2);
    AES_ige_encrypt((const unsigned char*)plaintext, ciphertext, plaintext_len, &aes_key, iv_copy, AES_ENCRYPT);

    PyObject* result = PyBytes_FromStringAndSize((char*)ciphertext, ciphertext_len);
    free(ciphertext);
    return result;
}

// Function to decrypt text using AES IGE
static PyObject* decrypt_text(PyObject* self, PyObject* args) {
    const char* ciphertext;
    const char* key;
    const char* iv;
    int ciphertext_len, key_len, iv_len;

    if (!PyArg_ParseTuple(args, "y#y#y#", &ciphertext, &ciphertext_len, &key, &key_len, &iv, &iv_len)) {
        return NULL;
    }

    if (key_len != AES_KEY_SIZE / 8 || iv_len != AES_BLOCK_SIZE * 2) {
        PyErr_SetString(PyExc_ValueError, "Invalid key or IV size");
        return NULL;
    }

    unsigned char* plaintext = (unsigned char*)malloc(ciphertext_len);
    if (!plaintext) {
        PyErr_SetString(PyExc_RuntimeError, "Memory allocation error");
        return NULL;
    }
    
    AES_KEY aes_key;
    AES_set_decrypt_key((const unsigned char*)key, AES_KEY_SIZE, &aes_key);
    unsigned char iv_copy[AES_BLOCK_SIZE * 2];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE * 2);
    AES_ige_encrypt((const unsigned char*)ciphertext, plaintext, ciphertext_len, &aes_key, iv_copy, AES_DECRYPT);

    PyObject* result = PyBytes_FromStringAndSize((char*)plaintext, ciphertext_len);
    free(plaintext);
    return result;
}

// Function to encrypt a file using AES IGE
static PyObject* encrypt_file(PyObject* self, PyObject* args) {
    const char* input_file;
    const char* output_file;
    const char* key;
    const char* iv;
    int key_len, iv_len;

    if (!PyArg_ParseTuple(args, "ssy#y#", &input_file, &output_file, &key, &key_len, &iv, &iv_len)) {
        return NULL;
    }

    if (key_len != AES_KEY_SIZE / 8 || iv_len != AES_BLOCK_SIZE * 2) {
        PyErr_SetString(PyExc_ValueError, "Invalid key or IV size");
        return NULL;
    }

    FILE* ifp = fopen(input_file, "rb");
    if (!ifp) {
        PyErr_SetString(PyExc_IOError, "Failed to open input file");
        return NULL;
    }

    FILE* ofp = fopen(output_file, "wb");
    if (!ofp) {
        fclose(ifp);
        PyErr_SetString(PyExc_IOError, "Failed to open output file");
        return NULL;
    }

    AES_KEY aes_key;
    AES_set_encrypt_key((const unsigned char*)key, AES_KEY_SIZE, &aes_key);
    unsigned char iv_copy[AES_BLOCK_SIZE * 2];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE * 2);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char ciphertext[AES_BLOCK_SIZE];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, ifp)) > 0) {
        if (bytes_read < AES_BLOCK_SIZE) {
            memset(buffer + bytes_read, AES_BLOCK_SIZE - bytes_read, AES_BLOCK_SIZE - bytes_read);
        }
        AES_ige_encrypt(buffer, ciphertext, AES_BLOCK_SIZE, &aes_key, iv_copy, AES_ENCRYPT);
        fwrite(ciphertext, 1, AES_BLOCK_SIZE, ofp);
    }

    fclose(ifp);
    fclose(ofp);

    Py_RETURN_NONE;
}

// Function to decrypt a file using AES IGE
static PyObject* decrypt_file(PyObject* self, PyObject* args) {
    const char* input_file;
    const char* output_file;
    const char* key;
    const char* iv;
    int key_len, iv_len;

    if (!PyArg_ParseTuple(args, "ssy#y#", &input_file, &output_file, &key, &key_len, &iv, &iv_len)) {
        return NULL;
    }

    if (key_len != AES_KEY_SIZE / 8 || iv_len != AES_BLOCK_SIZE * 2) {
        PyErr_SetString(PyExc_ValueError, "Invalid key or IV size");
        return NULL;
    }

    FILE* ifp = fopen(input_file, "rb");
    if (!ifp) {
        PyErr_SetString(PyExc_IOError, "Failed to open input file");
        return NULL;
    }

    FILE* ofp = fopen(output_file, "wb");
    if (!ofp) {
        fclose(ifp);
        PyErr_SetString(PyExc_IOError, "Failed to open output file");
        return NULL;
    }

    AES_KEY aes_key;
    AES_set_decrypt_key((const unsigned char*)key, AES_KEY_SIZE, &aes_key);
    unsigned char iv_copy[AES_BLOCK_SIZE * 2];
    memcpy(iv_copy, iv, AES_BLOCK_SIZE * 2);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char plaintext[AES_BLOCK_SIZE];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, ifp)) > 0) {
        AES_ige_encrypt(buffer, plaintext, AES_BLOCK_SIZE, &aes_key, iv_copy, AES_DECRYPT);
        int padding = plaintext[AES_BLOCK_SIZE - 1];
        if (padding < 1 || padding > AES_BLOCK_SIZE) {
            padding = 0;
        }
        fwrite(plaintext, 1, AES_BLOCK_SIZE - padding, ofp);
    }

    fclose(ifp);
    fclose(ofp);

    Py_RETURN_NONE;
}

// Function to encrypt metadata
static PyObject* encrypt_metadata(PyObject* self, PyObject* args) {
    return encrypt_text(self, args);
}

// Function to decrypt metadata
static PyObject* decrypt_metadata(PyObject* self, PyObject* args) {
    return decrypt_text(self, args);
}

static PyMethodDef AESMethods[] = {
    {"generate_key", generate_key, METH_VARARGS, "Generate a 256-bit AES key"},
    {"encrypt_text", encrypt_text, METH_VARARGS, "Encrypt text using AES IGE"},
    {"decrypt_text", decrypt_text, METH_VARARGS, "Decrypt text using AES IGE"},
    {"encrypt_file", encrypt_file, METH_VARARGS, "Encrypt a file using AES IGE"},
    {"decrypt_file", decrypt_file, METH_VARARGS, "Decrypt a file using AES IGE"},
    {"encrypt_metadata", encrypt_metadata, METH_VARARGS, "Encrypt metadata using AES IGE"},
    {"decrypt_metadata", decrypt_metadata, METH_VARARGS, "Decrypt metadata using AES IGE"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef aesmodule = {
    PyModuleDef_HEAD_INIT,
    "aes_ige",
    NULL,
    -1,
    AESMethods
};

PyMODINIT_FUNC PyInit_aes_ige(void) {
    return PyModule_Create(&aesmodule);
}
