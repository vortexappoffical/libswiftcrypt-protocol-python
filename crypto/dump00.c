#include <Python.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define AES_KEY_LENGTH 256
#define AES_BLOCK_SIZE 16

static PyObject *generate_key(PyObject *self, PyObject *args) {
    unsigned char key[AES_KEY_LENGTH/8];
    if (!RAND_bytes(key, sizeof(key))) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to generate key");
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)key, sizeof(key));
}

static PyObject *encrypt_data(PyObject *self, PyObject *args, int is_metadata) {
    const char *data;
    unsigned char key[AES_KEY_LENGTH/8];
    unsigned char iv[AES_BLOCK_SIZE];
    int data_len;
    if (!PyArg_ParseTuple(args, "s#y#y#", &data, &data_len, &key, sizeof(key), &iv, sizeof(iv))) {
        return NULL;
    }

    int encrypted_len = ((data_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *encrypted = malloc(encrypted_len);
    if (!encrypted) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory for encryption");
        return NULL;
    }

    AES_KEY aes_key;
    AES_set_encrypt_key(key, AES_KEY_LENGTH, &aes_key);
    AES_ige_encrypt((unsigned char *)data, encrypted, data_len, &aes_key, iv, AES_ENCRYPT);

    PyObject *result = PyBytes_FromStringAndSize((const char *)encrypted, encrypted_len);
    free(encrypted);
    return result;
}

static PyObject *decrypt_data(PyObject *self, PyObject *args, int is_metadata) {
    const unsigned char *data;
    unsigned char key[AES_KEY_LENGTH/8];
    unsigned char iv[AES_BLOCK_SIZE];
    int data_len;
    if (!PyArg_ParseTuple(args, "y#y#y#", &data, &data_len, &key, sizeof(key), &iv, sizeof(iv))) {
        return NULL;
    }

    unsigned char *decrypted = malloc(data_len);
    if (!decrypted) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory for decryption");
        return NULL;
    }

    AES_KEY aes_key;
    AES_set_decrypt_key(key, AES_KEY_LENGTH, &aes_key);
    AES_ige_encrypt(data, decrypted, data_len, &aes_key, iv, AES_DECRYPT);

    PyObject *result = PyBytes_FromStringAndSize((const char *)decrypted, data_len);
    free(decrypted);
    return result;
}

static PyObject *encrypt_text(PyObject *self, PyObject *args) {
    return encrypt_data(self, args, 0);
}

static PyObject *decrypt_text(PyObject *self, PyObject *args) {
    return decrypt_data(self, args, 0);
}

static PyObject *encrypt_metadata(PyObject *self, PyObject *args) {
    return encrypt_data(self, args, 1);
}

static PyObject *decrypt_metadata(PyObject *self, PyObject *args) {
    return decrypt_data(self, args, 1);
}

static PyObject *encrypt_file(PyObject *self, PyObject *args) {
    const char *input_filename, *output_filename;
    unsigned char key[AES_KEY_LENGTH/8];
    unsigned char iv[AES_BLOCK_SIZE];
    if (!PyArg_ParseTuple(args, "ssy#y#", &input_filename, &output_filename, &key, sizeof(key), &iv, sizeof(iv))) {
        return NULL;
    }

    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        PyErr_SetString(PyExc_FileNotFoundError, "Input file not found");
        return NULL;
    }

    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        fclose(input_file);
        PyErr_SetString(PyExc_FileNotFoundError, "Could not open output file");
        return NULL;
    }

    AES_KEY aes_key;
    AES_set_encrypt_key(key, AES_KEY_LENGTH, &aes_key);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char encrypted[AES_BLOCK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, input_file)) > 0) {
        if (bytes_read < AES_BLOCK_SIZE) {
            memset(buffer + bytes_read, 0, AES_BLOCK_SIZE - bytes_read);
        }
        AES_ige_encrypt(buffer, encrypted, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
        fwrite(encrypted, 1, AES_BLOCK_SIZE, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    Py_RETURN_NONE;
}

static PyObject *decrypt_file(PyObject *self, PyObject *args) {
    const char *input_filename, *output_filename;
    unsigned char key[AES_KEY_LENGTH/8];
    unsigned char iv[AES_BLOCK_SIZE];
    if (!PyArg_ParseTuple(args, "ssy#y#", &input_filename, &output_filename, &key, sizeof(key), &iv, sizeof(iv))) {
        return NULL;
    }

    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        PyErr_SetString(PyExc_FileNotFoundError, "Input file not found");
        return NULL;
    }

    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        fclose(input_file);
        PyErr_SetString(PyExc_FileNotFoundError, "Could not open output file");
        return NULL;
    }

    AES_KEY aes_key;
    AES_set_decrypt_key(key, AES_KEY_LENGTH, &aes_key);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, input_file)) > 0) {
        AES_ige_encrypt(buffer, decrypted, AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);
        fwrite(decrypted, 1, bytes_read, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    Py_RETURN_NONE;
}

static PyMethodDef AESMethods[] = {
    {"generate_key", generate_key, METH_NOARGS, "Generate a 256-bit AES key"},
    {"encrypt_text", encrypt_text, METH_VARARGS, "Encrypt text using AES IGE"},
    {"decrypt_text", decrypt_text, METH_VARARGS, "Decrypt text using AES IGE"},
    {"encrypt_metadata", encrypt_metadata, METH_VARARGS, "Encrypt metadata using AES IGE"},
    {"decrypt_metadata", decrypt_metadata, METH_VARARGS, "Decrypt metadata using AES IGE"},
    {"encrypt_file", encrypt_file, METH_VARARGS, "Encrypt a file using AES IGE"},
    {"decrypt_file", decrypt_file, METH_VARARGS, "Decrypt a file using AES IGE"},
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
