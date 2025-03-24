#include <Python.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 32 // 256 bits
#define BLOCK_SIZE 16 // AES block size

static void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

static int generate_key(unsigned char* key) {
    if (!RAND_bytes(key, KEY_SIZE)) {
        handleErrors();
        return 0;
    }
    return 1;
}

static int encrypt_ige(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, unsigned char* ciphertext) {
    AES_KEY aes_key;
    unsigned char iv[BLOCK_SIZE * 2];

    if (AES_set_encrypt_key(key, 256, &aes_key) < 0) {
        handleErrors();
        return 0;
    }

    if (!RAND_bytes(iv, BLOCK_SIZE * 2)) {
        handleErrors();
        return 0;
    }

    AES_ige_encrypt(plaintext, ciphertext, plaintext_len, &aes_key, iv, AES_ENCRYPT);
    return 1;
}

static int decrypt_ige(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, unsigned char* plaintext) {
    AES_KEY aes_key;
    unsigned char iv[BLOCK_SIZE * 2];

    if (AES_set_decrypt_key(key, 256, &aes_key) < 0) {
        handleErrors();
        return 0;
    }

    if (!RAND_bytes(iv, BLOCK_SIZE * 2)) {
        handleErrors();
        return 0;
    }

    AES_ige_encrypt(ciphertext, plaintext, ciphertext_len, &aes_key, iv, AES_DECRYPT);
    return 1;
}

static PyObject* py_generate_key(PyObject* self, PyObject* args) {
    unsigned char key[KEY_SIZE];
    if (!generate_key(key)) {
        return NULL;
    }
    return Py_BuildValue("y#", key, KEY_SIZE);
}

static PyObject* py_encrypt(PyObject* self, PyObject* args) {
    const char* plaintext;
    const char* key;
    int plaintext_len, key_len;

    if (!PyArg_ParseTuple(args, "y#y#", &plaintext, &plaintext_len, &key, &key_len)) {
        return NULL;
    }

    unsigned char ciphertext[plaintext_len + BLOCK_SIZE];
    if (!encrypt_ige((unsigned char*)plaintext, plaintext_len, (unsigned char*)key, ciphertext)) {
        return NULL;
    }

    return Py_BuildValue("y#", ciphertext, plaintext_len + BLOCK_SIZE);
}

static PyObject* py_decrypt(PyObject* self, PyObject* args) {
    const char* ciphertext;
    const char* key;
    int ciphertext_len, key_len;

    if (!PyArg_ParseTuple(args, "y#y#", &ciphertext, &ciphertext_len, &key, &key_len)) {
        return NULL;
    }

    unsigned char plaintext[ciphertext_len];
    if (!decrypt_ige((unsigned char*)ciphertext, ciphertext_len, (unsigned char*)key, plaintext)) {
        return NULL;
    }

    return Py_BuildValue("y#", plaintext, ciphertext_len);
}

static PyObject* py_encrypt_file(PyObject* self, PyObject* args) {
    const char* input_file;
    const char* output_file;
    const char* key;
    int key_len;

    if (!PyArg_ParseTuple(args, "ssy#", &input_file, &output_file, &key, &key_len)) {
        return NULL;
    }

    FILE* ifp = fopen(input_file, "rb");
    FILE* ofp = fopen(output_file, "wb");
    if (!ifp || !ofp) {
        return NULL;
    }

    fseek(ifp, 0, SEEK_END);
    long file_size = ftell(ifp);
    fseek(ifp, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(file_size);
    fread(buffer, 1, file_size, ifp);

    unsigned char* ciphertext = (unsigned char*)malloc(file_size + BLOCK_SIZE);
    if (!encrypt_ige(buffer, file_size, (unsigned char*)key, ciphertext)) {
        return NULL;
    }

    fwrite(ciphertext, 1, file_size + BLOCK_SIZE, ofp);

    free(buffer);
    free(ciphertext);
    fclose(ifp);
    fclose(ofp);

    Py_RETURN_NONE;
}

static PyObject* py_decrypt_file(PyObject* self, PyObject* args) {
    const char* input_file;
    const char* output_file;
    const char* key;
    int key_len;

    if (!PyArg_ParseTuple(args, "ssy#", &input_file, &output_file, &key, &key_len)) {
        return NULL;
    }

    FILE* ifp = fopen(input_file, "rb");
    FILE* ofp = fopen(output_file, "wb");
    if (!ifp || !ofp) {
        return NULL;
    }

    fseek(ifp, 0, SEEK_END);
    long file_size = ftell(ifp);
    fseek(ifp, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(file_size);
    fread(buffer, 1, file_size, ifp);

    unsigned char* plaintext = (unsigned char*)malloc(file_size);
    if (!decrypt_ige(buffer, file_size, (unsigned char*)key, plaintext)) {
        return NULL;
    }

    fwrite(plaintext, 1, file_size, ofp);

    free(buffer);
    free(plaintext);
    fclose(ifp);
    fclose(ofp);

    Py_RETURN_NONE;
}

static PyObject* py_encrypt_metadata(PyObject* self, PyObject* args) {
    const char* metadata;
    const char* key;
    int metadata_len, key_len;

    if (!PyArg_ParseTuple(args, "y#y#", &metadata, &metadata_len, &key, &key_len)) {
        return NULL;
    }

    unsigned char ciphertext[metadata_len + BLOCK_SIZE];
    if (!encrypt_ige((unsigned char*)metadata, metadata_len, (unsigned char*)key, ciphertext)) {
        return NULL;
    }

    return Py_BuildValue("y#", ciphertext, metadata_len + BLOCK_SIZE);
}

static PyObject* py_decrypt_metadata(PyObject* self, PyObject* args) {
    const char* ciphertext;
    const char* key;
    int ciphertext_len, key_len;

    if (!PyArg_ParseTuple(args, "y#y#", &ciphertext, &ciphertext_len, &key, &key_len)) {
        return NULL;
    }

    unsigned char plaintext[ciphertext_len];
    if (!decrypt_ige((unsigned char*)ciphertext, ciphertext_len, (unsigned char*)key, plaintext)) {
        return NULL;
    }

    return Py_BuildValue("y#", plaintext, ciphertext_len);
}

static PyMethodDef AESMethods[] = {
    {"generate_key", py_generate_key, METH_VARARGS, "Generate a 256-bit AES key"},
    {"encrypt", py_encrypt, METH_VARARGS, "Encrypt text using AES in IGE mode"},
    {"decrypt", py_decrypt, METH_VARARGS, "Decrypt text using AES in IGE mode"},
    {"encrypt_file", py_encrypt_file, METH_VARARGS, "Encrypt a file using AES in IGE mode"},
    {"decrypt_file", py_decrypt_file, METH_VARARGS, "Decrypt a file using AES in IGE mode"},
    {"encrypt_metadata", py_encrypt_metadata, METH_VARARGS, "Encrypt metadata using AES in IGE mode"},
    {"decrypt_metadata", py_decrypt_metadata, METH_VARARGS, "Decrypt metadata using AES in IGE mode"},
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
