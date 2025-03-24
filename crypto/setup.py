from setuptools import setup, Extension
import os

# Define the OpenSSL library and include directories
openssl_include_dir = r'C:\openssl\include'  # Update this path
openssl_lib_dir = r'C:\openssl\lib'  # Update this path

# Define the C extension
module = Extension(
    'aes_ige',  # The name of the Python module
    sources=['dump00.c'],  # Your source C file
    include_dirs=[openssl_include_dir],  # Path to OpenSSL headers
    library_dirs=[openssl_lib_dir],  # Path to OpenSSL libraries
    libraries=['ssl', 'crypto'],  # OpenSSL libraries
    extra_compile_args=['-O3'],  # Optional optimizations
)

# Set up the package
setup(
    name='aes_ige',
    version='1.0',
    description='AES IGE encryption module',
    ext_modules=[module],
)
