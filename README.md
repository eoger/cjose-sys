# cjose-sys

## Dependencies

- cjose
- jansson
- ssl

These will be linked dynamically. It is your responsibility to ship these libraries with your application.

If these are not found in your system libraries, you can specify the `CJOSE_DIR`, `JANSSON_DIR` or `SSL_DIR` env variables:

e.g: `CJOSE=DIR=/path/to/cjose/lib cargo build`