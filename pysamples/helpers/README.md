Helpers
=======

Small helper programs for developing the BCC bindings.

trace
-----
Collects and prints information about used classes and functions.

Usage:

```
    import trace
    trace.setup(r"MODULE_REGEX")
    ...
```

This prints information about used classes and functions on exit.

We use this to find the components of the Python bindings actually used in every example.

See [Finding all used Classes, Methods and Functions of a Python Module](https://mostlynerdless.de/blog/2023/12/01/finding-all-used-classes-methods-and-functions-of-a-python-module/)
for more information.
