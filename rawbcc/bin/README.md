jextract_bpf.py
==============
This script downloads jextract and uses it to generate the bcc bindings.

### Challenges

- jextract has not yet been released. It has to be downloaded from the project website
- it doesn't like lines matching `union.* __attribute__\(\(aligned\(8\)\)\);`
  - https://bugs.openjdk.org/browse/CODETOOLS-7903593
  - we have to introduce a field name to make it work
- bcc has no single header file, and we need bindings to some C lib functions
  - create combined header `misc/bcc_headers.h`

License
-------
MIT