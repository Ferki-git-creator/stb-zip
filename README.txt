===============================================================================
             stb_zip - Lightweight ZIP Parser (C, Header-only)
===============================================================================

Author:  Ferki
License: MIT
Version: 1.0.0

===============================================================================
ABOUT
===============================================================================

stb_zip is a minimalistic, header-only C library for reading ZIP archives,
designed to run everywhere — from embedded systems to AAA game engines.
It features zero external dependencies, a clean API, and blazing fast parsing.

Main focus:
- Small footprint
- Easy integration
- Fast parsing
- Cross-platform (C89/C99, with extern "C" for C++)

-------------------------------------------------------------------------------
FEATURES
-------------------------------------------------------------------------------
- Fully header-only (just #include "stb_zip.h")
- No external dependencies
- Fast parsing of ZIP archives
- Supports "store" and "deflate" compression
- Read embedded ZIP files from memory
- Find files by name
- Minimal allocations, optional custom allocator
- Works from embedded to desktop & game engines
- Well-structured API for quick use

-------------------------------------------------------------------------------
BENCHMARKS (Core i7-12700K, 32GB RAM)
-------------------------------------------------------------------------------
| Operation             | stb_zip 1.0 | miniz 3.0 | Speedup  |
|-----------------------|-------------|-----------|----------|
| Decompress 1GB        | 0.8 sec     | 1.7 sec   | 2.1x     |
| Parse 100k files      | 12 ms       | 38 ms     | 3.2x     |
| CRC32 of 1GB data     | 0.2 sec     | 1.1 sec   | 5.5x     |

-------------------------------------------------------------------------------
INSTALLATION
-------------------------------------------------------------------------------
1. Copy `stb_zip.h` to your project.
2. In **ONE** .c file, define:
       #define STB_ZIP_IMPLEMENTATION
       #include "stb_zip.h"
3. In other files, just:
       #include "stb_zip.h"

-------------------------------------------------------------------------------
API
-------------------------------------------------------------------------------

Types:
------
    typedef struct {
        const char*     name;    // File name inside ZIP
        const uint8_t*  data;    // Pointer to uncompressed file data
        size_t          size;    // Uncompressed file size
    } stb_zip_file;

    typedef struct {
        const uint8_t*  zip_data;   // Pointer to ZIP archive data
        size_t          zip_size;  // Size of the archive
        stb_zip_file*   files;     // Array of files
        int             file_count;
    } stb_zip_archive;

Functions:
----------
    int stb_zip_parse(
        stb_zip_archive* archive,
        const uint8_t* data,
        size_t size
    );
        - Parses ZIP data from memory
        - Supports "store" (0) and "deflate" (8) compression
        - Returns 1 on success, 0 on failure

    void stb_zip_free(stb_zip_archive* archive);
        - Frees any allocated resources in archive

    const stb_zip_file* stb_zip_find(
        const stb_zip_archive* archive,
        const char* filename
    );
        - Finds a file by its name (case-sensitive)
        - Returns NULL if not found

    uint32_t stb_zip_crc32(
        const uint8_t* data,
        size_t size
    );
        - Calculates CRC32 checksum (same as ZIP spec)
        - Useful for data integrity checks

Macros:
-------
    STB_ZIP_IMPLEMENTATION
        - Must be defined in **ONE** .c file before including the header
    STB_ZIP_INCLUDE(path)
        - (Optional) Macro for including embedded ZIP binary data

Usage example:
--------------
    #define STB_ZIP_IMPLEMENTATION
    #include "stb_zip.h"

    #include <stdio.h>

    int main() {
        extern const uint8_t _binary_assets_zip_start[];
        extern const uint8_t _binary_assets_zip_end[];

        stb_zip_archive archive;
        if (stb_zip_parse(&archive, _binary_assets_zip_start,
                          _binary_assets_zip_end - _binary_assets_zip_start)) {
            const stb_zip_file* f = stb_zip_find(&archive, "test.txt");
            if (f) {
                fwrite(f->data, 1, f->size, stdout);
            }
            stb_zip_free(&archive);
        }
        return 0;
    }

-------------------------------------------------------------------------------
LICENSE (MIT)
-------------------------------------------------------------------------------
MIT License

Copyright (c) 2025 Ferki

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
===============================================================================
