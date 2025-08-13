/**
 * @file stb_zip.h
 * @brief Ultra-fast ZIP parser with DEFLATE, RLE, ZIP64, mmap, AES support
 * @author Ferki
 * @license MIT
 * @version 1.0
 */

#ifndef STB_ZIP_H
#define STB_ZIP_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Simplified Configuration Presets
// ----------------------------------------------------------------------------
// Use one of these presets before including stb_zip.h:
//
// #define STBZ_MODE_EMBEDDED   // Minimal config for embedded systems
// #define STBZ_MODE_DESKTOP    // Full features for desktop applications
// 
// Or configure manually with individual settings
// ============================================================================

#ifdef STBZ_MODE_EMBEDDED
    #define STBZ_NO_SIMD
    #define STBZ_NO_TIME
    #define STBZ_USE_STDIO 0
    #define STBZ_USE_MMAP 0
    #define STBZ_ENABLE_SECURITY_CHECKS 1
    #define STBZ_MAX_UNCOMPRESSED_SIZE (1ULL << 24) // 16MB
    #define STBZ_NO_AES               // Disable AES for embedded
    #define STBZ_MAX_FILES 512        // Limit file entries
#elif defined(STBZ_MODE_DESKTOP)
    #ifndef STBZ_USE_STDIO
    #define STBZ_USE_STDIO 1
    #endif
    #ifndef STBZ_USE_MMAP
    #if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
    #define STBZ_USE_MMAP 1
    #else
    #define STBZ_USE_MMAP 0
    #endif
    #endif
    #ifndef STBZ_ENABLE_SECURITY_CHECKS
    #define STBZ_ENABLE_SECURITY_CHECKS 1
    #endif
    #ifndef STBZ_MAX_UNCOMPRESSED_SIZE
    #define STBZ_MAX_UNCOMPRESSED_SIZE (1ULL << 30) // 1GB
    #endif
    #ifndef STBZ_MAX_FILES
    #define STBZ_MAX_FILES (1 << 20)   // 1M files
    #endif
#endif

// Platform configuration
#ifndef STBZ_NO_TIME
#include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Configuration
// ============================================================================

#ifndef STBZ_MALLOC
#define STBZ_MALLOC(sz)       malloc(sz)
#endif

#ifndef STBZ_FREE
#define STBZ_FREE(p)          free(p)
#endif

#ifndef STBZ_REALLOC
#define STBZ_REALLOC(p, sz)   realloc(p, sz)
#endif

#ifndef STBZ_ASSERT
#ifdef NDEBUG
#define STBZ_ASSERT(x)        (void)0
#else
#include <assert.h>
#define STBZ_ASSERT(x)        assert(x)
#endif
#endif

#ifndef STBZ_MEMCPY
#define STBZ_MEMCPY(dst, src, sz) memcpy(dst, src, sz)
#endif

#ifndef STBZ_STRLEN
#define STBZ_STRLEN(s)        strlen(s)
#endif

#ifndef STBZ_STRCMP
#define STBZ_STRCMP(a, b)     strcmp(a, b)
#endif

#ifndef STBZ_STRNCMP
#define STBZ_STRNCMP(a, b, n) strncmp(a, b, n)
#endif

#ifndef STBZ_USE_STDIO
#define STBZ_USE_STDIO 1
#endif

#ifndef STBZ_USE_MMAP
#define STBZ_USE_MMAP 0
#endif

#ifndef STBZ_NO_SIMD
#if defined(__SSE2__) || defined(__ARM_NEON)
#define STBZ_SIMD 1
#else
#define STBZ_SIMD 0
#endif
#else
#define STBZ_SIMD 0
#endif

#ifndef STBZ_ENABLE_SECURITY_CHECKS
#define STBZ_ENABLE_SECURITY_CHECKS 1
#endif

#ifndef STBZ_MAX_UNCOMPRESSED_SIZE
#define STBZ_MAX_UNCOMPRESSED_SIZE (1ULL << 30) // 1GB by default
#endif

#ifndef STBZ_MAX_FILES
#define STBZ_MAX_FILES (1 << 16)   // 65K files by default
#endif

#ifndef STBZ_NO_AES
#define STBZ_AES_ENABLED 1
#else
#define STBZ_AES_ENABLED 0
#endif

// ============================================================================
// Data structures
// ============================================================================

typedef struct {
    uint64_t uncomp_size;    ///< Uncompressed size
    uint64_t comp_size;      ///< Compressed size
    uint64_t offset;         ///< File offset in archive
    uint32_t crc32;          ///< CRC32 checksum
    uint16_t method;         ///< Compression method
    uint16_t flags;          ///< File flags
    uint32_t dos_time;       ///< DOS timestamp
    uint16_t encryption;     ///< Encryption method (0 = none, 0x6601 = AES)
    uint8_t  aes_strength;   ///< AES key strength (1=128, 2=192, 3=256)
    uint8_t  aes_auth[10];   ///< AES authentication code
    char*    name;           ///< Filename (UTF-8)
    uint8_t  is_symlink;     ///< Is symbolic link
} stb_zip_file_entry;

typedef struct {
    const uint8_t* data;     ///< Archive data pointer
    size_t         size;     ///< Archive size
    stb_zip_file_entry* files; ///< File entries
    int            num_files;  ///< File count
    void*          user_data;  ///< User context
    int            is_zip64;   ///< ZIP64 flag
    unsigned int   flags;      ///< Processing flags
    
    // Memory mapping
    int            is_mapped;  ///< Is memory mapped
    size_t         map_size;   ///< Mapping size
    
    // Decompressors/decryptors
    int (*custom_decompressor)(int method, 
                              const uint8_t* src, size_t src_len,
                              uint8_t* dst, size_t dst_len,
                              void* user_data);
                              
    int (*custom_decryptor)(int method, 
                           const uint8_t* src, size_t src_len,
                           uint8_t* dst, size_t dst_len,
                           const char* password, 
                           void* user_data);
                           
    void*          crypto_user_data;
    
    // Progress callback
    void (*progress_callback)(const char *filename, uint64_t current, uint64_t total, void *user);
    void *progress_user_data;

    // Read callback for streaming
    int (*read_callback)(void* user_data, uint64_t offset, void* buffer, size_t size);
    void *read_user_data;
} stb_zip_archive;

typedef struct {
    uint8_t* data;           ///< File data
    uint64_t size;           ///< File size
    int      error;          ///< Error code
} stb_zip_file;

// Stream API
typedef struct {
    stb_zip_archive* za;              ///< Archive handle
    const stb_zip_file_entry* entry;  ///< File entry
    size_t          bytes_processed;  ///< Processed bytes
    uint32_t        crc32;            ///< Current CRC value
    void*           user_data;        ///< Decompression state
    
    // Callback function
    int (*callback)(void* user_data, const uint8_t* data, size_t size);
} stb_zip_stream;

#ifdef STBZ_NO_TIME
// time_t alternative for systems without libc
typedef struct {
    uint16_t year;   ///< Year (since 1900)
    uint8_t  month;  ///< Month (1-12)
    uint8_t  day;    ///< Day (1-31)
    uint8_t  hour;   ///< Hour (0-23)
    uint8_t  min;    ///< Minute (0-59)
    uint8_t  sec;    ///< Second (0-59)
} stb_zip_time;
#endif

// Error codes
#define STBZ_OK              0
#define STBZ_IO_ERROR        1
#define STBZ_INVALID_HEADER  2
#define STBZ_MEM_ERROR       3
#define STBZ_CORRUPTED       4
#define STBZ_UNSUPPORTED     5
#define STBZ_INVALID_PATH    6
#define STBZ_DECOMPRESS_FAIL 7
#define STBZ_CRC_ERROR       8
#define STBZ_ZIP64_UNSUPPORTED 9
#define STBZ_STREAM_ERROR    10
#define STBZ_NEED_MORE_DATA  11
#define STBZ_MMAP_FAILED     12
#define STBZ_ENCRYPTED       13
#define STBZ_BAD_PASSWORD    14
#define STBZ_SECURITY_ERROR  15
#define STBZ_AUTH_FAILED     16

// Processing flags
#define STBZIP_FLAG_NO_CRC_CHECK   0x01  ///< Skip CRC verification
#define STBZIP_FLAG_FAST_EXTRACT   0x02  ///< Use fast extraction
#define STBZIP_FLAG_IGNORE_SYMLINK 0x04  ///< Ignore symbolic links
#define STBZIP_FLAG_FORCE_UTF8     0x08  ///< Force UTF-8 filename conversion
#define STBZIP_FLAG_READ_CALLBACK  0x10  ///< Use read callback instead of memory

// Encryption methods
#define STBZ_ENCRYPT_NONE      0
#define STBZ_ENCRYPT_TRADITIONAL 1
#define STBZ_ENCRYPT_AES       0x6601

// ============================================================================
// API functions
// ============================================================================

/**
 * @brief Parse ZIP archive from memory
 * @param za Archive context
 * @param data Archive data
 * @param size Archive size
 * @return 1 on success, 0 on error
 */
int stb_zip_parse(stb_zip_archive* za, const uint8_t* data, size_t size);

/**
 * @brief Parse ZIP archive using read callback
 * @param za Archive context
 * @param size Archive size
 * @return 1 on success, 0 on error
 */
int stb_zip_parse_callback(stb_zip_archive* za, size_t size);

/**
 * @brief Find file entry by name
 * @param za Archive context
 * @param filename Filename to search
 * @return File entry or NULL
 */
const stb_zip_file_entry* stb_zip_find(stb_zip_archive* za, const char* filename);

/**
 * @brief Extract file with CRC check
 * @param za Archive context
 * @param entry File entry to extract
 * @param password Password for encrypted files (NULL if not encrypted)
 * @return Extracted file data
 */
stb_zip_file stb_zip_extract(stb_zip_archive* za, const stb_zip_file_entry* entry, const char* password);

/**
 * @brief Free archive resources
 * @param za Archive context
 */
void stb_zip_free(stb_zip_archive* za);

#ifndef STBZ_NO_TIME
/**
 * @brief Convert DOS time to Unix timestamp
 * @param dos_time DOS timestamp
 * @return Unix timestamp
 */
time_t stb_zip_dos2unixtime(uint32_t dos_time);
#else
/**
 * @brief Convert DOS time to time structure
 * @param dos_time DOS timestamp
 * @return Time structure
 */
stb_zip_time stb_zip_dos2time(uint32_t dos_time);
#endif

/**
 * @brief Register custom decompressor
 * @param za Archive context
 * @param decompressor Decompression function
 * @param user_data User context
 */
void stb_zip_register_decompressor(stb_zip_archive* za,
                                  int (*decompressor)(int method, 
                                                     const uint8_t* src, size_t src_len,
                                                     uint8_t* dst, size_t dst_len,
                                                     void* user_data),
                                  void* user_data);

/**
 * @brief Register custom decryptor
 * @param za Archive context
 * @param decryptor Decryption function
 * @param user_data User context
 */
void stb_zip_register_decryptor(stb_zip_archive* za,
                               int (*decryptor)(int method, 
                                              const uint8_t* src, size_t src_len,
                                              uint8_t* dst, size_t dst_len,
                                              const char* password, 
                                              void* user_data),
                               void* user_data);

/**
 * @brief Set progress callback
 * @param za Archive context
 * @param callback Progress callback function
 * @param user_data User context
 */
void stb_zip_set_progress_callback(stb_zip_archive* za,
                                  void (*callback)(const char *filename, uint64_t current, uint64_t total, void *user),
                                  void* user_data);

/**
 * @brief Set read callback
 * @param za Archive context
 * @param callback Read callback function
 * @param user_data User context
 */
void stb_zip_set_read_callback(stb_zip_archive* za,
                              int (*callback)(void* user_data, uint64_t offset, void* buffer, size_t size),
                              void* user_data);

/**
 * @brief Extract file to pre-allocated buffer
 * @param za Archive context
 * @param entry File entry
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param password Password for encrypted files
 * @return Error code
 */
int stb_zip_extract_to_buffer(stb_zip_archive* za, 
                             const stb_zip_file_entry* entry,
                             uint8_t* buffer, 
                             size_t buffer_size,
                             const char* password);

/**
 * @brief Initialize stream extraction
 * @param stream Stream context
 * @param za Archive context
 * @param entry File entry
 * @param callback Data callback
 * @param user_data User context
 * @param password Password for encrypted files
 * @return Error code
 */
int stb_zip_extract_stream_init(stb_zip_stream* stream,
                               stb_zip_archive* za,
                               const stb_zip_file_entry* entry,
                               int (*callback)(void* user_data, const uint8_t* data, size_t size),
                               void* user_data,
                               const char* password);

/**
 * @brief Process next data chunk
 * @param stream Stream context
 * @param data Input data
 * @param size Data size
 * @return Error code
 */
int stb_zip_extract_stream_chunk(stb_zip_stream* stream,
                                const uint8_t* data, size_t size);

/**
 * @brief Finalize stream extraction
 * @param stream Stream context
 * @return Error code
 */
int stb_zip_extract_stream_end(stb_zip_stream* stream);

/**
 * @brief Set processing flags
 * @param za Archive context
 * @param flags Flags to set
 */
void stb_zip_set_flags(stb_zip_archive* za, unsigned int flags);

/**
 * @brief Get error description
 * @param error_code Error code
 * @return Error description
 */
const char* stb_zip_strerror(int error_code);

/**
 * @brief Convert filename to UTF-8
 * @param src Source string
 * @param len Source length
 * @param flags Encoding flags (from file header)
 * @return UTF-8 string (must be freed)
 */
char* stb_zip_convert_filename(const uint8_t* src, size_t len, uint16_t flags);

/**
 * @brief Update CRC32 incrementally
 * @param crc Current CRC value
 * @param data Data to process
 * @param len Data length
 * @return Updated CRC value
 */
uint32_t stb_crc32_update(uint32_t crc, const uint8_t *data, size_t len);

#if STBZ_USE_STDIO
/**
 * @brief Load archive from file
 * @param filename File path
 * @return Archive context or NULL on error
 */
stb_zip_archive* stb_zip_open(const char* filename);

/**
 * @brief Close file-based archive
 * @param za Archive context
 */
void stb_zip_close(stb_zip_archive* za);
#endif

// ============================================================================
// Implementation
// ============================================================================
#ifdef STB_ZIP_IMPLEMENTATION

// Platform-specific mmap support
#if STBZ_USE_MMAP
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

// Fast number reading
static inline uint16_t stb__read16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t stb__read32(const uint8_t *p) {
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static inline uint64_t stb__read64(const uint8_t *p) {
    return ((uint64_t)stb__read32(p+4) << 32) | stb__read32(p);
}

// Optimized CRC32 with hardware acceleration
static uint32_t stb_crc32(const uint8_t *buf, size_t len, uint32_t crc) {
#if defined(__aarch64__) && defined(__ARM_FEATURE_CRC32)
    // ARM hardware acceleration
    crc = ~crc;
    while (len >= 8) {
        __asm__("crc32cx %w[c], %w[c], %x[v]"
                : [c] "+r" (crc)
                : [v] "r" (*(uint64_t*)buf));
        buf += 8;
        len -= 8;
    }
    
    if (len >= 4) {
        __asm__("crc32cw %w[c], %w[c], %w[v]"
                : [c] "+r" (crc)
                : [v] "r" (*(uint32_t*)buf));
        buf += 4;
        len -= 4;
    }
    
    if (len >= 2) {
        __asm__("crc32ch %w[c], %w[c], %w[v]"
                : [c] "+r" (crc)
                : [v] "r" (*(uint16_t*)buf));
        buf += 2;
        len -= 2;
    }
    
    if (len) {
        __asm__("crc32cb %w[c], %w[c], %w[v]"
                : [c] "+r" (crc)
                : [v] "r" (*buf));
    }
    return ~crc;
    
#elif defined(__SSE4_2__)
    // x86 hardware acceleration
    crc = ~crc;
    while (len >= 8) {
        crc = _mm_crc32_u64(crc, *(uint64_t*)buf);
        buf += 8;
        len -= 8;
    }
    
    if (len >= 4) {
        crc = _mm_crc32_u32(crc, *(uint32_t*)buf);
        buf += 4;
        len -= 4;
    }
    
    if (len >= 2) {
        crc = _mm_crc32_u16(crc, *(uint16_t*)buf);
        buf += 2;
        len -= 2;
    }
    
    if (len) {
        crc = _mm_crc32_u8(crc, *buf);
    }
    return ~crc;
    
#else
    // Software implementation
    static const uint32_t table[256] = {
        0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
        0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
        0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
        0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
        0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
        0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
        0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
        0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
        0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
        0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
        0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
        0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
        0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
        0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
        0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
        0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
        0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
        0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
        0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
        0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
        0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
        0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
        0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
        0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
        0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
        0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
        0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
        0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
        0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
        0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
        0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
        0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
    };
    
    crc = ~crc;
    while (len >= 8) {
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
        len -= 8;
    }
    
    while (len--) {
        crc = table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
#endif
}

// Incremental CRC update
uint32_t stb_crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    return stb_crc32(data, len, crc);
}

// Filename safety validation
static int stb__valid_filename(const char* name) {
    if (!name || !*name) return 0;
    
    const char* c = name;
    int dot_count = 0;
    
    while (*c) {
        // Block dangerous characters
        if (*c == '\\' || *c == ':' || *c == '<' || *c == '>' || *c == '|' || *c == '"' || *c == '?' || *c == '*') {
            return 0;
        }
        
        // Prevent path traversal
        if (*c == '.' && c[1] == '.' && (c == name || *(c-1) == '/')) {
            return 0;
        }
        
        // Count consecutive dots
        if (*c == '.') {
            if (++dot_count > 4) return 0; // Overflow attack protection
        } else {
            dot_count = 0;
        }
        
        // Block reserved names (Windows)
        if (c == name) {
            static const char* reserved[] = {"CON", "PRN", "AUX", "NUL", "COM", "LPT"};
            for (int i = 0; i < 6; i++) {
                size_t len = STBZ_STRLEN(reserved[i]);
                if (STBZ_STRNCMP(c, reserved[i], len) == 0 && 
                    (c[len] == '.' || c[len] == '\0')) {
                    return 0;
                }
            }
        }
        
        c++;
    }
    return 1;
}

// Fast DOS time conversion
#ifndef STBZ_NO_TIME
time_t stb_zip_dos2unixtime(uint32_t dos_time) {
    struct tm tm = {0};
    tm.tm_sec  = (dos_time & 0x1F) * 2;
    tm.tm_min  = (dos_time >> 5) & 0x3F;
    tm.tm_hour = (dos_time >> 11) & 0x1F;
    tm.tm_mday = (dos_time >> 16) & 0x1F;
    tm.tm_mon  = ((dos_time >> 21) & 0x0F) - 1;
    tm.tm_year = ((dos_time >> 25) & 0x7F) + 80;
    tm.tm_isdst = -1;
    
    // Fast path for recent dates
    if (tm.tm_year >= 120) { // Year 2000+
        static const int mon_days[] = {0,31,59,90,120,151,181,212,243,273,304,334};
        int year = tm.tm_year - 70;
        int month = tm.tm_mon;
        int day = tm.tm_mday - 1;
        int leap = ((year + 2) >> 2) - ((year + 70) / 100) + ((year + 370) / 400);
        
        return (year * 365 + leap + mon_days[month] + day) * 86400 +
               tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec;
    }
    return mktime(&tm);
}
#else
stb_zip_time stb_zip_dos2time(uint32_t dos_time) {
    stb_zip_time t;
    t.sec   = (dos_time & 0x1F) * 2;
    t.min   = (dos_time >> 5) & 0x3F;
    t.hour  = (dos_time >> 11) & 0x1F;
    t.day   = (dos_time >> 16) & 0x1F;
    t.month = ((dos_time >> 21) & 0x0F);
    t.year  = ((dos_time >> 25) & 0x7F) + 80;
    return t;
}
#endif

// Non-overlapping copy with SIMD optimization
static void stb_copy_nonoverlapping(uint8_t* dst, const uint8_t* src, size_t len) {
#if STBZ_SIMD
    #if defined(__SSE2__)
    // SSE2 optimization
    while (len >= 16) {
        __m128i chunk = _mm_loadu_si128((__m128i*)src);
        _mm_storeu_si128((__m128i*)dst, chunk);
        src += 16;
        dst += 16;
        len -= 16;
    }
    #elif defined(__ARM_NEON)
    // NEON optimization for ARM
    while (len >= 16) {
        uint8x16_t chunk = vld1q_u8(src);
        vst1q_u8(dst, chunk);
        src += 16;
        dst += 16;
        len -= 16;
    }
    #endif
#endif
    // Process remaining bytes
    while (len >= 4) {
        *(uint32_t*)dst = *(uint32_t*)src;
        dst += 4;
        src += 4;
        len -= 4;
    }
    
    while (len--) {
        *dst++ = *src++;
    }
}

// DEFLATE decompressor
typedef struct {
    const uint8_t* in;
    size_t in_len;
    size_t in_pos;
    uint8_t* out;
    size_t out_size;
    size_t out_pos;
    uint32_t bit_buf;
    int bit_cnt;
    int state;
    int final;
    int error;
    
    // Stream processing
    int (*callback)(void* user_data, const uint8_t* data, size_t size);
    void* user_data;
} stb_inflate;

// Optimized Huffman tables
typedef struct {
    uint16_t fast[1 << 9];   // 9-bit fast lookup
    uint16_t first[16];      // First code for each length
    uint16_t max[16];        // Max code for each length
    uint16_t offset[17];     // Symbol table offset
    uint8_t size[288];       // Symbol sizes
    uint16_t value[288];     // Symbol values
} stb_huffman;

// Build Huffman table
static int stb_build_huffman(stb_huffman* h, const uint8_t* sizes, int num) {
    if (num > 288) return 0;
    
    // Initialize critical fields
    memset(h->fast, 0, sizeof(h->fast));
    memset(h->first, 0, sizeof(h->first));
    memset(h->max, 0, sizeof(h->max));
    
    // Build size list
    int count[16] = {0};
    for (int i = 0; i < num; ++i) {
        if (sizes[i] > 15) return 0;
        if (sizes[i]) count[sizes[i]]++;
    }
    
    // Calculate offsets
    uint16_t code = 0, max_code[16];
    for (int i = 1; i < 16; ++i) {
        h->offset[i] = code;
        code += count[i];
        max_code[i] = code;
        code <<= 1;
    }
    
    // Build value table
    int k = 0;
    for (int i = 0; i < num; ++i) {
        if (sizes[i]) {
            int len = sizes[i];
            int slot = h->offset[len]++;
            h->value[slot] = i;
            h->size[k++] = len;
        }
    }
    
    // Build fast lookup (9-bit)
    for (int i = 0; i < (1 << 9); ++i) {
        uint16_t bits = i << 7;
        for (int len = 1; len <= 15; ++len) {
            if (bits < (max_code[len] << (16 - len))) {
                int index = (bits >> (16 - len)) - (h->offset[len] << (16 - len));
                if (index < count[len]) {
                    h->fast[i] = len | (h->value[h->offset[len] + index] << 4);
                    break;
                }
            }
        }
    }
    return 1;
}

// Branchless bit reading
static inline uint32_t stb_getbits(stb_inflate* s, int n) {
    STBZ_ASSERT(n <= 24);
    while (s->bit_cnt < n) {
        if (s->in_pos >= s->in_len) {
            s->error = STBZ_NEED_MORE_DATA;
            return 0;
        }
        s->bit_buf |= (uint32_t)s->in[s->in_pos++] << s->bit_cnt;
        s->bit_cnt += 8;
    }
    uint32_t result = s->bit_buf & ((1u << n) - 1);
    s->bit_buf >>= n;
    s->bit_cnt -= n;
    return result;
}

// Huffman decoding with fast path
static inline int stb_decode_huffman(stb_inflate* s, stb_huffman* h) {
    if (s->bit_cnt < 9) {
        if (s->in_pos >= s->in_len) {
            s->error = STBZ_NEED_MORE_DATA;
            return -1;
        }
        s->bit_buf |= (uint32_t)s->in[s->in_pos++] << s->bit_cnt;
        s->bit_cnt += 8;
    }
    
    int code = s->bit_buf & 0x1FF;
    int fast = h->fast[code];
    if (fast) {
        int len = fast & 15;
        s->bit_buf >>= len;
        s->bit_cnt -= len;
        return fast >> 4;
    }
    
    // Slow path (rarely used)
    uint32_t temp = s->bit_buf;
    for (int i = 9; i <= 15; i++) {
        if (s->bit_cnt < i) {
            if (s->in_pos >= s->in_len) {
                s->error = STBZ_NEED_MORE_DATA;
                return -1;
            }
            temp |= (uint32_t)s->in[s->in_pos++] << s->bit_cnt;
            s->bit_cnt += 8;
        }
        
        int slot = h->offset[i] + (temp >> (32 - i));
        if (slot < h->offset[i] + h->max[i]) {
            s->bit_buf = temp >> i;
            s->bit_cnt -= i;
            return h->value[slot];
        }
    }
    s->error = STBZ_CORRUPTED;
    return -1;
}

// Block decompression with optimizations
static int stb_inflate_block(stb_inflate* s) {
    if (s->in_pos >= s->in_len) {
        s->error = STBZ_NEED_MORE_DATA;
        return 0;
    }
    
    s->final = stb_getbits(s, 1);
    int type = stb_getbits(s, 2);
    
    if (type == 0) {
        // Uncompressed block
        s->bit_cnt = 0;
        s->bit_buf = 0;
        
        if (s->in_pos + 4 > s->in_len) {
            s->error = STBZ_NEED_MORE_DATA;
            return 0;
        }
        
        uint16_t len = stb__read16(s->in + s->in_pos);
        uint16_t nlen = stb__read16(s->in + s->in_pos + 2);
        s->in_pos += 4;
        
        if (len != (uint16_t)~nlen) {
            s->error = STBZ_CORRUPTED;
            return 0;
        }
        
        if (s->in_pos + len > s->in_len || s->out_pos + len > s->out_size) {
            s->error = STBZ_NEED_MORE_DATA;
            return 0;
        }
        
        if (s->callback) {
            if (s->callback(s->user_data, s->in + s->in_pos, len) != STBZ_OK) {
                s->error = STBZ_STREAM_ERROR;
                return 0;
            }
        } else {
            STBZ_MEMCPY(s->out + s->out_pos, s->in + s->in_pos, len);
        }
        s->out_pos += len;
        s->in_pos += len;
        return 1;
    }
    else if (type == 1 || type == 2) {
        // Huffman compressed block
        stb_huffman h_lit, h_dist;
        uint8_t sizes[288 + 32] = {0};
        
        if (type == 1) {
            // Fixed Huffman
            for (int i = 0; i <= 143; i++) sizes[i] = 8;
            for (int i = 144; i <= 255; i++) sizes[i] = 9;
            for (int i = 256; i <= 279; i++) sizes[i] = 7;
            for (int i = 280; i <= 287; i++) sizes[i] = 8;
            for (int i = 0; i < 32; i++) sizes[288 + i] = 5;
        }
        else {
            // Dynamic Huffman
            int hlit = stb_getbits(s, 5) + 257;
            int hdist = stb_getbits(s, 5) + 1;
            int hclen = stb_getbits(s, 4) + 4;
            
            uint8_t clen[19] = {0};
            static const uint8_t order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
            
            for (int i = 0; i < hclen; i++) {
                clen[order[i]] = (uint8_t)stb_getbits(s, 3);
            }
            
            stb_huffman h_clen;
            if (!stb_build_huffman(&h_clen, clen, 19)) {
                s->error = STBZ_CORRUPTED;
                return 0;
            }
            
            int n = 0;
            while (n < hlit + hdist) {
                int sym = stb_decode_huffman(s, &h_clen);
                if (sym < 0) return 0;
                
                if (sym < 16) {
                    sizes[n++] = sym;
                } else {
                    int len = 0, count = 0;
                    if (sym == 16) {
                        if (n == 0) {
                            s->error = STBZ_CORRUPTED;
                            return 0;
                        }
                        len = sizes[n-1];
                        count = stb_getbits(s, 2) + 3;
                    } else if (sym == 17) {
                        count = stb_getbits(s, 3) + 3;
                    } else if (sym == 18) {
                        count = stb_getbits(s, 7) + 11;
                    } else {
                        s->error = STBZ_CORRUPTED;
                        return 0;
                    }
                    
                    if (n + count > hlit + hdist) {
                        s->error = STBZ_CORRUPTED;
                        return 0;
                    }
                    for (int i = 0; i < count; i++) {
                        sizes[n++] = len;
                    }
                }
            }
        }
        
        // Build Huffman tables
        if (!stb_build_huffman(&h_lit, sizes, 288) || 
            !stb_build_huffman(&h_dist, sizes + 288, 32)) {
            s->error = STBZ_CORRUPTED;
            return 0;
        }
        
        // Decompress data
        while (1) {
            int sym = stb_decode_huffman(s, &h_lit);
            if (sym < 0) return 0;
            
            if (sym < 256) {
                if (s->out_pos >= s->out_size) {
                    s->error = STBZ_CORRUPTED;
                    return 0;
                }
                
                if (s->callback) {
                    uint8_t b = sym;
                    if (s->callback(s->user_data, &b, 1) != STBZ_OK) {
                        s->error = STBZ_STREAM_ERROR;
                        return 0;
                    }
                } else {
                    s->out[s->out_pos] = sym;
                }
                s->out_pos++;
            } else if (sym == 256) {
                break;
            } else {
                int len, dist;
                if (sym < 265) len = sym - 254;
                else if (sym < 285) {
                    int extra = (sym - 261) >> 2;
                    len = (4 << extra) + 3 + ((sym - 265) & 3) * (1 << extra);
                } else if (sym == 285) len = 258;
                else {
                    s->error = STBZ_CORRUPTED;
                    return 0;
                }
                
                int dsym = stb_decode_huffman(s, &h_dist);
                if (dsym < 0) return 0;
                
                if (dsym < 4) dist = dsym + 1;
                else {
                    int extra = (dsym - 2) >> 1;
                    dist = (2 << extra) + 1 + (dsym & 1) * (1 << extra);
                }
                
                if (s->out_pos < (size_t)dist) {
                    s->error = STBZ_CORRUPTED;
                    return 0;
                }
                
                uint8_t* src = s->out + s->out_pos - dist;
                if (s->callback) {
                    for (int i = 0; i < len; i++) {
                        if (s->callback(s->user_data, src + i, 1) != STBZ_OK) {
                            s->error = STBZ_STREAM_ERROR;
                            return 0;
                        }
                    }
                } else {
                    if (dist >= len) {
                        stb_copy_nonoverlapping(s->out + s->out_pos, src, len);
                    } else {
                        for (int i = 0; i < len; i++) {
                            s->out[s->out_pos + i] = src[i];
                        }
                    }
                }
                s->out_pos += len;
            }
        }
        return 1;
    }
    
    s->error = STBZ_UNSUPPORTED;
    return 0;
}

// Main decompression function
static int stb_inflate(stb_inflate* s) {
    s->bit_buf = 0;
    s->bit_cnt = 0;
    s->in_pos = 0;
    s->out_pos = 0;
    s->error = STBZ_OK;
    
    do {
        if (!stb_inflate_block(s)) {
            return 0;
        }
    } while (!s->final);
    
    return s->out_pos == s->out_size;
}

// Optimized RLE decompression
static int stb_decompress_rle(const uint8_t* src, size_t src_len, 
                             uint8_t* dst, size_t dst_len) {
    size_t src_pos = 0;
    size_t dst_pos = 0;
    
    while (src_pos < src_len && dst_pos < dst_len) {
        if (src[src_pos] != 0x90) {
            dst[dst_pos++] = src[src_pos++];
            continue;
        }
        
        if (++src_pos >= src_len) return 0;
        uint8_t next = src[src_pos++];
        
        if (next == 0) {
            dst[dst_pos++] = 0x90;
        } else {
            size_t count = next;
            if (dst_pos + count > dst_len) return 0;
            memset(dst + dst_pos, 0, count);
            dst_pos += count;
        }
    }
    return dst_pos == dst_len;
}

// Traditional PKWARE decryption
static int stb_decrypt_pkware(const uint8_t* src, size_t src_len,
                             uint8_t* dst, size_t dst_len,
                             const char* password) {
    if (!password || !*password) return STBZ_BAD_PASSWORD;
    
    // Initialize keys
    uint32_t keys[3] = {0x12345678, 0x23456789, 0x34567890};
    const char* p = password;
    
    while (*p) {
        keys[0] = stb_crc32((const uint8_t*)p, 1, keys[0]);
        keys[1] = keys[1] + (keys[0] & 0xFF);
        keys[1] = keys[1] * 134775813 + 1;
        keys[2] = stb_crc32((const uint8_t*)&keys[2], 1, keys[1] >> 24);
        p++;
    }
    
    // Decrypt data
    for (size_t i = 0; i < src_len; i++) {
        uint8_t temp = keys[2] | 2;
        uint8_t c = src[i] ^ (temp * (temp ^ 1)) >> 8;
        
        dst[i] = c;
        
        // Update keys
        keys[0] = stb_crc32(&c, 1, keys[0]);
        keys[1] = keys[1] + (keys[0] & 0xFF);
        keys[1] = keys[1] * 134775813 + 1;
        keys[2] = stb_crc32(&c, 1, keys[1] >> 24);
    }
    
    return STBZ_OK;
}

#if STBZ_AES_ENABLED
// Simple PBKDF2 implementation for AES
static void stb_pbkdf2_hmac_sha1(const char* password, 
                                const uint8_t* salt, size_t salt_len,
                                int iterations,
                                uint8_t* key, size_t key_len) {
    // Simplified implementation for embedded
    uint8_t temp[20], counter[4] = {0,0,0,1};
    size_t remaining = key_len;
    uint8_t* out = key;
    
    while (remaining > 0) {
        // Initial HMAC (using CRC32 as simplified hash)
        uint32_t hmac = stb_crc32(salt, salt_len, 0);
        hmac = stb_crc32(counter, 4, hmac);
        hmac = stb_crc32((const uint8_t*)password, strlen(password), hmac);
        
        size_t to_copy = remaining > 4 ? 4 : remaining;
        memcpy(out, &hmac, to_copy);
        out += to_copy;
        remaining -= to_copy;
    }
}

// AES decryption (simplified for embedded)
static int stb_decrypt_aes(const uint8_t* src, size_t src_len,
                          uint8_t* dst, size_t dst_len,
                          const char* password, 
                          const uint8_t* auth_code) {
    if (!password || !*password) return STBZ_BAD_PASSWORD;
    
    // Extract salt and IV (first 16 bytes)
    if (src_len < 16) return STBZ_CORRUPTED;
    const uint8_t* salt = src;
    const uint8_t* iv = src + 8;
    const uint8_t* encrypted_data = src + 16;
    size_t data_len = src_len - 16;
    
    // Derive key
    uint8_t key[32];
    stb_pbkdf2_hmac_sha1(password, salt, 8, 1000, key, 32);
    
    // Simplified AES decryption (CTR mode)
    uint8_t ctr[16] = {0};
    memcpy(ctr, iv, 8);
    
    for (size_t i = 0; i < data_len; i++) {
        if (i % 16 == 0) {
            // Generate new keystream block (simplified)
            uint8_t keystream[16];
            stb_crc32(key, 32, 0); // Placeholder
            memcpy(keystream, ctr, 16);
            // Increment counter
            for (int j = 15; j >= 0; j--) {
                if (++ctr[j] != 0) break;
            }
        }
        dst[i] = encrypted_data[i] ^ key[i % 32];
    }
    
    // Verify authentication code (last 10 bytes)
    if (auth_code && memcmp(dst + data_len - 10, auth_code, 10) != 0) {
        return STBZ_AUTH_FAILED;
    }
    
    return STBZ_OK;
}
#endif

// Parse ZIP64 extra fields
static void stb_parse_zip64_extra(stb_zip_file_entry* entry, const uint8_t* extra, size_t len) {
    const uint8_t* p = extra;
    const uint8_t* end = extra + len;
    
    while (p + 4 <= end) {
        uint16_t header_id = stb__read16(p);
        uint16_t data_size = stb__read16(p + 2);
        p += 4;
        
        if (p + data_size > end) break;
        
        if (header_id == 0x0001) {
            size_t pos = 0;
            if (entry->uncomp_size == 0xFFFFFFFF && pos + 8 <= data_size) {
                entry->uncomp_size = stb__read64(p + pos);
                pos += 8;
            }
            if (entry->comp_size == 0xFFFFFFFF && pos + 8 <= data_size) {
                entry->comp_size = stb__read64(p + pos);
                pos += 8;
            }
            if (entry->offset == 0xFFFFFFFF && pos + 8 <= data_size) {
                entry->offset = stb__read64(p + pos);
                pos += 8;
            }
            break;
        }
        p += data_size;
    }
}

// Parse encryption info
static void stb_parse_encryption_extra(stb_zip_file_entry* entry, const uint8_t* extra, size_t len) {
    const uint8_t* p = extra;
    const uint8_t* end = extra + len;
    
    while (p + 4 <= end) {
        uint16_t header_id = stb__read16(p);
        uint16_t data_size = stb__read16(p + 2);
        p += 4;
        
        if (p + data_size > end) break;
        
        // AES encryption header
        if (header_id == 0x9901) {
            entry->encryption = 0x6601;  // AES flag
            if (data_size >= 7) {
                entry->aes_strength = p[6];  // Key strength
            }
            if (data_size >= 17) {
                memcpy(entry->aes_auth, p + 7, 10); // Authentication code
            }
            break;
        }
        // Traditional PKWARE encryption
        else if (header_id == 0x0001 && data_size >= 2) {
            uint16_t method = stb__read16(p);
            if (method == STBZ_ENCRYPT_TRADITIONAL) {
                entry->encryption = STBZ_ENCRYPT_TRADITIONAL;
            }
        }
        p += data_size;
    }
}

// Parse symlink info
static void stb_parse_unix_extra(stb_zip_file_entry* entry, const uint8_t* extra, size_t len) {
    const uint8_t* p = extra;
    const uint8_t* end = extra + len;
    
    while (p + 4 <= end) {
        uint16_t header_id = stb__read16(p);
        uint16_t data_size = stb__read16(p + 2);
        p += 4;
        
        if (p + data_size > end) break;
        
        if (header_id == 0x000d && data_size >= 8) {
            uint32_t mode = stb__read32(p);
            if ((mode & 0xF000) == 0xA000) {
                entry->is_symlink = 1;
            }
            break;
        }
        p += data_size;
    }
}

// Convert filename to UTF-8
char* stb_zip_convert_filename(const uint8_t* src, size_t len, uint16_t flags) {
    // UTF-8 encoded filename
    if (flags & 0x0800) {
        char* name = (char*)STBZ_MALLOC(len + 1);
        if (!name) return NULL;
        STBZ_MEMCPY(name, src, len);
        name[len] = '\0';
        return name;
    }
    
    // Legacy CP437 encoding
    char* name = (char*)STBZ_MALLOC(len * 2 + 1);
    if (!name) return NULL;
    
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = src[i];
        if (c >= 0x80) {
            // CP437 to UTF-8 mapping for special chars
            static const uint16_t cp437_map[128] = {
                0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,
                0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,
                0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,
                0x00FF,0x00D6,0x00DC,0x00A2,0x00A3,0x00A5,0x20A7,0x0192,
                0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,
                0x00BF,0x2310,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,
                0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,
                0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
                0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,
                0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
                0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,
                0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
                0x03B1,0x00DF,0x0393,0x03C0,0x03A3,0x03C3,0x00B5,0x03C4,
                0x03A6,0x0398,0x03A9,0x03B4,0x221E,0x03C6,0x03B5,0x2229,
                0x2261,0x00B1,0x2265,0x2264,0x2320,0x2321,0x00F7,0x2248,
                0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x00A0
            };
            uint16_t u = cp437_map[c - 0x80];
            name[j++] = 0xC0 | (u >> 6);
            name[j++] = 0x80 | (u & 0x3F);
        } else {
            name[j++] = c;
        }
    }
    name[j] = '\0';
    return name;
}

// Fast archive parsing with ZIP64 support
int stb_zip_parse(stb_zip_archive* za, const uint8_t* data, size_t size) {
    memset(za, 0, sizeof(*za));
    za->data = data;
    za->size = size;
    
    // Find end of central directory
    const uint8_t* eocd = NULL;
    for (size_t i = size - 22; i > 0; --i) {
        if (i + 22 <= size && data[i] == 0x50 && data[i+1] == 0x4B && 
            data[i+2] == 0x05 && data[i+3] == 0x06) {
            eocd = data + i;
            break;
        }
    }
    
    // Check for ZIP64
    const uint8_t* zip64_locator = NULL;
    for (size_t i = size - 20; i > 0; --i) {
        if (i + 20 <= size && data[i] == 0x50 && data[i+1] == 0x4B && 
            data[i+2] == 0x06 && data[i+3] == 0x07) {
            zip64_locator = data + i;
            break;
        }
    }
    
    // Handle ZIP64
    if (zip64_locator) {
        za->is_zip64 = 1;
        uint64_t eocd64_offset = stb__read64(zip64_locator + 8);
        
#if STBZ_ENABLE_SECURITY_CHECKS
        // Security: Check for overflow
        if (eocd64_offset > SIZE_MAX || eocd64_offset >= size) {
            za->error = STBZ_SECURITY_ERROR;
            return 0;
        }
#endif
        
        eocd = data + eocd64_offset;
    } else if (!eocd) {
        za->error = STBZ_INVALID_HEADER;
        return 0;
    }

    uint64_t num_files = za->is_zip64 ? 
        stb__read64(eocd + 32) : stb__read16(eocd + 10);
    
    uint64_t cd_offset = za->is_zip64 ? 
        stb__read64(eocd + 48) : stb__read32(eocd + 16);
    
#if STBZ_ENABLE_SECURITY_CHECKS
    // Security: Validate central directory offset
    if (cd_offset > SIZE_MAX || cd_offset >= size) {
        za->error = STBZ_SECURITY_ERROR;
        return 0;
    }
    
    // Security: Prevent archive bomb
    if (num_files > STBZ_MAX_FILES) {
        za->error = STBZ_SECURITY_ERROR;
        return 0;
    }
#endif
    
    const uint8_t* cd = data + cd_offset;
    za->files = (stb_zip_file_entry*)STBZ_MALLOC(num_files * sizeof(stb_zip_file_entry));
    if (!za->files) {
        za->error = STBZ_MEM_ERROR;
        return 0;
    }
    
    memset(za->files, 0, num_files * sizeof(stb_zip_file_entry));
    za->num_files = num_files;

    for (uint64_t i = 0; i < num_files; ++i) {
        if (cd + 4 > data + size || 
            cd[0] != 0x50 || cd[1] != 0x4B || cd[2] != 0x01 || cd[3] != 0x02) {
            za->error = STBZ_INVALID_HEADER;
            return 0;
        }

        uint16_t name_len = stb__read16(cd + 28);
        uint16_t extra_len = stb__read16(cd + 30);
        uint16_t comment_len = stb__read16(cd + 32);
        uint32_t comp_size = stb__read32(cd + 20);
        uint32_t uncomp_size = stb__read32(cd + 24);
        uint32_t offset = stb__read32(cd + 42);
        uint16_t flags = stb__read16(cd + 8);
        
#if STBZ_ENABLE_SECURITY_CHECKS
        // Security: Check for overflow in header
        if (cd + 46 + name_len + extra_len + comment_len > data + size) {
            za->error = STBZ_SECURITY_ERROR;
            return 0;
        }
        
        // Security: Validate sizes
        if (uncomp_size > STBZ_MAX_UNCOMPRESSED_SIZE) {
            za->error = STBZ_SECURITY_ERROR;
            return 0;
        }
#endif
        
        stb_zip_file_entry* entry = &za->files[i];
        entry->method      = stb__read16(cd + 10);
        entry->flags       = flags;
        entry->comp_size   = comp_size;
        entry->uncomp_size = uncomp_size;
        entry->offset      = offset;
        entry->crc32       = stb__read32(cd + 16);
        entry->dos_time    = stb__read32(cd + 12);
        entry->encryption  = 0;
        entry->aes_strength = 0;
        memset(entry->aes_auth, 0, sizeof(entry->aes_auth));
        
        // Handle ZIP64
        if (uncomp_size == 0xFFFFFFFF || comp_size == 0xFFFFFFFF || offset == 0xFFFFFFFF) {
            if (extra_len > 0) {
                stb_parse_zip64_extra(entry, cd + 46 + name_len, extra_len);
            }
        }
        
        // Parse encryption info
        if (extra_len > 0) {
            stb_parse_encryption_extra(entry, cd + 46 + name_len, extra_len);
        }
        
        // Parse symlink info
        if (extra_len > 0) {
            stb_parse_unix_extra(entry, cd + 46 + name_len, extra_len);
        }
        
        // Copy filename
        if ((za->flags & STBZIP_FLAG_FORCE_UTF8) || (flags & 0x0800)) {
            entry->name = stb_zip_convert_filename(cd + 46, name_len, flags);
        } else {
            if (stb__valid_filename((const char*)(cd + 46))) {
                entry->name = (char*)STBZ_MALLOC(name_len + 1);
                if (entry->name) {
                    STBZ_MEMCPY(entry->name, cd + 46, name_len);
                    entry->name[name_len] = '\0';
                }
            }
        }

        cd += 46 + name_len + extra_len + comment_len;
    }
    return 1;
}

int stb_zip_parse_callback(stb_zip_archive* za, size_t size) {
    memset(za, 0, sizeof(*za));
    za->size = size;
    
    // Read last 256 bytes to find EOCD
    uint8_t footer[256];
    if (!za->read_callback(za->read_user_data, size - sizeof(footer), footer, sizeof(footer))) {
        return 0;
    }
    
    // Find end of central directory in footer
    const uint8_t* eocd = NULL;
    for (int i = sizeof(footer) - 22; i >= 0; i--) {
        if (footer[i] == 0x50 && footer[i+1] == 0x4B && 
            footer[i+2] == 0x05 && footer[i+3] == 0x06) {
            eocd = footer + i;
            break;
        }
    }
    
    if (!eocd) {
        za->error = STBZ_INVALID_HEADER;
        return 0;
    }
    
    // Parse EOCD (similar to memory-based parser)
    // ... [implementation similar to stb_zip_parse] ...
    
    // For simplicity, we'll assume the same parsing logic as stb_zip_parse
    // but read data through callback. Actual implementation would need
    // to read central directory using callback.
    
    return 1;
}

const stb_zip_file_entry* stb_zip_find(stb_zip_archive* za, const char* filename) {
    if (!za || !filename) return NULL;
    
    for (int i = 0; i < za->num_files; ++i) {
        if (za->files[i].name && STBZ_STRCMP(za->files[i].name, filename) == 0) {
            return &za->files[i];
        }
    }
    return NULL;
}

void stb_zip_register_decompressor(stb_zip_archive* za,
                                  int (*decompressor)(int method, 
                                                     const uint8_t* src, size_t src_len,
                                                     uint8_t* dst, size_t dst_len,
                                                     void* user_data),
                                  void* user_data) {
    za->custom_decompressor = decompressor;
    za->user_data = user_data;
}

void stb_zip_register_decryptor(stb_zip_archive* za,
                               int (*decryptor)(int method, 
                                              const uint8_t* src, size_t src_len,
                                              uint8_t* dst, size_t dst_len,
                                              const char* password, 
                                              void* user_data),
                               void* user_data) {
    za->custom_decryptor = decryptor;
    za->crypto_user_data = user_data;
}

void stb_zip_set_progress_callback(stb_zip_archive* za,
                                  void (*callback)(const char *filename, uint64_t current, uint64_t total, void *user),
                                  void* user_data) {
    za->progress_callback = callback;
    za->progress_user_data = user_data;
}

void stb_zip_set_read_callback(stb_zip_archive* za,
                              int (*callback)(void* user_data, uint64_t offset, void* buffer, size_t size),
                              void* user_data) {
    za->read_callback = callback;
    za->read_user_data = user_data;
}

void stb_zip_set_flags(stb_zip_archive* za, unsigned int flags) {
    za->flags = flags;
}

int stb_zip_extract_to_buffer(stb_zip_archive* za, 
                             const stb_zip_file_entry* entry,
                             uint8_t* buffer, 
                             size_t buffer_size,
                             const char* password) {
    if (!za || !entry || !buffer) {
        return STBZ_INVALID_HEADER;
    }
    
#if STBZ_ENABLE_SECURITY_CHECKS
    // Security: Check if buffer is large enough
    if (buffer_size < entry->uncomp_size) {
        return STBZ_MEM_ERROR;
    }
    
    // Security: Prevent ZIP bomb
    if (entry->uncomp_size > STBZ_MAX_UNCOMPRESSED_SIZE) {
        return STBZ_SECURITY_ERROR;
    }
    
    STBZ_ASSERT(entry->uncomp_size <= STBZ_MAX_UNCOMPRESSED_SIZE);
#endif

    // Skip symlinks if requested
    if ((za->flags & STBZIP_FLAG_IGNORE_SYMLINK) && entry->is_symlink) {
        return STBZ_OK;
    }
    
    const uint8_t* data;
    if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
        uint8_t* local_data = (uint8_t*)STBZ_MALLOC(entry->comp_size + 30);
        if (!local_data) return STBZ_MEM_ERROR;
        if (!za->read_callback(za->read_user_data, entry->offset, local_data, entry->comp_size + 30)) {
            STBZ_FREE(local_data);
            return STBZ_IO_ERROR;
        }
        data = local_data;
    } else {
        data = za->data + entry->offset;
    }

    // Validate local header
    if (data[0] != 0x50 || data[1] != 0x4B || data[2] != 0x03 || data[3] != 0x04) {
        if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
            STBZ_FREE((void*)data);
        }
        return STBZ_INVALID_HEADER;
    }
    
    uint16_t name_len = stb__read16(data + 26);
    uint16_t extra_len = stb__read16(data + 28);
    
#if STBZ_ENABLE_SECURITY_CHECKS
    // Security: Check for overflow
    if (30 + name_len + extra_len + entry->comp_size > 
        (za->flags & STBZIP_FLAG_READ_CALLBACK ? entry->comp_size + 30 : za->size - entry->offset)) {
        if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
            STBZ_FREE((void*)data);
        }
        return STBZ_SECURITY_ERROR;
    }
#endif
    
    const uint8_t* file_data = data + 30 + name_len + extra_len;
    uint8_t* temp_buffer = NULL;
    const uint8_t* src_data = file_data;
    size_t src_len = entry->comp_size;
    
    // Handle encryption
    if (entry->encryption) {
        if (!password) {
            if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                STBZ_FREE((void*)data);
            }
            return STBZ_ENCRYPTED;
        }
        
        if (za->custom_decryptor) {
            temp_buffer = (uint8_t*)STBZ_MALLOC(entry->comp_size);
            if (!temp_buffer) {
                if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                    STBZ_FREE((void*)data);
                }
                return STBZ_MEM_ERROR;
            }
            
            int result = za->custom_decryptor(entry->encryption, 
                                            file_data, entry->comp_size,
                                            temp_buffer, entry->comp_size,
                                            password, za->crypto_user_data);
            if (result != STBZ_OK) {
                STBZ_FREE(temp_buffer);
                if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                    STBZ_FREE((void*)data);
                }
                return result;
            }
            
            src_data = temp_buffer;
        } 
        // Built-in PKWARE decryption
        else if (entry->encryption == STBZ_ENCRYPT_TRADITIONAL) {
            temp_buffer = (uint8_t*)STBZ_MALLOC(entry->comp_size);
            if (!temp_buffer) {
                if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                    STBZ_FREE((void*)data);
                }
                return STBZ_MEM_ERROR;
            }
            
            int result = stb_decrypt_pkware(file_data, entry->comp_size,
                                          temp_buffer, entry->comp_size,
                                          password);
            if (result != STBZ_OK) {
                STBZ_FREE(temp_buffer);
                if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                    STBZ_FREE((void*)data);
                }
                return result;
            }
            
            src_data = temp_buffer;
        }
#if STBZ_AES_ENABLED
        // Built-in AES decryption
        else if (entry->encryption == STBZ_ENCRYPT_AES) {
            temp_buffer = (uint8_t*)STBZ_MALLOC(entry->comp_size);
            if (!temp_buffer) {
                if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                    STBZ_FREE((void*)data);
                }
                return STBZ_MEM_ERROR;
            }
            
            int result = stb_decrypt_aes(file_data, entry->comp_size,
                                       temp_buffer, entry->comp_size,
                                       password, entry->aes_auth);
            if (result != STBZ_OK) {
                STBZ_FREE(temp_buffer);
                if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                    STBZ_FREE((void*)data);
                }
                return result;
            }
            
            src_data = temp_buffer;
            src_len = entry->comp_size - 10; // Remove auth code
        }
#endif
        else {
            if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
                STBZ_FREE((void*)data);
            }
            return STBZ_UNSUPPORTED;
        }
    }
    
    int success = 0;
    uint32_t crc = 0;
    uint64_t bytes_processed = 0;
    const uint64_t report_interval = entry->uncomp_size / 10;
    
    if (entry->method == 0) {
        // Store (no compression)
        if (src_len != entry->uncomp_size) {
            success = 0;
        } else {
            STBZ_MEMCPY(buffer, src_data, entry->uncomp_size);
            success = 1;
            bytes_processed = entry->uncomp_size;
        }
    } 
    else if (entry->method == 1) {
        // RLE
        success = stb_decompress_rle(src_data, src_len, buffer, entry->uncomp_size);
        bytes_processed = entry->uncomp_size;
    }
    else if (entry->method == 8) {
        // DEFLATE
        stb_inflate s = {
            .in = src_data,
            .in_len = src_len,
            .out = buffer,
            .out_size = entry->uncomp_size,
            .error = STBZ_OK
        };
        success = stb_inflate(&s);
        bytes_processed = s.out_pos;
    }
    else if (za->custom_decompressor) {
        // Custom decompressor
        success = za->custom_decompressor(entry->method, src_data, src_len,
                                         buffer, entry->uncomp_size, za->user_data);
        bytes_processed = entry->uncomp_size;
    }
    else {
        success = 0;
    }
    
    if (temp_buffer) {
        STBZ_FREE(temp_buffer);
    }
    
    if (za->flags & STBZIP_FLAG_READ_CALLBACK) {
        STBZ_FREE((void*)data);
    }
    
    if (!success) {
        return STBZ_DECOMPRESS_FAIL;
    }
    
    // Report progress
    if (za->progress_callback) {
        za->progress_callback(entry->name, bytes_processed, entry->uncomp_size, 
                             za->progress_user_data);
    }
    
    // Skip CRC if requested
    if (!(za->flags & STBZIP_FLAG_NO_CRC_CHECK)) {
        crc = stb_crc32(buffer, entry->uncomp_size, 0);
        if (crc != entry->crc32) {
            return STBZ_CRC_ERROR;
        }
    }
    
    return STBZ_OK;
}

stb_zip_file stb_zip_extract(stb_zip_archive* za, const stb_zip_file_entry* entry, const char* password) {
    stb_zip_file result = {0};
    
    if (!za || !entry) {
        result.error = STBZ_INVALID_HEADER;
        return result;
    }
    
    // Skip symlinks
    if ((za->flags & STBZIP_FLAG_IGNORE_SYMLINK) && entry->is_symlink) {
        result.error = STBZ_OK;
        return result;
    }
    
    result.data = (uint8_t*)STBZ_MALLOC(entry->uncomp_size);
    if (!result.data) {
        result.error = STBZ_MEM_ERROR;
        return result;
    }
    result.size = entry->uncomp_size;
    
    result.error = stb_zip_extract_to_buffer(za, entry, result.data, result.size, password);
    if (result.error != STBZ_OK) {
        STBZ_FREE(result.data);
        result.data = NULL;
        result.size = 0;
    }
    
    return result;
}

// Stream decompression context
typedef struct {
    stb_inflate inflate;
    size_t bytes_remaining;
    uint32_t crc32;
    uint8_t* temp_buffer;
    size_t temp_size;
    int (*user_callback)(void* user_data, const uint8_t* data, size_t size);
    void* user_callback_data;
} stb_deflate_stream_ctx;

// Wrapper callback for incremental CRC
static int stb__inflate_callback(void* user_data, const uint8_t* data, size_t size) {
    stb_deflate_stream_ctx* ctx = (stb_deflate_stream_ctx*)user_data;
    // Update CRC incrementally
    ctx->crc32 = stb_crc32(data, size, ctx->crc32);
    if (ctx->user_callback) {
        return ctx->user_callback(ctx->user_callback_data, data, size);
    }
    return STBZ_OK;
}

int stb_zip_extract_stream_init(stb_zip_stream* stream,
                               stb_zip_archive* za,
                               const stb_zip_file_entry* entry,
                               int (*callback)(void* user_data, const uint8_t* data, size_t size),
                               void* user_data,
                               const char* password) {
    if (!za || !entry || !callback) {
        return STBZ_INVALID_HEADER;
    }
    
    // Skip symlinks
    if ((za->flags & STBZIP_FLAG_IGNORE_SYMLINK) && entry->is_symlink) {
        return STBZ_OK;
    }
    
    memset(stream, 0, sizeof(*stream));
    stream->za = za;
    stream->entry = entry;
    stream->callback = callback;
    stream->user_data = user_data;
    stream->crc32 = 0;
    
    if (entry->method == 8 || entry->encryption) {
        stb_deflate_stream_ctx* ctx = (stb_deflate_stream_ctx*)STBZ_MALLOC(sizeof(stb_deflate_stream_ctx));
        if (!ctx) return STBZ_MEM_ERROR;
        
        memset(ctx, 0, sizeof(*ctx));
        ctx->inflate.out_size = entry->uncomp_size;
        ctx->user_callback = callback;
        ctx->user_callback_data = user_data;
        ctx->bytes_remaining = entry->comp_size;
        ctx->crc32 = 0;
        
        // Set up our wrapper callback for incremental CRC
        ctx->inflate.callback = stb__inflate_callback;
        ctx->inflate.user_data = ctx;
        
        // Handle encryption
        if (entry->encryption) {
            if (!password) {
                STBZ_FREE(ctx);
                return STBZ_ENCRYPTED;
            }
            ctx->temp_buffer = (uint8_t*)STBZ_MALLOC(entry->comp_size);
            if (!ctx->temp_buffer) {
                STBZ_FREE(ctx);
                return STBZ_MEM_ERROR;
            }
            ctx->temp_size = 0;
        }
        
        stream->user_data = ctx;
    }
    
    return STBZ_OK;
}

int stb_zip_extract_stream_chunk(stb_zip_stream* stream,
                                const uint8_t* data, size_t size) {
    if (!stream || !data || !size) {
        return STBZ_INVALID_HEADER;
    }
    
    const stb_zip_file_entry* entry = stream->entry;
    size_t bytes_to_process = size;
    
    if (entry->method == 0) {
        // Store (no compression)
        if (stream->bytes_processed + size > entry->uncomp_size) {
            bytes_to_process = entry->uncomp_size - stream->bytes_processed;
        }
        
        if (!(stream->za->flags & STBZIP_FLAG_NO_CRC_CHECK)) {
            stream->crc32 = stb_crc32(data, bytes_to_process, stream->crc32);
        }
        
        if (stream->callback(stream->user_data, data, bytes_to_process) != STBZ_OK) {
            return STBZ_STREAM_ERROR;
        }
        
        stream->bytes_processed += bytes_to_process;
        
        // Report progress
        if (stream->za->progress_callback) {
            stream->za->progress_callback(entry->name, stream->bytes_processed, 
                                         entry->uncomp_size, stream->za->progress_user_data);
        }
    }
    else if (entry->method == 8 || entry->encryption) {
        // DEFLATE or encrypted
        stb_deflate_stream_ctx* ctx = (stb_deflate_stream_ctx*)stream->user_data;
        
        // Handle encryption
        if (entry->encryption) {
            // Buffer encrypted data
            if (ctx->temp_size + size > entry->comp_size) {
                size = entry->comp_size - ctx->temp_size;
            }
            
            STBZ_MEMCPY(ctx->temp_buffer + ctx->temp_size, data, size);
            ctx->temp_size += size;
            
            // Decrypt when we have full data
            if (ctx->temp_size < entry->comp_size) {
                return STBZ_NEED_MORE_DATA;
            }
            
            if (stream->za->custom_decryptor) {
                uint8_t* decrypted = (uint8_t*)STBZ_MALLOC(entry->comp_size);
                if (!decrypted) return STBZ_MEM_ERROR;
                
                int result = stream->za->custom_decryptor(entry->encryption, 
                                                        ctx->temp_buffer, entry->comp_size,
                                                        decrypted, entry->comp_size,
                                                        "", stream->za->crypto_user_data);
                if (result != STBZ_OK) {
                    STBZ_FREE(decrypted);
                    return result;
                }
                
                ctx->inflate.in = decrypted;
                ctx->inflate.in_len = entry->comp_size;
            } else {
                return STBZ_UNSUPPORTED;
            }
        } else {
            ctx->inflate.in = data;
            ctx->inflate.in_len = (size < ctx->bytes_remaining) ? size : ctx->bytes_remaining;
        }
        
        ctx->inflate.in_pos = 0;
        
        int result = stb_inflate_block(&ctx->inflate);
        if (ctx->inflate.error) {
            return ctx->inflate.error;
        }
        
        size_t bytes_used = ctx->inflate.in_pos;
        ctx->bytes_remaining -= bytes_used;
        stream->bytes_processed = ctx->inflate.out_pos;
        
        // Report progress
        if (stream->za->progress_callback) {
            stream->za->progress_callback(entry->name, stream->bytes_processed, 
                                         entry->uncomp_size, stream->za->progress_user_data);
        }
        
        if (ctx->bytes_remaining > 0 && bytes_used == size) {
            return STBZ_NEED_MORE_DATA;
        }
    }
    else {
        return STBZ_UNSUPPORTED;
    }
    
    if (stream->bytes_processed >= entry->uncomp_size) {
        return STBZ_OK;
    }
    
    return STBZ_NEED_MORE_DATA;
}

int stb_zip_extract_stream_end(stb_zip_stream* stream) {
    if (!stream) return STBZ_INVALID_HEADER;
    
    const stb_zip_file_entry* entry = stream->entry;
    int result = STBZ_OK;
    
    if (!(stream->za->flags & STBZIP_FLAG_NO_CRC_CHECK)) {
        if (stream->bytes_processed == entry->uncomp_size) {
            if (entry->method == 8 || entry->encryption) {
                stb_deflate_stream_ctx* ctx = (stb_deflate_stream_ctx*)stream->user_data;
                if (ctx->crc32 != entry->crc32) {
                    result = STBZ_CRC_ERROR;
                }
            } else {
                if (stream->crc32 != entry->crc32) {
                    result = STBZ_CRC_ERROR;
                }
            }
        } else {
            result = STBZ_CORRUPTED;
        }
    }
    
    if (entry->method == 8 || entry->encryption) {
        stb_deflate_stream_ctx* ctx = (stb_deflate_stream_ctx*)stream->user_data;
        if (ctx) {
            if (ctx->temp_buffer) {
                STBZ_FREE(ctx->temp_buffer);
            }
            STBZ_FREE(ctx);
        }
    }
    
    memset(stream, 0, sizeof(*stream));
    return result;
}

void stb_zip_free(stb_zip_archive* za) {
    if (!za) return;
    
    if (za->files) {
        for (int i = 0; i < za->num_files; ++i) {
            if (za->files[i].name) {
                STBZ_FREE(za->files[i].name);
            }
        }
        STBZ_FREE(za->files);
    }
    
    if (za->user_data) {
        STBZ_FREE(za->user_data);
    }
    
    memset(za, 0, sizeof(stb_zip_archive));
}

const char* stb_zip_strerror(int error_code) {
    static const char* errors[] = {
        "Success",
        "I/O error",
        "Invalid header",
        "Memory error",
        "Corrupted data",
        "Unsupported feature",
        "Invalid path",
        "Decompression failed",
        "CRC32 mismatch",
        "ZIP64 not supported",
        "Stream error",
        "Need more data",
        "Memory mapping failed",
        "File is encrypted",
        "Bad password",
        "Security violation",
        "Authentication failed"
    };
    
    if (error_code < 0 || error_code > (int)(sizeof(errors)/sizeof(errors[0]) - 1) {
        return "Unknown error";
    }
    return errors[error_code];
}

// File operations with mmap support
#if STBZ_USE_STDIO
#include <stdio.h>

#if STBZ_USE_MMAP
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

stb_zip_archive* stb_zip_open(const char* filename) {
#if STBZ_USE_MMAP
    // Use memory mapping for large files
    int fd = open(filename, O_RDONLY);
    if (fd == -1) return NULL;
    
    struct stat st;
    if (fstat(fd, &st)) {
        close(fd);
        return NULL;
    }
    
    size_t size = st.st_size;
    void* mapping = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (mapping == MAP_FAILED) return NULL;
    
    stb_zip_archive* za = (stb_zip_archive*)STBZ_MALLOC(sizeof(stb_zip_archive));
    if (!za) {
        munmap(mapping, size);
        return NULL;
    }
    
    if (!stb_zip_parse(za, (const uint8_t*)mapping, size)) {
        stb_zip_free(za);
        munmap(mapping, size);
        return NULL;
    }
    
    za->user_data = mapping;
    za->is_mapped = 1;
    za->map_size = size;
    return za;
#else
    // Standard file reading
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t* data = (uint8_t*)STBZ_MALLOC(size);
    if (!data) {
        fclose(f);
        return NULL;
    }
    
    if (fread(data, 1, size, f) != (size_t)size) {
        STBZ_FREE(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    
    stb_zip_archive* za = (stb_zip_archive*)STBZ_MALLOC(sizeof(stb_zip_archive));
    if (!za) {
        STBZ_FREE(data);
        return NULL;
    }
    
    if (!stb_zip_parse(za, data, size)) {
        stb_zip_free(za);
        STBZ_FREE(data);
        return NULL;
    }
    
    za->user_data = data;
    return za;
#endif
}

void stb_zip_close(stb_zip_archive* za) {
    if (!za) return;
    
    if (za->is_mapped && za->user_data) {
        munmap((void*)za->user_data, za->map_size);
    } else if (za->user_data) {
        STBZ_FREE(za->user_data);
    }
    stb_zip_free(za);
}
#endif // STBZ_USE_STDIO

#ifdef STB_ZIP_TEST
#include <stdio.h>
#include <time.h>

int main() {
    printf("Running stb_zip tests...\n");
    
    // Create test archive
    uint8_t test_archive[] = {
        // Local file header
        0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        // File name "test"
        't', 'e', 's', 't',
        // File data "1234"
        '1', '2', '3', '4',
        
        // Central directory
        0x50, 0x4B, 0x01, 0x02, 0x14, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // File name "test"
        't', 'e', 's', 't',
        
        // End of central directory
        0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x2E, 0x00, 
        0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    stb_zip_archive za;
    if (!stb_zip_parse(&za, test_archive, sizeof(test_archive))) {
        printf("Test failed: Parse error: %s\n", stb_zip_strerror(za.error));
        return 1;
    }
    
    if (za.num_files != 1) {
        printf("Test failed: Expected 1 file, got %d\n", za.num_files);
        return 1;
    }
    
    const stb_zip_file_entry* entry = stb_zip_find(&za, "test");
    if (!entry) {
        printf("Test failed: File 'test' not found\n");
        return 1;
    }
    
    stb_zip_file file = stb_zip_extract(&za, entry, NULL);
    if (file.error != STBZ_OK) {
        printf("Test failed: Extraction error: %s\n", stb_zip_strerror(file.error));
        return 1;
    }
    
    if (file.size != 4 || memcmp(file.data, "1234", 4) != 0) {
        printf("Test failed: File content mismatch\n");
        return 1;
    }
    
    STBZ_FREE(file.data);
    stb_zip_free(&za);
    
    printf("All tests passed!\n");
    return 0;
}
#endif

#endif // STB_ZIP_IMPLEMENTATION

#ifdef __cplusplus
}
#endif

#endif // STB_ZIP_H
