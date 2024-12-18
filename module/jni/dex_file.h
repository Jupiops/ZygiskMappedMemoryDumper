//
// Created by Jupio on 17.12.2024.
// https://cs.android.com/android/platform/superproject/main/+/main:art/libdexfile/dex/dex_file.h
//

#ifndef ZYGISKMAPPEDMEMORYDUMPER_DEX_FILE_H
#define ZYGISKMAPPEDMEMORYDUMPER_DEX_FILE_H

// A macro to disallow the copy constructor and operator= functions
// This must be placed in the private: declarations for a class.
//
// For disallowing only assign or copy, delete the relevant operator or
// constructor, for example:
// void operator=(const TypeName&) = delete;
// Note, that most uses of DISALLOW_ASSIGN and DISALLOW_COPY are broken
// semantically, one should either use disallow both or neither. Try to
// avoid these in new code.
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&) = delete;      \
  void operator=(const TypeName&) = delete

#define PACKED(x) __attribute__ ((__aligned__(x), __packed__))

// Some of the libs (e.g. libarttest(d)) require more public symbols when built
// in debug configuration.
// Using symbol visibility only for release builds allows to reduce the list of
// exported symbols and eliminates the need to check debug build configurations
// when changing the exported symbols.
#ifdef NDEBUG
#define HIDDEN __attribute__((visibility("hidden")))
#define PROTECTED __attribute__((visibility("protected")))
#define EXPORT __attribute__((visibility("default")))
#else
#define HIDDEN
#define PROTECTED
#define EXPORT
#endif

// Changing this definition will cause you a lot of pain.  A majority of
// vendor code defines LIKELY and UNLIKELY this way, and includes
// this header through an indirect path.
#define LIKELY( exp )       (__builtin_expect( (exp) != 0, true  ))
#define UNLIKELY( exp )     (__builtin_expect( (exp) != 0, false ))

struct DexHeader {
    uint8_t magic_[8];           // includes magic number & version
    uint32_t checksum_;           // adler32 checksum of the rest of the file (everything but magic & this field)
    uint8_t signature_[20];      // SHA-1 signature (hash)
    uint32_t file_size_ = 0;  // size of entire file
    uint32_t header_size_ = 0;  // offset to start of next section
    uint32_t endian_tag_ = 0;
    uint32_t link_size_ = 0;  // unused
    uint32_t link_off_ = 0;  // unused
    uint32_t map_off_ = 0;  // map list offset from data_off_
    uint32_t string_ids_size_ = 0;  // number of StringIds
    uint32_t string_ids_off_ = 0;  // file offset of StringIds array
    uint32_t type_ids_size_ = 0;  // number of TypeIds, we don't support more than 65535
    uint32_t type_ids_off_ = 0;  // file offset of TypeIds array
    uint32_t proto_ids_size_ = 0;  // number of ProtoIds, we don't support more than 65535
    uint32_t proto_ids_off_ = 0;  // file offset of ProtoIds array
    uint32_t field_ids_size_ = 0;  // number of FieldIds
    uint32_t field_ids_off_ = 0;  // file offset of FieldIds array
    uint32_t method_ids_size_ = 0;  // number of MethodIds
    uint32_t method_ids_off_ = 0;  // file offset of MethodIds array
    uint32_t class_defs_size_ = 0;  // number of ClassDefs
    uint32_t class_defs_off_ = 0;  // file offset of ClassDef array
    uint32_t data_size_ = 0;  // size of data section
    uint32_t data_off_ = 0;  // file offset of data section
};

// Map item type codes.
enum MapItemType : uint16_t {  // private
    kDexTypeHeaderItem = 0x0000,
    kDexTypeStringIdItem = 0x0001,
    kDexTypeTypeIdItem = 0x0002,
    kDexTypeProtoIdItem = 0x0003,
    kDexTypeFieldIdItem = 0x0004,
    kDexTypeMethodIdItem = 0x0005,
    kDexTypeClassDefItem = 0x0006,
    kDexTypeCallSiteIdItem = 0x0007,
    kDexTypeMethodHandleItem = 0x0008,
    kDexTypeMapList = 0x1000,
    kDexTypeTypeList = 0x1001,
    kDexTypeAnnotationSetRefList = 0x1002,
    kDexTypeAnnotationSetItem = 0x1003,
    kDexTypeClassDataItem = 0x2000,
    kDexTypeCodeItem = 0x2001,
    kDexTypeStringDataItem = 0x2002,
    kDexTypeDebugInfoItem = 0x2003,
    kDexTypeAnnotationItem = 0x2004,
    kDexTypeEncodedArrayItem = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
    kDexTypeHiddenapiClassData = 0xF000,
};

// https://cs.android.com/android/platform/superproject/main/+/main:art/libdexfile/dex/dex_file_structs.h
// Map items start after the 4-byte size, each item is 12 bytes:
// Layout: type(2), unused(2), size(4), offset(4)
struct MapItem {
    uint16_t type_;
    uint16_t unused_;
    uint32_t size_;
    uint32_t offset_;
};

struct MapList {
    uint32_t size_;
    MapItem list_[1];

    size_t Size() const { return sizeof(uint32_t) + (size_ * sizeof(MapItem)); }

private:
    DISALLOW_COPY_AND_ASSIGN(MapList);
};

enum class InstructionSet {
    kNone,
    kArm,
    kArm64,
    kThumb2,
    kRiscv64,
    kX86,
    kX86_64,
    kLast = kX86_64
};

/**
 * The header of the Oat file.
 * Contains the version of the file and the necessary data to initialize the runtime.
 * @see https://cs.android.com/android/platform/superproject/main/+/main:art/runtime/oat/oat.h
 * https://cs.android.com/android/platform/superproject/main/+/main:art/libartbase/arch/instruction_set.h
 * @see https://cs.android.com/android/_/android/platform/art/+/f8a57338dce3af596799eb44daa60333cc3894a3:runtime/oat/oat.h;drf=runtime%2Foat.h;drc=63af30b8fe8d4e1dc32db4dcb5e5dae1efdc7f31
 * https://cs.android.com/android/_/android/platform/art/+/f8a57338dce3af596799eb44daa60333cc3894a3:libartbase/arch/instruction_set.h;drc=4184f23701a64e9902ffced803968fcc5601764b
 */
class PACKED(4) OatHeader {
public:
    static constexpr std::array<uint8_t, 4> kOatMagic{{'o', 'a', 't', '\n'}};
    // Last oat version changed reason: ARM64: Enable implicit suspend checks; compiled code check.
    static constexpr std::array<uint8_t, 4> kOatVersion{{'2', '3', '0', '\0'}};

    static constexpr const char *kDex2OatCmdLineKey = "dex2oat-cmdline";
    static constexpr const char *kDebuggableKey = "debuggable";
    static constexpr const char *kNativeDebuggableKey = "native-debuggable";
    static constexpr const char *kCompilerFilter = "compiler-filter";
    static constexpr const char *kClassPathKey = "classpath";
    static constexpr const char *kBootClassPathKey = "bootclasspath";
    static constexpr const char *kBootClassPathChecksumsKey = "bootclasspath-checksums";
    static constexpr const char *kApexVersionsKey = "apex-versions";
    static constexpr const char *kConcurrentCopying = "concurrent-copying";
    static constexpr const char *kCompilationReasonKey = "compilation-reason";
    static constexpr const char *kRequiresImage = "requires-image";

    static constexpr const char kTrueValue[] = "true";

    const char *GetStoreValueByKey(const char *key) const {
        std::string_view key_view(key);
        const char *ptr = reinterpret_cast<const char *>(&key_value_store_);
        const char *end = ptr + key_value_store_size_;

        while (ptr < end) {
            // Scan for a closing zero.
            const char *str_end = reinterpret_cast<const char *>(memchr(ptr, 0, end - ptr));
            if (UNLIKELY(str_end == nullptr)) {
                LOGW("OatHeader: Unterminated key in key value store.");
                return nullptr;
            }
            const char *value_start = str_end + 1;
            const char *value_end = reinterpret_cast<const char *>(memchr(value_start, 0, end - value_start));
            if (UNLIKELY(value_end == nullptr)) {
                LOGW("OatHeader: Unterminated value in key value store.");
                return nullptr;
            }
            if (key_view == std::string_view(ptr, str_end - ptr)) {
                // Same as key.
                return value_start;
            }
            // Different from key. Advance over the value.
            ptr = value_end + 1;
        }
        // Not found.
        return nullptr;
    }

    bool GetStoreKeyValuePairByIndex(size_t index, const char **key, const char **value) const {
        const char *ptr = reinterpret_cast<const char *>(&key_value_store_);
        const char *end = ptr + key_value_store_size_;
        size_t counter = index;

        while (ptr < end) {
            // Scan for a closing zero.
            const char *str_end = reinterpret_cast<const char *>(memchr(ptr, 0, end - ptr));
            if (UNLIKELY(str_end == nullptr)) {
                LOGW("OatHeader: Unterminated key in key value store.");
                return false;
            }
            const char *value_start = str_end + 1;
            const char *value_end = reinterpret_cast<const char *>(memchr(value_start, 0, end - value_start));
            if (UNLIKELY(value_end == nullptr)) {
                LOGW("OatHeader: Unterminated value in key value store.");
                return false;
            }
            if (counter == 0) {
                *key = ptr;
                *value = value_start;
                return true;
            } else {
                --counter;
            }
            // Advance over the value.
            ptr = value_end + 1;
        }
        // Not found.
        return false;
    }

    size_t GetHeaderSize() const {
        return sizeof(OatHeader) + key_value_store_size_;
    }

    bool IsDebuggable() const {
        return IsKeyEnabled(OatHeader::kDebuggableKey);
    }

    bool IsConcurrentCopying() const {
        return IsKeyEnabled(OatHeader::kConcurrentCopying);
    }

    bool IsNativeDebuggable() const {
        return IsKeyEnabled(OatHeader::kNativeDebuggableKey);
    }

    bool RequiresImage() const {
        return IsKeyEnabled(OatHeader::kRequiresImage);
    }

    const char *GetCompilerFilter() const {
        const char *key_value = GetStoreValueByKey(kCompilerFilter);
        return key_value;
    }

    bool KeyHasValue(const char *key, const char *value, size_t value_size) const {
        const char *key_value = GetStoreValueByKey(key);
        return (key_value != nullptr && strncmp(key_value, value, value_size) == 0);
    }

    bool IsKeyEnabled(const char *key) const {
        return KeyHasValue(key, kTrueValue, sizeof(kTrueValue));
    }

//private:

//    std::array<uint8_t, 4> magic_;
    uint8_t magic_[4];
//    std::array<uint8_t, 4> version_;
    uint8_t version_[4];
    uint32_t oat_checksum_;

    InstructionSet instruction_set_;
    uint32_t instruction_set_features_bitmap_;
    uint32_t dex_file_count_;
    uint32_t oat_dex_files_offset_;
    uint32_t bcp_bss_info_offset_;
    uint32_t executable_offset_;
    uint32_t jni_dlsym_lookup_trampoline_offset_;
    uint32_t jni_dlsym_lookup_critical_trampoline_offset_;
    uint32_t quick_generic_jni_trampoline_offset_;
    uint32_t quick_imt_conflict_trampoline_offset_;
    uint32_t quick_resolution_trampoline_offset_;
    uint32_t quick_to_interpreter_bridge_offset_;
    uint32_t nterp_trampoline_offset_;

    uint32_t key_value_store_size_;
    uint8_t key_value_store_[0];  // note variable width data at end

    DISALLOW_COPY_AND_ASSIGN(OatHeader);
};

static inline const uint8_t *dex_base(const struct DexHeader *dex_header) {
    return (const uint8_t *) dex_header;
}

// Retrieves the MapList if it exists and is within the range; otherwise returns NULL.
static const struct MapList *get_map_list(const struct DexHeader *dex_header, const uint8_t *range_base, const uint8_t *range_end) {
    if (dex_header->map_off_ == 0) {
        return NULL;
    }

    // Check basic boundaries
    if ((uintptr_t) dex_header->map_off_ > (uintptr_t) (range_end - range_base)) {
        return NULL;
    }

    const struct MapList *map_list = (const struct MapList *) (dex_base(dex_header) + dex_header->map_off_);
    if (map_list->size_ < 1 || map_list->size_ > 1000) {
        return NULL;
    }

    size_t total_map_size = map_list->Size();
    const uint8_t *map_list_end = ((const uint8_t *) map_list) + total_map_size;
    if (map_list_end < range_base || map_list_end > range_end) {
        return NULL;
    }

    return map_list;
}

// verify_by_maps checks if dex_header->map_off_ matches a map item of type kDexTypeMapList.
static bool verify_by_maps(const struct DexHeader *dex_header, const uint8_t *range_base, const uint8_t *range_end) {
    const struct MapList *map_list = get_map_list(dex_header, range_base, range_end);
    if (map_list == NULL) {
        LOGW("No map list found");
        return false;
    }

    uint32_t maps_offset = dex_header->map_off_;
    for (uint32_t i = 0; i < map_list->size_; i++) {
        const struct MapItem *item = &map_list->list_[i];
        if (item->type_ == kDexTypeMapList) {
            if (item->offset_ == maps_offset) {
                return true;
            }
        }
    }
    return false;
}

// get_dex_real_size tries to determine the "real" dex size from the map list if present.
static size_t get_dex_real_size(const struct DexHeader *dex_header, const uint8_t *range_base, const uint8_t *range_end) {
    uint32_t dex_size = dex_header->file_size_;
    const struct MapList *map_list = get_map_list(dex_header, range_base, range_end);

    if (map_list == NULL) {
        // No map list, fallback to file_size_ from the header
        LOGW("No map list found, using file_size_");
        return dex_size;
    }

    // If we have a valid map list, "real size" can be considered up to the end of the map list.
    // maps_end = map_off_ + map_list->Size()
    const uint8_t *maps_end = dex_base(dex_header) + dex_header->map_off_ + map_list->Size();
    if (maps_end > range_end) {
        // If maps_end is outside our range, fall back to file_size_
        LOGW("Map list end is outside range, using file_size_");
        return dex_size;
    }

    // Return the offset difference to get real size
    return (size_t) (maps_end - dex_base(dex_header));
}

// verify_ids_off checks if the various IDs offsets are within the dex size and >= 0x70.
static bool verify_ids_off(const struct DexHeader *dex_header, size_t dex_size) {
    LOGD("String IDs offset: 0x%x, Type IDs offset: 0x%x, Proto IDs offset: 0x%x, Field IDs offset: 0x%x, Method IDs offset: 0x%x",
         dex_header->string_ids_off_, dex_header->type_ids_off_, dex_header->proto_ids_off_, dex_header->field_ids_off_, dex_header->method_ids_off_);
    return (dex_header->string_ids_off_ < dex_size && dex_header->string_ids_off_ >= 0x70) &&
           (dex_header->type_ids_off_ < dex_size && dex_header->type_ids_off_ >= 0x70) &&
           (dex_header->proto_ids_off_ < dex_size && dex_header->proto_ids_off_ >= 0x70) &&
           (dex_header->field_ids_off_ < dex_size && dex_header->field_ids_off_ >= 0x70) &&
           (dex_header->method_ids_off_ < dex_size && dex_header->method_ids_off_ >= 0x70);
}

// verify checks that we can read the header and optionally verifies by map list.
// enable_verify_maps: If true, verify by map; if false, just ensure string_ids_off == 0x70.
static bool verify(const struct DexHeader *dex_header, const uint8_t *range_base, size_t range_size, bool enable_verify_maps) {
    if (range_base == NULL || dex_header == NULL) {
        LOGW("Invalid arguments for verify");
        return false;
    }

    const uint8_t *range_end = range_base + range_size;

    // Verify we can read at least 0x70 bytes from dex_header
    if ((const uint8_t *) dex_header + 0x70 > range_end) {
        LOGW("Invalid range for verify");
        return false;
    }

    if (enable_verify_maps) {
        // Perform map verification
        return verify_by_maps(dex_header, range_base, range_end);
    } else {
        // Without map verification, just ensure string_ids_off_ == 0x70 as a basic check.
        return (dex_header->string_ids_off_ == 0x70);
    }
}

#endif //ZYGISKMAPPEDMEMORYDUMPER_DEX_FILE_H
