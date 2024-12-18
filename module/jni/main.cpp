/* Copyright 2022-2023 John "topjohnwu" Wu
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstddef>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysmacros.h> // For makedev
#include <android/log.h>
#include <android/dlext.h>

#include "log.h"
#include "zygisk.hpp"
#include "no_strings.hpp"
#include "dex_file.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

/**
 * @brief Represents a single entry from /proc/self/maps.
 */
struct MapEntry {
    uintptr_t start_address;
    uintptr_t end_address;
    std::string permissions;
    uintptr_t offset;
//    std::string device;
//    int inode;
    dev_t device;
    ino_t inode;
    std::string pathname;
};

/**
 * @brief Parse the current process' memory maps from /proc/self/maps.
 *
 * @param mapsPath Path to the maps file (usually "/proc/self/maps").
 * @return A vector of parsed MapEntry structures.
 */
std::vector <MapEntry> parseMaps(const std::string &mapsPath) {
    std::vector <MapEntry> entries;
    std::ifstream mapsFile(mapsPath);

    if (!mapsFile.is_open()) {
        LOGE("Failed to open %s", mapsPath.c_str());
        return entries;
    }

    std::string line;
    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        MapEntry entry;
        int dev_major, dev_minor;
        char dummy_char;

        // Parse the line
        if (!(iss >> std::hex >> entry.start_address >> dummy_char >> entry.end_address >> entry.permissions >> entry.offset >> dev_major >> dummy_char >> dev_minor >> std::dec >> entry.inode)) {
            LOGW("Failed to parse line: %s", line.c_str());
            continue;
        }

        // Convert major and minor to device
        entry.device = makedev(dev_major, dev_minor);

        if (!(iss >> entry.pathname)) {
            entry.pathname = make_string("[anonymous]");
        }

        entries.push_back(entry);
    }

    mapsFile.close();
    return entries;
}

/**
 * @brief Logs a hex dump of a memory region.
 *
 * @param data Pointer to the data to print.
 * @param size Number of bytes to print.
 * @param start_addr The base address for labeling the dump.
 */
void hexdump(const void *data, size_t size, uintptr_t start_addr) {
    const uint8_t *ptr = (const uint8_t *) data;
    size_t i, j;
    char line_buffer[128]; // buffer to format a line
    for (i = 0; i < size; i += 16) {
        int pos = 0;
        pos += snprintf(line_buffer + pos, sizeof(line_buffer) - pos, "%08lx: ", (unsigned long) (start_addr + i));

        // Print hex
        for (j = 0; j < 16 && (i + j) < size; j++) {
            pos += snprintf(line_buffer + pos, sizeof(line_buffer) - pos, "%02x ", ptr[i + j]);
        }

        // Add spacing if last line is shorter
        for (; j < 16; j++) {
            pos += snprintf(line_buffer + pos, sizeof(line_buffer) - pos, "   ");
        }

        // Print ASCII
        pos += snprintf(line_buffer + pos, sizeof(line_buffer) - pos, "|");
        for (j = 0; j < 16 && (i + j) < size; j++) {
            uint8_t c = ptr[i + j];
            pos += snprintf(line_buffer + pos, sizeof(line_buffer) - pos, "%c", isprint(c) ? c : '.');
        }
        pos += snprintf(line_buffer + pos, sizeof(line_buffer) - pos, "|");

        LOGD("%s", line_buffer);
    }
}

/**
 * @brief Parse a pattern string (e.g., "64 65 78 0a ...") into byte and mask arrays.
 *
 * '?' bytes are treated as wildcards.
 *
 * @param pattern The input pattern string.
 * @param pattern_bytes Output array for pattern bytes.
 * @param pattern_mask Output array for mask (true=match exact byte, false=wildcard).
 * @param max_len Maximum length to parse.
 * @return Number of parsed bytes in the pattern.
 */
int parse_pattern(const char *pattern, uint8_t *pattern_bytes, bool *pattern_mask, int max_len) {
    int count = 0;

    while (*pattern != '\0' && count < max_len) {
        // Skip spaces
        while (*pattern == ' ') {
            pattern++;
        }

        if (*pattern == '\0') {
            break;
        }

        if (*pattern == '?') {
            // Wildcard byte
            pattern_bytes[count] = 0;  // Arbitrary value for wildcard
            pattern_mask[count] = false; // false means wildcard
            count++;
            pattern++;
            // If it's a double '?', just move past the second '?'
            if (*pattern == '?') {
                pattern++;
            }
        } else if (isxdigit((unsigned char) pattern[0]) && isxdigit((unsigned char) pattern[1])) {
            // Parse a hex byte
            uint8_t val = 0;
            for (int i = 0; i < 2; i++) {
                char c = pattern[i];
                val <<= 4;
                if (c >= '0' && c <= '9') {
                    val |= (c - '0');
                } else if (c >= 'a' && c <= 'f') {
                    val |= (c - 'a' + 10);
                } else if (c >= 'A' && c <= 'F') {
                    val |= (c - 'A' + 10);
                }
            }

            pattern_bytes[count] = val;
            pattern_mask[count] = true; // must match exact byte
            count++;
            pattern += 2; // move past the two hex digits
        } else {
            // Unrecognized character, move forward
            pattern++;
        }
    }

    return count;
}

/**
 * @brief Find a pattern in the given memory range.
 *
 * @param start_addr Start of the memory range.
 * @param end_addr End of the memory range.
 * @param pattern_bytes Byte pattern to match.
 * @param pattern_mask Mask array (true=exact match, false=wildcard).
 * @param pattern_len Length of the pattern.
 * @return The address of the first match, or 0 if not found.
 */
static uintptr_t find_pattern(const uint8_t *start_addr, const uint8_t *end_addr, const uint8_t *pattern_bytes, const bool *pattern_mask, int pattern_len) {
    if (!start_addr || !end_addr || !pattern_bytes || !pattern_mask || pattern_len <= 0) {
        return 0;
    }

    if (end_addr <= start_addr) {
        return 0;
    }

    size_t region_size = (size_t) (end_addr - start_addr);

    // Naive search
    for (size_t i = 0; i + pattern_len <= region_size; i++) {
        const uint8_t *ptr = start_addr + i;
        bool match = true;
        for (int j = 0; j < pattern_len; j++) {
            if (pattern_mask[j] && ptr[j] != pattern_bytes[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return (uintptr_t) ptr;
        }
    }

    return 0; // not found
}

/**
 * @brief Original pointer to android_dlopen_ext function.
 */
void *(*orig_android_dlopen_ext)(
        void *self,
        const char *filename,
        int flags,
        const android_dlextinfo *info
) = nullptr;

/**
 * @brief Hooked android_dlopen_ext function for debugging.
 *
 * @param __filename The filename of the library to load.
 * @param __flags Flags used in dlopen.
 * @param __info Extended load info.
 * @return Pointer to the loaded library.
 */
static void *android_dlopen_ext_hooked(
        void *self,
        const char *filename,
        int flags,
        const android_dlextinfo *info
) {
    LOGD("android_dlopen_ext called: %s, flags: %08x", filename, flags);
    return orig_android_dlopen_ext(self, filename, flags, info);
}

void *(*orig_do_dlopen)(void *self, const char *name, int flags,
                        const android_dlextinfo *extinfo,
                        const void *caller_addr) = nullptr;

void *do_dlopen(void *self, const char *name, int flags,
                const android_dlextinfo *extinfo,
                const void *caller_addr) {
    LOGD("do_dlopen called: %s, flags: %08x", name, flags);
    return orig_do_dlopen(self, name, flags, extinfo, caller_addr);
}

/**
 * @brief Attempts to hook a symbol by name in the given library.
 *
 * @param api Zygisk API instance.
 * @param libName Name of the library to hook.
 * @param symbolName The symbol name to hook.
 * @param hookFunc The function to call instead of the original.
 * @param origFunc A pointer to store the original function address.
 * @return True on success, false otherwise.
 */
bool hookPLTByName(
        zygisk::Api *api,
        const std::string &libName,
        const std::string &symbolName,
        void *hookFunc,
        void **origFunc
) {
    // Get all memory mappings for this process
    const std::string mapsPath = make_string("/proc/self/maps");
    std::vector <MapEntry> entries = parseMaps(mapsPath);
    if (entries.empty()) {
        return false;
    }

    // Iterate through each map
    for (const auto &entry: entries) {
        // Check if the pathname ends with the specified library name
        if (entry.pathname.size() >= libName.size() &&
            entry.pathname.compare(entry.pathname.size() - libName.size(), libName.size(), libName) == 0) {

            // Attempt to register the PLT hook
            api->pltHookRegister(
                    entry.device,
                    entry.inode,
                    symbolName.c_str(),
                    hookFunc,
                    origFunc
            );
            LOGD("Hooking %s in %s with device %x:%x inode %lu",
                 symbolName.c_str(), entry.pathname.c_str(), major(entry.device), minor(entry.device), entry.inode);
            return true;
        }
    }

    return false;
}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) {
            return;
        }
        // Use JNI to fetch our process name
        const char *raw_app_name = env_->GetStringUTFChars(args->nice_name, nullptr);

        std::string app_name = std::string(raw_app_name);
        env_->ReleaseStringUTFChars(args->nice_name, raw_app_name);

        if (app_name != make_string("ar.tvplayer.tv")) {
            return;
        }

        //hook android_dlopen_ext
        if (!hookPLTByName(api_, make_string("libdl.so"), "android_dlopen_ext", (void *) android_dlopen_ext_hooked, (void **) &orig_android_dlopen_ext)) {
            LOGE("%s", make_string("Failed to hook android_dlopen_ext").c_str());
        }
#ifdef __LP64__
        const std::string linker = make_string("linker64");
#else
        const std::string linker = make_string("linker");
#endif
        if (!hookPLTByName(api_, linker, "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv", (void *) do_dlopen, (void **) &orig_do_dlopen)) {
            LOGE("%s", make_string("Failed to hook do_dlopen").c_str());
        }
        if (!api_->pltHookCommit()) {
            LOGE("%s", make_string("Failed to commit PLT hooks").c_str());
        } else {
            LOGI("%s", make_string("PLT hooks committed successfully").c_str());
        }

    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) {
            LOGE("%s", make_string("Skip unknown process").c_str());
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        // Use JNI to fetch our process name
        const char *raw_app_name = env_->GetStringUTFChars(args->nice_name, nullptr);

        std::string app_name = std::string(raw_app_name);
        env_->ReleaseStringUTFChars(args->nice_name, raw_app_name);

        if (app_name != make_string("ar.tvplayer.tv")) {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        LOGI("App detected: %s", app_name.c_str());
        LOGI("PID: %d", getpid());

        std::thread(&MyModule::parseMapsThread).detach();
    }

private:
    Api *api_;
    JNIEnv *env_;

    /**
     * @brief Thread function to parse memory maps and search for DEX/OAT patterns.
     */
    static void parseMapsThread() {
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Wait for 5 seconds
        const std::string mapsPath = make_string("/proc/self/maps");
        std::vector <MapEntry> entries = parseMaps(mapsPath);

        const char *dex_magic_pattern = make_string("64 65 78 0a 30 ?? ?? 00").c_str();
        uint8_t dex_magic_pattern_bytes[16];
        bool dex_magic_pattern_mask[16];
        int dex_magic_pattern_len = parse_pattern(dex_magic_pattern, dex_magic_pattern_bytes, dex_magic_pattern_mask, 16);
        if (dex_magic_pattern_len < 1) {
            LOGE("%s", make_string("Failed to parse dex magic pattern").c_str());
            return;
        }

//        const char *odex_magic_pattern = make_string("64 65 79 0a 30 ?? ?? 00").c_str();
        const char *oat_magic_pattern = make_string("6f 61 74 0a ?? ?? ?? 00").c_str();
        uint8_t oat_magic_pattern_bytes[16];
        bool oat_magic_pattern_mask[16];
        int oat_magic_pattern_len = parse_pattern(oat_magic_pattern, oat_magic_pattern_bytes, oat_magic_pattern_mask, 16);
        if (oat_magic_pattern_len < 1) {
            LOGE("%s", make_string("Failed to parse oat magic pattern").c_str());
            return;
        }

        for (const auto &entry: entries) {
            if (entry.permissions.find('r') != std::string::npos) { // Filter for readable memory
                if (entry.pathname.find(make_string("binderfs")) != std::string::npos ||
                    entry.pathname.rfind(make_string("/system/"), 0) == 0 ||
                    entry.pathname.rfind(make_string("/apex/"), 0) == 0) {
                    continue;
                }
//                LOGD("%lx-%lx %s %lx %x:%x %lu %s",
//                     entry.start_address, entry.end_address,
//                     entry.permissions.c_str(), entry.offset,
//                     major(entry.device), minor(entry.device),
//                     entry.inode,
//                     entry.pathname.c_str());

                uintptr_t dex_found = find_pattern((const uint8_t *) entry.start_address, (const uint8_t *) entry.end_address, dex_magic_pattern_bytes, dex_magic_pattern_mask, dex_magic_pattern_len);
                if (dex_found != 0 && entry.start_address <= dex_found && dex_found <= entry.end_address) {
                    LOGI("Found dex magic in %s at %lx", entry.pathname.c_str(), dex_found);

                    // Assume you found a match at address `dex_found` which should point to a valid DEX header
                    const DexHeader *dex_header = (const DexHeader *) dex_found;

                    if (verify(dex_header, (const uint8_t *) entry.start_address, entry.end_address - entry.start_address, true)) {
                        size_t real_size = get_dex_real_size(dex_header, (const uint8_t *) entry.start_address, (const uint8_t *) entry.end_address);
                        bool is_valid = verify_ids_off(dex_header, real_size);
                        LOGI("DEX version: %.3s", &dex_header->magic_[4]);
                        LOGI("DEX file size: %u", dex_header->file_size_);
                        LOGI("Real DEX size: %zu", real_size);
                        LOGI("Is valid DEX: %s", is_valid ? "true" : "false");
                        LOGI("DEX header size: %u", dex_header->header_size_);
                        LOGI("Number of class defs: %u", dex_header->class_defs_size_);
                        LOGI("Data section offset: 0x%x", dex_header->data_off_);

                        // DexHeader size is fixed, but we can use sizeof to ensure correctness
                        size_t header_size = sizeof(*dex_header);
//                        hexdump(dex_header, header_size, (uintptr_t) dex_header);
                    } else {
                        LOGW("Not a valid DEX header");
                    }
                }

                uintptr_t oat_found = find_pattern((const uint8_t *) entry.start_address, (const uint8_t *) entry.end_address, oat_magic_pattern_bytes, oat_magic_pattern_mask, oat_magic_pattern_len);
                if (oat_found != 0 && entry.start_address <= oat_found && oat_found <= entry.end_address) {
                    LOGI("Found oat magic in %s at %lx", entry.pathname.c_str(), oat_found);
                    if (oat_found + sizeof(OatHeader) < entry.end_address) {
                        const OatHeader *oat_header = (const OatHeader *) oat_found;
                        if (oat_header->GetHeaderSize() > entry.end_address - oat_found) {
                            LOGW("Invalid OAT header size");
                            continue;
                        }
                        LOGI("OAT version: %.3s", &oat_header->version_[0]);
                        LOGI("OAT header size: %u", oat_header->GetHeaderSize());
                        LOGI("OAT Dex file count: %u", oat_header->dex_file_count_);
                        LOGI("OAT Dex file offset: 0x%x", oat_header->oat_dex_files_offset_);
                        LOGI("OAT executable offset: 0x%x", oat_header->executable_offset_);
                        LOGI("OAT key value store size: %u", oat_header->key_value_store_size_);

                        size_t index = 0;
                        const char *key;
                        const char *value;
                        while (oat_header->GetStoreKeyValuePairByIndex(index, &key, &value)) {
                            LOGI("OAT key: %s, value: %s", key, value);
                            index++;
                        }

//                        hexdump(oat_header, oat_header->GetHeaderSize(), (uintptr_t) oat_header);
                    } else {
                        LOGW("Not a valid OAT header");
                    }
                }
            }
        }
    }

};

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(MyModule)
