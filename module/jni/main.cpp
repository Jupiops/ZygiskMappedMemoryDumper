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
#include <android/log.h>

#include "log.h"
#include "zygisk.hpp"
#include "no_strings.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) {
            LOGE("%s", make_string("Skip unknown process").c_str());
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        // Use JNI to fetch our process name
        const char *raw_app_name = env->GetStringUTFChars(args->nice_name, nullptr);

        std::string app_name = std::string(raw_app_name);
        env->ReleaseStringUTFChars(args->nice_name, raw_app_name);

        if (app_name.compare(make_string("ar.tvplayer.tv")) != 0) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        LOGI("App detected: %s", app_name.c_str());
        LOGI("PID: %d", getpid());

        std::thread(parseMapsThread).detach();
    }

private:
    Api *api;
    JNIEnv *env;

    struct MapEntry {
        uintptr_t start_address;
        uintptr_t end_address;
        std::string permissions;
        long offset;
        std::string device;
        int inode;
        std::string pathname;
    };

    static std::vector <MapEntry> parseMaps(const std::string &mapsPath) {
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
            std::string addresses;

            // Parse the line
            if (!(iss >> addresses >> entry.permissions >> std::hex >> entry.offset >> entry.device
                      >> entry.inode)) {
                LOGW("Failed to parse line: %s", line.c_str());
                continue;
            }

            size_t dashPos = addresses.find('-');
            if (dashPos == std::string::npos) {
                LOGW("Invalid address format: %s", addresses.c_str());
                continue;
            }

            entry.start_address = std::stoul(addresses.substr(0, dashPos), nullptr, 16);
            entry.end_address = std::stoul(addresses.substr(dashPos + 1), nullptr, 16);

            if (iss >> entry.pathname) {
                entries.push_back(entry);
            } else {
                entry.pathname = make_string("[anonymous]");
                entries.push_back(entry);
            }
        }

        mapsFile.close();
        return entries;
    }

    static int parse_pattern(const char *pattern, uint8_t *pattern_bytes, bool *pattern_mask, int max_len) {
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


    static void parseMapsThread() {
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Wait for 5 seconds
        const std::string mapsPath = make_string("/proc/self/maps");
        std::vector <MapEntry> entries = parseMaps(mapsPath);

        const char *dex_magic_pattern = make_string("64 65 78 0a 30 ?? ?? 00").c_str();
        uint8_t dex_magic_pattern_bytes[16];
        bool dex_magic_pattern_mask[16];
        int dex_magic_pattern_len = parse_pattern(dex_magic_pattern, dex_magic_pattern_bytes, dex_magic_pattern_mask, 16);
        LOGD("Searching for DEX magic pattern: %s", dex_magic_pattern);

        if (dex_magic_pattern_len < 1) {
            LOGE("%s", make_string("Failed to parse dex magic pattern").c_str());
            return;
        }

        for (const auto &entry: entries) {
            if (entry.permissions.find('r') != std::string::npos) { // Filter for readable memory
                if (entry.pathname.find(make_string("binderfs")) != std::string::npos) {
                    continue;
                }
                LOGD("%lx-%lx %s %lx %s %d %s",
                     entry.start_address, entry.end_address,
                     entry.permissions.c_str(), entry.offset,
                     entry.device.c_str(), entry.inode,
                     entry.pathname.c_str());
                uintptr_t found = find_pattern((const uint8_t *) entry.start_address, (const uint8_t *) entry.end_address, dex_magic_pattern_bytes, dex_magic_pattern_mask, dex_magic_pattern_len);
                if (found != 0) {
                    LOGI("Found dex magic in %s at %lx", entry.pathname.c_str(), found);
                }

            }
        }
    }

};

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(MyModule)
