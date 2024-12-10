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

    static void parseMapsThread() {
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Wait for 5 seconds
        const std::string mapsPath = make_string("/proc/self/maps");
        std::vector <MapEntry> entries = parseMaps(mapsPath);

        for (const auto &entry: entries) {
            if (entry.permissions.find('r') != std::string::npos) { // Filter for readable memory
                LOGD("%lx-%lx %s %lx %s %d %s",
                     entry.start_address, entry.end_address,
                     entry.permissions.c_str(), entry.offset,
                     entry.device.c_str(), entry.inode,
                     entry.pathname.c_str());
            }
        }
    }

};

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(MyModule)
