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
#include <string>
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

    }

private:
    Api *api;
    JNIEnv *env;

};

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(MyModule)
