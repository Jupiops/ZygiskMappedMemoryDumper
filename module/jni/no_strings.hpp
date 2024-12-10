#pragma once
// Copyright (C) 2022 Evan McBroom
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// If you are using Visual Studio, you will need to disable the "Edit and Continue" feature.

// Prng based off of Parker Miller's
// "Multiplicative Linear Congruential Generator"
// https://en.wikipedia.org/wiki/Lehmer_random_number_generator
namespace mlcg {
    constexpr uint32_t modulus() {
        return 0x7fffffff;
    }

    // Create entropy using __FILE__ and __LINE__
    template<size_t N>
    constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
        auto value{ iv };
        for (size_t i{ 0 }; i < N; i++) {
            // Xor 1st byte of seed with input byte
            value = (value & ((~0) << 8)) | ((value & 0xFF) ^ entropy[i]);
            // Rotl 1 byte
            value = value << 8 | value >> ((sizeof(value) * 8) - 8);
        }
        // The seed is required to be less than the modulus and odd
        while (value > modulus()) value = value >> 1;
        return value << 1 | 1;
    }

    constexpr uint32_t prng(const uint32_t input) {
        return (input * 48271) % modulus();
    }
}

template<typename T, size_t N>
struct encrypted {
    int seed;
    T data[N];
};

template<size_t N>
constexpr auto crypt(const char(&input)[N], const uint32_t seed = 0) {
    encrypted<char, N> blob{};
    blob.seed = seed;
    for (uint32_t index{ 0 }, stream{ seed }; index < N; index++) {
        blob.data[index] = input[index] ^ stream;
        stream = mlcg::prng(stream);
    }
    return blob;
}

#define make_string(STRING) ([&] {                                     \
    constexpr auto _{ crypt(STRING, mlcg::seed(__FILE__, __LINE__)) }; \
    return std::string{ crypt(_.data, _.seed).data };                  \
}())