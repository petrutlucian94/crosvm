// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

void host_cpuid(uint32_t func, uint32_t func2, uint32_t *pEax,
                uint32_t *pEbx, uint32_t *pEcx, uint32_t *pEdx) {
    #ifndef _MSC_VER
        asm volatile("cpuid" : "=a"(*pEax), "=b"(*pEbx), "=c"(*pEcx), "=d"(*pEdx) :
                     "0"(func), "2"(func2) : "cc");
    #else
        uint32_t cpuInfo[4];
        __cpuidex(cpuInfo, func, func2);

        *pEax = cpuInfo[0];
        *pEbx = cpuInfo[1];
        *pEcx = cpuInfo[2];
        *pEdx = cpuInfo[3];
    #endif
}
