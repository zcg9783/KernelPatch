/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_IMAGE_H_
#define _KP_TOOL_IMAGE_H_

#include <stdint.h>

// 添加架构定义
#define ARCH_ARM32 1
#define ARCH_ARM64 2

typedef struct
{
    int8_t is_be; // 0: little, 1: big
    int8_t uefi; //
    int32_t load_offset;
    int32_t kernel_size;
    int32_t page_shift;
    int32_t b_stext_insn_offset;
    int32_t primary_entry_offset;
    // 添加架构字段
    int32_t arch;
} kernel_info_t;

int32_t get_kernel_info(kernel_info_t *kinfo, const char *img, int32_t imglen);
int32_t kernel_resize(kernel_info_t *kinfo, char *img, int32_t size);

#endif