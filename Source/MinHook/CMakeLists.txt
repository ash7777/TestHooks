cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0048 NEW)

project(MinHook
       LANGUAGES C)

add_library(MinHook STATIC
            src/buffer.c
            src/hook.c
            src/trampoline.c
            src/hde/hde32.c
            src/hde/hde64.c)
