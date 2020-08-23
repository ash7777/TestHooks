cmake_minimum_required(VERSION 3.13)

project(MinHook
       LANGUAGES C)

add_library(MinHook STATIC
            src/buffer.c
            src/hook.c
            src/trampoline.c
            src/hde/hde32.c
            src/hde/hde64.c)
