#pragma once

#define LOG_(FORMAT, ...) printf("%s:%d %s| " FORMAT "%s", __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__);

#define LogD(...) LOG_(__VA_ARGS__, "\n")

#define LogE(...) LOG_(__VA_ARGS__, "\n")
