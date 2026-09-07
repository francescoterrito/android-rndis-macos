#ifndef CABLED_HOTSPOT_LOG_H
#define CABLED_HOTSPOT_LOG_H

#include <stdio.h>

extern int g_verbose;

#define LOGI(fmt, ...) do { fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__); } while (0)
#define LOGE(fmt, ...) do { fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__); } while (0)
#define LOGV(fmt, ...) do { if (g_verbose) fprintf(stderr, "[v] " fmt "\n", ##__VA_ARGS__); } while (0)

#endif
