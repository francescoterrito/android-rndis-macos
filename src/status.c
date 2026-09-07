#include "status.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

static struct status_metrics metrics;
void status_set_metrics(const struct status_metrics *m) { metrics = *m; }

void status_write(const char *state, const char *ip, const char *ifname,
                  unsigned long long tx_bytes, unsigned long long rx_bytes,
                  unsigned long long tx_pkts, unsigned long long rx_pkts,
                  long uptime_sec) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.XXXXXX", STATUS_PATH);
    int fd = mkstemp(tmp);
    if (fd < 0) return;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return; }
    fprintf(f,
            "{\"state\":\"%s\",\"ip\":\"%s\",\"ifname\":\"%s\","
            "\"tx_bytes\":%llu,\"rx_bytes\":%llu,"
            "\"tx_pkts\":%llu,\"rx_pkts\":%llu,"
            "\"uptime_sec\":%ld,\"pid\":%d,\"time\":%ld,"
            "\"tx_transfers\":%llu,\"tx_errors\":%llu,"
            "\"tx_drops\":%llu,\"rx_drops\":%llu,"
            "\"dhcp_renewals\":%u,\"lease_remaining_sec\":%ld}\n",
            state ? state : "unknown", ip ? ip : "", ifname ? ifname : "",
            tx_bytes, rx_bytes, tx_pkts, rx_pkts, uptime_sec, (int)getpid(),
            (long)time(NULL), metrics.tx_transfers, metrics.tx_errors,
            metrics.tx_drops, metrics.rx_drops, metrics.renewals, metrics.lease_remaining);
    int failed = ferror(f);
    if (fchmod(fd, 0644) != 0) failed = 1;
    if (fclose(f) != 0) failed = 1;
    if (failed || rename(tmp, STATUS_PATH) != 0) unlink(tmp);
}

int auto_enabled(void) {
    return access(DISABLE_FLAG_PATH, F_OK) != 0;
}
