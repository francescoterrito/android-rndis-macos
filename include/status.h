#ifndef CABLED_HOTSPOT_STATUS_H
#define CABLED_HOTSPOT_STATUS_H

/* Machine-readable session state for the menu bar app (and humans).
 * Written atomically (tmp + rename), world-readable, to a fixed path so
 * an unprivileged UI can poll it while the daemon runs as root. */
#define STATUS_PATH "/tmp/android-rndis-macos-status.json"
/* Presence of this file disables auto-connect (created by the menu app,
 * read by --watch). Absent (e.g. after reboot, /tmp is cleared) = enabled. */
#define DISABLE_FLAG_PATH "/tmp/android-rndis-macos.disabled"

struct status_metrics {
    unsigned long long tx_transfers, tx_errors, tx_drops, rx_drops;
    unsigned renewals;
    long lease_remaining;
};
/* Called by the supervision thread before writing a snapshot. */
void status_set_metrics(const struct status_metrics *metrics);
void status_write(const char *state, const char *ip, const char *ifname,
                  unsigned long long tx_bytes, unsigned long long rx_bytes,
                  unsigned long long tx_pkts, unsigned long long rx_pkts,
                  long uptime_sec);
int auto_enabled(void);

#endif
