// dns_loader.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "dns.h"

#define REFRESH_INTERVAL 60    // Cache refresh interval (seconds)
#define RINGBUF_POLL_TIMEOUT 100 // Ring buffer poll timeout (ms)
#define DEDUP_TTL 60           // Deduplication TTL (seconds)

// Upstream DNS servers
static const char *upstream_dns_servers[] = {
    "8.8.8.8",    // Google DNS
    "1.1.1.1",    // Cloudflare DNS
    "9.9.9.9",    // Quad9 DNS
    NULL
};

// Global IP index counter
static __u32 next_ip_index = 0;

// Resolve A or AAAA records with DNSSEC
int resolve_record(const char *domain, uint16_t qtype, struct cache_entry *entry, int ip_map_fd) {
    ldns_resolver *res = NULL;
    ldns_rdf *domain_rdf = NULL;
    ldns_pkt *pkt = NULL;
    ldns_status status;
    int ret = -1;

    status = ldns_resolver_new_frm_file(&res, NULL);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to initialize resolver: %s\n", ldns_get_errorstr_by_id(status));
        goto cleanup;
    }

    ldns_resolver_set_dnssec(res, true);
    domain_rdf = ldns_dname_new_frm_str(domain);
    if (!domain_rdf) {
        fprintf(stderr, "Failed to parse domain %s\n", domain);
        goto cleanup;
    }

    for (int i = 0; upstream_dns_servers[i]; i++) {
        ldns_rdf *ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, upstream_dns_servers[i]);
        if (!ns) continue;

        ldns_resolver_push_nameserver(res, ns);
        pkt = ldns_resolver_query(res, domain_rdf, qtype, LDNS_RR_CLASS_IN, LDNS_RD | LDNS_AD);
        ldns_rdf_free(ns);

        if (pkt && ldns_pkt_get_rcode(pkt) == LDNS_RCODE_NOERROR) {
            ldns_rr_list *rrs = ldns_pkt_answer(pkt);
            size_t rr_count = ldns_rr_list_rr_count(rrs);
            if (rr_count > 0) {
                entry->type = qtype;
                entry->ttl = 0xFFFFFFFF;
                entry->last_updated = time(NULL);
                entry->last_accessed = entry->last_updated;
                entry->dnssec_valid = ldns_pkt_ad(pkt);
                entry->ip_count = 0;
                entry->next_ip_index = 0;

                for (size_t j = 0; j < rr_count && entry->ip_count < MAX_IPS_PER_DOMAIN; j++) {
                    ldns_rr *rr = ldns_rr_list_rr(rrs, j);
                    if (ldns_rr_get_type(rr) != qtype || ldns_rr_rd_count(rr) != 1)
                        continue;

                    struct ip_entry ip = {0};
                    ldns_rdf *rdf = ldns_rr_rdf(rr, 0);
                    __u32 index = __sync_fetch_and_add(&next_ip_index, 1);
                    if (index >= MAX_CACHE_SIZE * MAX_IPS_PER_DOMAIN)
                        continue;

                    if (qtype == LDNS_RR_TYPE_A) {
                        memcpy(ip.rdata, ldns_rdf_data(rdf), 4);
                    } else if (qtype == LDNS_RR_TYPE_AAAA) {
                        memcpy(ip.rdata, ldns_rdf_data(rdf), 16);
                    } else {
                        continue;
                    }

                    if (bpf_map_update_elem(ip_map_fd, &index, &ip, BPF_ANY) < 0) {
                        fprintf(stderr, "Failed to update ip_map for index %u\n", index);
                        continue;
                    }

                    entry->ip_indices[entry->ip_count++] = index;
                    entry->ttl = entry->ttl < ldns_rr_ttl(rr) ? entry->ttl : ldns_rr_ttl(rr);
                    printf("Resolved %s (type %s, IP %u) via %s (DNSSEC: %s)\n", domain,
                           qtype == LDNS_RR_TYPE_A ? "A" : "AAAA", entry->ip_count,
                           upstream_dns_servers[i], entry->dnssec_valid ? "valid" : "not validated");
                }

                if (entry->ip_count > 0) {
                    ret = 0;
                    break;
                }
            }
        }
        ldns_pkt_free(pkt);
        pkt = NULL;
    }

    if (ret != 0)
        fprintf(stderr, "All upstream DNS servers failed for %s\n", domain);
    
    ldns_rdf_deep_free(domain_rdf);
    ldns_pkt_free(pkt);
    ldns_resolver_deep_free(res);
    return ret;
}

// Update eBPF cache
int update_cache(int cache_map_fd, int ip_map_fd, const char *domain, uint16_t qtype) {
    struct cache_entry entry = {0};
    if (resolve_record(domain, qtype, &entry, ip_map_fd) < 0)
        return -1;

    char key[MAX_DNS_NAME];
    strncpy(key, domain, MAX_DNS_NAME - 1);
    key[MAX_DNS_NAME - 1] = '\0';

    // Preserve next_ip_index if updating existing entry
    struct cache_entry old_entry;
    if (bpf_map_lookup_elem(cache_map_fd, key, &old_entry) == 0) {
        entry.next_ip_index = old_entry.next_ip_index;
    }

    if (bpf_map_update_elem(cache_map_fd, key, &entry, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to update cache map for %s: %s\n", domain, strerror(errno));
        return -1;
    }

    printf("Cached %s (%u IPs, TTL: %u)\n", domain, entry.ip_count, entry.ttl);
    return 0;
}

// Refresh cache and implement LRU eviction
void refresh_cache(int cache_map_fd, int dedup_map_fd, int ip_map_fd) {
    char key[MAX_DNS_NAME];
    struct cache_entry entry;
    __u64 now = time(NULL);
    int entries = 0;

    // Count entries
    char prev_key[MAX_DNS_NAME] = {0};
    while (bpf_map_get_next_key(cache_map_fd, prev_key, key, MAX_DNS_NAME) == 0) {
        entries++;
        strncpy(prev_key, key, MAX_DNS_NAME);
    }

    // Evict if cache is full
    if (entries >= MAX_CACHE_SIZE - 10) {
        prev_key[0] = 0;
        __u64 oldest_time = now;
        char oldest_key[MAX_DNS_NAME] = {0};
        while (bpf_map_get_next_key(cache_map_fd, prev_key, key, MAX_DNS_NAME) == 0) {
            if (bpf_map_lookup_elem(cache_map_fd, key, &entry) == 0) {
                if (entry.last_accessed < oldest_time) {
                    oldest_time = entry.last_accessed;
                    strncpy(oldest_key, key, MAX_DNS_NAME);
                }
            }
            strncpy(prev_key, key, MAX_DNS_NAME);
        }
        if (oldest_key[0]) {
            if (bpf_map_lookup_elem(cache_map_fd, oldest_key, &entry) == 0) {
                for (__u8 i = 0; i < entry.ip_count; i++) {
                    bpf_map_delete_elem(ip_map_fd, &entry.ip_indices[i]);
                }
                bpf_map_delete_elem(cache_map_fd, oldest_key);
                printf("Evicted %s from cache\n", oldest_key);
            }
        }
    }

    // Refresh expired entries
    prev_key[0] = 0;
    while (bpf_map_get_next_key(cache_map_fd, prev_key, key, MAX_DNS_NAME) == 0) {
        if (bpf_map_lookup_elem(cache_map_fd, key, &entry) == 0) {
            if (now >= entry.last_updated + entry.ttl) {
                printf("Refreshing cache for %s\n", key);
                __u8 old_next_ip_index = entry.next_ip_index;
                for (__u8 i = 0; i < entry.ip_count; i++) {
                    bpf_map_delete_elem(ip_map_fd, &entry.ip_indices[i]);
                }
                if (update_cache(cache_map_fd, ip_map_fd, key, entry.type) == 0) {
                    if (bpf_map_lookup_elem(cache_map_fd, key, &entry) == 0) {
                        entry.next_ip_index = old_next_ip_index % entry.ip_count;
                        bpf_map_update_elem(cache_map_fd, key, &entry, BPF_EXIST);
                    }
                } else {
                    bpf_map_delete_elem(cache_map_fd, key);
                    printf("Removed stale cache entry for %s\n", key);
                }
            }
        }
        strncpy(prev_key, key, MAX_DNS_NAME);
    }

    // Clean deduplication map
    prev_key[0] = 0;
    while (bpf_map_get_next_key(dedup_map_fd, prev_key, key, MAX_DNS_NAME) == 0) {
        bpf_map_delete_elem(dedup_map_fd, key);
        strncpy(prev_key, key, MAX_DNS_NAME);
    }
}

// Ring buffer callback
static int handle_ringbuf_event(void *ctx, void *data, size_t len) {
    struct { int cache_fd; int ip_fd; } *fds = ctx;
    struct ringbuf_event *event = data;

    if (len != sizeof(struct ringbuf_event)) {
        fprintf(stderr, "Invalid ringbuf event size\n");
        return 0;
    }

    char domain[MAX_DNS_NAME];
    strncpy(domain, (char *)event->domain, MAX_DNS_NAME - 1);
    domain[MAX_DNS_NAME - 1] = '\0';
    uint16_t qtype = event->qtype;

    printf("Received uncached domain: %s (type %s)\n", domain, qtype == LDNS_RR_TYPE_A ? "A" : "AAAA");
    update_cache(fds->cache_fd, fds->ip_fd, domain, qtype);

    return 0;
}

// Thread for cache refresh
void *cache_refresh_thread(void *arg) {
    struct { int cache_fd; int dedup_fd; int ip_fd; } *fds = arg;
    while (1) {
        refresh_cache(fds->cache_fd, fds->dedup_fd, fds->ip_fd);
        sleep(REFRESH_INTERVAL);
    }
    return NULL;
}

// Thread for metrics
void *metrics_thread(void *arg) {
    int metrics_fd = *(int *)arg;
    while (1) {
        struct metrics m;
        uint32_t key = 0;
        if (bpf_map_lookup_elem(metrics_fd, &key, &m) == 0) {
            printf("Metrics: Cache Hits=%llu, Cache Misses=%llu, Uncached Queries=%llu\n",
                   m.cache_hits, m.cache_misses, m.uncached_queries);
        }
        sleep(10);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }


    struct bpf_object *obj;
    int err = bpf_object__open_file("xdp-dns.o", NULL, &obj);
    if (err) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(-err));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(-err));
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_dns");
    if (!prog) {
        fprintf(stderr, "Failed to find xdp_dns program\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *cache_map = bpf_object__find_map_by_name(obj, "dns_cache");
    if (!cache_map) {
        fprintf(stderr, "Failed to find dns_cache map\n");
        return 1;
    }
    int cache_map_fd = bpf_map__fd(cache_map);

    struct bpf_map *ip_map = bpf_object__find_map_by_name(obj, "ip_map");
    if (!ip_map) {
        fprintf(stderr, "Failed to find ip_map\n");
        return 1;
    }
    int ip_map_fd = bpf_map__fd(ip_map);

    struct bpf_map *dedup_map = bpf_object__find_map_by_name(obj, "dedup_map");
    if (!dedup_map) {
        fprintf(stderr, "Failed to find dedup_map\n");
        return 1;
    }
    int dedup_map_fd = bpf_map__fd(dedup_map);

    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(obj, "ringbuf");
    if (!ringbuf_map) {
        fprintf(stderr, "Failed to find ringbuf map\n");
        return 1;
    }

    struct bpf_map *metrics_map = bpf_object__find_map_by_name(obj, "metrics");
    if (!metrics_map) {
        fprintf(stderr, "Failed to find metrics map\n");
        return 1;
    }
    int metrics_map_fd = bpf_map__fd(metrics_map);

    struct { int cache_fd; int ip_fd; } fds = {cache_map_fd, ip_map_fd};
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_ringbuf_event, &fds, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        return 1;
    }

    printf("XDP DNS program attached to %s\n", argv[1]);

    pthread_t refresh_thread;
    struct { int cache_fd; int dedup_fd; int ip_fd; } refresh_fds = {cache_map_fd, dedup_map_fd, ip_map_fd};
    if (pthread_create(&refresh_thread, NULL, cache_refresh_thread, &refresh_fds) != 0) {
        fprintf(stderr, "Failed to create refresh thread: %s\n", strerror(errno));
        return 1;
    }

    pthread_t metrics_thread_id;
    if (pthread_create(&metrics_thread_id, NULL, metrics_thread, &metrics_map_fd) != 0) {
        fprintf(stderr, "Failed to create metrics thread: %s\n", strerror(errno));
        return 1;
    }

    printf("Press Ctrl+C to exit...\n");

    // Main loop: Poll ring buffer
    while (1) {
        ring_buffer__poll(rb, RINGBUF_POLL_TIMEOUT);
    }

    // Cleanup
    ring_buffer__free(rb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_object__close(obj);
    return 0;
}