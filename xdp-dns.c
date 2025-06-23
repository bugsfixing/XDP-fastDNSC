#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "dns.h"

#define MAX_PACKET_SIZE 1500

// DNS cache
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CACHE_SIZE);
    __type(key, __u8[MAX_DNS_NAME]);
    __type(value, struct cache_entry);
} dns_cache SEC(".maps");

// IP address map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CACHE_SIZE * MAX_IPS_PER_DOMAIN);
    __type(key, __u32);
    __type(value, struct ip_entry);
} ip_map SEC(".maps");

// Ring buffer for uncached domains
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB
} ringbuf SEC(".maps");

// Deduplication map for queued domains
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CACHE_SIZE);
    __type(key, __u8[MAX_DNS_NAME]);
    __type(value, __u8);
} dedup_map SEC(".maps");

// Metrics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metrics);
} metrics SEC(".maps");

// Helper to swap Ethernet addresses
static inline void swap_eth_addr(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

// Parse DNS name
static inline int parse_dns_name(__u8 *data, __u8 *end, __u8 *name, int max_len) {
    int pos = 0;
    while (pos < max_len && data < end) {
        __u8 len = *data++;
        if (len == 0) break;
        if (data + len > end) return -1;
        if (pos + len + 1 > max_len) return -1;
        __builtin_memcpy(name + pos, data, len);
        pos += len;
        name[pos++] = '.';
        data += len;
    }
    if (pos > 0 && name[pos - 1] == '.') name[pos - 1] = 0;
    return pos;
}

// Update metrics
static inline void update_metrics(__u32 key, __u64 increment, int metric_type) {
    struct metrics *m = bpf_map_lookup_elem(&metrics, &key);
    if (m) {
        if (metric_type == 0) m->cache_hits += increment;
        else if (metric_type == 1) m->cache_misses += increment;
        else if (metric_type == 2) m->uncached_queries += increment;
    }
}

SEC("xdp_dns")
int xdp_dns_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Parse UDP header
    struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udp->dest) != DNS_PORT)
        return XDP_PASS;

    // Parse DNS header
    struct dns_header *dns = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*dns) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(dns->flags) & 0x8000)
        return XDP_PASS;

    if (bpf_ntohs(dns->qdcount) != 1)
        return XDP_PASS;

    // Parse question
    __u8 *qname_ptr = (__u8 *)(dns + 1);
    __u8 name[MAX_DNS_NAME] = {0};
    int name_len = parse_dns_name(qname_ptr, data_end, name, MAX_DNS_NAME);
    if (name_len < 0)
        return XDP_PASS;

    struct dns_question *q = (struct dns_question *)(qname_ptr + name_len + 1);
    if ((void *)(q + 1) > data_end)
        return XDP_PASS;

    __u16 qtype = bpf_ntohs(q->qtype);
    if (qtype != 1 && qtype != 28) // A or AAAA
        return XDP_PASS;

    if (bpf_ntohs(q->qclass) != 1) // IN class
        return XDP_PASS;

    // Lookup in cache
    struct cache_entry *entry = bpf_map_lookup_elem(&dns_cache, name);
    if (entry && entry->type == qtype && entry->ip_count > 0) {
        // Cache hit
        update_metrics(zero, 1, 0);
        entry->last_accessed = bpf_ktime_get_ns() / 1000000000;

        // Select IP for round-robin with efficient cycling
        __u8 idx = entry->next_ip_index % entry->ip_count;
        entry->next_ip_index = (entry->next_ip_index + 1) % entry->ip_count;

        // Atomic update of cache entry
        bpf_map_update_elem(&dns_cache, name, entry, BPF_EXIST);

        struct ip_entry *ip_entry = bpf_map_lookup_elem(&ip_map, &entry->ip_indices[idx]);
        if (!ip_entry)
            return XDP_PASS;

        swap_eth_addr(eth);
        __u32 tmp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp_ip;

        __u16 tmp_port = udp->source;
        udp->source = udp->dest;
        udp->dest = tmp_port;

        dns->flags = bpf_htons(0x8180 | (entry->dnssec_valid ? 0x0400 : 0));
        dns->ancount = bpf_htons(1); // Single RR for round-robin

        struct dns_rr *rr = (struct dns_rr *)(q + 1);
        if ((void *)(rr + 1) > data_end)
            return XDP_DROP;

        rr->name[0] = 0xc0; // Pointer to qname
        rr->name[1] = 0x0c;
        rr->type = bpf_htons(qtype);
        rr->class = bpf_htons(1);
        rr->ttl = bpf_htonl(entry->ttl);
        rr->rdlength = bpf_htons(qtype == 1 ? 4 : 16);
        __builtin_memcpy(rr->rdata, ip_entry->rdata, qtype == 1 ? 4 : 16);

        __u16 new_len = (__u8 *)(rr + 1) - (__u8 *)data;
        if (new_len > MAX_PACKET_SIZE)
            return XDP_DROP;

        ip->tot_len = bpf_htons(new_len - sizeof(*eth));
        udp->len = bpf_htons(new_len - sizeof(*eth) - sizeof(*ip));

        ip->check = 0;
        udp->check = 0;

        return XDP_TX;
    }

    // Cache miss
    update_metrics(zero, 1, 1);

    // Check deduplication map
    __u8 *dedup = bpf_map_lookup_elem(&dedup_map, name);
    if (!dedup) {
        struct ringbuf_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct ringbuf_event), 0);
        if (event) {
            __builtin_memcpy(event->domain, name, MAX_DNS_NAME);
            event->qtype = qtype;
            bpf_ringbuf_submit(event, 0);

            __u8 one = 1;
            bpf_map_update_elem(&dedup_map, name, &one, BPF_ANY);
            update_metrics(zero, 1, 2);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";