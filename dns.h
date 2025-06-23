#ifndef __DNS_H__
#define __DNS_H__

#include <linux/types.h>

#define DNS_PORT 53
#define MAX_DNS_NAME 256
#define MAX_CACHE_SIZE 1024
#define MAX_IPS_PER_DOMAIN 8 // Maximum A/AAAA records per domain

// DNS header structure
struct dns_header {
    __u16 id;          // Query ID
    __u16 flags;       // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    __u16 qdcount;     // Question count
    __u16 ancount;     // Answer count
    __u16 nscount;     // Authority count
    __u16 arcount;     // Additional count
};

// Question structure
struct dns_question {
    __u8 qname[MAX_DNS_NAME]; // Query name
    __u16 qtype;              // Query type (A=1, AAAA=28)
    __u16 qclass;             // Query class (IN=1)
};

// Resource record
struct dns_rr {
    __u8 name[MAX_DNS_NAME];
    __u16 type;   // A=1, AAAA=28
    __u16 class;  // IN=1
    __u32 ttl;    // Time to live
    __u16 rdlength; // Resource data length
    __u8 rdata[16]; // IPv4 (4 bytes) or IPv6 (16 bytes)
};

// IP address entry (for multiple records)
struct ip_entry {
    __u8 rdata[16]; // IPv4 or IPv6 address
};

// Cache entry
struct cache_entry {
    __u16 type;        // A=1, AAAA=28
    __u32 ttl;         // Time to live
    __u64 last_updated; // Timestamp
    __u64 last_accessed; // For LRU eviction
    __u8 dnssec_valid; // DNSSEC validation status (1=valid, 0=not)
    __u8 ip_count;     // Number of IPs
    __u8 next_ip_index; // Round-robin index
    __u32 ip_indices[MAX_IPS_PER_DOMAIN]; // Indices in ip_map
};

// Ring buffer event for uncached domains
struct ringbuf_event {
    __u8 domain[MAX_DNS_NAME];
    __u16 qtype; // A=1, AAAA=28
};

// Metrics counters
struct metrics {
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 uncached_queries;
};

#endif