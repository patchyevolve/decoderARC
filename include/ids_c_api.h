#pragma once
#include <cstdint>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void* ids_central_create();
void  ids_central_destroy(void* handle);

// Returns 1 if an alert was generated, 0 otherwise.
// alert_json_out receives a malloc'd JSON string — caller must free with ids_central_free_string.
int ids_central_ingest(
    void* handle,
    const char* user_id,
    const char* src_ip, int src_port,
    const char* dst_ip, int dst_port,
    int protocol,   // 6=TCP, 17=UDP, 1=ICMP, 0=other
    long bytes,
    const char* event_type,
    double unix_ts,
    char** alert_json_out
);

// Batch ingest — processes multiple events for the same user in one lock acquisition.
// Returns number of alerts generated.
// alerts_json_out receives an array of malloc'd JSON strings (one per alert).
// num_alerts_out is set to the number of alerts.
// Caller must free each string with ids_central_free_string and free the array with ids_central_free_alerts.
int ids_central_ingest_batch(
    void* handle,
    const char* user_id,
    const char** src_ips, const int* src_ports,
    const char** dst_ips, const int* dst_ports,
    const int* protocols,
    const long* bytes,
    const char** event_types,
    const double* unix_ts,
    int batch_size,
    char*** alerts_json_out,
    int* num_alerts_out
);

void ids_central_free_string(char* s);
void ids_central_free_alerts(char** alerts, int num);

#ifdef __cplusplus
}
#endif
