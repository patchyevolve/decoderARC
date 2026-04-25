#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace ids {

// ─── Dimensions ───────────────────────────────────────────────
inline constexpr size_t kEmbeddingDim    = 64;
inline constexpr size_t kStateVecDim     = 128;
inline constexpr size_t kLocalWindow     = 64;
inline constexpr size_t kSSMStateDim     = 32;
inline constexpr size_t kNumHierarchyLvl = 4;
inline constexpr size_t kTopKRetrieval   = 8;
inline constexpr size_t kMaxReasoningTokens = 12;

using Vec   = std::array<float, kEmbeddingDim>;
using State = std::array<float, kStateVecDim>;
using Time  = std::chrono::steady_clock::time_point;

// ─── Event types ──────────────────────────────────────────────
enum class EventType : uint8_t {
    NetworkPacket, SysLog, ProcessEvent, AuthEvent,
    FileAccess, ApiCall, Signal, Unknown
};

struct PayloadFeatures {
    uint32_t bytes_in  = 0, bytes_out = 0;
    uint16_t port_src  = 0, port_dst  = 0;
    uint8_t  protocol  = 0, flags     = 0;
    float    entropy   = 0.f, rate_hz = 0.f;
};

struct Event {
    Time             time        = std::chrono::steady_clock::now();
    std::string      source;
    std::string      destination;
    EventType        type        = EventType::Unknown;
    PayloadFeatures  payload;
    std::unordered_map<std::string, std::string> metadata;
};

// ─── Level outputs ────────────────────────────────────────────
struct LocalState {
    Vec   embedding     = {};
    float anomaly_score = 0.f;
    float entropy       = 0.f;
    float burst_metric  = 0.f;
};

struct SegmentState {
    State state_vector  = {};
    float anomaly_trend = 0.f;
    float rate_mean     = 0.f;
    float error_freq    = 0.f;
    std::string dominant_type;
};

struct GlobalState {
    std::array<State, kNumHierarchyLvl> level_states = {};
    State  baseline_model  = {};
    float  anomaly_history = 0.f;
    float  drift_score     = 0.f;
};

// ─── State management ─────────────────────────────────────────
enum class MemoryScope { Global, Host, User, IP, Session, Process };

struct MemoryKey {
    std::string host, user, ip, session, process;
    MemoryScope scope = MemoryScope::IP;
};

inline MemoryKey key_from_event(const Event& ev, MemoryScope scope = MemoryScope::IP) {
    MemoryKey k;
    k.ip      = ev.source;
    k.host    = ev.destination;
    k.scope   = scope;
    if (ev.metadata.count("user"))    k.user    = ev.metadata.at("user");
    if (ev.metadata.count("session")) k.session = ev.metadata.at("session");
    if (ev.metadata.count("proc"))    k.process = ev.metadata.at("proc");
    return k;
}

struct StateKey {
    std::string ip, host, user, session;
    bool operator==(const StateKey& o) const {
        return ip==o.ip && host==o.host && user==o.user && session==o.session;
    }
};

enum class StatePhase { Active, Idle, Expired };

struct StateMeta {
    Time       created;
    Time       last_update;
    StatePhase phase          = StatePhase::Active;
    float      energy         = 0.f;
    uint64_t   event_count    = 0;
    uint64_t   segment_count  = 0;
};

struct StateConfig {
    float decay_l1          = 0.95f;
    float decay_l2s         = 0.98f;
    float decay_l2m         = 0.99f;
    float decay_l2l         = 0.999f;
    float max_energy        = 100.f;
    float clamp_limit       = 10.f;
    float idle_timeout_s    = 300.f;
    float expire_timeout_s  = 3600.f;
    size_t max_l1_instances = 10000;
    size_t max_l2s_instances= 5000;
    size_t max_l2m_instances= 1000;
};

// ─── Routing policy ───────────────────────────────────────────
struct FlushRules {
    size_t flush_n              = 100;
    float  flush_t              = 10.f;
    float  flush_anomaly        = 0.70f;
    bool   flush_on_session_end = true;
    bool   flush_on_type_change = true;
};

struct L1ToL2sPromotionRules {
    bool  promote_on_flush  = true;
    float promote_threshold = 0.50f;
    float promote_time      = 30.f;
};

struct L2sToL2mPromotionRules {
    uint32_t mid_tick    = 10;
    float    mid_anomaly = 0.55f;
    float    mid_drift   = 3.0f;
    bool     promote_on_session_end = true;
};

struct L2mToL2lPromotionRules {
    uint32_t global_tick  = 60;
    float    global_drift = 8.0f;
    float    global_hist  = 0.70f;
};

struct SkipRules {
    float    skip_threshold = 0.20f;
    float    skip_drift     = 1.0f;
    uint32_t min_segments   = 3;
};

struct SplitRules {
    bool split_on_new_ip       = true;
    bool split_on_new_session  = true;
    bool split_on_new_user     = true;
    bool split_on_proto_change = false;
};

struct MergeRules {
    bool  enable_merge             = false;
    float merge_similarity         = 0.90f;
    bool  merge_same_host_ips      = false;
    bool  merge_same_user_sessions = false;
};

struct ForceRules {
    float force_anomaly       = 0.90f;
    bool  force_on_block      = true;
    bool  force_on_rule_block = true;
    bool  force_global        = false;
};

struct RoutingConfig {
    FlushRules              flush;
    L1ToL2sPromotionRules   promote_l1_l2s;
    L2sToL2mPromotionRules  promote_l2s_l2m;
    L2mToL2lPromotionRules  promote_l2m_l2l;
    SkipRules               skip;
    SplitRules              split;
    MergeRules              merge;
    ForceRules              force;
};

// ─── Memory ───────────────────────────────────────────────────
struct MemoryRecord {
    uint64_t    id        = 0;
    Vec         embedding = {};
    float       score     = 0.f;
    std::string label;
    std::string raw_summary;
    Time        inserted_at = std::chrono::steady_clock::now();
    MemoryKey   key;
};

struct RetrievedContext {
    std::vector<MemoryRecord> records;
    std::vector<std::string>  matched_rules;
    float                     similarity_max = 0.f;
};

struct WritePolicy {
    float memory_write_gate     = 0.50f;
    float memory_force_gate     = 0.85f;
    bool  write_on_rule_match   = true;
    bool  write_on_block        = true;
    bool  write_on_escalate     = true;
    bool  write_on_high_drift   = false;
    float drift_write_threshold = 5.0f;
};

struct EvictionConfig {
    size_t max_global_records  = 100000;
    size_t max_host_records    = 10000;
    size_t max_ip_records      = 5000;
    size_t max_user_records    = 5000;
    size_t max_session_records = 1000;
    size_t max_process_records = 1000;
};

struct RetrievalTimeConfig {
    float retrieval_max_age_s = 3600.f;
    float recency_tau         = 600.f;
};

struct RetrievalWeights {
    float w_sim     = 0.50f;
    float w_anomaly = 0.30f;
    float w_time    = 0.20f;
};

struct ForceRetrievalConfig {
    bool  force_on_rule_match   = true;
    bool  force_on_block        = true;
    float drift_force_threshold = 5.0f;
    bool  force_retrieve        = false;
};

struct MemoryCleanupConfig {
    float record_ttl_s            = 86400.f;
    bool  cleanup_on_session_end  = true;
    bool  cleanup_on_state_expire = true;
};

// ─── Decision types ───────────────────────────────────────────
enum class Decision : uint8_t { Ignore, Log, Alert, Block, Escalate };

struct DecisionThresholds {
    float ignore_threshold = 0.20f;
    float log_threshold    = 0.40f;
    float alert_threshold  = 0.60f;
    float block_threshold  = 0.85f;
};

inline Decision score_to_decision(float score, const DecisionThresholds& t) {
    if (score < t.ignore_threshold) return Decision::Ignore;
    if (score < t.log_threshold)    return Decision::Log;
    if (score < t.alert_threshold)  return Decision::Alert;
    return Decision::Block;
}

// ─── Reasoning gate ───────────────────────────────────────────
struct GateWeights {
    float w_local     = 0.35f;
    float w_segment   = 0.25f;
    float w_history   = 0.15f;
    float w_drift     = 0.10f;
    float w_retrieval = 0.10f;
    float w_rule      = 0.05f;
};

struct ReasoningGateConfig {
    float       gate_threshold = 0.35f;
    GateWeights weights        = {};
};

struct ForcedReasoningConfig {
    bool  force_on_rule_match = true;
    bool  force_on_block_list = true;
    float force_drift         = 6.0f;
    float force_history       = 0.70f;
    float force_local         = 0.90f;
    bool  force_reasoning     = false;
};

struct SkipReasoningConfig {
    float skip_local_threshold = 0.10f;
    bool  skip_on_allow_list   = true;
    bool  skip_when_idle       = false;
};

struct ScoreFusionWeights {
    float w_local     = 0.50f;
    float w_segment   = 0.25f;
    float w_history   = 0.15f;
    float w_drift     = 0.10f;
    float w_retrieval = 0.15f;
    float w_rule      = 0.10f;
};

// ─── Decision policy ─────────────────────────────────────────
struct EscalationConfig {
    float    escalate_hist        = 0.75f;
    float    escalate_drift       = 8.0f;
    uint32_t repeat_escalate_n    = 3;
    float    repeat_window_s      = 300.f;
    uint32_t multi_host_threshold = 3;
    float    campaign_window_s    = 600.f;
};

struct HysteresisConfig {
    float decision_hysteresis  = 0.05f;
    float decision_hold_time_s = 10.f;
};

struct CooldownConfig {
    float alert_cooldown_s = 5.f;
    float block_cooldown_s = 30.f;
    bool  allow_stronger   = true;
};

struct DecisionPolicy {
    std::vector<std::string> block_list;
    std::vector<std::string> allow_list;
    float escalate_hist_threshold = 0.75f;
    float min_confidence          = 0.1f;
};

// ─── Reasoning result ─────────────────────────────────────────
struct DecisionTrace {
    float    local_score            = 0.f;
    float    segment_trend          = 0.f;
    float    anomaly_history        = 0.f;
    float    drift_score            = 0.f;
    float    retrieval_similarity_max = 0.f;
    bool     rule_matched           = false;
    float    gate_score             = 0.f;
    bool     forced                 = false;
    bool     skipped                = false;
    float    fused_score            = 0.f;
    float    corr_score             = 0.f;
    float    final_score            = 0.f;
    Decision base_decision          = Decision::Ignore;
    Decision final_decision         = Decision::Ignore;
    std::string attack_class;
    std::string correlation_type;
    std::string campaign_id;
};

struct ReasoningResult {
    Decision    decision       = Decision::Ignore;
    float       confidence     = 0.f;
    std::string attack_class;
    std::string explanation;
    bool        false_positive = false;
    DecisionTrace trace;
};

// ─── Fault handling ───────────────────────────────────────────
enum class FaultType { Numeric, State, Memory, Queue, Thread, Input, Config, Storage };

struct FaultRecord {
    FaultType   type;
    std::string key;
    std::string detail;
    Time        time = std::chrono::steady_clock::now();
};

struct PipelineStats {
    std::atomic<uint64_t> events_ingested   {0};
    std::atomic<uint64_t> events_dropped    {0};
    std::atomic<uint64_t> reasoning_calls   {0};
    std::atomic<uint64_t> alerts_emitted    {0};
    std::atomic<uint64_t> blocks_emitted    {0};
    std::atomic<uint64_t> escalations       {0};
    std::atomic<uint64_t> state_resets      {0};
    std::atomic<uint64_t> memory_evictions  {0};
    std::atomic<uint64_t> queue_full_events {0};
    std::atomic<uint64_t> fault_count       {0};
};

struct HealthStats {
    std::atomic<uint64_t> numeric_faults  {0};
    std::atomic<uint64_t> state_resets    {0};
    std::atomic<uint64_t> memory_evictions{0};
    std::atomic<uint64_t> queue_drops     {0};
    std::atomic<uint64_t> reasoning_fails {0};
    std::atomic<uint64_t> retrieval_fails {0};
    std::atomic<uint64_t> storage_fails   {0};
    std::atomic<uint64_t> thread_restarts {0};
    bool                  panic_mode      = false;
};

struct PanicConfig {
    uint32_t panic_threshold      = 100;
    float    panic_window_s       = 60.f;
    bool     disable_reasoning    = true;
    bool     disable_memory_write = true;
    bool     rules_only           = true;
};

// ─── Concurrency / sharding (§4) ─────────────────────────────
struct ShardingConfig {
    uint32_t    num_pipelines = 8;
    std::string hash_key      = "ip";  // "ip" | "session" | "user"
};

enum class BackpressurePolicy { Block, Drop, Priority, Sample };

struct BackpressureConfig {
    BackpressurePolicy policy              = BackpressurePolicy::Priority;
    float              priority_keep_above = 0.60f;
    uint32_t           sample_rate         = 10;
};

struct QueueConfig {
    size_t queue_depth  = 4096;
    bool   backpressure = true;
};

// §5.9 Watchdog
struct WatchdogConfig {
    float    heartbeat_interval_s = 1.0f;
    uint32_t max_missed_beats     = 3;
    bool     auto_restart         = true;
};

// ─── Training / adaptation ────────────────────────────────────
// Forward-declared: actual SSM param types live in ids_ssm.hpp
// ModelParams stores serialisable metadata + raw param blobs (§6.3)
struct ModelParams {
    std::string version;
    std::string checksum;
    Time        trained_at    = std::chrono::steady_clock::now();
    // Serialised parameter blobs — populated by load_model() / save_model()
    // Typed accessors live in ids_ssm.hpp to avoid circular includes
    std::vector<float> l1_A_log;
    std::vector<float> l1_B_proj;
    std::vector<float> l1_C_proj;
    std::vector<float> l1_D_skip;
    std::vector<float> l1_delta_proj;
    // L2 hierarchy layer params (one blob per layer, interleaved A/B/C/D/delta)
    std::vector<std::vector<float>> l2_layer_blobs;
    bool is_valid() const {
        return !version.empty() && !l1_A_log.empty();
    }
};

struct ParameterVersion {
    std::string model_version;
    std::string rule_version;
    std::string config_version;
    std::string signature_version;
    Time        loaded_at = std::chrono::steady_clock::now();
    std::string operator_note;
};

struct ThresholdSuggestion {
    float gate_threshold;
    float alert_threshold;
    float block_threshold;
    float flush_anomaly;
    float promote_threshold;
};

struct LearningModeConfig {
    bool  enabled          = false;
    bool  disable_blocking = true;
    bool  log_only         = true;
    bool  collect_baseline = true;
    float duration_s       = 3600.f;
};

struct BaselineConfig {
    float alpha     = 0.01f;
    float min_value = -50.f;
    float max_value =  50.f;
    bool  freeze    = false;
};

// ─── Correlation ──────────────────────────────────────────────
struct AlertRecord {
    Time        time    = std::chrono::steady_clock::now();
    StateKey    key;
    std::string attack_class;
    float       score   = 0.f;
    Decision    decision = Decision::Ignore;
    std::string source;
    std::string destination;
};

struct CampaignState {
    std::string              id;
    std::string              attack_class;
    std::vector<std::string> sources;
    std::vector<std::string> hosts;
    std::vector<std::string> users;
    Time                     first_seen = std::chrono::steady_clock::now();
    Time                     last_seen  = std::chrono::steady_clock::now();
    uint32_t                 event_count = 0;
    float                    max_score   = 0.f;
    bool                     active      = true;
};

struct CorrelationResult {
    float       corr_score          = 0.f;
    bool        repeat_detected     = false;
    bool        multi_stage_detected= false;
    bool        distributed_detected= false;
    bool        slow_attack_detected= false;
    std::string campaign_id;
    Decision    upgraded_decision   = Decision::Ignore;
    std::string correlation_type;
};

// ─── Adaptive baseline ────────────────────────────────────────
struct ScopeBaseline {
    std::array<float, kEmbeddingDim> mean     = {};
    std::array<float, kEmbeddingDim> variance = {};
    float avg_anomaly_score = 0.f;
    float avg_rate_hz       = 0.f;
    float avg_entropy       = 0.f;
    float avg_drift         = 0.f;
    float avg_state_energy  = 0.f;
    Time  last_update       = std::chrono::steady_clock::now();
    bool  frozen            = false;
};

struct BaselineStore {
    std::unordered_map<std::string, ScopeBaseline> ip_baseline;
    std::unordered_map<std::string, ScopeBaseline> user_baseline;
    std::unordered_map<std::string, ScopeBaseline> host_baseline;
    ScopeBaseline                                   global_baseline;
};

struct AdaptationStats {
    std::atomic<uint64_t> baseline_updates  {0};
    std::atomic<uint64_t> baseline_freezes  {0};
    std::atomic<uint64_t> threshold_changes {0};
    std::atomic<uint64_t> decay_changes     {0};
    std::atomic<uint64_t> gate_changes      {0};
    std::atomic<uint64_t> baseline_resets   {0};
    std::atomic<uint64_t> drift_alerts      {0};
};

// ─── Telemetry ────────────────────────────────────────────────
struct TimeSeriesSample {
    Time  time;
    float drift_score;
    float anomaly_history;
    float alert_threshold;
    float gate_threshold;
    float baseline_energy;
};

enum class RoutingEvent { Flush, Promote, Skip, Split, Merge, Reset, ForcePromote };

struct RoutingLogEntry {
    Time         time = std::chrono::steady_clock::now();
    RoutingEvent event;
    StateKey     key;
    int          from_level = 0;
    int          to_level   = 0;
    std::string  reason;
};

struct StageLatency {
    float l0_avg_us           = 0.f;
    float l1_avg_us           = 0.f;
    float l2_avg_us           = 0.f;
    float memory_write_avg_us = 0.f;
    float retrieval_avg_us    = 0.f;
    float reasoning_avg_us    = 0.f;
    float correlation_avg_us  = 0.f;
    float decision_avg_us     = 0.f;
    float total_avg_us        = 0.f;
    float l0_p99_us           = 0.f;
    float retrieval_p99_us    = 0.f;
    float reasoning_p99_us    = 0.f;
    float total_p99_us        = 0.f;
};

struct ShardStats {
    uint32_t shard_id                = 0;
    size_t   queue_depth             = 0;
    float    events_per_sec          = 0.f;
    float    avg_latency_us          = 0.f;
    size_t   drops                   = 0;
    size_t   active_states           = 0;
    bool     reasoning_pool_saturated= false;
};

enum class LogLevel { Error, Warn, Info, Debug, Trace };

struct TelemetryConfig {
    LogLevel log_level        = LogLevel::Info;
    bool     routing_debug    = false;
    bool     decision_trace   = true;
    bool     latency_tracking = true;
    bool     drift_series     = true;
    size_t   drift_series_max = 10000;
    size_t   fault_log_max    = 1000;
    size_t   routing_log_max  = 10000;
};

struct Metrics {
    std::atomic<uint64_t> events_total      {0};
    std::atomic<uint64_t> events_per_sec    {0};
    std::atomic<uint64_t> alerts_total      {0};
    std::atomic<uint64_t> blocks_total      {0};
    std::atomic<uint64_t> escalations_total {0};
    std::atomic<uint64_t> drops_total       {0};
    std::atomic<uint64_t> reasoning_calls   {0};
    std::atomic<uint64_t> forced_reasoning  {0};
    std::atomic<uint64_t> memory_writes     {0};
    std::atomic<uint64_t> memory_evictions  {0};
    std::atomic<uint64_t> state_resets      {0};
    std::atomic<uint64_t> faults_total      {0};
    std::atomic<uint64_t> queue_overflows   {0};
    std::atomic<uint64_t> campaigns_active  {0};
    std::atomic<uint64_t> baseline_freezes  {0};
};

// ─── AggregateMetrics — copyable snapshot for ShardedIDS ────
struct AggregateMetrics {
    uint64_t events_total      = 0;
    uint64_t alerts_total      = 0;
    uint64_t blocks_total      = 0;
    uint64_t escalations_total = 0;
    uint64_t drops_total       = 0;
    uint64_t reasoning_calls   = 0;
    uint64_t memory_writes     = 0;
    uint64_t faults_total      = 0;
    uint64_t campaigns_active  = 0;
};

// ─── Alert ────────────────────────────────────────────────────
struct Alert {
    Decision      decision;
    float         confidence;
    std::string   attack_class;
    std::string   explanation;
    std::string   source;
    std::string   destination;
    EventType     event_type;
    Time          time;
    DecisionTrace trace;
};

using AlertCallback    = std::function<void(const Alert&)>;
using BlockCallback    = std::function<void(const std::string&)>;
using EscalateCallback = std::function<void(const Alert&)>;

}  // namespace ids
