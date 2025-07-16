/**
 * @file c300_constants.hpp
 * @brief Konstanta sistem terpusat untuk seluruh modul SystemC C300
 * @version 1.0.0
 * @date 2024-12-19
 * @author Tim C300 Engineering Indonesia
 * @copyright C300 ASIC Mining Technology
 * 
 * Definisi konstanta sistem untuk sintesis RTL dengan 300 core processing units
 * Hardware implementation ready untuk chip fabrication
 * 
 * SYNTHESIS COMPLIANCE:
 * - Compile-time constants only
 * - No dynamic values atau runtime calculations
 * - Static sizing untuk synthesis optimization
 * - Multi-foundry compatible definitions
 */

#ifndef C300_CONSTANTS_HPP
#define C300_CONSTANTS_HPP

#include <systemc.h>

// ========================================================================
// SYSTEM ARCHITECTURE CONSTANTS
// ========================================================================

// CORE ARCHITECTURE
static const int C300_NUM_CORES = 300;
static const int C300_CORE_ID_BITS = 9;
static const int C300_CORES_PER_CLUSTER = 25;
static const int C300_NUM_CLUSTERS = 12;
static const int C300_CLUSTER_ID_BITS = 4;
static const int C300_CORE_PIPELINE_STAGES = 8;
static const int C300_CORE_REGISTER_FILE_SIZE = 32;
static const int C300_CORE_INSTRUCTION_WIDTH = 32;
static const int C300_CORE_DATA_WIDTH = 256;

// ENGINE ARCHITECTURE
static const int C300_NUM_ENGINES = 300;
static const int C300_ENGINE_ID_BITS = 9;
static const int C300_ENGINES_PER_CORE = 1;
static const int C300_ENGINE_PIPELINE_DEPTH = 64;
static const int C300_ENGINE_ROUND_STAGES = 16;
static const int C300_ENGINE_BUFFER_DEPTH = 8;
static const int C300_ENGINE_RESULT_WIDTH = 256;

// CONTROLLER ARCHITECTURE
static const int C300_NUM_CONTROLLERS = 12;
static const int C300_CONTROLLER_ID_BITS = 4;
static const int C300_CONTROLLERS_PER_CLUSTER = 1;
static const int C300_CONTROLLER_FIFO_DEPTH = 512;
static const int C300_CONTROLLER_PRIORITY_LEVELS = 8;
static const int C300_CONTROLLER_TIMEOUT_CYCLES = 10000;

// NETWORK ARCHITECTURE
static const int C300_NETWORK_INTERFACES = 4;
static const int C300_NETWORK_CHANNELS = 16;
static const int C300_NETWORK_BUFFER_SIZE = 4096;
static const int C300_NETWORK_PACKET_SIZE = 1500;
static const int C300_NETWORK_QUEUE_DEPTH = 256;
static const int C300_NETWORK_BANDWIDTH_GBPS = 100;

// SYSTEM ARCHITECTURE
static const int C300_SYSTEM_CLOCK_DOMAINS = 4;
static const int C300_SYSTEM_POWER_DOMAINS = 8;
static const int C300_SYSTEM_RESET_DOMAINS = 4;
static const int C300_SYSTEM_MONITOR_POINTS = 128;
static const int C300_SYSTEM_DEBUG_CHANNELS = 32;

// ========================================================================
// HASH ALGORITHM CONSTANTS
// ========================================================================

// SHA256 PARAMETERS
static const int C300_SHA256_BLOCK_SIZE = 512;
static const int C300_SHA256_HASH_SIZE = 256;
static const int C300_SHA256_WORD_SIZE = 32;
static const int C300_SHA256_ROUNDS = 64;
static const int C300_SHA256_SCHEDULE_SIZE = 64;
static const int C300_SHA256_STATE_SIZE = 8;

// DOUBLE SHA256 PARAMETERS
static const int C300_DOUBLE_SHA256_STAGES = 2;
static const int C300_DOUBLE_SHA256_LATENCY = 128;
static const int C300_DOUBLE_SHA256_THROUGHPUT = 2;

// NONCE PARAMETERS
static const int C300_NONCE_BITS = 32;
static const int C300_NONCE_START = 0x00000000;
static const int C300_NONCE_END = 0xFFFFFFFF;
static const int C300_NONCE_STEP = 1;
static const int C300_NONCE_RANGE_PER_CORE = 0x155555;

// TARGET PARAMETERS
static const int C300_TARGET_BITS = 256;
static const int C300_DIFFICULTY_BITS = 32;
static const int C300_DIFFICULTY_ADJUST_BLOCKS = 2016;
static const int C300_BLOCK_TIME_SECONDS = 600;

// ========================================================================
// MEMORY ARCHITECTURE CONSTANTS
// ========================================================================

// MEMORY HIERARCHY
static const int C300_L1_CACHE_SIZE = 32768;
static const int C300_L1_CACHE_WAYS = 8;
static const int C300_L1_CACHE_LINE_SIZE = 64;
static const int C300_L1_CACHE_SETS = 64;
static const int C300_L2_CACHE_SIZE = 262144;
static const int C300_L2_CACHE_WAYS = 16;
static const int C300_L2_CACHE_LINE_SIZE = 128;
static const int C300_L2_CACHE_SETS = 128;

// MEMORY BANKS
static const int C300_MEMORY_BANKS = 16;
static const int C300_MEMORY_BANK_SIZE = 4096;
static const int C300_MEMORY_BANK_WIDTH = 256;
static const int C300_MEMORY_BANK_DEPTH = 16384;
static const int C300_MEMORY_INTERLEAVING = 8;

// BUFFER SIZES
static const int C300_WORK_BUFFER_SIZE = 2048;
static const int C300_RESULT_BUFFER_SIZE = 1024;
static const int C300_NETWORK_BUFFER_SIZE = 4096;
static const int C300_DEBUG_BUFFER_SIZE = 512;
static const int C300_ERROR_BUFFER_SIZE = 256;

// QUEUE DEPTHS
static const int C300_WORK_QUEUE_DEPTH = 1024;
static const int C300_RESULT_QUEUE_DEPTH = 512;
static const int C300_COMMAND_QUEUE_DEPTH = 128;
static const int C300_STATUS_QUEUE_DEPTH = 64;
static const int C300_ERROR_QUEUE_DEPTH = 32;

// ========================================================================
// TIMING CONSTANTS (1GHZ CLOCK DOMAIN)
// ========================================================================

// CLOCK PARAMETERS
static const double C300_MASTER_CLOCK_FREQ_GHZ = 1.0;
static const double C300_MASTER_CLOCK_PERIOD_NS = 1.0;
static const double C300_CORE_CLOCK_FREQ_GHZ = 1.0;
static const double C300_CORE_CLOCK_PERIOD_NS = 1.0;
static const double C300_ENGINE_CLOCK_FREQ_GHZ = 1.0;
static const double C300_ENGINE_CLOCK_PERIOD_NS = 1.0;
static const double C300_NETWORK_CLOCK_FREQ_GHZ = 0.5;
static const double C300_NETWORK_CLOCK_PERIOD_NS = 2.0;

// TIMING CONSTRAINTS
static const double C300_SETUP_TIME_NS = 0.1;
static const double C300_HOLD_TIME_NS = 0.05;
static const double C300_CLOCK_SKEW_NS = 0.02;
static const double C300_CLOCK_JITTER_NS = 0.01;
static const double C300_PROPAGATION_DELAY_NS = 0.03;
static const double C300_WIRE_DELAY_NS = 0.02;

// PIPELINE TIMING
static const int C300_PIPELINE_SETUP_CYCLES = 2;
static const int C300_PIPELINE_FLUSH_CYCLES = 8;
static const int C300_PIPELINE_STALL_CYCLES = 1;
static const int C300_PIPELINE_BYPASS_CYCLES = 1;

// RESET TIMING
static const int C300_RESET_ASSERTION_CYCLES = 16;
static const int C300_RESET_DEASSERTION_CYCLES = 8;
static const int C300_RESET_SYNC_CYCLES = 4;
static const int C300_RESET_RECOVERY_CYCLES = 32;

// TIMEOUT CONSTANTS
static const int C300_WORK_TIMEOUT_CYCLES = 100000;
static const int C300_NETWORK_TIMEOUT_CYCLES = 50000;
static const int C300_MEMORY_TIMEOUT_CYCLES = 1000;
static const int C300_DEBUG_TIMEOUT_CYCLES = 10000;

// ========================================================================
// POWER MANAGEMENT CONSTANTS
// ========================================================================

// POWER DOMAINS
static const int C300_POWER_DOMAIN_CORE = 0;
static const int C300_POWER_DOMAIN_ENGINE = 1;
static const int C300_POWER_DOMAIN_CONTROLLER = 2;
static const int C300_POWER_DOMAIN_NETWORK = 3;
static const int C300_POWER_DOMAIN_MEMORY = 4;
static const int C300_POWER_DOMAIN_SYSTEM = 5;
static const int C300_POWER_DOMAIN_IO = 6;
static const int C300_POWER_DOMAIN_DEBUG = 7;

// POWER LEVELS
static const int C300_POWER_LEVEL_OFF = 0;
static const int C300_POWER_LEVEL_STANDBY = 1;
static const int C300_POWER_LEVEL_IDLE = 2;
static const int C300_POWER_LEVEL_ACTIVE = 3;
static const int C300_POWER_LEVEL_BOOST = 4;
static const int C300_POWER_LEVEL_CRITICAL = 5;

// POWER THRESHOLDS
static const double C300_POWER_BUDGET_TOTAL_W = 240.0;
static const double C300_POWER_BUDGET_CORE_W = 180.0;
static const double C300_POWER_BUDGET_ENGINE_W = 120.0;
static const double C300_POWER_BUDGET_NETWORK_W = 20.0;
static const double C300_POWER_BUDGET_SYSTEM_W = 40.0;

// THERMAL CONSTANTS
static const int C300_THERMAL_SENSOR_COUNT = 64;
static const int C300_THERMAL_TEMP_NORMAL_C = 25;
static const int C300_THERMAL_TEMP_WARNING_C = 75;
static const int C300_THERMAL_TEMP_CRITICAL_C = 85;
static const int C300_THERMAL_TEMP_SHUTDOWN_C = 95;

// ========================================================================
// SECURITY CONSTANTS
// ========================================================================

// SECURITY LEVELS
static const int C300_SECURITY_LEVEL_NONE = 0;
static const int C300_SECURITY_LEVEL_BASIC = 1;
static const int C300_SECURITY_LEVEL_MEDIUM = 2;
static const int C300_SECURITY_LEVEL_HIGH = 3;
static const int C300_SECURITY_LEVEL_CRITICAL = 4;

// ENCRYPTION PARAMETERS
static const int C300_AES_KEY_SIZE = 256;
static const int C300_AES_BLOCK_SIZE = 128;
static const int C300_AES_ROUNDS = 14;
static const int C300_RSA_KEY_SIZE = 2048;
static const int C300_HASH_SALT_SIZE = 256;

// AUTHENTICATION
static const int C300_UUID_SIZE = 128;
static const int C300_SESSION_ID_SIZE = 64;
static const int C300_ACCESS_TOKEN_SIZE = 256;
static const int C300_SIGNATURE_SIZE = 256;

// SECURITY TIMEOUTS
static const int C300_AUTH_TIMEOUT_SECONDS = 300;
static const int C300_SESSION_TIMEOUT_SECONDS = 3600;
static const int C300_TOKEN_REFRESH_SECONDS = 1800;
static const int C300_LOCKOUT_DURATION_SECONDS = 900;

// ========================================================================
// PERFORMANCE CONSTANTS
// ========================================================================

// THROUGHPUT TARGETS
static const double C300_TARGET_THROUGHPUT_THS = 144.0;
static const double C300_PER_CORE_THROUGHPUT_THS = 0.48;
static const double C300_PER_ENGINE_THROUGHPUT_THS = 0.48;
static const double C300_SYSTEM_EFFICIENCY_PERCENT = 95.0;

// LATENCY TARGETS
static const int C300_WORK_DISTRIBUTION_LATENCY_CYCLES = 10;
static const int C300_HASH_COMPUTATION_LATENCY_CYCLES = 128;
static const int C300_RESULT_COLLECTION_LATENCY_CYCLES = 20;
static const int C300_NETWORK_RESPONSE_LATENCY_CYCLES = 100;

// BANDWIDTH TARGETS
static const double C300_MEMORY_BANDWIDTH_GBPS = 21.0;
static const double C300_NETWORK_BANDWIDTH_GBPS = 100.0;
static const double C300_INTER_CORE_BANDWIDTH_GBPS = 50.0;
static const double C300_CONTROLLER_BANDWIDTH_GBPS = 25.0;

// UTILIZATION TARGETS
static const double C300_CORE_UTILIZATION_PERCENT = 98.0;
static const double C300_ENGINE_UTILIZATION_PERCENT = 99.0;
static const double C300_MEMORY_UTILIZATION_PERCENT = 85.0;
static const double C300_NETWORK_UTILIZATION_PERCENT = 80.0;

// ========================================================================
// ERROR HANDLING CONSTANTS
// ========================================================================

// ERROR CODES
static const int C300_ERROR_NONE = 0;
static const int C300_ERROR_TIMEOUT = 1;
static const int C300_ERROR_INVALID_DATA = 2;
static const int C300_ERROR_MEMORY_FAULT = 3;
static const int C300_ERROR_SECURITY_VIOLATION = 4;
static const int C300_ERROR_THERMAL_SHUTDOWN = 5;
static const int C300_ERROR_POWER_FAILURE = 6;
static const int C300_ERROR_NETWORK_DISCONNECT = 7;
static const int C300_ERROR_SYSTEM_FAULT = 8;

// ERROR THRESHOLDS
static const int C300_ERROR_THRESHOLD_SOFT = 10;
static const int C300_ERROR_THRESHOLD_HARD = 100;
static const int C300_ERROR_THRESHOLD_CRITICAL = 1000;

// RETRY PARAMETERS
static const int C300_RETRY_COUNT_MAX = 3;
static const int C300_RETRY_DELAY_CYCLES = 1000;
static const int C300_RETRY_BACKOFF_FACTOR = 2;

// ========================================================================
// DEBUG AND MONITORING CONSTANTS
// ========================================================================

// DEBUG LEVELS
static const int C300_DEBUG_LEVEL_NONE = 0;
static const int C300_DEBUG_LEVEL_ERROR = 1;
static const int C300_DEBUG_LEVEL_WARNING = 2;
static const int C300_DEBUG_LEVEL_INFO = 3;
static const int C300_DEBUG_LEVEL_VERBOSE = 4;
static const int C300_DEBUG_LEVEL_TRACE = 5;

// MONITORING INTERVALS
static const int C300_MONITOR_INTERVAL_CYCLES = 1000;
static const int C300_PERFORMANCE_SAMPLE_CYCLES = 10000;
static const int C300_THERMAL_SAMPLE_CYCLES = 100000;
static const int C300_POWER_SAMPLE_CYCLES = 50000;

// LOG BUFFER SIZES
static const int C300_LOG_BUFFER_SIZE = 1024;
static const int C300_TRACE_BUFFER_SIZE = 4096;
static const int C300_EVENT_BUFFER_SIZE = 512;
static const int C300_STAT_BUFFER_SIZE = 256;

// ========================================================================
// INTERFACE CONSTANTS
// ========================================================================

// PROTOCOL PARAMETERS
static const int C300_PROTOCOL_VERSION = 1;
static const int C300_PROTOCOL_HEADER_SIZE = 16;
static const int C300_PROTOCOL_PAYLOAD_SIZE = 1024;
static const int C300_PROTOCOL_CHECKSUM_SIZE = 4;

// HANDSHAKE PARAMETERS
static const int C300_HANDSHAKE_TIMEOUT_CYCLES = 1000;
static const int C300_HANDSHAKE_RETRY_COUNT = 3;
static const int C300_HANDSHAKE_BACKOFF_CYCLES = 100;

// FLOW CONTROL
static const int C300_FLOW_CONTROL_WINDOW_SIZE = 64;
static const int C300_FLOW_CONTROL_THRESHOLD = 48;
static const int C300_FLOW_CONTROL_RESUME_THRESHOLD = 16;

// ========================================================================
// SYNTHESIS OPTIMIZATION CONSTANTS
// ========================================================================

// RESOURCE SHARING
static const int C300_ADDER_SHARING_FACTOR = 4;
static const int C300_MULTIPLIER_SHARING_FACTOR = 2;
static const int C300_MEMORY_SHARING_FACTOR = 8;

// PIPELINE OPTIMIZATION
static const int C300_PIPELINE_BALANCING_STAGES = 8;
static const int C300_PIPELINE_REGISTER_INSERTION = 2;
static const int C300_PIPELINE_LOGIC_DEPTH = 6;

// AREA OPTIMIZATION
static const int C300_AREA_OPTIMIZATION_LEVEL = 3;
static const int C300_GATE_SHARING_THRESHOLD = 16;
static const int C300_LOGIC_MINIMIZATION_EFFORT = 5;

// TIMING OPTIMIZATION
static const int C300_TIMING_OPTIMIZATION_LEVEL = 5;
static const int C300_CRITICAL_PATH_OPTIMIZATION = 1;
static const int C300_SLACK_MARGIN_PS = 50;

// ========================================================================
// MANUFACTURING CONSTANTS
// ========================================================================

// PROCESS PARAMETERS
static const int C300_PROCESS_NODE_NM = 7;
static const int C300_METAL_LAYERS = 12;
static const int C300_VDD_NOMINAL_MV = 900;
static const int C300_VDD_MIN_MV = 810;
static const int C300_VDD_MAX_MV = 990;

// YIELD PARAMETERS
static const double C300_YIELD_TARGET_PERCENT = 95.0;
static const double C300_DEFECT_DENSITY_PER_CM2 = 0.1;
static const double C300_CRITICAL_AREA_CM2 = 2.5;

// RELIABILITY PARAMETERS
static const int C300_MTBF_HOURS = 100000;
static const int C300_OPERATING_LIFE_YEARS = 10;
static const double C300_FAILURE_RATE_FIT = 100.0;

// ========================================================================
// COMPILE-TIME VALIDATION
// ========================================================================

// Architecture validation
static_assert(C300_NUM_CORES == 300, "System must have exactly 300 cores");
static_assert(C300_CORES_PER_CLUSTER * C300_NUM_CLUSTERS == C300_NUM_CORES, "Core clustering must be consistent");
static_assert(C300_NUM_ENGINES == C300_NUM_CORES, "Each core must have one engine");

// Timing validation
static_assert(C300_MASTER_CLOCK_PERIOD_NS == 1.0, "Master clock must be 1GHz");
static_assert(C300_SETUP_TIME_NS < C300_MASTER_CLOCK_PERIOD_NS, "Setup time must be less than clock period");
static_assert(C300_HOLD_TIME_NS < C300_MASTER_CLOCK_PERIOD_NS, "Hold time must be less than clock period");

// Memory validation
static_assert(C300_L1_CACHE_SIZE > 0, "L1 cache size must be positive");
static_assert(C300_L2_CACHE_SIZE > C300_L1_CACHE_SIZE, "L2 cache must be larger than L1");
static_assert(C300_MEMORY_BANKS > 0, "Memory banks must be positive");

// Power validation
static_assert(C300_POWER_BUDGET_TOTAL_W > 0, "Total power budget must be positive");
static_assert(C300_THERMAL_TEMP_CRITICAL_C > C300_THERMAL_TEMP_WARNING_C, "Critical temperature must be higher than warning");

// Performance validation
static_assert(C300_TARGET_THROUGHPUT_THS > 0, "Target throughput must be positive");
static_assert(C300_PER_CORE_THROUGHPUT_THS * C300_NUM_CORES >= C300_TARGET_THROUGHPUT_THS * 0.9, "Per-core throughput must support system target");

#endif // C300_CONSTANTS_HPP
