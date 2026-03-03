//! Monitoring - Metrics, Alerting, Log Aggregation
//!
//! Comprehensive monitoring infrastructure for VM observability.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Metrics Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Metric types
pub mod metric_type {
    pub const COUNTER: u8 = 0;
    pub const GAUGE: u8 = 1;
    pub const HISTOGRAM: u8 = 2;
    pub const SUMMARY: u8 = 3;
    pub const UNTYPED: u8 = 4;
}

/// Metric categories
pub mod metric_cat {
    pub const CPU: u8 = 0;
    pub const MEMORY: u8 = 1;
    pub const DISK: u8 = 2;
    pub const NETWORK: u8 = 3;
    pub const VM: u8 = 4;
    pub const VCPU: u8 = 5;
    pub const HYPERVISOR: u8 = 6;
    pub const SECURITY: u8 = 7;
}

/// Maximum metrics
pub const MAX_METRICS: usize = 1024;
/// Maximum metric labels
pub const MAX_LABELS: usize = 8;
/// Maximum histogram buckets
pub const MAX_HISTOGRAM_BUCKETS: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
// Metric Definition
// ─────────────────────────────────────────────────────────────────────────────

/// Metric label
pub struct MetricLabel {
    /// Label key (hashed)
    pub key: AtomicU64,
    /// Label value (hashed)
    pub value: AtomicU64,
}

impl MetricLabel {
    pub const fn new() -> Self {
        Self {
            key: AtomicU64::new(0),
            value: AtomicU64::new(0),
        }
    }
}

/// Metric entry
pub struct Metric {
    /// Metric ID
    pub id: AtomicU32,
    /// Metric name hash
    pub name_hash: AtomicU64,
    /// Metric type
    pub metric_type: AtomicU8,
    /// Category
    pub category: AtomicU8,
    /// Labels
    pub labels: [MetricLabel; MAX_LABELS],
    /// Label count
    pub label_count: AtomicU8,
    /// Current value
    pub value: AtomicU64,
    /// Counter total
    pub counter_total: AtomicU64,
    /// Gauge min
    pub gauge_min: AtomicU64,
    /// Gauge max
    pub gauge_max: AtomicU64,
    /// Last update timestamp
    pub last_update: AtomicU64,
    /// Update count
    pub update_count: AtomicU64,
    /// Histogram buckets
    pub histogram_buckets: [AtomicU64; MAX_HISTOGRAM_BUCKETS],
    /// Histogram bucket limits
    pub histogram_limits: [AtomicU64; MAX_HISTOGRAM_BUCKETS],
    /// Histogram bucket count
    pub histogram_count: AtomicU8,
    /// Histogram sum
    pub histogram_sum: AtomicU64,
    /// Histogram count
    pub histogram_total: AtomicU64,
    /// Enabled
    pub enabled: AtomicBool,
}

impl Metric {
    pub const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            name_hash: AtomicU64::new(0),
            metric_type: AtomicU8::new(metric_type::COUNTER),
            category: AtomicU8::new(0),
            labels: [const { MetricLabel::new() }; MAX_LABELS],
            label_count: AtomicU8::new(0),
            value: AtomicU64::new(0),
            counter_total: AtomicU64::new(0),
            gauge_min: AtomicU64::new(u64::MAX),
            gauge_max: AtomicU64::new(0),
            last_update: AtomicU64::new(0),
            update_count: AtomicU64::new(0),
            histogram_buckets: [const { AtomicU64::new(0) }; MAX_HISTOGRAM_BUCKETS],
            histogram_limits: [const { AtomicU64::new(0) }; MAX_HISTOGRAM_BUCKETS],
            histogram_count: AtomicU8::new(0),
            histogram_sum: AtomicU64::new(0),
            histogram_total: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
        }
    }

    /// Initialize metric
    pub fn init(&self, id: u32, name_hash: u64, metric_type: u8, category: u8) {
        self.id.store(id, Ordering::Release);
        self.name_hash.store(name_hash, Ordering::Release);
        self.metric_type.store(metric_type, Ordering::Release);
        self.category.store(category, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Add label
    pub fn add_label(&self, key: u64, value: u64) {
        let count = self.label_count.load(Ordering::Acquire) as usize;
        if count < MAX_LABELS {
            self.labels[count].key.store(key, Ordering::Release);
            self.labels[count].value.store(value, Ordering::Release);
            self.label_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Update counter
    pub fn increment(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::Release);
        self.counter_total.fetch_add(delta, Ordering::Release);
        self.last_update.store(Self::get_timestamp(), Ordering::Release);
        self.update_count.fetch_add(1, Ordering::Release);
    }

    /// Update gauge
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Release);
        
        // Update min/max
        loop {
            let min = self.gauge_min.load(Ordering::Acquire);
            if value >= min || self.gauge_min.compare_exchange(min, value, Ordering::Release, Ordering::Acquire).is_ok() {
                break;
            }
        }
        
        loop {
            let max = self.gauge_max.load(Ordering::Acquire);
            if value <= max || self.gauge_max.compare_exchange(max, value, Ordering::Release, Ordering::Acquire).is_ok() {
                break;
            }
        }
        
        self.last_update.store(Self::get_timestamp(), Ordering::Release);
        self.update_count.fetch_add(1, Ordering::Release);
    }

    /// Observe histogram
    pub fn observe(&self, value: u64) {
        self.histogram_sum.fetch_add(value, Ordering::Release);
        self.histogram_total.fetch_add(1, Ordering::Release);
        
        // Find bucket
        let bucket_count = self.histogram_count.load(Ordering::Acquire) as usize;
        for i in 0..bucket_count {
            let limit = self.histogram_limits[i].load(Ordering::Acquire);
            if value <= limit {
                self.histogram_buckets[i].fetch_add(1, Ordering::Release);
                break;
            }
        }
        
        self.last_update.store(Self::get_timestamp(), Ordering::Release);
        self.update_count.fetch_add(1, Ordering::Release);
    }

    /// Get value
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for Metric {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Metrics Registry
// ─────────────────────────────────────────────────────────────────────────────

/// Metrics registry
pub struct MetricsRegistry {
    /// Metrics
    pub metrics: [Metric; MAX_METRICS],
    /// Metric count
    pub metric_count: AtomicU32,
    /// Collection enabled
    pub enabled: AtomicBool,
    /// Collection interval (ms)
    pub interval: AtomicU32,
    /// Last collection
    pub last_collection: AtomicU64,
    /// Total collections
    pub total_collections: AtomicU64,
    /// Export format (0=Prometheus, 1=OpenMetrics, 2=JSON)
    pub export_format: AtomicU8,
}

impl MetricsRegistry {
    pub const fn new() -> Self {
        Self {
            metrics: [const { Metric::new() }; MAX_METRICS],
            metric_count: AtomicU32::new(0),
            enabled: AtomicBool::new(true),
            interval: AtomicU32::new(1000),
            last_collection: AtomicU64::new(0),
            total_collections: AtomicU64::new(0),
            export_format: AtomicU8::new(0),
        }
    }

    /// Register metric
    pub fn register(&mut self, name_hash: u64, metric_type: u8, category: u8) -> Result<u32, HvError> {
        let count = self.metric_count.load(Ordering::Acquire);
        if count as usize >= MAX_METRICS {
            return Err(HvError::LogicalFault);
        }
        
        let id = count + 1;
        let metric = &self.metrics[count as usize];
        metric.init(id, name_hash, metric_type, category);
        
        self.metric_count.fetch_add(1, Ordering::Release);
        Ok(id)
    }

    /// Get metric by ID
    pub fn get_metric(&self, id: u32) -> Option<&Metric> {
        if id == 0 || id as usize > self.metric_count.load(Ordering::Acquire) as usize {
            return None;
        }
        Some(&self.metrics[(id - 1) as usize])
    }

    /// Increment counter
    pub fn counter_inc(&self, id: u32, delta: u64) -> Result<(), HvError> {
        let metric = self.get_metric(id).ok_or(HvError::LogicalFault)?;
        if metric.metric_type.load(Ordering::Acquire) != metric_type::COUNTER {
            return Err(HvError::LogicalFault);
        }
        metric.increment(delta);
        Ok(())
    }

    /// Set gauge
    pub fn gauge_set(&self, id: u32, value: u64) -> Result<(), HvError> {
        let metric = self.get_metric(id).ok_or(HvError::LogicalFault)?;
        if metric.metric_type.load(Ordering::Acquire) != metric_type::GAUGE {
            return Err(HvError::LogicalFault);
        }
        metric.set(value);
        Ok(())
    }

    /// Observe histogram
    pub fn histogram_observe(&self, id: u32, value: u64) -> Result<(), HvError> {
        let metric = self.get_metric(id).ok_or(HvError::LogicalFault)?;
        if metric.metric_type.load(Ordering::Acquire) != metric_type::HISTOGRAM {
            return Err(HvError::LogicalFault);
        }
        metric.observe(value);
        Ok(())
    }

    /// Collect all metrics
    pub fn collect(&mut self) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        // Would aggregate metrics from all sources
        self.last_collection.store(Self::get_timestamp(), Ordering::Release);
        self.total_collections.fetch_add(1, Ordering::Release);
    }

    /// Export metrics
    pub fn export(&self, format: u8) -> [u8; 65536] {
        let mut output = [0u8; 65536];
        let mut offset = 0;
        
        match format {
            0 => {
                // Prometheus format
                for i in 0..self.metric_count.load(Ordering::Acquire) as usize {
                    let metric = &self.metrics[i];
                    if !metric.enabled.load(Ordering::Acquire) {
                        continue;
                    }
                    
                    // Would write metric in Prometheus format
                    let _ = metric;
                    offset += 100; // Placeholder
                }
            }
            1 | 2 => {
                // OpenMetrics or JSON
                let _ = offset;
            }
            _ => {}
        }
        
        output
    }

    /// Get statistics
    pub fn get_stats(&self) -> MetricsStats {
        MetricsStats {
            metric_count: self.metric_count.load(Ordering::Acquire),
            enabled: self.enabled.load(Ordering::Acquire),
            total_collections: self.total_collections.load(Ordering::Acquire),
            interval: self.interval.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics statistics
#[repr(C)]
pub struct MetricsStats {
    pub metric_count: u32,
    pub enabled: bool,
    pub total_collections: u64,
    pub interval: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Alerting System
// ─────────────────────────────────────────────────────────────────────────────

/// Alert severity
pub mod alert_severity {
    pub const INFO: u8 = 0;
    pub const WARNING: u8 = 1;
    pub const ERROR: u8 = 2;
    pub const CRITICAL: u8 = 3;
}

/// Alert states
pub mod alert_state {
    pub const INACTIVE: u8 = 0;
    pub const PENDING: u8 = 1;
    pub const FIRING: u8 = 2;
    pub const RESOLVED: u8 = 3;
}

/// Maximum alert rules
pub const MAX_ALERT_RULES: usize = 256;
/// Maximum active alerts
pub const MAX_ACTIVE_ALERTS: usize = 128;

/// Alert rule
pub struct AlertRule {
    /// Rule ID
    pub rule_id: AtomicU32,
    /// Rule name hash
    pub name_hash: AtomicU64,
    /// Metric ID to watch
    pub metric_id: AtomicU32,
    /// Threshold value
    pub threshold: AtomicU64,
    /// Comparison operator (0=<, 1=>, 2==, 3!=)
    pub operator: AtomicU8,
    /// Severity
    pub severity: AtomicU8,
    /// Duration threshold (ms)
    pub duration: AtomicU32,
    /// Current state
    pub state: AtomicU8,
    /// Time entered current state
    pub state_since: AtomicU64,
    /// Fires count
    pub fires: AtomicU64,
    /// Last fire time
    pub last_fire: AtomicU64,
    /// Labels for alert
    pub labels: [MetricLabel; MAX_LABELS],
    /// Label count
    pub label_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
}

impl AlertRule {
    pub const fn new() -> Self {
        Self {
            rule_id: AtomicU32::new(0),
            name_hash: AtomicU64::new(0),
            metric_id: AtomicU32::new(0),
            threshold: AtomicU64::new(0),
            operator: AtomicU8::new(0),
            severity: AtomicU8::new(alert_severity::WARNING),
            duration: AtomicU32::new(0),
            state: AtomicU8::new(alert_state::INACTIVE),
            state_since: AtomicU64::new(0),
            fires: AtomicU64::new(0),
            last_fire: AtomicU64::new(0),
            labels: [const { MetricLabel::new() }; MAX_LABELS],
            label_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
        }
    }

    /// Initialize rule
    pub fn init(&self, rule_id: u32, name_hash: u64, metric_id: u32, 
                threshold: u64, operator: u8, severity: u8, duration: u32) {
        self.rule_id.store(rule_id, Ordering::Release);
        self.name_hash.store(name_hash, Ordering::Release);
        self.metric_id.store(metric_id, Ordering::Release);
        self.threshold.store(threshold, Ordering::Release);
        self.operator.store(operator, Ordering::Release);
        self.severity.store(severity, Ordering::Release);
        self.duration.store(duration, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Evaluate rule
    pub fn evaluate(&self, value: u64) -> bool {
        let threshold = self.threshold.load(Ordering::Acquire);
        match self.operator.load(Ordering::Acquire) {
            0 => value < threshold,
            1 => value > threshold,
            2 => value == threshold,
            3 => value != threshold,
            _ => false,
        }
    }
}

impl Default for AlertRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Active alert
pub struct ActiveAlert {
    /// Rule ID
    pub rule_id: AtomicU32,
    /// Alert ID
    pub alert_id: AtomicU32,
    /// Start time
    pub start_time: AtomicU64,
    /// End time
    pub end_time: AtomicU64,
    /// Current value
    pub value: AtomicU64,
    /// Severity
    pub severity: AtomicU8,
    /// State
    pub state: AtomicU8,
    /// Acknowledged
    pub acknowledged: AtomicBool,
    /// Acknowledged by
    pub ack_by: AtomicU32,
    /// Active
    pub active: AtomicBool,
}

impl ActiveAlert {
    pub const fn new() -> Self {
        Self {
            rule_id: AtomicU32::new(0),
            alert_id: AtomicU32::new(0),
            start_time: AtomicU64::new(0),
            end_time: AtomicU64::new(0),
            value: AtomicU64::new(0),
            severity: AtomicU8::new(0),
            state: AtomicU8::new(alert_state::PENDING),
            acknowledged: AtomicBool::new(false),
            ack_by: AtomicU32::new(0),
            active: AtomicBool::new(false),
        }
    }
}

impl Default for ActiveAlert {
    fn default() -> Self {
        Self::new()
    }
}

/// Alerting controller
pub struct AlertingController {
    /// Alert rules
    pub rules: [AlertRule; MAX_ALERT_RULES],
    /// Rule count
    pub rule_count: AtomicU32,
    /// Active alerts
    pub alerts: [ActiveAlert; MAX_ACTIVE_ALERTS],
    /// Alert count
    pub alert_count: AtomicU32,
    /// Next alert ID
    pub next_alert_id: AtomicU32,
    /// Alerting enabled
    pub enabled: AtomicBool,
    /// Evaluation interval (ms)
    pub eval_interval: AtomicU32,
    /// Last evaluation
    pub last_eval: AtomicU64,
    /// Total alerts fired
    pub total_fired: AtomicU64,
    /// Total alerts resolved
    pub total_resolved: AtomicU64,
}

impl AlertingController {
    pub const fn new() -> Self {
        Self {
            rules: [const { AlertRule::new() }; MAX_ALERT_RULES],
            rule_count: AtomicU32::new(0),
            alerts: [const { ActiveAlert::new() }; MAX_ACTIVE_ALERTS],
            alert_count: AtomicU32::new(0),
            next_alert_id: AtomicU32::new(1),
            enabled: AtomicBool::new(true),
            eval_interval: AtomicU32::new(1000),
            last_eval: AtomicU64::new(0),
            total_fired: AtomicU64::new(0),
            total_resolved: AtomicU64::new(0),
        }
    }

    /// Add rule
    pub fn add_rule(&mut self, name_hash: u64, metric_id: u32, threshold: u64,
                    operator: u8, severity: u8, duration: u32) -> Result<u32, HvError> {
        let count = self.rule_count.load(Ordering::Acquire);
        if count as usize >= MAX_ALERT_RULES {
            return Err(HvError::LogicalFault);
        }
        
        let rule_id = count + 1;
        let rule = &self.rules[count as usize];
        rule.init(rule_id, name_hash, metric_id, threshold, operator, severity, duration);
        
        self.rule_count.fetch_add(1, Ordering::Release);
        Ok(rule_id)
    }

    /// Evaluate all rules
    pub fn evaluate_all(&mut self, metrics: &MetricsRegistry) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        let now = Self::get_timestamp();
        
        for i in 0..self.rule_count.load(Ordering::Acquire) as usize {
            let rule = &self.rules[i];
            if !rule.enabled.load(Ordering::Acquire) {
                continue;
            }
            
            let metric = match metrics.get_metric(rule.metric_id.load(Ordering::Acquire)) {
                Some(m) => m,
                None => continue,
            };
            
            let value = metric.get();
            let triggered = rule.evaluate(value);
            
            match rule.state.load(Ordering::Acquire) {
                alert_state::INACTIVE => {
                    if triggered {
                        rule.state.store(alert_state::PENDING, Ordering::Release);
                        rule.state_since.store(now, Ordering::Release);
                    }
                }
                alert_state::PENDING => {
                    let duration = rule.duration.load(Ordering::Acquire) as u64;
                    let since = rule.state_since.load(Ordering::Acquire);
                    
                    if triggered && now - since >= duration {
                        // Fire alert
                        rule.state.store(alert_state::FIRING, Ordering::Release);
                        rule.fires.fetch_add(1, Ordering::Release);
                        rule.last_fire.store(now, Ordering::Release);
                        self.fire_alert(rule, value);
                    } else if !triggered {
                        rule.state.store(alert_state::INACTIVE, Ordering::Release);
                    }
                }
                alert_state::FIRING => {
                    if !triggered {
                        // Resolve alert
                        rule.state.store(alert_state::RESOLVED, Ordering::Release);
                        self.resolve_alert(rule.rule_id.load(Ordering::Acquire));
                    }
                }
                alert_state::RESOLVED => {
                    rule.state.store(alert_state::INACTIVE, Ordering::Release);
                }
                _ => {}
            }
        }
        
        self.last_eval.store(now, Ordering::Release);
    }

    /// Fire alert
    fn fire_alert(&self, rule: &AlertRule, value: u64) {
        let count = self.alert_count.load(Ordering::Acquire);
        if count as usize >= MAX_ACTIVE_ALERTS {
            return;
        }
        
        let alert_id = self.next_alert_id.fetch_add(1, Ordering::Release);
        let alert = &self.alerts[count as usize];
        
        alert.rule_id.store(rule.rule_id.load(Ordering::Acquire), Ordering::Release);
        alert.alert_id.store(alert_id, Ordering::Release);
        alert.start_time.store(Self::get_timestamp(), Ordering::Release);
        alert.value.store(value, Ordering::Release);
        alert.severity.store(rule.severity.load(Ordering::Acquire), Ordering::Release);
        alert.state.store(alert_state::FIRING, Ordering::Release);
        alert.active.store(true, Ordering::Release);
        
        self.alert_count.fetch_add(1, Ordering::Release);
        self.total_fired.fetch_add(1, Ordering::Release);
    }

    /// Resolve alert
    fn resolve_alert(&self, rule_id: u32) {
        for i in 0..self.alert_count.load(Ordering::Acquire) as usize {
            let alert = &self.alerts[i];
            if alert.rule_id.load(Ordering::Acquire) == rule_id && 
               alert.active.load(Ordering::Acquire) {
                alert.end_time.store(Self::get_timestamp(), Ordering::Release);
                alert.state.store(alert_state::RESOLVED, Ordering::Release);
                alert.active.store(false, Ordering::Release);
                self.total_resolved.fetch_add(1, Ordering::Release);
                break;
            }
        }
    }

    /// Acknowledge alert
    pub fn acknowledge(&self, alert_id: u32, ack_by: u32) -> Result<(), HvError> {
        for i in 0..self.alert_count.load(Ordering::Acquire) as usize {
            let alert = &self.alerts[i];
            if alert.alert_id.load(Ordering::Acquire) == alert_id {
                alert.acknowledged.store(true, Ordering::Release);
                alert.ack_by.store(ack_by, Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Get statistics
    pub fn get_stats(&self) -> AlertingStats {
        AlertingStats {
            rule_count: self.rule_count.load(Ordering::Acquire),
            alert_count: self.alert_count.load(Ordering::Acquire),
            total_fired: self.total_fired.load(Ordering::Acquire),
            total_resolved: self.total_resolved.load(Ordering::Acquire),
            enabled: self.enabled.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for AlertingController {
    fn default() -> Self {
        Self::new()
    }
}

/// Alerting statistics
#[repr(C)]
pub struct AlertingStats {
    pub rule_count: u32,
    pub alert_count: u32,
    pub total_fired: u64,
    pub total_resolved: u64,
    pub enabled: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Log Aggregation
// ─────────────────────────────────────────────────────────────────────────────

/// Log levels
pub mod log_level {
    pub const TRACE: u8 = 0;
    pub const DEBUG: u8 = 1;
    pub const INFO: u8 = 2;
    pub const WARN: u8 = 3;
    pub const ERROR: u8 = 4;
    pub const FATAL: u8 = 5;
}

/// Log sources
pub mod log_source {
    pub const HYPERVISOR: u8 = 0;
    pub const VM: u8 = 1;
    pub const VCPU: u8 = 2;
    pub const DEVICE: u8 = 3;
    pub const MEMORY: u8 = 4;
    pub const NETWORK: u8 = 5;
    pub const STORAGE: u8 = 6;
    pub const SECURITY: u8 = 7;
}

/// Maximum log entries
pub const MAX_LOG_ENTRIES: usize = 16384;
/// Log entry max message length
pub const MAX_LOG_MSG_LEN: usize = 256;

/// Log entry
pub struct LogEntry {
    /// Timestamp
    pub timestamp: AtomicU64,
    /// Log level
    pub level: AtomicU8,
    /// Source
    pub source: AtomicU8,
    /// VM ID
    pub vm_id: AtomicU32,
    /// VCPU ID
    pub vcpu_id: AtomicU16,
    /// Message (hashed or first 8 bytes)
    pub msg_hash: AtomicU64,
    /// Sequence number
    pub seq: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl LogEntry {
    pub const fn new() -> Self {
        Self {
            timestamp: AtomicU64::new(0),
            level: AtomicU8::new(log_level::INFO),
            source: AtomicU8::new(0),
            vm_id: AtomicU32::new(0),
            vcpu_id: AtomicU16::new(0),
            msg_hash: AtomicU64::new(0),
            seq: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }
}

impl Default for LogEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Log aggregation controller
pub struct LogAggregator {
    /// Log entries (ring buffer)
    pub entries: [LogEntry; MAX_LOG_ENTRIES],
    /// Write index
    pub write_idx: AtomicU32,
    /// Read index
    pub read_idx: AtomicU32,
    /// Total logs written
    pub total_written: AtomicU64,
    /// Total logs read
    pub total_read: AtomicU64,
    /// Logs dropped (buffer full)
    pub logs_dropped: AtomicU64,
    /// Minimum log level
    pub min_level: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Filter by VM ID (0 = all)
    pub filter_vm: AtomicU32,
    /// Filter by source (0xFF = all)
    pub filter_source: AtomicU8,
    /// Sequence counter
    pub seq_counter: AtomicU64,
}

impl LogAggregator {
    pub const fn new() -> Self {
        Self {
            entries: [const { LogEntry::new() }; MAX_LOG_ENTRIES],
            write_idx: AtomicU32::new(0),
            read_idx: AtomicU32::new(0),
            total_written: AtomicU64::new(0),
            total_read: AtomicU64::new(0),
            logs_dropped: AtomicU64::new(0),
            min_level: AtomicU8::new(log_level::INFO),
            enabled: AtomicBool::new(true),
            filter_vm: AtomicU32::new(0),
            filter_source: AtomicU8::new(0xFF),
            seq_counter: AtomicU64::new(0),
        }
    }

    /// Write log entry
    pub fn write(&self, level: u8, source: u8, vm_id: u32, vcpu_id: u16, msg_hash: u64) -> Result<(), HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(());
        }
        
        // Check level filter
        if level < self.min_level.load(Ordering::Acquire) {
            return Ok(());
        }
        
        // Check VM filter
        let filter_vm = self.filter_vm.load(Ordering::Acquire);
        if filter_vm != 0 && vm_id != filter_vm {
            return Ok(());
        }
        
        // Check source filter
        let filter_src = self.filter_source.load(Ordering::Acquire);
        if filter_src != 0xFF && source != filter_src {
            return Ok(());
        }
        
        let idx = self.write_idx.fetch_add(1, Ordering::Release) as usize;
        let entry = &self.entries[idx % MAX_LOG_ENTRIES];
        
        entry.timestamp.store(Self::get_timestamp(), Ordering::Release);
        entry.level.store(level, Ordering::Release);
        entry.source.store(source, Ordering::Release);
        entry.vm_id.store(vm_id, Ordering::Release);
        entry.vcpu_id.store(vcpu_id, Ordering::Release);
        entry.msg_hash.store(msg_hash, Ordering::Release);
        entry.seq.store(self.seq_counter.fetch_add(1, Ordering::Release), Ordering::Release);
        entry.valid.store(true, Ordering::Release);
        
        self.total_written.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Read log entry
    pub fn read(&self) -> Option<&LogEntry> {
        let read = self.read_idx.load(Ordering::Acquire);
        let write = self.write_idx.load(Ordering::Acquire);
        
        if read >= write {
            return None;
        }
        
        let entry = &self.entries[(read % MAX_LOG_ENTRIES as u32) as usize];
        self.read_idx.fetch_add(1, Ordering::Release);
        self.total_read.fetch_add(1, Ordering::Release);
        
        Some(entry)
    }

    /// Read batch
    pub fn read_batch(&self, count: u32) -> u32 {
        let mut read = 0u32;
        for _ in 0..count {
            if self.read().is_some() {
                read += 1;
            } else {
                break;
            }
        }
        read
    }

    /// Clear logs
    pub fn clear(&mut self) {
        self.write_idx.store(0, Ordering::Release);
        self.read_idx.store(0, Ordering::Release);
        self.seq_counter.store(0, Ordering::Release);
        
        for entry in &self.entries {
            entry.valid.store(false, Ordering::Release);
        }
    }

    /// Set filters
    pub fn set_filters(&self, min_level: u8, vm_id: u32, source: u8) {
        self.min_level.store(min_level, Ordering::Release);
        self.filter_vm.store(vm_id, Ordering::Release);
        self.filter_source.store(source, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> LogStats {
        LogStats {
            total_written: self.total_written.load(Ordering::Acquire),
            total_read: self.total_read.load(Ordering::Acquire),
            logs_dropped: self.logs_dropped.load(Ordering::Acquire),
            buffer_used: (self.write_idx.load(Ordering::Acquire) - self.read_idx.load(Ordering::Acquire)) as usize,
            enabled: self.enabled.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for LogAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Log statistics
#[repr(C)]
pub struct LogStats {
    pub total_written: u64,
    pub total_read: u64,
    pub logs_dropped: u64,
    pub buffer_used: usize,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_register() {
        let mut registry = MetricsRegistry::new();
        let id = registry.register(0x12345678, metric_type::COUNTER, metric_cat::CPU).unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn counter_increment() {
        let mut registry = MetricsRegistry::new();
        let id = registry.register(0x12345678, metric_type::COUNTER, metric_cat::CPU).unwrap();
        
        registry.counter_inc(id, 10).unwrap();
        assert_eq!(registry.get_metric(id).unwrap().get(), 10);
    }

    #[test]
    fn gauge_set() {
        let mut registry = MetricsRegistry::new();
        let id = registry.register(0x12345678, metric_type::GAUGE, metric_cat::MEMORY).unwrap();
        
        registry.gauge_set(id, 1024).unwrap();
        assert_eq!(registry.get_metric(id).unwrap().get(), 1024);
    }

    #[test]
    fn alert_rule() {
        let mut alerts = AlertingController::new();
        let rule_id = alerts.add_rule(0x12345678, 1, 100, 1, alert_severity::WARNING, 1000).unwrap();
        assert_eq!(rule_id, 1);
    }

    #[test]
    fn log_write() {
        let logs = LogAggregator::new();
        logs.write(log_level::INFO, log_source::HYPERVISOR, 1, 0, 0x12345678).unwrap();
        
        let entry = logs.read().unwrap();
        assert_eq!(entry.level.load(Ordering::Acquire), log_level::INFO);
    }
}
