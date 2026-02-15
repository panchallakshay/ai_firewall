import 'package:flutter/material.dart';

enum LogAction { ALLOWED, BLOCKED, WARNED }
enum LogSeverity { LOW, MEDIUM, HIGH, CRITICAL }

class LogEvent {
  final String id;
  final DateTime ts;
  final String destination;
  final LogAction action;
  final LogSeverity severity;
  final double confidence;
  final String reasonShort;
  final String reasonLong;
  final String appName;
  final String protocol;
  final int port;
  final int bytesUp;
  final int bytesDown;

  // ✅ 26 AI Parameters representation for UI
  final Map<String, dynamic> aiFeatures;

  LogEvent({
    required this.id, required this.ts, required this.destination,
    required this.action, required this.severity, required this.confidence,
    required this.reasonShort, required this.reasonLong,
    this.appName = "System", this.protocol = "TCP", this.port = 443,
    this.bytesUp = 0, this.bytesDown = 0,
    required this.aiFeatures,
  });

  /**
   * ✅ PRODUCTION PARSER: Kotlin ke advanced LogBus format ko decode karta hai.
   * Format: ACT:BLOCK|dst=example.com|conf=0.94|reason=AI Threat|proto=6|port=443|bytes=1024
   */
  factory LogEvent.fromNativeMessage(String msg) {
    final now = DateTime.now();
    String dest = "unknown";
    double conf = 0.0;
    String reason = "AI Analysis";
    String proto = "TCP";
    int dPort = 443;
    LogAction act = LogAction.ALLOWED;

    if (msg.startsWith("ACT:")) {
      final parts = msg.substring(4).split('|');
      final actStr = parts[0];

      for (var p in parts) {
        if (p.startsWith("dst=")) dest = p.substring(4);
        if (p.startsWith("conf=")) conf = double.tryParse(p.substring(5)) ?? 0.0;
        if (p.startsWith("reason=")) reason = p.substring(7);
        if (p.startsWith("proto=")) proto = (p.substring(6) == "17") ? "UDP" : "TCP";
        if (p.startsWith("port=")) dPort = int.tryParse(p.substring(5)) ?? 443;
      }

      if (actStr.contains("BLOCK")) act = LogAction.BLOCKED;
      else if (actStr.contains("WARN")) act = LogAction.WARNED;
    }

    return LogEvent(
      id: "${now.millisecondsSinceEpoch}",
      ts: now,
      destination: dest,
      action: act,
      confidence: conf,
      reasonShort: reason,
      protocol: proto,
      port: dPort,
      severity: conf > 0.7 ? LogSeverity.CRITICAL : (conf > 0.4 ? LogSeverity.HIGH : LogSeverity.LOW),
      reasonLong: "Traffic to $dest was ${act.name} by AI Shield with ${(conf * 100).toInt()}% threat probability.",
      aiFeatures: {
        "entropy": "3.27", // Placeholder for actual 26 features if passed in msg
        "tld_risk": conf > 0.5 ? "HIGH" : "LOW",
      },
    );
  }

  Color get actionColor => action == LogAction.BLOCKED ? Colors.redAccent : Colors.greenAccent;
}