import 'package:flutter/services.dart';
import 'dart:async';

/**
 * FirewallEvents - Kotlin (Native) aur Flutter (UI) ka bridge.
 * Ye file Kotlin ke 'LogBus' se aane waale signals ko listen karti hai.
 */
class FirewallEvents {
  // ✅ Dashboard Sync Channel
  static const EventChannel _eventChannel = EventChannel('com.aifirewall/events');

  // Singleton stream taaki poori app mein ek hi connection rahe
  static Stream<String>? _broadcastStream;

  static Stream<String> stream() {
    _broadcastStream ??= _eventChannel
        .receiveBroadcastStream()
        .map((event) => event as String)
        .handleError((error) {
      // Error logging agar stream break ho jaye
      print("Firewall Stream Error: $error");
    });
    return _broadcastStream!;
  }
}