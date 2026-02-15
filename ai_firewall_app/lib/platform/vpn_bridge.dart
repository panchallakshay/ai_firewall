import 'package:flutter/services.dart';
import 'dart:async';

/**
 * VpnBridge - The Dart side of the ShaktiX Tunnel.
 * Connects Flutter UI directly to Kotlin MainActivity.
 */
class VpnBridge {
  // ✅ EXACT MATCH with MainActivity.kt (Zero-Galti Sync)
  static const MethodChannel _channel = MethodChannel('com.aifirewall/vpn');
  static const EventChannel _eventChannel = EventChannel('com.aifirewall/events');

  /// Starts the VPN. If permission is missing, Android will show the system dialog.
  static Future<bool> startVpn() async {
    try {
      final bool result = await _channel.invokeMethod('startVpn');
      return result;
    } on PlatformException catch (e) {
      print("SHAKTIX_ERROR: Failed to start VPN: ${e.message}");
      return false;
    }
  }

  /// Stops the VPN immediately.
  static Future<bool> stopVpn() async {
    try {
      final bool result = await _channel.invokeMethod('stopVpn');
      return result;
    } on PlatformException catch (e) {
      print("SHAKTIX_ERROR: Failed to stop VPN: ${e.message}");
      return false;
    }
  }

  /// Checks if Android VPN permission is already granted.
  static Future<bool> checkPermission() async {
    try {
      final bool hasPermission = await _channel.invokeMethod('checkPermission');
      return hasPermission;
    } catch (e) {
      return false;
    }
  }

  /// ✅ REAL-TIME ENGINE STREAM
  /// This listens to ACT:BLOCK and ACT:ALLOW events from Kotlin.
  static Stream<String> get eventStream {
    return _eventChannel.receiveBroadcastStream().map((event) => event as String);
  }

  /// Updates AI Policy (Strict/Balanced)
  static Future<void> setPolicy(String mode) async {
    await _channel.invokeMethod('setPolicyMode', {'mode': mode});
  }
}