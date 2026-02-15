import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// FirewallService - Flutter service for VPN control
/// 
/// Communicates with Android VPN service via method channel
class FirewallService {
  static const platform = MethodChannel('com.aifirewall/vpn');
  
  /// Start VPN service
  /// Returns map with success status and message
  Future<Map<String, dynamic>> startVpn() async {
    try {
      final result = await platform.invokeMethod('startVpn');
      return Map<String, dynamic>.from(result);
    } on PlatformException catch (e) {
      print('Error starting VPN: ${e.message}');
      return {
        'success': false,
        'needsPermission': false,
        'message': 'Error: ${e.message}'
      };
    }
  }
  
  /// Stop VPN service
  /// Returns map with success status and message
  Future<Map<String, dynamic>> stopVpn() async {
    try {
      final result = await platform.invokeMethod('stopVpn');
      return Map<String, dynamic>.from(result);
    } on PlatformException catch (e) {
      print('Error stopping VPN: ${e.message}');
      return {
        'success': false,
        'message': 'Error: ${e.message}'
      };
    }
  }
  
  /// Check if VPN permission is granted
  /// Returns map with granted status
  Future<bool> checkPermission() async {
    try {
      final result = await platform.invokeMethod('checkPermission');
      return result['granted'] ?? false;
    } on PlatformException catch (e) {
      print('Error checking permission: ${e.message}');
      return false;
    }
  }
  
  /// Get firewall statistics
  /// Returns map with packet counts and threat stats
  Future<Map<String, dynamic>> getStats() async {
    try {
      final result = await platform.invokeMethod('getStats');
      return Map<String, dynamic>.from(result);
    } on PlatformException catch (e) {
      print('Error getting stats: ${e.message}');
      return {
        'packetsProcessed': 0,
        'packetsAllowed': 0,
        'packetsBlocked': 0,
        'threatsBlocked': 0
      };
    }
  }
  
  /// Set policy mode (STRICT, BALANCED, PERMISSIVE)
  Future<bool> setPolicyMode(String mode) async {
    try {
      final result = await platform.invokeMethod('setPolicyMode', {
        'mode': mode
      });
      return result['success'] ?? false;
    } on PlatformException catch (e) {
      print('Error setting policy mode: ${e.message}');
      return false;
    }
  }
  
  /// Reset strikes for a flow (user override)
  Future<bool> resetStrikes(String flowKey) async {
    try {
      final result = await platform.invokeMethod('resetStrikes', {
        'flowKey': flowKey
      });
      return result['success'] ?? false;
    } on PlatformException catch (e) {
      print('Error resetting strikes: ${e.message}');
      return false;
    }
  }
}

/// Example usage in a Flutter widget
class FirewallControlWidget extends StatefulWidget {
  @override
  _FirewallControlWidgetState createState() => _FirewallControlWidgetState();
}

class _FirewallControlWidgetState extends State<FirewallControlWidget> {
  final FirewallService _firewallService = FirewallService();
  bool _isVpnActive = false;
  bool _isLoading = false;
  Map<String, dynamic> _stats = {};
  
  @override
  void initState() {
    super.initState();
    _loadStats();
  }
  
  Future<void> _loadStats() async {
    final stats = await _firewallService.getStats();
    setState(() {
      _stats = stats;
    });
  }
  
  Future<void> _toggleVpn() async {
    setState(() {
      _isLoading = true;
    });
    
    try {
      if (_isVpnActive) {
        // Stop VPN
        final result = await _firewallService.stopVpn();
        if (result['success']) {
          setState(() {
            _isVpnActive = false;
          });
          _showSnackBar('Firewall stopped');
        } else {
          _showSnackBar('Failed to stop firewall: ${result['message']}');
        }
      } else {
        // Start VPN
        final result = await _firewallService.startVpn();
        if (result['success']) {
          setState(() {
            _isVpnActive = true;
          });
          _showSnackBar('Firewall started');
        } else if (result['needsPermission']) {
          _showSnackBar('VPN permission required');
        } else {
          _showSnackBar('Failed to start firewall: ${result['message']}');
        }
      }
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }
  
  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message))
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('AI Firewall'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // VPN Status
            Icon(
              _isVpnActive ? Icons.shield : Icons.shield_outlined,
              size: 100,
              color: _isVpnActive ? Colors.green : Colors.grey,
            ),
            SizedBox(height: 20),
            Text(
              _isVpnActive ? 'Protected' : 'Not Protected',
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 40),
            
            // Toggle Button
            ElevatedButton(
              onPressed: _isLoading ? null : _toggleVpn,
              child: _isLoading
                  ? CircularProgressIndicator()
                  : Text(_isVpnActive ? 'Stop Firewall' : 'Start Firewall'),
              style: ElevatedButton.styleFrom(
                padding: EdgeInsets.symmetric(horizontal: 40, vertical: 15),
              ),
            ),
            
            SizedBox(height: 40),
            
            // Statistics
            if (_stats.isNotEmpty) ...[
              Text('Statistics', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              SizedBox(height: 10),
              Text('Packets Processed: ${_stats['packetsProcessed']}'),
              Text('Packets Allowed: ${_stats['packetsAllowed']}'),
              Text('Packets Blocked: ${_stats['packetsBlocked']}'),
              Text('Threats Blocked: ${_stats['threatsBlocked']}'),
            ],
          ],
        ),
      ),
    );
  }
}
