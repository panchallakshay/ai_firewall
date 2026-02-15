import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async'; // Timer ke liye
import 'dart:math';
import '../ui/screens/logs/models/log_event.dart';

class AppState extends ChangeNotifier {
  ThemeMode _themeMode = ThemeMode.dark;
  bool _vpnEnabled = false;
  bool _isQuickScanning = false;

  List<LogEvent> _events = [];
  int _blockedCount = 0;
  int _allowedCount = 0;
  String _lastBlocked = "-";
  String _datasetStatus = "AI Core Ready";

  // ✅ Live Simulation Variables
  Timer? _simulationTimer;
  double _fakeRisk = 0.0;
  List<double> _fakeTrendData = List.generate(7, (index) => 0.0);

  // ✅ Getters
  ThemeMode get themeMode => _themeMode;
  bool get vpnEnabled => _vpnEnabled;
  bool get isQuickScanning => _isQuickScanning;
  List<LogEvent> get events => _events;
  int get blockedCount => _blockedCount;
  int get allowedCount => _allowedCount;
  String get lastBlocked => _lastBlocked;
  String get datasetStatus => _datasetStatus;
  double get fakeRisk => _fakeRisk;
  List<double> get fakeTrendData => _fakeTrendData;

  static const _methodChannel = MethodChannel('com.example.shaktix/vpn');
  static const _eventChannel = EventChannel('com.example.shaktix/logs');

  AppState() {
    _listenToNativeLogs();
  }

  void _listenToNativeLogs() {
    _eventChannel.receiveBroadcastStream().listen((dynamic message) {
      if (message is String) {
        final newEvent = LogEvent.fromNativeMessage(message);
        _processNewEvent(newEvent);
      }
    });
  }

  void _processNewEvent(LogEvent event) {
    _events.insert(0, event);
    if (event.action == LogAction.BLOCKED) {
      _blockedCount++;
      _lastBlocked = event.destination;
    } else {
      _allowedCount++;
    }
    if (_events.length > 50) _events.removeLast();
    notifyListeners();
  }

  // ✅ Updated VPN Toggle with Simulation
  Future<void> toggleVpn() async {
    try {
      final bool newState = !_vpnEnabled;
      await _methodChannel.invokeMethod(newState ? 'startVpn' : 'stopVpn');
      _vpnEnabled = newState;
      _datasetStatus = newState ? "Shield: Active" : "Shield: Idle";

      if (_vpnEnabled) {
        _startSimulation(); // Start fake live data
      } else {
        _stopSimulation(); // Stop fake live data
      }
      notifyListeners();
    } catch (e) {
      debugPrint("VPN Toggle Error: $e");
    }
  }

  void _startSimulation() {
    _simulationTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      final random = Random();
      // Fake metrics updates
      _fakeRisk = 5 + random.nextDouble() * 12; // 5% se 17% ke beech risk rahega
      _fakeTrendData.removeAt(0);
      _fakeTrendData.add(10 + random.nextDouble() * 40); // Random spikes for trend
      notifyListeners();
    });
  }

  void _stopSimulation() {
    _simulationTimer?.cancel();
    _fakeRisk = 0.0;
    _fakeTrendData = List.generate(7, (index) => 0.0);
    notifyListeners();
  }

  Future<void> runQuickScan() async {
    if (_isQuickScanning) return;
    _isQuickScanning = true;
    _datasetStatus = "Scanning 26 Parameters...";
    notifyListeners();
    await Future.delayed(const Duration(seconds: 2));
    _isQuickScanning = false;
    _datasetStatus = _vpnEnabled ? "Shield: Active" : "AI Core Ready";
    notifyListeners();
  }

  void clearLogs() {
    _events.clear();
    _blockedCount = 0;
    _allowedCount = 0;
    _lastBlocked = "-";
    notifyListeners();
  }

  void toggleTheme(bool isLight) {
    _themeMode = isLight ? ThemeMode.light : ThemeMode.dark;
    notifyListeners();
  }
}