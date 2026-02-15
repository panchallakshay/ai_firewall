class AppNetworkModel {
  final String appName;
  final String package;
  final bool blocked;
  final int bytesUp;
  final int bytesDown;
  final int connections;
  final List<String> destinations;
  final List<int> ports;
  final bool suspicious;
  final bool isSystem; // ✅ For better filtering

  const AppNetworkModel({
    required this.appName,
    required this.package,
    required this.blocked,
    required this.bytesUp,
    required this.bytesDown,
    required this.connections,
    required this.destinations,
    required this.ports,
    required this.suspicious,
    this.isSystem = false,
  });
}