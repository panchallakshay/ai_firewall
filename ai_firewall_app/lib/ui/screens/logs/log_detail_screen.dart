import 'package:flutter/material.dart';
import '../../../theme/app_theme.dart';
import 'models/log_event.dart';

class LogDetailScreen extends StatelessWidget {
  final LogEvent event;
  const LogDetailScreen({super.key, required this.event});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final accent = event.actionColor;

    return Scaffold(
      backgroundColor: isDark ? AppColors.dBg1 : AppColors.lBg1,
      appBar: AppBar(title: const Text("DEEP FORENSICS")),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 🛡️ Risk Header
            _buildRiskHeader(accent, text0),
            const SizedBox(height: 32),

            // 🧠 26-Parameter AI Grid
            Text("AI ENGINE PARAMETERS (LAKSHAY'S MODEL)",
                style: AppTextStyles.caption.copyWith(fontWeight: FontWeight.bold, color: AppColors.accent)),
            const Divider(color: Colors.white10),
            const SizedBox(height: 16),
            _buildFeatureGrid(bg2, text0),

            const SizedBox(height: 32),
            Text("TRAFFIC METADATA", style: AppTextStyles.caption.copyWith(fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            _buildForensicsCard(bg2, text0),
          ],
        ),
      ),
    );
  }

  Widget _buildRiskHeader(Color color, Color text0) {
    return Center(
      child: Column(
        children: [
          Stack(
            alignment: Alignment.center,
            children: [
              SizedBox(width: 120, height: 120, child: CircularProgressIndicator(
                  value: event.confidence, strokeWidth: 10, color: color, backgroundColor: Colors.white10)),
              Text("${(event.confidence * 100).toInt()}%", style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold, color: text0)),
            ],
          ),
          const SizedBox(height: 16),
          Text(event.destination, style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: text0)),
          Text(event.reasonShort, style: TextStyle(color: color, fontWeight: FontWeight.w600)),
        ],
      ),
    );
  }

  Widget _buildFeatureGrid(Color bg, Color text0) {
    // Simulated grid for AI features
    final features = [
      {"k": "Entropy", "v": event.aiFeatures['entropy'] ?? "3.27"},
      {"k": "IAT Delay", "v": "0.04ms"},
      {"k": "TLD Risk", "v": event.aiFeatures['tld_risk'] ?? "Normal"},
      {"k": "Payload Size", "v": "${event.bytesUp + event.bytesDown}b"},
    ];

    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: 2, crossAxisSpacing: 12, mainAxisSpacing: 12, childAspectRatio: 2.8),
      itemCount: features.length,
      itemBuilder: (context, i) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(color: bg, borderRadius: AppRadii.r12, border: Border.all(color: Colors.white10)),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(features[i]['k']!, style: AppTextStyles.caption.copyWith(fontSize: 10)),
            Text(features[i]['v']!, style: TextStyle(color: text0, fontWeight: FontWeight.bold)),
          ],
        ),
      ),
    );
  }

  Widget _buildForensicsCard(Color bg, Color text0) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: bg, borderRadius: AppRadii.r16, border: Border.all(color: Colors.white10)),
      child: Column(
        children: [
          _infoRow("Protocol", event.protocol, text0),
          const Divider(height: 24, color: Colors.white10),
          _infoRow("Destination Port", event.port.toString(), text0),
          const Divider(height: 24, color: Colors.white10),
          _infoRow("Timestamp", "${event.ts.hour}:${event.ts.minute}:${event.ts.second}", text0),
        ],
      ),
    );
  }

  Widget _infoRow(String l, String v, Color t0) => Row(
    mainAxisAlignment: MainAxisAlignment.spaceBetween,
    children: [Text(l, style: AppTextStyles.body), Text(v, style: TextStyle(fontWeight: FontWeight.bold, color: t0))],
  );
}