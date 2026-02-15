import 'package:flutter/material.dart';
import '../../../theme/app_theme.dart';
import 'models/app_network_model.dart';
import 'widgets/app_stat_tile.dart';
import 'widgets/destination_tile.dart';
import 'widgets/app_action_bar.dart';

class AppDetailScreen extends StatelessWidget {
  final AppNetworkModel app;
  const AppDetailScreen({super.key, required this.app});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;

    return Scaffold(
      backgroundColor: isDark ? AppColors.dBg1 : AppColors.lBg1,
      appBar: AppBar(
        title: Text("APP FORENSICS", style: AppTextStyles.h2.copyWith(color: text0)),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        physics: const BouncingScrollPhysics(),
        children: [
          // 🛡️ Header with Block/Allow Button
          AppActionBar(app: app),
          const SizedBox(height: 24),

          // 📊 Traffic Statistics
          Text("TRAFFIC METRICS", style: AppTextStyles.caption.copyWith(fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(child: AppStatTile(label: "UPLOADED", value: "${(app.bytesUp / 1e6).toStringAsFixed(1)} MB")),
              const SizedBox(width: 12),
              Expanded(child: AppStatTile(label: "DOWNLOADED", value: "${(app.bytesDown / 1e6).toStringAsFixed(1)} MB")),
            ],
          ),
          const SizedBox(height: 12),
          AppStatTile(label: "ACTIVE CONNECTIONS", value: app.connections.toString()),

          const SizedBox(height: 32),

          // 🌐 Network Destinations
          Text("TARGET DESTINATIONS", style: AppTextStyles.section.copyWith(fontSize: 14)),
          const Divider(color: Colors.white10),
          const SizedBox(height: 8),
          ...app.destinations.map((d) => DestinationTile(dest: d)),

          const SizedBox(height: 32),

          // 🔌 Exposed Ports
          Text("COMMUNICATION PORTS", style: AppTextStyles.section.copyWith(fontSize: 14)),
          const Divider(color: Colors.white10),
          const SizedBox(height: 12),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: app.ports.map((p) => Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: AppColors.accent.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.accent.withOpacity(0.3)),
              ),
              child: Text(p.toString(), style: const TextStyle(fontWeight: FontWeight.bold, color: AppColors.accent)),
            )).toList(),
          ),

          const SizedBox(height: 40),
        ],
      ),
    );
  }
}