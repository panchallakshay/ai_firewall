import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../../../components/glow_container.dart';

class LiveDashboardCard extends StatelessWidget {
  const LiveDashboardCard({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return GlowContainer(
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: isDark ? AppColors.dBg2 : AppColors.lBg2,
          borderRadius: AppRadii.r20,
          border: Border.all(color: isDark ? AppColors.dStroke : AppColors.lStroke),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text("LIVE TELEMETRY", style: AppTextStyles.caption.copyWith(fontWeight: FontWeight.bold)),
                const Icon(Icons.bolt, color: AppColors.accent, size: 16),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                _metricTile("LATENCY", "12ms", AppColors.safe),
                _metricTile("LOAD", "14%", AppColors.accent),
                _metricTile("PPS", "42", AppColors.warn),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _metricTile(String label, String val, Color color) {
    return Column(
      children: [
        Text(val, style: TextStyle(color: color, fontWeight: FontWeight.bold, fontSize: 18)),
        Text(label, style: const TextStyle(fontSize: 9, color: Colors.grey)),
      ],
    );
  }
}