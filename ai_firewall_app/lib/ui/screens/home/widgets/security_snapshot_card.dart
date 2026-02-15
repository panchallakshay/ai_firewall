import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import '../../../../main.dart';
import '../../../../theme/app_theme.dart';

class SecuritySnapshotCard extends StatelessWidget {
  const SecuritySnapshotCard({super.key});

  @override
  Widget build(BuildContext context) {
    final appState = AppStateScope.of(context);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;

    // Use simulated risk when VPN is active
    final double currentRisk = appState.vpnEnabled ? appState.fakeRisk : 0.0;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: bg2,
        borderRadius: AppRadii.r20,
        border: Border.all(color: stroke),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.spaceBetween, // For perfect vertical spacing
        children: [
          Text("RISK RATIO", style: AppTextStyles.caption.copyWith(fontWeight: FontWeight.bold, letterSpacing: 1.2)),
          const SizedBox(height: 12),
          SizedBox(
            height: 90, // Fixed height to match Activity Trend
            child: Stack(
              alignment: Alignment.center,
              children: [
                PieChart(
                  PieChartData(
                    sectionsSpace: 2,
                    centerSpaceRadius: 28,
                    sections: [
                      PieChartSectionData(
                          value: currentRisk,
                          color: AppColors.danger,
                          radius: 10,
                          showTitle: false
                      ),
                      PieChartSectionData(
                          value: 100 - currentRisk,
                          color: currentRisk == 0 ? Colors.white10 : AppColors.safe,
                          radius: 10,
                          showTitle: false
                      ),
                    ],
                  ),
                ),
                Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text("${currentRisk.toInt()}%", style: AppTextStyles.h2.copyWith(fontSize: 16, color: text0)),
                    Text("RISK", style: AppTextStyles.caption.copyWith(fontSize: 8)),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          _Legend(label: "Blocked", color: AppColors.danger),
          _Legend(label: "Allowed", color: AppColors.safe),
        ],
      ),
    );
  }
}

class _Legend extends StatelessWidget {
  final String label;
  final Color color;
  const _Legend({required this.label, required this.color});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(width: 6, height: 6, decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
        const SizedBox(width: 8),
        Text(label, style: AppTextStyles.caption.copyWith(fontSize: 10)),
      ],
    );
  }
}