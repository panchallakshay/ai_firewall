import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import '../../../../main.dart';
import '../../../../theme/app_theme.dart';

class DataUsageCard extends StatelessWidget {
  const DataUsageCard({super.key});

  @override
  Widget build(BuildContext context) {
    // ✅ AppStateScope se connection
    final appState = AppStateScope.of(context);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final accent = AppColors.accent;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: bg2,
        borderRadius: AppRadii.r20,
        border: Border.all(color: stroke),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
              "ACTIVITY TREND",
              style: AppTextStyles.caption.copyWith(fontWeight: FontWeight.bold, letterSpacing: 1.2)
          ),
          const SizedBox(height: 8),

          // ✅ VPN Status ke hisab se dynamic text
          Text(
              appState.vpnEnabled ? "LIVE FLOWS" : "0 FLOWS",
              style: AppTextStyles.h2.copyWith(fontSize: 18, color: appState.vpnEnabled ? accent : Colors.grey)
          ),
          const SizedBox(height: 12),

          // ✅ LIVE GRAPH SECTION
          SizedBox(
            height: 90, // Fixed height to match Risk Ratio
            child: LineChart(
              LineChartData(
                gridData: const FlGridData(show: false),
                titlesData: const FlTitlesData(show: false),
                borderData: FlBorderData(show: false),
                lineBarsData: [
                  LineChartBarData(
                    // ✅ AppState ke fakeTrendData se spots generate ho rahe hain
                    spots: List.generate(
                        appState.fakeTrendData.length,
                            (i) => FlSpot(i.toDouble(), appState.fakeTrendData[i])
                    ),
                    isCurved: true,
                    curveSmoothness: 0.35,
                    barWidth: 3,
                    color: accent,
                    isStrokeCapRound: true,
                    dotData: const FlDotData(show: false),
                    // ✅ Area fill for professional look
                    belowBarData: BarAreaData(
                        show: true,
                        color: accent.withOpacity(0.1)
                    ),
                  ),
                ],
                minY: 0,
                maxY: 60, // Data spikes control karne ke liye
              ),
            ),
          ),
          const SizedBox(height: 12),

          // ✅ Packets per second dynamic update
          Text(
              "Packets/Sec: ${appState.vpnEnabled ? appState.fakeTrendData.last.toInt() : 0}",
              style: AppTextStyles.caption.copyWith(fontSize: 10)
          ),
        ],
      ),
    );
  }
}