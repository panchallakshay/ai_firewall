import 'package:flutter/material.dart';
import '../../../main.dart';
import '../../state/app_state.dart';
import '../../theme/app_theme.dart';

import 'home/widgets/vpn_status_card.dart';
import 'home/widgets/security_snapshot_card.dart';
import 'home/widgets/recent_activity_card.dart';
import 'home/widgets/quick_scan_card.dart';
import 'home/widgets/data_usage_card.dart';
import 'home/widgets/live_dashboard_card.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // ✅ Custom Provider call to avoid 'of' null errors
    final appState = AppStateScope.of(context);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: isDark ? AppColors.dBg1 : AppColors.lBg1,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Row(
          children: [
            const Icon(Icons.shield_rounded, color: AppColors.accent, size: 28),
            const SizedBox(width: 12),
            Text("SHAKTIX AI", style: AppTextStyles.h2.copyWith(letterSpacing: 2)),
          ],
        ),
      ),
      body: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        physics: const BouncingScrollPhysics(),
        children: [
          // 🛡️ Heart of the App (VPN Switch)
          VpnStatusCard(
            vpnEnabled: appState.vpnEnabled,
            onToggleVpn: (val) => appState.toggleVpn(),
            blockedConnections: appState.blockedCount,
            datasetStatus: appState.datasetStatus,
          ),
          const SizedBox(height: 20),

          // 📡 Live Telemetry
          const LiveDashboardCard(),
          const SizedBox(height: 20),

          // 📊 AI Logic Snapshot (FIXED ALIGNMENT)
          IntrinsicHeight(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch, // Boxes ko barabar khinchega
              children: const [
                Expanded(child: SecuritySnapshotCard()),
                SizedBox(width: 12),
                Expanded(child: DataUsageCard()),
              ],
            ),
          ),
          const SizedBox(height: 20),

          // 🔍 Quick Health Check
          QuickScanCard(
            isScanning: appState.isQuickScanning,
            onScan: () => appState.runQuickScan(),
          ),
          const SizedBox(height: 20),

          // 📝 Real-time Logs Feed (Dashboard Preview)
          const RecentActivityCard(),
          const SizedBox(height: 30),
        ],
      ),
    );
  }
}