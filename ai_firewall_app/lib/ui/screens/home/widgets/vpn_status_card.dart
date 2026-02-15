import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../../../components/glow_container.dart';

class VpnStatusCard extends StatelessWidget {
  final bool vpnEnabled;
  final ValueChanged<bool> onToggleVpn;
  final int blockedConnections;
  final String datasetStatus;

  const VpnStatusCard({
    super.key,
    required this.vpnEnabled,
    required this.onToggleVpn,
    required this.blockedConnections,
    required this.datasetStatus,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final statusColor = vpnEnabled ? AppColors.safe : AppColors.danger;

    return GlowContainer(
      glow: vpnEnabled,
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: bg2,
          borderRadius: AppRadii.r20,
          border: Border.all(
            color: vpnEnabled ? AppColors.accent : Colors.white10,
            width: vpnEnabled ? 2 : 1,
          ),
        ),
        child: Column(
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text("SYSTEM SECURITY", style: TextStyle(fontSize: 10, color: Colors.grey)),
                    const SizedBox(height: 4),
                    Text(
                      vpnEnabled ? "ACTIVE PROTECTION" : "SHIELD DEACTIVATED",
                      style: AppTextStyles.h2.copyWith(color: statusColor, fontSize: 18),
                    ),
                  ],
                ),
                Switch.adaptive(
                  value: vpnEnabled,
                  onChanged: onToggleVpn,
                  activeColor: AppColors.accent,
                ),
              ],
            ),
            const Divider(height: 40, color: Colors.white10),
            Row(
              children: [
                _buildStat("BLOCKED", blockedConnections.toString(), AppColors.danger),
                const Spacer(),
                _buildStat("STABILITY", vpnEnabled ? "HIGH" : "N/A", AppColors.accent),
                const Spacer(),
                _buildStat("ENGINE", datasetStatus.toUpperCase(), AppColors.safe),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStat(String label, String value, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(fontSize: 9, color: Colors.grey)),
        const SizedBox(height: 4),
        Text(value, style: AppTextStyles.h2.copyWith(color: color, fontSize: 16)),
      ],
    );
  }
}