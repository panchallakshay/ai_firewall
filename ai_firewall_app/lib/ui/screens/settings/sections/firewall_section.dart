import 'package:flutter/material.dart';
import '../../../../main.dart';
import '../../../../theme/app_theme.dart';
import '../widgets/settings_section_header.dart';
import '../widgets/settings_tile.dart';

class FirewallSection extends StatelessWidget {
  const FirewallSection({super.key});

  @override
  Widget build(BuildContext context) {
    final appState = AppStateScope.of(context); //

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SettingsSectionHeader(title: "FIREWALL BEHAVIOR"),
        const SizedBox(height: 10),

        // ✅ AI Rule Engine Toggle
        SettingsTile(
          icon: Icons.auto_awesome_rounded,
          title: "AI Rule Engine",
          subtitle: "Auto-block based on 26 parameters",
          trailing: Switch.adaptive(
            value: appState.vpnEnabled, // Linked to engine state
            onChanged: (val) => appState.toggleVpn(),
            activeColor: AppColors.accent,
          ),
        ),
        const SizedBox(height: 8),

        // ✅ Anomaly Detection Toggle
        SettingsTile(
          icon: Icons.analytics_rounded,
          title: "Anomaly Detection",
          subtitle: "Detect unusual traffic spikes & DDoS",
          trailing: Switch.adaptive(
            value: true, // Placeholder for specific feature toggle
            onChanged: (val) {},
            activeColor: AppColors.accent,
          ),
        ),
        const SizedBox(height: 8),

        // ✅ Policy Mode Selector
        SettingsTile(
          icon: Icons.gavel_rounded,
          title: "Protection Level",
          subtitle: "Currently set to Balanced Mode",
          onTap: () {
            // Future logic for Strict vs Balanced
          },
          trailing: const Icon(Icons.chevron_right_rounded),
        ),
      ],
    );
  }
}