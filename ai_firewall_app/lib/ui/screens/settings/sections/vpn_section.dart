import 'package:flutter/material.dart';
import '../../../../main.dart';
import '../../../../theme/app_theme.dart';
import '../widgets/settings_section_header.dart';
import '../widgets/settings_tile.dart';

class VpnSection extends StatelessWidget {
  const VpnSection({super.key});

  @override
  Widget build(BuildContext context) {
    // ✅ SYNCED: Real-time AppState listening
    final appState = AppStateScope.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SettingsSectionHeader(title: "VPN & CONNECTIVITY"),
        const SizedBox(height: 10),

        // ✅ Main Kill Switch
        SettingsTile(
          icon: Icons.shield_rounded,
          title: "AI Tunneling",
          subtitle: "Routes flows through local AI inspector",
          trailing: Switch.adaptive(
            value: appState.vpnEnabled,
            onChanged: (val) => appState.toggleVpn(), // Linked to Native Bridge
            activeColor: AppColors.accent,
          ),
        ),
        const SizedBox(height: 8),

        // ✅ System Permission Check
        SettingsTile(
          icon: Icons.security_update_good_rounded,
          title: "VPN Profile Status",
          subtitle: appState.vpnEnabled ? "Configuration Active" : "Requires Activation",
          onTap: () {
            if (!appState.vpnEnabled) appState.toggleVpn();
          },
          trailing: Icon(
            appState.vpnEnabled ? Icons.check_circle_rounded : Icons.chevron_right_rounded,
            color: appState.vpnEnabled ? AppColors.safe : Colors.grey,
          ),
        ),
      ],
    );
  }
}