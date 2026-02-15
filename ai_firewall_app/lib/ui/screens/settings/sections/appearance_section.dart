import 'package:flutter/material.dart';
import '../../../../main.dart';
import '../../../../theme/app_theme.dart';
import '../widgets/settings_section_header.dart';
import '../widgets/settings_tile.dart';

class AppearanceSection extends StatelessWidget {
  const AppearanceSection({super.key});

  @override
  Widget build(BuildContext context) {
    // ✅ SYNCED: Fetching theme state from AppState
    final appState = AppStateScope.of(context);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SettingsSectionHeader(title: "INTERFACE CONFIGURATION"),
        const SizedBox(height: 10),

        SettingsTile(
          icon: Icons.dark_mode_rounded,
          title: "Dark Mode",
          subtitle: "Optimized for OLED & low-light usage",
          trailing: Switch.adaptive(
            value: isDark,
            onChanged: (val) => appState.toggleTheme(!val), // Fixed to toggle
            activeColor: AppColors.accent,
          ),
        ),
      ],
    );
  }
}