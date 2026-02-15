import 'package:flutter/material.dart';
import '../widgets/settings_section_header.dart';
import '../widgets/settings_tile.dart';
import '../../../../theme/app_theme.dart';

class AboutSection extends StatelessWidget {
  const AboutSection({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SettingsSectionHeader(title: "ABOUT SHAKTIX"),
        const SizedBox(height: 10),

        // ✅ Version Info
        SettingsTile(
          icon: Icons.info_outline_rounded,
          title: "Version",
          subtitle: "v1.0.2-stable (Panipat Build)",
          trailing: Text("UP TO DATE",
              style: TextStyle(color: AppColors.safe, fontSize: 10, fontWeight: FontWeight.bold)),
        ),
        const SizedBox(height: 8),

        // ✅ Team Info
        const SettingsTile(
          icon: Icons.groups_rounded,
          title: "Developers",
          subtitle: "TEAM COMBINERS",
        ),
        const SizedBox(height: 8),

        // ✅ Open Source
        SettingsTile(
          icon: Icons.code_rounded,
          title: "Open Source Licenses",
          subtitle: "Legal & Third-party notices",
          onTap: () => showLicensePage(context: context),
          trailing: const Icon(Icons.chevron_right_rounded),
        ),
      ],
    );
  }
}