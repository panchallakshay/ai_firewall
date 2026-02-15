import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../widgets/settings_section_header.dart';
import '../widgets/settings_tile.dart';

class PrivacySection extends StatelessWidget {
  const PrivacySection({super.key});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SettingsSectionHeader(title: "PRIVACY ASSURANCE"),
        const SizedBox(height: 10),

        const SettingsTile(
          icon: Icons.lock_person_rounded,
          title: "On-Device Processing",
          subtitle: "AI analysis never leaves your phone",
          trailing: Icon(Icons.verified_user_rounded, color: AppColors.safe, size: 20),
        ),
        const SizedBox(height: 8),

        SettingsTile(
          icon: Icons.description_outlined,
          title: "Data Policy",
          subtitle: "How ShaktiX protects your flows",
          onTap: () {},
          trailing: const Icon(Icons.open_in_new_rounded, size: 18),
        ),
      ],
    );
  }
}