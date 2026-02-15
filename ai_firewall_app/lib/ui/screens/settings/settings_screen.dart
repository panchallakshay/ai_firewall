import 'package:flutter/material.dart';
import '../../../main.dart';
import '../../../theme/app_theme.dart';
import 'sections/appearance_section.dart';
import 'sections/vpn_section.dart';
import 'sections/firewall_section.dart';
import 'sections/logs_section.dart';
import 'sections/privacy_section.dart';
import 'sections/about_section.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;

    return Scaffold(
      backgroundColor: isDark ? AppColors.dBg1 : AppColors.lBg1,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Text("SHIELD SETTINGS",
            style: AppTextStyles.h2.copyWith(color: text0, letterSpacing: 1.5)),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        physics: const BouncingScrollPhysics(),
        children: const [
          // ✅ Appearance Configuration
          AppearanceSection(),
          SizedBox(height: 24),

          // ✅ Core VPN Configuration
          VpnSection(),
          SizedBox(height: 24),

          // ✅ AI Policy & Behavior
          FirewallSection(),
          SizedBox(height: 24),

          // ✅ Storage Management
          LogsSection(),
          SizedBox(height: 24),

          // ✅ Privacy & Legal
          PrivacySection(),
          SizedBox(height: 24),

          // ✅ Version Info
          AboutSection(),
          SizedBox(height: 40),

          Center(
            child: Text("ShaktiX AI Engine v1.0.2 - Panipat Edition",
                style: TextStyle(fontSize: 10, color: Colors.grey)),
          ),
          SizedBox(height: 20),
        ],
      ),
    );
  }
}