import 'package:flutter/material.dart';
import '../../../main.dart'; // ✅ AppStateScope ke liye
import '../../../theme/app_theme.dart';
import 'models/app_network_model.dart';
import 'widgets/app_filter_bar.dart';
import 'widgets/app_list_item.dart';
import 'app_detail_screen.dart';

class AppsScreen extends StatefulWidget {
  const AppsScreen({super.key});

  @override
  State<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends State<AppsScreen> {
  int filterIndex = 0;

  final List<AppNetworkModel> apps = const [
    AppNetworkModel(
      appName: "Chrome",
      package: "com.android.chrome",
      blocked: false,
      bytesUp: 140000000,
      bytesDown: 420000000,
      connections: 32,
      destinations: ["google.com", "accounts.google.com"],
      ports: [443, 80],
      suspicious: false,
      isSystem: false,
    ),
    AppNetworkModel(
      appName: "Unknown App",
      package: "com.bad.actor",
      blocked: true,
      bytesUp: 1200000,
      bytesDown: 800000,
      connections: 14,
      destinations: ["185.231.xxx.xxx"],
      ports: [8080],
      suspicious: true,
      isSystem: false,
    ),
    AppNetworkModel(
      appName: "System UI",
      package: "com.android.systemui",
      blocked: false,
      bytesUp: 50000,
      bytesDown: 120000,
      connections: 5,
      destinations: ["internal.android"],
      ports: [0],
      suspicious: false,
      isSystem: true,
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final appState = AppStateScope.of(context); // ✅ Sync with global state
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;

    // Filter Logic: All, Active, Blocked, System
    final filteredApps = apps.where((app) {
      if (filterIndex == 1) return !app.blocked && !app.isSystem;
      if (filterIndex == 2) return app.blocked;
      if (filterIndex == 3) return app.isSystem;
      return true;
    }).toList();

    return Scaffold(
      backgroundColor: isDark ? AppColors.dBg1 : AppColors.lBg1,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Text("APPS CONTROL", style: AppTextStyles.h2.copyWith(color: text0, letterSpacing: 1.5)),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
            child: AppFilterBar(
              selected: filterIndex,
              onChange: (v) => setState(() => filterIndex = v),
            ),
          ),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              itemCount: filteredApps.length,
              itemBuilder: (context, index) {
                final app = filteredApps[index];
                return Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: AppListItem(
                    app: app,
                    onTap: () => Navigator.push(
                      context,
                      MaterialPageRoute(builder: (_) => AppDetailScreen(app: app)),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}