import 'package:flutter/material.dart';
import '../../../../main.dart';
import '../../../../theme/app_theme.dart';
import '../widgets/settings_section_header.dart';
import '../widgets/settings_tile.dart';

class LogsSection extends StatelessWidget {
  const LogsSection({super.key});

  @override
  Widget build(BuildContext context) {
    final appState = AppStateScope.of(context); //

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SettingsSectionHeader(title: "LOGS & STORAGE"),
        const SizedBox(height: 10),

        SettingsTile(
          icon: Icons.history_rounded,
          title: "Retention Period",
          subtitle: "Currently storing last 7 days",
          trailing: const Icon(Icons.chevron_right_rounded),
        ),
        const SizedBox(height: 8),

        SettingsTile(
          icon: Icons.delete_sweep_outlined,
          title: "Clear All Logs",
          subtitle: "Permanently delete ${appState.events.length} records",
          onTap: () => _confirmClear(context, appState),
          trailing: const Icon(Icons.delete_outline, color: AppColors.danger),
        ),
      ],
    );
  }

  void _confirmClear(BuildContext context, dynamic state) {
    state.clearLogs(); //
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text("All logs cleared successfully")),
    );
  }
}