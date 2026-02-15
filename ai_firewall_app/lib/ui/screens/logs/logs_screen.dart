import 'package:flutter/material.dart';
import 'package:shaktix/ui/screens/logs/widgets/log_list_item.dart';
import 'package:shaktix/ui/screens/logs/widgets/logs_filter_bar.dart';
import '../../../main.dart';
import '../../../state/app_state.dart';
import '../../../theme/app_theme.dart';

import 'log_detail_screen.dart';
import 'models/log_event.dart';

class LogsScreen extends StatefulWidget {
  const LogsScreen({super.key});

  @override
  State<LogsScreen> createState() => _LogsScreenState();
}

class _LogsScreenState extends State<LogsScreen> {
  LogAction? _activeFilter;

  @override
  Widget build(BuildContext context) {
    final appState = AppStateScope.of(context);
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;

    // ✅ Filtering Logic for UI Cleanliness
    final filteredEvents = _activeFilter == null
        ? appState.events
        : appState.events.where((e) => e.action == _activeFilter).toList();

    return Scaffold(
      backgroundColor: isDark ? AppColors.dBg1 : AppColors.lBg1,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Text("THREAT INTEL", style: AppTextStyles.h2.copyWith(color: text0, letterSpacing: 1.5)),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_sweep_outlined, color: AppColors.danger),
            onPressed: () => appState.clearLogs(), //
          ),
        ],
      ),
      body: Column(
        children: [
          // 🔎 Real-time Filter Bar
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8.0),
            child: LogFilterBar(
              selectedAction: _activeFilter,
              onActionChanged: (newFilter) => setState(() => _activeFilter = newFilter),
            ),
          ),

          Expanded(
            child: filteredEvents.isEmpty
                ? _buildEmptyState(text0)
                : ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: filteredEvents.length,
              itemBuilder: (context, i) => LogListItem(
                e: filteredEvents[i],
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => LogDetailScreen(event: filteredEvents[i])),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState(Color color) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.shield_outlined, size: 64, color: color.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text("No network activity recorded", style: TextStyle(color: color.withOpacity(0.5))),
        ],
      ),
    );
  }
}