import 'package:flutter/material.dart';
import '../../../../main.dart'; // ✅ AppStateScope ke liye added
import '../../../../theme/app_theme.dart';
import '../../../components/glow_container.dart';
import '../../../root/root_screen.dart';

class QuickScanCard extends StatelessWidget {
  // ✅ Parameters synced with HomeScreen
  final bool isScanning;
  final Future<void> Function() onScan;

  const QuickScanCard({
    super.key,
    required this.isScanning,
    required this.onScan,
  });

  @override
  Widget build(BuildContext context) {
    // ✅ SMART SYNC: Khud AppState se data fetch kar raha hai
    final appState = AppStateScope.of(context);

    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;

    // Derived logic from AppState
    final vpnEnabled = appState.vpnEnabled;
    final datasetReady = appState.datasetStatus.toLowerCase().contains("ready");
    final hasBlocks = appState.lastBlocked != "-";

    final statusColor = !vpnEnabled
        ? AppColors.warn
        : (!datasetReady ? AppColors.warn : AppColors.safe);

    final statusText = !vpnEnabled
        ? "Action required: enable firewall"
        : (!datasetReady ? "Dataset not loaded" : "Quick health check ready");

    return GlowContainer(
      glow: vpnEnabled,
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: bg2,
          borderRadius: AppRadii.r20,
          border: Border.all(color: stroke.withOpacity(0.95)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text("Quick Scan", style: AppTextStyles.h2.copyWith(color: text0)),
                      const SizedBox(height: 6),
                      Text(
                        statusText,
                        style: AppTextStyles.caption.copyWith(
                          color: statusColor.withOpacity(0.95),
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                SizedBox(
                  height: 44,
                  child: ElevatedButton.icon(
                    onPressed: isScanning ? null : () => onScan(),
                    icon: AnimatedSwitcher(
                      duration: const Duration(milliseconds: 160),
                      child: isScanning
                          ? const SizedBox(
                        key: ValueKey("p"),
                        height: 16,
                        width: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                          : const Icon(Icons.search, key: ValueKey("s"), size: 18),
                    ),
                    label: Text(isScanning ? "Scanning..." : "Run"),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            _CheckRow(
              label: "Firewall",
              ok: vpnEnabled,
              hint: vpnEnabled ? "Enabled" : "Disabled",
            ),
            _CheckRow(
              label: "Dataset",
              ok: datasetReady,
              hint: datasetReady ? "Loaded" : "Not loaded",
            ),
            _CheckRow(
              label: "Recent blocks",
              ok: hasBlocks,
              hint: hasBlocks ? "Detected" : "None yet",
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                onPressed: () => RootScreen.switchTab(2), // ✅ Synced with Root Navigation
                icon: const Icon(Icons.receipt_long),
                label: const Text("View details"),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CheckRow extends StatelessWidget {
  final String label;
  final bool ok;
  final String hint;

  const _CheckRow({
    required this.label,
    required this.ok,
    required this.hint,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final c = ok ? AppColors.safe : AppColors.warn;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Icon(ok ? Icons.check_circle : Icons.info, color: c.withOpacity(0.95), size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(label, style: AppTextStyles.body.copyWith(color: text0, fontWeight: FontWeight.w700)),
          ),
          Text(hint, style: AppTextStyles.caption.copyWith(color: text2)),
        ],
      ),
    );
  }
}