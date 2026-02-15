import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';

// ✅ AI Engine ke naye levels ke saath match kiya
enum Severity { safe, warn, danger, critical, info }

class SecurityBadge extends StatelessWidget {
  final Severity severity;
  final String? label;

  const SecurityBadge({super.key, required this.severity, this.label});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;

    Color color;
    String text;

    switch (severity) {
      case Severity.safe:
        color = AppColors.safe;
        text = "SAFE";
        break;
      case Severity.warn:
        color = AppColors.warn;
        text = "SUSPICIOUS";
        break;
      case Severity.danger:
        color = AppColors.danger;
        text = "BLOCKED";
        break;
      case Severity.critical: // ✅ Naya "Critical" Level
        color = AppColors.danger;
        text = "THREAT";
        break;
      case Severity.info:
        color = AppColors.accent;
        text = "SCANNED";
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        borderRadius: AppRadii.r12,
        color: color.withOpacity(0.14),
        border: Border.all(color: color.withOpacity(0.4)), // Border color color se match ki
      ),
      child: Text(
        label ?? text,
        style: AppTextStyles.mono.copyWith(color: color, fontWeight: FontWeight.bold),
      ),
    );
  }
}