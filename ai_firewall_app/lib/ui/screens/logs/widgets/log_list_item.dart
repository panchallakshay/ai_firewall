import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../models/log_event.dart';

class LogListItem extends StatelessWidget {
  final LogEvent e;
  final VoidCallback onTap;

  const LogListItem({super.key, required this.e, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;
    final accent = e.actionColor;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        onTap: onTap,
        borderRadius: AppRadii.r16,
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: isDark ? AppColors.dBg2 : AppColors.lBg2,
            borderRadius: AppRadii.r16,
            border: Border.all(
                color: e.action == LogAction.BLOCKED
                    ? AppColors.danger.withOpacity(0.3)
                    : (isDark ? AppColors.dStroke : AppColors.lStroke)
            ),
          ),
          child: Row(
            children: [
              // ✅ Dynamic Protocol/Action Icon
              Container(
                height: 42, width: 42,
                decoration: BoxDecoration(
                  color: accent.withOpacity(0.1),
                  borderRadius: AppRadii.r12,
                ),
                child: Icon(
                  e.action == LogAction.BLOCKED ? Icons.security_rounded : Icons.verified_user_rounded,
                  color: accent,
                  size: 22,
                ),
              ),
              const SizedBox(width: 16),
              // ✅ Metadata Info
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      e.destination,
                      style: AppTextStyles.body.copyWith(color: text0, fontWeight: FontWeight.bold),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      "${e.reasonShort} • ${(e.confidence * 100).toInt()}% AI Confidence",
                      style: AppTextStyles.caption.copyWith(color: text2),
                    ),
                  ],
                ),
              ),
              // ✅ Timestamp
              Text(
                "${e.ts.hour}:${e.ts.minute.toString().padLeft(2, '0')}",
                style: AppTextStyles.caption.copyWith(fontSize: 10),
              ),
            ],
          ),
        ),
      ),
    );
  }
}