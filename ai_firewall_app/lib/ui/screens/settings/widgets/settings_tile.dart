import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';

class SettingsTile extends StatelessWidget {
  final IconData icon;
  final String title;
  final String? subtitle;
  final Widget? trailing;
  final VoidCallback? onTap;

  const SettingsTile({
    super.key,
    required this.icon,
    required this.title,
    this.subtitle,
    this.trailing,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return InkWell(
      onTap: onTap,
      borderRadius: AppRadii.r16,
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          borderRadius: AppRadii.r16,
          border: Border.all(color: stroke),
        ),
        child: Row(
          children: [
            Icon(icon, color: AppColors.accent),
            const SizedBox(width: 12),

            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: AppTextStyles.body.copyWith(color: text0)),
                  if (subtitle != null) ...[
                    const SizedBox(height: 2),
                    Text(subtitle!,
                        style: AppTextStyles.caption.copyWith(color: text2)),
                  ],
                ],
              ),
            ),

            if (trailing != null) trailing!,
          ],
        ),
      ),
    );
  }
}
