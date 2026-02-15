import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';

class ReasonChip extends StatelessWidget {
  final String text;
  final IconData? icon;

  const ReasonChip({super.key, required this.text, this.icon});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final text1 = isDark ? AppColors.dText1 : AppColors.lText1;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: bg2,
        borderRadius: AppRadii.r12,
        border: Border.all(color: stroke.withOpacity(0.9)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            Icon(icon, size: 14, color: text2),
            const SizedBox(width: 6),
          ],
          Text(
            text,
            style: AppTextStyles.caption.copyWith(color: text1),
          ),
        ],
      ),
    );
  }
}
