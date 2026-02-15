import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';

class SettingsSectionHeader extends StatelessWidget {
  final String title;
  const SettingsSectionHeader({super.key, required this.title});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 10),
      child: Text(
        title.toUpperCase(),
        style: AppTextStyles.caption.copyWith(
          color: text2,
          letterSpacing: 1.1,
        ),
      ),
    );
  }
}
