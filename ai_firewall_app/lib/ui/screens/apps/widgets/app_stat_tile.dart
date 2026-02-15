import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';

class AppStatTile extends StatelessWidget {
  final String label;
  final String value;
  const AppStatTile({super.key, required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        borderRadius: AppRadii.r16,
        border: Border.all(color: Theme.of(context).brightness == Brightness.dark
            ? AppColors.dStroke
            : AppColors.lStroke),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: AppTextStyles.caption),
          const SizedBox(height: 6),
          Text(value, style: AppTextStyles.h2),
        ],
      ),
    );
  }
}
