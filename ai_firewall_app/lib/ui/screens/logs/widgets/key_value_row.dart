import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';

class KeyValueRow extends StatelessWidget {
  final String k;
  final String v;

  const KeyValueRow({super.key, required this.k, required this.v});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;
    final text1 = isDark ? AppColors.dText1 : AppColors.lText1;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          SizedBox(
            width: 120,
            child: Text(k, style: AppTextStyles.caption.copyWith(color: text2)),
          ),
          Expanded(
            child: Text(v, style: AppTextStyles.body.copyWith(color: text1)),
          ),
        ],
      ),
    );
  }
}
