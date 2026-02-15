import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';

class AppUsageRow extends StatelessWidget {
  final int up;
  final int down;
  final String dest;

  const AppUsageRow({
    super.key,
    required this.up,
    required this.down,
    required this.dest,
  });

  String _mb(int b) => "${(b / 1024 / 1024).toStringAsFixed(1)} MB";

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          "↑ ${_mb(up)}   ↓ ${_mb(down)}",
          style: AppTextStyles.caption.copyWith(color: text2),
        ),
        const SizedBox(height: 2),
        Text(
          dest,
          style: AppTextStyles.caption.copyWith(
            color: text2,
            fontSize: 11,
          ),
          overflow: TextOverflow.ellipsis,
        ),
      ],
    );
  }
}
