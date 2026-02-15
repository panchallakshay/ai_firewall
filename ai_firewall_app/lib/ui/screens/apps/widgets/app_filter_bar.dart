import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../../../theme/app_theme.dart';

class AppFilterBar extends StatelessWidget {
  final int selected;
  final ValueChanged<int> onChange;

  const AppFilterBar({super.key, required this.selected, required this.onChange});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final filters = ["ALL", "ACTIVE", "BLOCKED", "SYSTEM"];

    return SizedBox(
      height: 40,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        itemCount: filters.length,
        padding: const EdgeInsets.symmetric(horizontal: 4),
        separatorBuilder: (_, __) => const SizedBox(width: 10),
        itemBuilder: (context, i) {
          final active = i == selected;
          return GestureDetector(
            onTap: () {
              HapticFeedback.lightImpact(); // Professional feel
              onChange(i);
            },
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 200),
              padding: const EdgeInsets.symmetric(horizontal: 20),
              alignment: Alignment.center,
              decoration: BoxDecoration(
                borderRadius: AppRadii.r20,
                color: active ? AppColors.accent : (isDark ? Colors.white.withOpacity(0.05) : Colors.black.withOpacity(0.05)),
                border: Border.all(color: active ? AppColors.accent : Colors.white10),
                boxShadow: active ? [BoxShadow(color: AppColors.accent.withOpacity(0.3), blurRadius: 8)] : null,
              ),
              child: Text(
                filters[i],
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.bold,
                  color: active ? Colors.black : Colors.grey,
                  letterSpacing: 1.1,
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}