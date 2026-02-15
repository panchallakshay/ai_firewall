import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';

class GlowContainer extends StatelessWidget {
  final Widget child;
  final bool glow;
  final EdgeInsets padding;

  const GlowContainer({
    super.key,
    required this.child,
    this.glow = false,
    this.padding = const EdgeInsets.all(16),
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final bg1 = isDark ? AppColors.dBg1 : AppColors.lBg1;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;

    return AnimatedContainer(
      duration: const Duration(milliseconds: 180), // minimal animation
      curve: Curves.easeOut,
      padding: padding,
      decoration: BoxDecoration(
        color: bg1,
        borderRadius: AppRadii.r20,
        border: Border.all(color: stroke.withOpacity(isDark ? 0.9 : 1.0)),
        boxShadow: glow
            ? [
          BoxShadow(
            color: AppColors.accent.withOpacity(isDark ? 0.14 : 0.10),
            blurRadius: 22,
            offset: const Offset(0, 10),
          )
        ]
            : [
          BoxShadow(
            color: Colors.black.withOpacity(isDark ? 0.22 : 0.08),
            blurRadius: 18,
            offset: const Offset(0, 10),
          )
        ],
      ),
      child: child,
    );
  }
}
