import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';

class LivePulseDot extends StatelessWidget {
  final bool enabled;
  const LivePulseDot({super.key, required this.enabled});

  @override
  Widget build(BuildContext context) {
    if (!enabled) {
      return const SizedBox(width: 10, height: 10);
    }

    // Battery-safe: small implicit animation only
    return TweenAnimationBuilder<double>(
      tween: Tween<double>(begin: 0.65, end: 1.0),
      duration: const Duration(milliseconds: 900),
      curve: Curves.easeInOut,
      builder: (_, v, __) {
        return Opacity(
          opacity: 0.9,
          child: Transform.scale(
            scale: v,
            child: Container(
              width: 10,
              height: 10,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: AppColors.accent,
                boxShadow: [
                  BoxShadow(
                    color: AppColors.accent.withOpacity(0.25),
                    blurRadius: 10,
                  )
                ],
              ),
            ),
          ),
        );
      },
      onEnd: () {}, // no loop; keeps battery low
    );
  }
}
