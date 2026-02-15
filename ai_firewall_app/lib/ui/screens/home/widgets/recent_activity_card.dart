import 'package:flutter/material.dart';
import '../../../../main.dart';
import '../../../../theme/app_theme.dart';
import '../../logs/models/log_event.dart';

class RecentActivityCard extends StatelessWidget {
  const RecentActivityCard({super.key});



  @override
  Widget build(BuildContext context) {
    final appState = AppStateScope.of(context); //
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;

    // Latest 3 events dashboard par dikhane ke liye
    final latestEvents = appState.events.take(3).toList();

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isDark ? AppColors.dBg2 : AppColors.lBg2,
        borderRadius: AppRadii.r20,
        border: Border.all(color: stroke),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text("RECENT ACTIVITY", style: AppTextStyles.caption.copyWith(fontWeight: FontWeight.bold, letterSpacing: 1.2)),
              const Icon(Icons.circle, color: AppColors.safe, size: 8),
            ],
          ),
          const SizedBox(height: 16),
          if (latestEvents.isEmpty)
            Center(child: Text("Monitoring packets...", style: TextStyle(color: text2, fontSize: 12)))
          else
            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: latestEvents.length,
              separatorBuilder: (_, __) => Divider(height: 20, color: stroke.withOpacity(0.5)),
              itemBuilder: (context, index) {
                final e = latestEvents[index];
                final isBlocked = e.action == LogAction.BLOCKED;
                return Row(
                  children: [
                    Icon(isBlocked ? Icons.gpp_maybe_outlined : Icons.verified_user_outlined,
                        color: isBlocked ? AppColors.danger : AppColors.safe, size: 20),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(e.destination, style: TextStyle(color: text0, fontWeight: FontWeight.bold, fontSize: 13),
                              maxLines: 1, overflow: TextOverflow.ellipsis),
                          Text("${e.protocol} • AI Score: ${(e.confidence * 100).toInt()}%", style: AppTextStyles.caption),
                        ],
                      ),
                    ),
                    Text("${e.ts.hour}:${e.ts.minute.toString().padLeft(2, '0')}", style: AppTextStyles.caption),
                  ],
                );
              },
            ),
        ],
      ),
    );
  }
}