import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../models/app_network_model.dart';

class AppListItem extends StatelessWidget {
  final AppNetworkModel app;
  final VoidCallback onTap;

  const AppListItem({super.key, required this.app, required this.onTap});

  String _mb(int b) => "${(b / 1024 / 1024).toStringAsFixed(1)} MB";

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;

    // Status-based accent
    final accentColor = app.blocked ? AppColors.danger : (app.suspicious ? AppColors.warn : AppColors.safe);

    return InkWell(
      onTap: onTap,
      borderRadius: AppRadii.r16,
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: isDark ? AppColors.dBg2 : AppColors.lBg2,
          borderRadius: AppRadii.r16,
          border: Border.all(color: app.suspicious ? accentColor.withOpacity(0.5) : stroke),
        ),
        child: Row(
          children: [
            // App Icon Placeholder
            Container(
              height: 48, width: 48,
              decoration: BoxDecoration(
                color: accentColor.withOpacity(0.1),
                borderRadius: AppRadii.r12,
              ),
              child: Icon(
                app.blocked ? Icons.block_flipped : Icons.apps_rounded,
                color: accentColor,
              ),
            ),
            const SizedBox(width: 14),

            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(app.appName, style: AppTextStyles.body.copyWith(color: text0, fontWeight: FontWeight.bold)),
                  Text(app.package, style: AppTextStyles.caption.copyWith(fontSize: 10)),
                  const SizedBox(height: 6),
                  // Real-time metrics feel
                  Row(
                    children: [
                      Icon(Icons.arrow_upward, size: 10, color: Colors.grey),
                      Text(_mb(app.bytesUp), style: AppTextStyles.caption.copyWith(fontSize: 10)),
                      const SizedBox(width: 10),
                      Icon(Icons.arrow_downward, size: 10, color: Colors.grey),
                      Text(_mb(app.bytesDown), style: AppTextStyles.caption.copyWith(fontSize: 10)),
                    ],
                  ),
                ],
              ),
            ),

            // AI Status Badge
            Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                if (app.suspicious)
                  const Padding(
                    padding: EdgeInsets.only(bottom: 4),
                    child: Text("SUSPICIOUS", style: TextStyle(color: AppColors.warn, fontSize: 8, fontWeight: FontWeight.bold)),
                  ),
                Icon(
                  app.blocked ? Icons.security_rounded : Icons.verified_user_rounded,
                  color: accentColor,
                  size: 20,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}