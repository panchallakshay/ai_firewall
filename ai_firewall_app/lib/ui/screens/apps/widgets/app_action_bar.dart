import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../models/app_network_model.dart';

class AppActionBar extends StatelessWidget {
  final AppNetworkModel app;
  const AppActionBar({super.key, required this.app});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final color = app.blocked ? AppColors.safe : AppColors.danger;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isDark ? AppColors.dBg2 : AppColors.lBg2,
        borderRadius: AppRadii.r20,
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Icon(app.blocked ? Icons.block : Icons.verified_user, color: color, size: 32),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(app.appName, style: AppTextStyles.h2),
                    Text(app.package, style: AppTextStyles.caption),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: ElevatedButton.icon(
              icon: Icon(app.blocked ? Icons.lock_open_rounded : Icons.security_rounded),
              label: Text(app.blocked ? "REVOKE BLOCK" : "BLOCK APP TRAFFIC"),
              style: ElevatedButton.styleFrom(
                backgroundColor: color,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: AppRadii.r12),
              ),
              onPressed: () {
                // TODO: Link with AppState to update Rule Engine
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text("${app.appName} policy updated")),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}