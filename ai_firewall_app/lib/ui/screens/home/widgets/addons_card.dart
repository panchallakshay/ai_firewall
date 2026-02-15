import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../../../components/glow_container.dart';
import '../../../components/security_badge.dart';

class AddonsCard extends StatelessWidget {
  const AddonsCard({super.key});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return GlowContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text("Security Add-ons", style: AppTextStyles.section.copyWith(color: text2)),
          const SizedBox(height: 12),

          Row(
            children: const [
              Expanded(child: _ThreatFeedPreview()),
              SizedBox(width: 12),
              Expanded(child: _TopRiskyAppsPreview()),
            ],
          ),
          const SizedBox(height: 12),
          const _ProtectionTip(),
          // TODO(backend):
          // - Threat feed comes from local rules + VT (opt-in)
          // - Top risky apps from behavior scoring
        ],
      ),
    );
  }
}

class _ThreatFeedPreview extends StatelessWidget {
  const _ThreatFeedPreview();

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: bg2,
        borderRadius: AppRadii.r16,
        border: Border.all(color: stroke.withOpacity(0.95)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text("Threat Feed", style: AppTextStyles.caption.copyWith(color: text2)),
          const SizedBox(height: 10),
          Row(
            children: [
              const SecurityBadge(severity: Severity.warn, label: "PHISHING"),
              const SizedBox(width: 8),
              Expanded(
                child: Text("Suspicious domain detected", style: AppTextStyles.body.copyWith(color: text0)),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text("—", style: AppTextStyles.caption.copyWith(color: text2)),
          const SizedBox(height: 10),
          Text("View all in Logs", style: AppTextStyles.caption.copyWith(color: AppColors.accent)),
        ],
      ),
    );
  }
}

class _TopRiskyAppsPreview extends StatelessWidget {
  const _TopRiskyAppsPreview();

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final text0 = isDark ? AppColors.dText0 : AppColors.lText0;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: bg2,
        borderRadius: AppRadii.r16,
        border: Border.all(color: stroke.withOpacity(0.95)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text("Top Risky Apps", style: AppTextStyles.caption.copyWith(color: text2)),
          const SizedBox(height: 10),
          Text("1) —", style: AppTextStyles.body.copyWith(color: text0)),
          const SizedBox(height: 6),
          Text("2) —", style: AppTextStyles.body.copyWith(color: text0)),
          const SizedBox(height: 6),
          Text("3) —", style: AppTextStyles.body.copyWith(color: text0)),
          const SizedBox(height: 10),
          Text("Open Apps tab", style: AppTextStyles.caption.copyWith(color: AppColors.accent)),
        ],
      ),
    );
  }
}

class _ProtectionTip extends StatelessWidget {
  const _ProtectionTip();

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg2 = isDark ? AppColors.dBg2 : AppColors.lBg2;
    final stroke = isDark ? AppColors.dStroke : AppColors.lStroke;
    final text2 = isDark ? AppColors.dText2 : AppColors.lText2;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: bg2,
        borderRadius: AppRadii.r16,
        border: Border.all(color: stroke.withOpacity(0.95)),
      ),
      child: Row(
        children: [
          const Icon(Icons.lightbulb_outline, color: AppColors.warn),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              "Tip: Enable VirusTotal only if you’re okay sharing domain/IP indicators (privacy-first).",
              style: AppTextStyles.caption.copyWith(color: text2),
            ),
          ),
        ],
      ),
    );
  }
}
