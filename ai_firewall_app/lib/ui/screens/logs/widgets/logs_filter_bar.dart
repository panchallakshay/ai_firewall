import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';
import '../models/log_event.dart';

class LogFilterBar extends StatelessWidget {
  final LogAction? selectedAction;
  final Function(LogAction?) onActionChanged;

  const LogFilterBar({super.key, required this.selectedAction, required this.onActionChanged});

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          _filterChip("LIVE FEED", null),
          const SizedBox(width: 8),
          _filterChip("BLOCKED", LogAction.BLOCKED),
          const SizedBox(width: 8),
          _filterChip("SECURE", LogAction.ALLOWED),
          const SizedBox(width: 8),
          _filterChip("WARNINGS", LogAction.WARNED),
        ],
      ),
    );
  }

  Widget _filterChip(String label, LogAction? action) {
    final isSelected = selectedAction == action;
    return ChoiceChip(
      label: Text(label),
      selected: isSelected,
      onSelected: (_) => onActionChanged(action),
      selectedColor: AppColors.accent.withOpacity(0.2),
      labelStyle: TextStyle(
        fontSize: 10,
        fontWeight: FontWeight.bold,
        color: isSelected ? AppColors.accent : Colors.grey,
      ),
      backgroundColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: AppRadii.r12,
        side: BorderSide(color: isSelected ? AppColors.accent : Colors.white12),
      ),
    );
  }
}