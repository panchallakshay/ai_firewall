import 'package:flutter/material.dart';
import '../../../../theme/app_theme.dart';

class DestinationTile extends StatelessWidget {
  final String dest;
  const DestinationTile({super.key, required this.dest});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: const Icon(Icons.public),
      title: Text(dest, style: AppTextStyles.body),
    );
  }
}
