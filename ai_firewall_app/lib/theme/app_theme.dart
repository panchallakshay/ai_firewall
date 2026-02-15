import 'package:flutter/material.dart';

class AppColors {
  // ===== Dark palette =====
  static const Color dBg0 = Color(0xFF060A12);
  static const Color dBg1 = Color(0xFF0B1220);
  static const Color dBg2 = Color(0xFF0F1B2D);
  static const Color dStroke = Color(0xFF1B2B44);

  static const Color dText0 = Color(0xFFEAF2FF);
  static const Color dText1 = Color(0xFFB8C6E3);
  static const Color dText2 = Color(0xFF7F92B5);

  // ===== Light palette (for testing) =====
  static const Color lBg0 = Color(0xFFF6F8FC);
  static const Color lBg1 = Color(0xFFFFFFFF);
  static const Color lBg2 = Color(0xFFF0F4FB);
  static const Color lStroke = Color(0xFFD7E1F2);

  static const Color lText0 = Color(0xFF0A1220);
  static const Color lText1 = Color(0xFF24324A);
  static const Color lText2 = Color(0xFF55657F);

  // Accents + status (shared)
  static const Color accent = Color(0xFF00fa9a);
  static const Color electric = Color(0xFF2F7CFF);
  static const Color safe = Color(0xFF2FE5B8);
  static const Color warn = Color(0xFFFFC857);
  static const Color danger = Color(0xFFFF6B35);
  static const Color critical = Color(0xFFFF3B5C);
  static const Color info = Color(0xFF56A3FF);
}

class AppRadii {
  static const BorderRadius r12 = BorderRadius.all(Radius.circular(12));
  static const BorderRadius r16 = BorderRadius.all(Radius.circular(16));
  static const BorderRadius r20 = BorderRadius.all(Radius.circular(20));
}

class AppTextStyles {
  static const TextStyle h1 = TextStyle(fontSize: 24, fontWeight: FontWeight.w800, letterSpacing: 0.2);
  static const TextStyle h2 = TextStyle(fontSize: 18, fontWeight: FontWeight.w800, letterSpacing: 0.2);
  static const TextStyle section = TextStyle(fontSize: 13, fontWeight: FontWeight.w800, letterSpacing: 0.8);
  static const TextStyle body = TextStyle(fontSize: 14, fontWeight: FontWeight.w600, height: 1.35);
  static const TextStyle bodyMuted = TextStyle(fontSize: 13, fontWeight: FontWeight.w600, height: 1.35);
  static const TextStyle caption = TextStyle(fontSize: 12, fontWeight: FontWeight.w600);
  static const TextStyle mono = TextStyle(fontSize: 12, fontWeight: FontWeight.w700, letterSpacing: 0.4);
}

ThemeData buildDarkTheme() {
  return ThemeData(
    brightness: Brightness.dark,
    scaffoldBackgroundColor: AppColors.dBg0,
    colorScheme: const ColorScheme.dark(
      primary: AppColors.accent,
      secondary: AppColors.electric,
      surface: AppColors.dBg1,
      error: AppColors.critical,
    ),
    dividerColor: AppColors.dStroke,
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.dBg0,
      elevation: 0,
    ),
    cardColor: AppColors.dBg1,
  );
}

ThemeData buildLightTheme() {
  return ThemeData(
    brightness: Brightness.light,
    scaffoldBackgroundColor: AppColors.lBg0,
    colorScheme: const ColorScheme.light(
      primary: AppColors.electric,
      secondary: AppColors.accent,
      surface: AppColors.lBg1,
      error: AppColors.critical,
    ),
    dividerColor: AppColors.lStroke,
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.lBg0,
      elevation: 0,
    ),
    cardColor: AppColors.lBg1,
  );
}
