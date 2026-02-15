import 'package:flutter/material.dart';
import 'ui/root/root_screen.dart';
import 'state/app_state.dart';
import 'ui/screens/home_screen.dart';

void main() {
  runApp(
    // ✅ 1. Pehle AppState ko initialize karo
    AppStateScope(
      notifier: AppState(),
      child: const ShaktiXApp(),
    ),
  );
}

// ✅ 2. Ye hai wo Magic Wrapper jo Red Lines aur 'of' null error hatayega
class AppStateScope extends InheritedNotifier<AppState> {
  const AppStateScope({
    required super.notifier,
    required super.child,
    super.key,
  });

  static AppState of(BuildContext context) {
    // Ye line widget tree mein AppStateScope ko dhoondti hai
    final scope = context.dependOnInheritedWidgetOfExactType<AppStateScope>();
    if (scope == null) {
      throw Exception("AppStateScope not found in context. Check your main.dart wrap!");
    }
    return scope.notifier!;
  }
}

class ShaktiXApp extends StatelessWidget {
  const ShaktiXApp({super.key});

  @override
  Widget build(BuildContext context) {
    // ✅ 3. AppStateScope se theme fetch ho rahi hai
    final appState = AppStateScope.of(context);

    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'SHAKTIX AI',
      themeMode: appState.themeMode, // Dark/Light mode sync
      theme: ThemeData(brightness: Brightness.light),
      darkTheme: ThemeData(brightness: Brightness.dark),
      home: const RootScreen(), // Ab HomeScreen ko AppState mil jayega
    );
  }
}