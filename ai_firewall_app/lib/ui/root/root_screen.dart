import 'package:flutter/material.dart';
import 'package:shaktix/ui/screens/apps/apps_screen.dart';
import 'package:shaktix/ui/screens/settings/settings_screen.dart';
// ✅ IMPORT PATH CHECK: Ensure this matches your folder structure
import '../screens/home_screen.dart';
import '../screens/logs/logs_screen.dart';

class RootScreen extends StatefulWidget {
  const RootScreen({super.key});

  static final GlobalKey<_RootScreenState> navKey = GlobalKey<_RootScreenState>();

  static void switchTab(int index) {
    navKey.currentState?.setState(() {
      navKey.currentState?._selectedIndex = index;
    });
  }

  @override
  State<RootScreen> createState() => _RootScreenState();
}

class _RootScreenState extends State<RootScreen> {
  int _selectedIndex = 0;

  // ✅ Screens list without 'const' so dynamic AppState can work
  late final List<Widget> _screens = [
    const HomeScreen(), // ✅ Added 'const' here because HomeScreen usually has a const constructor
    const AppsScreen(),
    const LogsScreen(),
    const SettingsScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: IndexedStack(
        index: _selectedIndex,
        children: _screens,
      ),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _selectedIndex,
        onTap: (index) => setState(() => _selectedIndex = index),
        type: BottomNavigationBarType.fixed,
        backgroundColor: const Color(0xFF0D1117), // Dark background match
        selectedItemColor: const Color(0xFF00E676), // ShaktiX Accent Color
        unselectedItemColor: Colors.grey,
        items: const [
          BottomNavigationBarItem(icon: Icon(Icons.shield_outlined), label: "Home"),
          BottomNavigationBarItem(icon: Icon(Icons.apps), label: "Apps"),
          BottomNavigationBarItem(icon: Icon(Icons.receipt_long), label: "Logs"),
          BottomNavigationBarItem(icon: Icon(Icons.settings), label: "Settings"),
        ],
      ),
    );
  }
}