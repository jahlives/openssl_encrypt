import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:openssl_encrypt_desktop/main.dart';
import 'package:openssl_encrypt_desktop/settings_service.dart';

void main() {
  setUp(() async {
    // Initialize SharedPreferences mock for tests
    SharedPreferences.setMockInitialValues({});
    await SettingsService.initialize();
  });

  testWidgets('Desktop GUI smoke test', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const OpenSSLEncryptApp());

    // Verify that our app starts up without crashing
    expect(find.byType(MaterialApp), findsOneWidget);
    
    // Look for the main navigation
    expect(find.byType(NavigationRail), findsOneWidget);
    
    // Look for text encryption tab (should be selected by default)
    expect(find.text('Text'), findsOneWidget);
    expect(find.text('File'), findsOneWidget);
    expect(find.text('Info'), findsOneWidget);
    expect(find.text('Settings'), findsOneWidget);
  });

  testWidgets('Text encryption UI elements present', (WidgetTester tester) async {
    await tester.pumpWidget(const OpenSSLEncryptApp());
    
    // Check for key UI elements in the text encryption tab
    expect(find.byType(TextField), findsWidgets); // Input text field and password field
    expect(find.text('Encrypt'), findsOneWidget);
    expect(find.text('Decrypt'), findsOneWidget);
  });

  testWidgets('Navigation works', (WidgetTester tester) async {
    await tester.pumpWidget(const OpenSSLEncryptApp());
    
    // Tap on File tab
    await tester.tap(find.text('File'));
    await tester.pumpAndSettle();
    
    // Should see file-related UI
    expect(find.text('Select File'), findsOneWidget);
    
    // Tap on Settings tab  
    await tester.tap(find.text('Settings'));
    await tester.pumpAndSettle();
    
    // Should see settings UI
    expect(find.text('Application Settings'), findsOneWidget);
  });
}