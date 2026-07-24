import 'dart:async';

import 'package:flutter/material.dart';

import '../cli_service.dart';

/// A live password-strength indicator driven by the CLI `check-password --json`
/// command. Listens to a [TextEditingController], debounces changes (to avoid
/// spawning a CLI process per keystroke), and renders a strength bar, the
/// reported category, the entropy in bits, and any weakness warnings.
///
/// The bar fraction and colour are derived from the pattern-aware entropy
/// (bits) so they remain sensible regardless of the exact category wording.
class PasswordStrengthMeter extends StatefulWidget {
  final TextEditingController controller;
  final Duration debounce;

  const PasswordStrengthMeter({
    super.key,
    required this.controller,
    this.debounce = const Duration(milliseconds: 500),
  });

  @override
  State<PasswordStrengthMeter> createState() => _PasswordStrengthMeterState();
}

class _PasswordStrengthMeterState extends State<PasswordStrengthMeter> {
  Timer? _debounce;
  PasswordStrength? _strength;
  bool _checking = false;
  String _lastChecked = '';

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onChanged);
  }

  @override
  void dispose() {
    _debounce?.cancel();
    widget.controller.removeListener(_onChanged);
    super.dispose();
  }

  void _onChanged() {
    _debounce?.cancel();
    final text = widget.controller.text;
    if (text.isEmpty) {
      setState(() {
        _strength = null;
        _checking = false;
      });
      return;
    }
    setState(() => _checking = true);
    _debounce = Timer(widget.debounce, () => _check(text));
  }

  Future<void> _check(String text) async {
    if (text == _lastChecked) {
      if (mounted) setState(() => _checking = false);
      return;
    }
    try {
      final s = await CLIService.checkPassword(text);
      // Ignore stale results if the field changed while we were checking.
      if (!mounted || widget.controller.text != text) return;
      setState(() {
        _strength = s;
        _lastChecked = text;
        _checking = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _strength = null;
        _checking = false;
      });
    }
  }

  double _fraction(double bits) => (bits / 128.0).clamp(0.0, 1.0);

  Color _color(double bits) {
    if (bits < 40) return Colors.red;
    if (bits < 60) return Colors.orange;
    if (bits < 80) return Colors.amber;
    if (bits < 100) return Colors.lightGreen;
    return Colors.green;
  }

  @override
  Widget build(BuildContext context) {
    final s = _strength;
    if (s == null) {
      if (_checking) {
        return const Padding(
          padding: EdgeInsets.only(top: 8),
          child: LinearProgressIndicator(minHeight: 4),
        );
      }
      return const SizedBox.shrink();
    }

    final color = _color(s.bits);
    return Padding(
      padding: const EdgeInsets.only(top: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: _fraction(s.bits),
              minHeight: 6,
              backgroundColor: Colors.grey.shade300,
              valueColor: AlwaysStoppedAnimation<Color>(color),
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'Strength: ${s.category}  (${s.bits.toStringAsFixed(0)} bits)',
            style: TextStyle(fontSize: 12, color: color, fontWeight: FontWeight.w600),
          ),
          for (final w in s.warnings)
            Padding(
              padding: const EdgeInsets.only(top: 2),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.info_outline, size: 13, color: Colors.orange),
                  const SizedBox(width: 4),
                  Expanded(
                    child: Text(w,
                        style: const TextStyle(
                            fontSize: 11, color: Colors.orange)),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
