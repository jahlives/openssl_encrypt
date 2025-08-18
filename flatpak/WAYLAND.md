# Securing Flatpak GUI applications on Wayland without xhost

The "xhost +local:" command creates a critical security vulnerability by completely disabling X11 access control, allowing any local process to capture keystrokes, screenshots, and manipulate windows. This report provides secure alternatives for running Flatpak GUI applications under Wayland, addressing the technical challenges and offering practical solutions.

## Why xhost +local: is dangerous and sometimes needed

The **xhost +local:** command disables all X11 authentication for local connections, bypassing the MIT-MAGIC-COOKIE-1 security mechanism. This creates severe security risks: any local application can now keylog, capture screenshots, monitor clipboard contents, and inject synthetic events into other applications. Tools like `xspy` and `xkbcat` can capture passwords without root privileges once this command is executed.

Flatpak applications sometimes fail without this command because they run in isolated namespaces with restricted access to the host's display server. When Flatpak creates isolated display environments (like :99.0 instead of :0), the sandboxed applications lack matching authentication records in ~/.Xauthority. If Flatpak is compiled without libXau support or has namespace isolation issues, the X11 authentication fails entirely, leading users to this insecure workaround.

## Proper Wayland configuration for Flatpak applications

The secure approach involves granting appropriate socket permissions and configuring the environment correctly. Start by using Flatpak's socket permission system:

```bash
# Recommended configuration for Wayland-capable applications
flatpak override org.example.App --socket=wayland --socket=fallback-x11

# Check current permissions
flatpak info --show-permissions org.example.App
```

Essential environment variables must be properly configured. **WAYLAND_DISPLAY** (typically "wayland-0") is automatically set by compositors, while **XDG_RUNTIME_DIR** (usually /run/user/UID) enables socket communication. Some applications require additional variables:

```bash
# Firefox/Thunderbird Wayland support
flatpak override org.mozilla.firefox --env=MOZ_ENABLE_WAYLAND=1

# Electron applications
flatpak override app.id --env=ELECTRON_OZONE_PLATFORM_HINT=auto
```

Portal configuration is crucial for proper Wayland operation. Install the appropriate portal backend for your desktop environment (xdg-desktop-portal-gtk for GNOME, xdg-desktop-portal-kde for KDE, xdg-desktop-portal-wlr for wlroots compositors). Configure ~/.config/xdg-desktop-portal/portals.conf to specify preferred backends for different operations.

## Common problems and troubleshooting steps

The **"Cannot open display"** error typically indicates missing Wayland socket permissions or incorrect environment variables. First, verify the Wayland socket exists:

```bash
ls -la $XDG_RUNTIME_DIR/wayland*
```

If applications show blank windows or fail to start, grant both Wayland and fallback X11 permissions. For Electron applications that display transparent windows, force Wayland mode with specific environment variables.

Recent updates reveal a **critical regression in Ubuntu 24.10** where most Flatpak applications fail on Wayland sessions. Users must currently disable Wayland socket permissions and use X11 through Flatseal as a workaround. Fedora 40/41 provides the most stable Flatpak Wayland experience as of 2025.

## Environment variables and permissions configuration

Beyond basic socket permissions, several environment variables influence Flatpak behavior under Wayland. The **GDK_BACKEND** variable should be set to "wayland,x11" for GTK applications to prefer Wayland while maintaining X11 fallback capability. For Qt applications, **QT_QPA_PLATFORM** serves a similar purpose.

Portal permissions require careful configuration. Applications need **--share=ipc** for Wayland communication and **--device=dri** for GPU acceleration. Use Flatseal (a GUI permission manager) or command-line overrides to manage these settings:

```bash
# Comprehensive permission grant for graphics applications
flatpak override app.id \
  --socket=wayland \
  --socket=fallback-x11 \
  --device=dri \
  --share=ipc
```

## X11 versus Wayland architectural differences

X11's security model assumes all connected applications are trusted, allowing any X11 client to read input from any other application. This fundamental design flaw makes secure application isolation impossible. The MIT-MAGIC-COOKIE-1 authentication provides minimal protection and transmits credentials in plain text.

Wayland's architecture enforces application isolation by design. Each application communicates only with the compositor, preventing cross-application snooping. Applications cannot capture global keystrokes or screen content without explicit user permission through portals. This security-first design eliminates entire categories of attacks possible under X11.

XWayland provides compatibility for legacy X11 applications but reduces security. Applications running through XWayland can potentially access each other's content, though they remain isolated from native Wayland applications.

## Desktop environment specific configurations

**GNOME (Mutter)** users should enable experimental features for better Wayland support:
```bash
gsettings set org.gnome.mutter experimental-features "['autostart-xwayland']"
```

**KDE Plasma** requires specific overrides for desktop detection:
```bash
flatpak override --env=KDE_FULL_SESSION=true org.example.App
```

**Sway and wlroots-based compositors** need proper portal configuration in the Sway config:
```bash
exec /usr/libexec/xdg-desktop-portal-gtk
exec /usr/libexec/xdg-desktop-portal-wlr
```

Each desktop environment has unique quirks. GNOME handles fractional scaling differently than KDE, while Sway requires manual cursor theme configuration for Flatpak applications.

## Secure alternatives to xhost +local:

Instead of completely disabling access control, use **user-specific authorization**:
```bash
xhost "+si:localuser:$(id -nu)"
```

This grants access only to your user account, maintaining some security boundaries. However, the best approach avoids xhost entirely by properly configuring Flatpak permissions.

For debugging, create a temporary isolated environment rather than compromising system security:
```bash
# Debug shell with development access
flatpak run --command=sh --devel org.example.App
```

Recent Flatpak 1.16.0 (December 2024) introduces the security-context-v1 Wayland extension, allowing compositors to identify sandboxed connections and apply appropriate security policies. This advancement will reduce the need for insecure workarounds.

## Conclusion

Running Flatpak GUI applications securely under Wayland requires proper socket permissions, environment configuration, and portal setup rather than disabling security with xhost. While Ubuntu 24.10's regression presents temporary challenges, the Flatpak ecosystem continues improving Wayland integration. Users should prioritize secure configurations using --socket=wayland and --socket=fallback-x11 permissions, configure appropriate environment variables, and leverage tools like Flatseal for permission management. The transition from X11's fundamentally insecure architecture to Wayland's isolation-by-design approach represents a crucial security improvement that justifies the additional configuration complexity.
