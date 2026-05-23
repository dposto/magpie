# Magpie — Flathub Build Guide

## File layout

Your **GitHub repo** should contain these files (Flathub requires metadata
to live upstream, not in the submission PR):

```
magpie/
├── Magpie.py
├── magpie-launcher.sh
├── com.magpie.Magpie.desktop
├── com.magpie.Magpie.metainfo.xml
├── icons/
│   ├── com.magpie.Magpie.svg          # scalable (required)
│   ├── com.magpie.Magpie-64.png       # 64×64
│   └── com.magpie.Magpie-128.png      # 128×128
└── screenshots/
    └── main-window.png                # for the Flathub listing
```

Your **Flathub submission PR** contains only:

```
com.magpie.Magpie/
├── com.magpie.Magpie.json             # the manifest
└── python3-dependencies.json          # generated (see below)
```

## Step 1: Install build prerequisites

```bash
# Install the runtime, SDK, and PyQt BaseApp
flatpak install flathub org.kde.Platform//6.9
flatpak install flathub org.kde.Sdk//6.9
flatpak install flathub com.riverbankcomputing.PyQt.BaseApp//6.9

# Install the dependency generator
pip install flatpak-pip-generator
# or: pip install req2flatpak
```

## Step 2: Generate python3-dependencies.json

Flathub builds are fully offline — no pip installs during build.
You generate a manifest of pinned wheels ahead of time:

```bash
# Using flatpak-pip-generator (from flatpak-builder-tools):
python3 flatpak-pip-generator \
    Pillow numpy paramiko keyring SecretStorage \
    -o python3-dependencies

# Or using req2flatpak:
echo "Pillow
numpy
paramiko
keyring
SecretStorage" > requirements.txt

python3 -m req2flatpak \
    --requirements-file requirements.txt \
    --target-platforms 312-x86_64 312-aarch64 \
    --output python3-dependencies.json
```

This creates `python3-dependencies.json` with all the download URLs
and sha256 hashes.  Include this file alongside the manifest in your
Flathub PR.

**Note:** `SecretStorage` is the keyring backend for Linux — it talks
to the Freedesktop Secrets D-Bus API (`org.freedesktop.secrets`),
which is why `--talk-name=org.freedesktop.secrets` is in finish-args.

## Step 3: Build and test locally

```bash
flatpak-builder --force-clean --user \
    --install-deps-from=flathub \
    --repo=repo \
    --install \
    builddir com.magpie.Magpie.json

# Run it
flatpak run com.magpie.Magpie
```

## Step 4: Validate metadata

```bash
# Validate the metainfo file
appstreamcli validate --explain \
    com.magpie.Magpie.metainfo.xml

# Validate the desktop file
desktop-file-validate com.magpie.Magpie.desktop
```

## Step 5: Submit to Flathub

1. Fork https://github.com/flathub/flathub
2. Create a new branch
3. Add a folder `com.magpie.Magpie/` containing:
   - `com.magpie.Magpie.json` (the manifest)
   - `python3-dependencies.json` (generated above)
4. Open a PR against the `new-pr` branch
5. Wait for review (typically a few days to a couple weeks)

Once approved, Flathub creates a repo for your app and you get
write access.  Future updates are just pushes — no review needed.

## Manifest notes

### finish-args explained

| Permission | Why |
|---|---|
| `--share=ipc` | Required for X11 shared memory |
| `--share=network` | FTP/FTPS/SFTP upload support |
| `--socket=fallback-x11` | X11 display (falls back from Wayland) |
| `--socket=wayland` | Native Wayland support |
| `--device=dri` | GPU rendering for Qt |
| `--filesystem=home` | Open/save images anywhere in home |
| `--talk-name=org.freedesktop.secrets` | Keyring for password storage |
| `--talk-name=org.freedesktop.portal.Desktop` | File dialogs, notifications |

### Why the PyQt BaseApp?

Building PyQt6 from source takes 30+ minutes and requires SIP, Qt
headers, and a C++ compiler.  The BaseApp provides a pre-built PyQt6
that layers on top of the KDE runtime — your build just adds Magpie
and its Python dependencies.

### License

Set `project_license` in the metainfo to match your actual license.
The manifest currently says MIT — change it if you use something else.
Flathub also requires that license files for each module are installed
to `$FLATPAK_DEST/share/licenses/$FLATPAK_ID/`.
