# Magpie

A lightweight screenshot annotation tool for technical writers, built with PyQt6.

---

## Features

- Shape tools: Rectangle, Oval, Line, Arrow (with Bezier curve control points)
- Annotation tools: Text, Step Marker, Highlight (Pen, Rectangle, Spotlight)
- Freehand drawing: Pen, Brush, Spray Can, Flood Fill, Color Eraser, Eraser
- Image tools: Crop, Cut Out, Pixelate, Blur, Remove Space, Magnify Inset
- Adjustments: Color & Light (Brightness, Contrast, Hue, Sharpness), Transform (Rotate, Flip, Resize), Outline
- Customizable color palette with Primary/Secondary colors and eyedropper
- Full clipboard integration (copy, paste, paste from system clipboard)
- FTP, FTPS, and SFTP publishing with saved destinations
- Dark, Light, and System theme support
- Pixel grid overlay for precise editing

---

## Install
**Flatpak (recommended):**

Prerequisites — install Flatpak if you don't already have it:
```bash
# Debian/Ubuntu
sudo apt install flatpak flatpak-builder
# Fedora
sudo dnf install flatpak flatpak-builder
# Arch
sudo pacman -S flatpak flatpak-builder
```
(Other distros: see the [official Flatpak setup guide](https://flatpak.org/setup/).)

Add the Flathub remote:
```bash
flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```

Build and run — `--install-deps-from=flathub` pulls in the required KDE runtime automatically:
```bash
git clone https://github.com/dposto/magpie.git
cd magpie
flatpak-builder --user --install --force-clean --install-deps-from=flathub builddir com.magpie.Magpie.json
flatpak run com.magpie.Magpie
```

**Run directly:**
```bash
git clone https://github.com/dposto/magpie.git
cd magpie
pip install Pillow numpy paramiko keyring SecretStorage
python3 Magpie.py
```
Requires PyQt6:
```
Debian/Ubuntu: sudo apt install python3-pyqt6
Fedora:        sudo dnf install python3-pyqt6
Arch:          sudo pacman -S python-pyqt6
pip:           pip install PyQt6
```

---

## License

GPL-3.0 — see [LICENSE](LICENSE)

---

## Credits

Built with:

- [PyQt6](https://riverbankcomputing.com/software/pyqt/) — Riverbank Computing
- [Qt6](https://qt.io/) — The Qt Company
- [Pillow](https://python-pillow.org/) — Jeffrey A. Clark and contributors
- [NumPy](https://numpy.org/) — NumPy Developers
- [Paramiko](https://www.paramiko.org/) — Jeff Forcier and contributors

Icons from [SVG Repo](https://www.svgrepo.com).
