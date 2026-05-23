# magpie

A screenshot annotation tool geared towards technical writers. Crop, annotate, redact, and publish — without the overhead of a full image editor.

A [sudo sketchy](https://github.com/dposto) project by David Posto.

---

### Features

- Shape tools: Rectangle, Oval, Line, Arrow (with Bézier curve control points)
- Annotation tools: Text, Step Marker, Highlight (Pen, Rectangle, Spotlight)
- Freehand drawing: Pen, Brush, Spray Can, Flood Fill, Color Eraser, Eraser
- Image tools: Crop, Cut Out, Pixelate, Blur, Remove Space, Magnify Inset
- Adjustments: Color & Light (Brightness, Contrast, Hue, Sharpness), Transform (Rotate, Flip, Resize), Outline
- Color palette with Primary and Secondary colors and pick-from-canvas eyedropper
- Full clipboard integration
- FTP/FTPS/SFTP publishing with saved destinations
- Dark mode support

### Requirements

- Python 3.10+
- PyQt6
- Pillow
- NumPy
- keyring
- paramiko (optional, for SFTP)
- qt6-svg (for icon rendering)

### Running

```
python Magpie.py
```

The `icons/` folder should be in the same directory as `Magpie.py`.

### License

MIT License — see [LICENSE](LICENSE) for details.

Icons sourced from [SVG Repo](https://www.svgrepo.com/) with attribution. See Help → Licenses in the app for full details.
