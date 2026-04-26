---
layout: default
title: Magpie User Guide
---

# Magpie User Guide

*Permissive Annotation Extension*

Magpie is a screenshot annotation tool built for technical writers. This guide covers everything you need to get started and make the most of the app.

---

## Getting Started

### Open an Image

- **File → Open** (Ctrl+O) — browse for an image file
- **Drag and drop** an image file onto the window
- **Ctrl+V** — paste from clipboard (works from any tool)
- **File → New** — create a blank canvas

### Navigate the Canvas

- **Ctrl+Scroll** — zoom in/out
- **Ctrl+Drag** — pan when zoomed in
- **Ctrl+0** — reset zoom to fit
- **+/- buttons** — zoom in/out

### Select a Tool

Choose a tool from the Toolbox dropdown in the toolbar or from the sidebar. Click the **?** button to open the help panel — it updates automatically as you switch tools with detailed instructions for each one.

---

## Tools

### Shapes

**Rectangle** — Click and drag to draw. Hold Shift for a perfect square. Drag handles to resize. Enable Fill to use the Secondary color. Click outside to apply, right-click to cancel.

**Oval** — Click and drag to draw. Hold Shift for a perfect circle. Same editing and commit behavior as Rectangle.

**Line** — Click and drag to draw. Four control point handles appear — drag endpoints to reposition, drag inner handles to bend into a curve. Once an inner handle is moved, endpoints no longer move them. Click outside to apply, right-click to cancel.

**Arrow** — Same as Line, but with an arrowhead at the end point.

### Annotation

**Text** — Click and drag to create a text box, then type. Adjust font, size, alignment, bold/italic/underline, shadow, and outline in the toolbar. Click outside to apply, right-click to cancel.

**Step Marker** — Click to place numbered badges that auto-increment. Drag the badge to reposition, drag the tail handle to point at a target. Click Apply All to commit all markers.

**Highlight** — Three styles: Pen (freehand stroke), Rectangle (semi-transparent box), and Spotlight (dims everything outside the rectangle).

### Image Editing

**Crop** — Drag to define the area to keep. Adjust with handles or drag inside to reposition. Click Apply Crop to apply, Cancel or Escape to discard.

**Cut Out** — Removes a horizontal or vertical strip from the image and joins the two halves. Choose a seam style: Sawtooth, Line, or No effect.

**Remove Space** — Automatically detects and removes empty rows or columns. Choose a direction, detection mode, and adjust Keep, Min Gap, and Tolerance sliders. Click Preview, then Apply.

**Magnify Inset** — Click and drag to select a source area, then click elsewhere to place a zoomed callout. Adjust shape, zoom level, border, and connection lines.

**Transform** — Rotate (90° buttons or custom angle), flip horizontally/vertically, and resize by pixels or percentage. Changes preview live. Click Apply to commit.

### Redaction

**Pixelate** — Drag a rectangle over sensitive content. The mosaic effect previews in real time. Adjust Block Size for more or less obscuring. Click outside to apply.

**Blur** — Drag a rectangle to define the area. Choose Inside or Outside, adjust Radius and Feather. Click outside to apply.

### Drawing

**Freehand** — Six modes: Pen, Brush, Spray Can, Flood Fill, Color Eraser, and Eraser. Adjust size and tolerance as needed.

### Other

**Outline** — Adds a border around the entire image. Set thickness and corner radius, click Preview, then Apply.

**Color & Light** — Adjust Brightness, Contrast, Hue, and Sharpness with sliders. All adjustments preview live. Click Apply to commit, Reset to revert.

**Cut / Paste** — Drag to select a region. Cut, Copy, or Delete. Drag inside a selection to move it. After pasting, drag to reposition and use handles to resize. Click outside to apply.

---

## Colors

Click the **Primary** or **Secondary** swatch to choose which one to edit, then pick a color from the palette. Use the eyedropper to pick a color directly from the canvas.

Most tools use the Primary color. Fill and text outline use the Secondary color.

---

## Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Open | Ctrl+O |
| Save | Ctrl+S |
| Save As | Ctrl+Shift+S |
| Copy | Ctrl+C |
| Paste | Ctrl+V |
| Undo | Ctrl+Z |
| Redo | Ctrl+Y |
| New | Ctrl+N |
| Zoom In | Ctrl+= |
| Zoom Out | Ctrl+- |
| Reset Zoom | Ctrl+0 |

---

## Publishing

Configure FTP destinations in Settings → FTP Settings. Use the Upload dropdown in the toolbar to publish via FTP, FTPS, or SFTP.

---

## Getting Help

- **In-app help panel** — click the **?** button for tool-specific instructions
- **Help → Getting Started** — quick overview of all features
- **[Report a bug](https://github.com/dposto/magpie/issues)**
- **[Request a feature](https://github.com/dposto/magpie/issues)**

---

*Magpie is a [sudo sketchy](https://github.com/dposto) project by David Posto.*
