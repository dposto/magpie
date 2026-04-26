#!/usr/bin/env python3

# =========================================================
# Early debug / logging setup (MUST be first)
# =========================================================

import sys
import traceback
import logging
import os
from pathlib import Path

APP_NAME = "Magpie"
APP_VERSION = "1.0.0"

# Hard safety ceiling for image dimensions.  A 16000x16000 RGBA image is ~1 GB
# in memory.  This limit is NOT user-configurable — it exists purely to prevent
# the app from freezing or crashing on absurdly large inputs.  The user's
# configurable resize prompt (check_image_size / max_image_dimension) handles
# normal "large screenshot" scenarios well below this threshold.
_MAX_IMAGE_HARD_LIMIT = 16000

state_base = Path(
    os.getenv("XDG_STATE_HOME", Path.home() / ".local" / "state")
)

log_dir = state_base / APP_NAME
try:
    log_dir.mkdir(parents=True, exist_ok=True)
except Exception:
    log_dir = Path.home()

log_file = log_dir / "debug.log"

from logging.handlers import RotatingFileHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        ),
    ],
)

logging.info(f"Magpie v{APP_VERSION} starting")

# =========================================================
# Global crash handler (must be early)
# =========================================================

def global_excepthook(exc_type, exc_value, exc_tb):
    logging.critical(
        "Uncaught exception",
        exc_info=(exc_type, exc_value, exc_tb)
    )
    # Try to show a dialog so the user knows what happened.
    # QApplication may not exist yet (crash during startup) so wrap everything.
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance()
        if app is not None:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Icon.Critical)
            msg.setWindowTitle("Magpie — Crash")
            msg.setText("Something went wrong and the app needs to close.")
            msg.setInformativeText(
                f"Details have been saved to the log file:\n\n{log_file}\n\n"
                f"Error: {exc_type.__name__}: {exc_value}"
            )
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()
    except Exception:
        pass  # If the dialog itself fails, just exit quietly
    sys.exit(1)

sys.excepthook = global_excepthook

# =========================================================
# Standard imports
# =========================================================

import math
import json
import ftplib
import platform
from io import BytesIO
from PIL import Image
import warnings

# Guard against decompression bombs — enforce pixel limit before decode/copy.
# Pillow's default is ~178M pixels; we promote the warning to an error
# so Image.open() raises instead of silently allocating gigabytes of RAM.
Image.MAX_IMAGE_PIXELS = 178_956_970  # ~13354x13354
warnings.filterwarnings("error", category=Image.DecompressionBombWarning)

# Verify numpy is available — it's a hard dependency for blur, pixelate,
# color/light, text rendering, and other core features.
try:
    import numpy as np
    _numpy_available = True
except ImportError:
    _numpy_available = False
    logging.critical(
        "NumPy is not installed. Many features will not work. "
        "Install it with:  pip install numpy"
    )

# =========================================================
# PyQt imports (after logging + crash hook)
# =========================================================

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QComboBox, QSpinBox, QDoubleSpinBox,
    QStackedWidget, QCheckBox, QColorDialog, QDialog,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
    QFormLayout, QDialogButtonBox, QGroupBox, QInputDialog, QGridLayout, QScrollArea,
    QSizePolicy, QFrame, QStyle, QSlider
)
from PyQt6.QtCore import Qt, QPoint, QMimeData, QRect, QRectF, QEvent, QEventLoop, QByteArray, QBuffer, pyqtSignal, QSize, QThread
from PyQt6.QtGui import (
    QPixmap, QImage, QPainter, QPainterPath,
    QColor, QPen, QPainterPathStroker, QBrush, QDrag, QIcon
)

# =========================================================
# Config file handling
# =========================================================

import ast
import base64

# --- Secure credential storage via OS keyring ---
# Falls back to legacy base64 if keyring is not available or insecure.
_KEYRING_SERVICE = "Magpie"
_keyring_available = False
try:
    import keyring as _keyring
    # Reject insecure backends (PlaintextKeyring, ChainerBackend wrapping it, etc.)
    _backend_name = type(_keyring.get_keyring()).__name__
    if "Plaintext" in _backend_name or "Fail" in _backend_name or "Null" in _backend_name:
        logging.warning(f"Keyring backend '{_backend_name}' is not secure — passwords will not be saved between sessions")
        _keyring_available = False
    else:
        # Quick smoke-test: some Linux installs have keyring but no working backend
        _keyring.get_credential(_KEYRING_SERVICE, "connectivity-test")
        _keyring_available = True
except Exception:
    _keyring_available = False


def is_keyring_available():
    """Check if secure credential storage is available."""
    return _keyring_available


def save_password(username, password):
    """Save password to OS keyring. Returns '' on success or if no keyring."""
    if _keyring_available and username:
        try:
            _keyring.set_password(_KEYRING_SERVICE, username, password or "")
            return ""  # empty string signals "stored in keyring"
        except Exception:
            pass
    # No fallback — password will not persist. User re-enters each session.
    return ""


def load_password(username, encoded_fallback=""):
    """Load password from OS keyring.
    If a legacy base64 value exists in config, migrate it to keyring and
    signal that the caller should clear ftp_pass_encoded from config."""
    if _keyring_available and username:
        try:
            pw = _keyring.get_password(_KEYRING_SERVICE, username)
            if pw is not None:
                return pw
        except Exception:
            pass
    # Migrate legacy base64 if present
    if encoded_fallback:
        legacy_pw = _decode_password_b64(encoded_fallback)
        if legacy_pw and _keyring_available and username:
            try:
                _keyring.set_password(_KEYRING_SERVICE, username, legacy_pw)
                logging.info("Migrated legacy base64 password to OS keyring")
            except Exception:
                pass
        return legacy_pw
    return ""


def delete_password(username):
    """Remove password from OS keyring (best-effort)."""
    if _keyring_available and username:
        try:
            _keyring.delete_password(_KEYRING_SERVICE, username)
        except Exception:
            pass


def _decode_password_b64(encoded):
    """Legacy base64 decode (kept for migration from older config files)."""
    if not encoded:
        return ""
    try:
        return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
    except Exception:
        return encoded


def get_config_dir():
    """Get platform-appropriate config directory"""
    if platform.system() == "Windows":
        config_base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        config_base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    config_dir = config_base / "magpie"
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    return config_dir

def load_config():
    """Load config from file, return defaults if not found"""
    config_path = get_config_dir() / "settings.json"
    default_config = {
        "ftp_host": "",
        "ftp_url": "",
        "ftp_user": "",
        "ftp_pass_encoded": "",
        "upload_protocol": "FTP",
        "web_url_base": "",
        "url_template": "",
        "destinations": [],
        "last_destination": "",
        "destination_last_paths": {},  # {"NEST": "/knowledge/NEST/12345/67890/", ...}
        "remember_last_folder": True,
        "copy_url_after_upload": True,
        "toolbox_most_used": [],  # Tools to show in top section (by default, empty = all tools)
        "toolbox_less_used": [],  # Tools to show in bottom section
        "toolbox_hidden": [],      # Tools to hide from dropdown
        "toolbar_most_used": [],   # Tools to show on left side of toolbar divider
        "toolbar_less_used": [],   # Tools to show on right side of toolbar divider
        "toolbar_hidden": [],      # Tools to hide from toolbar
        "recent_files": [],        # Recent files list
        "check_image_size": True,  # Prompt when images exceed size limit
        "max_image_dimension": 1920,  # Maximum width or height in pixels
        "large_image_action": "prompt",  # Options: "prompt", "always_resize", "ignore"
        # Status bar settings
        "status_bar_visible": True,
        "status_bar_cursor": True,
        "status_bar_color": True,
        "status_bar_color_format": "rgb",  # "rgb" or "hex"
        "status_bar_size": True,
        "status_bar_zoom": True,
        "status_bar_modified": True,
        # Drawing settings
        "smooth_drawing": False,  # Anti-aliased drawing (True) vs pixel-perfect (False)
    }
    
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                loaded = json.load(f)
                # Merge with defaults in case new fields were added
                return {**default_config, **loaded}
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
    
    return default_config

def save_config(config):
    """Save config to file"""
    config_path = get_config_dir() / "settings.json"
    try:
        # Convert positioned palette dict to JSON-serializable format
        if 'custom_palette' in config and isinstance(config['custom_palette'], dict):
            serializable_palette = {}
            for key, rgba in config['custom_palette'].items():
                # Check if key is already a string (already serialized)
                if isinstance(key, str):
                    serializable_palette[key] = list(rgba) if isinstance(rgba, tuple) else rgba
                else:
                    # Key is a tuple - convert to string
                    row, col = key
                    serializable_palette[f"({row},{col})"] = list(rgba)
            config = config.copy()
            config['custom_palette'] = serializable_palette
        
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to save config: {e}")
        import traceback
        traceback.print_exc()

# =========================================================
# QImage <-> PIL
# =========================================================

def PilToQImage(pil, for_painting=False):
    """Convert a PIL Image to QImage.

    Note: QImage can reference the provided Python buffer without owning it.
    We attach the buffer to the QImage instance to keep it alive for the
    lifetime of the QImage.

    When putting a QImage on the system clipboard, you should pass a detached
    copy (qimg.copy()) so the clipboard owns its bytes.
    
    If for_painting=True, returns a QImage in ARGB32_Premultiplied format
    which is optimal for QPainter operations with anti-aliasing.
    """
    img = pil.convert("RGBA")
    data = img.tobytes("raw", "RGBA")
    qimg = QImage(
        data,
        img.width,
        img.height,
        img.width * 4,
        QImage.Format.Format_RGBA8888,
    )
    # Keep the backing store alive for as long as this QImage object exists.
    qimg._buf = data  # type: ignore[attr-defined]
    
    # For painting, convert to ARGB32_Premultiplied (Qt's preferred format for anti-aliased painting)
    if for_painting:
        return qimg.convertToFormat(QImage.Format.Format_ARGB32_Premultiplied)
    return qimg



def QImageToPil(qimg):
    qimg = qimg.convertToFormat(QImage.Format.Format_RGBA8888)
    ptr = qimg.bits()
    ptr.setsize(qimg.sizeInBytes())
    return Image.frombuffer(
        "RGBA", (qimg.width(), qimg.height()),
        bytes(ptr), "raw", "RGBA", 0, 1
    )

# =========================================================
# Seam rendering (Sawtooth)
# =========================================================

def apply_seam_effect(painter, seam, step, gap_percent, outline_color):
    # Calculate stroke width based on gap percentage (this controls the "black space between teeth")
    width = max(2, int(step * (gap_percent / 100.0)))

    if outline_color is None:
        stroker = QPainterPathStroker()
        stroker.setWidth(width)
        stroker.setCapStyle(Qt.PenCapStyle.FlatCap)
        stroker.setJoinStyle(Qt.PenJoinStyle.MiterJoin)
        gap = stroker.createStroke(seam)

        painter.save()
        painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
        painter.fillPath(gap, Qt.GlobalColor.transparent)
        painter.restore()
    else:
        painter.setPen(QPen(
            QColor(*outline_color),
            width,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.FlatCap,
            Qt.PenJoinStyle.MiterJoin
        ))
        painter.drawPath(seam)

# =========================================================
# Cut logic
# =========================================================

def horizontal_cut(img, y1, y2, step, gap_percent, outline_color, style):
    w, h = img.size
    if y1 >= y2:
        return img

    removed = y2 - y1
    out_h = h - removed
    amp = step // 2

    src = PilToQImage(img)
    out = QImage(w, out_h, QImage.Format.Format_RGBA8888)
    out.fill(Qt.GlobalColor.transparent)

    painter = QPainter(out)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    if style == "Sawtooth":
        # Check if cutting at top or bottom edge
        at_top_edge = (y1 <= 0)
        at_bottom_edge = (y2 >= h)
        
        # Only draw sawtooth on sides that remain (not at edges)
        if not at_top_edge or not at_bottom_edge:
            seam = QPainterPath()
            seam.moveTo(0, y1)
            up = True
            # Extend loop by half a tooth past the edge to complete the final point
            for x in range(0, w + step + (step // 2), step):
                # Calculate tooth position - let teeth extend to full points
                tooth_y = y1 - amp if up else y1 + amp
                seam.lineTo(x, tooth_y)
                up = not up

            # Draw top section if it remains
            if not at_top_edge and y1 > 0:
                top = QPainterPath(seam)
                top.lineTo(w, 0)
                top.lineTo(0, 0)
                top.closeSubpath()

                painter.save()
                painter.setClipPath(top)
                painter.drawImage(0, 0, src)
                painter.restore()

            # Draw bottom section if it remains
            if not at_bottom_edge and y2 < h:
                bottom = QPainterPath(seam)
                bottom.lineTo(w, out_h)
                bottom.lineTo(0, out_h)
                bottom.closeSubpath()

                painter.save()
                painter.setClipPath(bottom)
                painter.drawImage(0, -removed, src)
                painter.restore()

            # Only apply seam effect if not cutting at both edges
            if not (at_top_edge and at_bottom_edge):
                apply_seam_effect(painter, seam, step, gap_percent, outline_color)
        else:
            # Cutting entire image - just return empty
            pass
    elif style == "Line":
        # Line style - draw a straight line at the seam using primary color and size as thickness
        if y1 > 0:
            painter.drawImage(0, 0, src, 0, 0, w, y1)
        if y2 < h:
            painter.drawImage(0, y1, src, 0, y2, w, h - y2)
        if outline_color:
            line_pen = QPen(QColor(*outline_color), step, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap)
            painter.setPen(line_pen)
            painter.drawLine(0, y1, w, y1)
    else:
        # No effect style
        if y1 > 0:
            painter.drawImage(0, 0, src, 0, 0, w, y1)
        if y2 < h:
            painter.drawImage(0, y1, src, 0, y2, w, h - y2)

    painter.end()
    return QImageToPil(out)

def vertical_cut(img, x1, x2, step, gap_percent, outline_color, style):
    w, h = img.size
    if x1 >= x2:
        return img

    removed = x2 - x1
    out_w = w - removed
    amp = step // 2

    src = PilToQImage(img)
    out = QImage(out_w, h, QImage.Format.Format_RGBA8888)
    out.fill(Qt.GlobalColor.transparent)

    painter = QPainter(out)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    if style == "Sawtooth":
        # Check if cutting at left or right edge
        at_left_edge = (x1 <= 0)
        at_right_edge = (x2 >= w)
        
        # Only draw sawtooth on sides that remain (not at edges)
        if not at_left_edge or not at_right_edge:
            seam = QPainterPath()
            seam.moveTo(x1, 0)
            up = True
            # Extend loop by half a tooth past the edge to complete the final point
            for y in range(0, h + step + (step // 2), step):
                # Calculate tooth position - let teeth extend to full points
                tooth_x = x1 - amp if up else x1 + amp
                seam.lineTo(tooth_x, y)
                up = not up

            # Draw left section if it remains
            if not at_left_edge and x1 > 0:
                left = QPainterPath(seam)
                left.lineTo(0, h)
                left.lineTo(0, 0)
                left.closeSubpath()

                painter.save()
                painter.setClipPath(left)
                painter.drawImage(0, 0, src)
                painter.restore()

            # Draw right section if it remains
            if not at_right_edge and x2 < w:
                right = QPainterPath(seam)
                right.lineTo(out_w, h)
                right.lineTo(out_w, 0)
                right.closeSubpath()

                painter.save()
                painter.setClipPath(right)
                painter.drawImage(-removed, 0, src)
                painter.restore()

            # Only apply seam effect if not cutting at both edges
            if not (at_left_edge and at_right_edge):
                apply_seam_effect(painter, seam, step, gap_percent, outline_color)
        else:
            # Cutting entire image - just return empty
            pass
    elif style == "Line":
        # Line style - draw a straight line at the seam using primary color and size as thickness
        if x1 > 0:
            painter.drawImage(0, 0, src, 0, 0, x1, h)
        if x2 < w:
            painter.drawImage(x1, 0, src, x2, 0, w - x2, h)
        if outline_color:
            line_pen = QPen(QColor(*outline_color), step, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap)
            painter.setPen(line_pen)
            painter.drawLine(x1, 0, x1, h)
    else:
        # No effect style
        if x1 > 0:
            painter.drawImage(0, 0, src, 0, 0, x1, h)
        if x2 < w:
            painter.drawImage(x1, 0, src, x2, 0, w - x2, h)

    painter.end()
    return QImageToPil(out)

# =========================================================
# Auto-scrolling Toolbar Wrapper
# =========================================================

class AutoScrollToolbarWrapper(QWidget):
    """Wraps a QToolBar in a clipping container with hover-to-scroll edges.
    
    Uses move() to shift the toolbar up/down within a clipped container,
    avoiding QScrollArea which doesn't work well with QToolBar's layout.
    Hovering near the top or bottom edge auto-scrolls (Ubuntu sidebar style).
    """
    _HOT_ZONE_PX = 28
    _SCROLL_INTERVAL_MS = 30
    _SCROLL_BASE_SPEED = 2
    _SCROLL_MAX_SPEED = 12
    _RAMP_TICKS = 15

    def __init__(self, toolbar, parent=None):
        super().__init__(parent)
        self._toolbar = toolbar
        self._scroll_offset = 0  # how far the toolbar is shifted up (positive = scrolled down)
        self._scroll_dir = 0
        self._ramp_count = 0

        # Clip children so toolbar doesn't overflow
        self.setFixedWidth(toolbar.width())
        toolbar.setParent(self)
        toolbar.move(0, 0)
        toolbar.show()

        # Timer for smooth scrolling
        from PyQt6.QtCore import QTimer
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setInterval(self._SCROLL_INTERVAL_MS)
        self._scroll_timer.timeout.connect(self._do_scroll)

        # Track mouse for hot zone detection
        self.setMouseTracking(True)
        toolbar.setMouseTracking(True)
        toolbar.installEventFilter(self)

    def _toolbar_overflow(self):
        """How many pixels the toolbar extends beyond the visible area."""
        return max(0, self._toolbar.sizeHint().height() - self.height())

    def resizeEvent(self, event):
        """When the wrapper resizes, clamp the scroll offset."""
        super().resizeEvent(event)
        self._clamp_and_apply()

    def paintEvent(self, event):
        """Clip painting to our bounds."""
        super().paintEvent(event)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.MouseMove:
            local = self.mapFromGlobal(event.globalPosition().toPoint())
            self._check_hot_zones(local.y())
        elif event.type() == QEvent.Type.Leave:
            self._stop_scroll()
        return super().eventFilter(obj, event)

    def enterEvent(self, event):
        pos = event.position() if hasattr(event, 'position') else event.pos()
        self._check_hot_zones(int(pos.y()))
        super().enterEvent(event)

    def mouseMoveEvent(self, event):
        self._check_hot_zones(event.pos().y())
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        self._stop_scroll()
        super().leaveEvent(event)

    def wheelEvent(self, event):
        """Allow mouse wheel to scroll the toolbar too."""
        overflow = self._toolbar_overflow()
        if overflow > 0:
            delta = event.angleDelta().y()
            self._scroll_offset = max(0, min(overflow, self._scroll_offset - delta // 4))
            self._clamp_and_apply()
            event.accept()
        else:
            super().wheelEvent(event)

    def _check_hot_zones(self, y):
        overflow = self._toolbar_overflow()
        if overflow <= 0:
            self._stop_scroll()
            return

        if y < self._HOT_ZONE_PX and self._scroll_offset > 0:
            if self._scroll_dir != -1:
                self._scroll_dir = -1
                self._ramp_count = 0
                self._scroll_timer.start()
        elif y > self.height() - self._HOT_ZONE_PX and self._scroll_offset < overflow:
            if self._scroll_dir != 1:
                self._scroll_dir = 1
                self._ramp_count = 0
                self._scroll_timer.start()
        else:
            self._stop_scroll()

    def _do_scroll(self):
        overflow = self._toolbar_overflow()
        self._ramp_count = min(self._ramp_count + 1, self._RAMP_TICKS)
        t = self._ramp_count / self._RAMP_TICKS
        speed = int(self._SCROLL_BASE_SPEED + t * (self._SCROLL_MAX_SPEED - self._SCROLL_BASE_SPEED))
        self._scroll_offset += self._scroll_dir * speed
        self._clamp_and_apply()

        if (self._scroll_dir < 0 and self._scroll_offset <= 0) or \
           (self._scroll_dir > 0 and self._scroll_offset >= overflow):
            self._stop_scroll()

    def _clamp_and_apply(self):
        overflow = self._toolbar_overflow()
        self._scroll_offset = max(0, min(overflow, self._scroll_offset))
        self._toolbar.move(0, -self._scroll_offset)

    def _stop_scroll(self):
        self._scroll_dir = 0
        self._ramp_count = 0
        self._scroll_timer.stop()


# =========================================================
# Crosshair Overlay Widget
# =========================================================

class CrosshairOverlay(QWidget):
    """Transparent overlay for drawing crosshair over the viewport (including black area)"""
    def __init__(self, main_window, scroll_area, viewer):
        super().__init__(scroll_area.viewport())
        self.main = main_window
        self.scroll_area = scroll_area
        self.viewer = viewer
        
        # Transparent to mouse events and background
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setMouseTracking(True)
        
        # Size to viewport
        self.resize(scroll_area.viewport().size())
        self.show()
        
        # Keep sized to viewport
        scroll_area.viewport().installEventFilter(self)
    
    def eventFilter(self, obj, event):
        from PyQt6.QtCore import QEvent
        if obj is self.scroll_area.viewport():
            if event.type() == QEvent.Type.Resize:
                self.resize(self.scroll_area.viewport().size())
                self.update()
            elif event.type() == QEvent.Type.MouseButtonPress:
                # Handle clicks in the black area (outside the image) for paste apply
                from PyQt6.QtCore import Qt
                if event.button() == Qt.MouseButton.LeftButton:
                    if self.viewer.cutpaste_paste_pos and self.viewer.cutpaste_clipboard:
                        # Check if click is outside the paste preview
                        px1, py1, px2, py2 = self.viewer.cutpaste_paste_pos
                        # Map click position from viewport to viewer coordinates
                        viewer_pos = self.viewer.mapFrom(self.scroll_area.viewport(), event.pos())
                        click_x, click_y = viewer_pos.x(), viewer_pos.y()
                        
                        # Check if outside paste preview
                        if not (px1 <= click_x <= px2 and py1 <= click_y <= py2):
                            # Apply the paste
                            self.main.apply_paste()
                            return True  # Event handled
        return False
    
    def paintEvent(self, event):
        if not getattr(self.main, "crosshair_enabled", False):
            return
        if not self.viewer.image:
            return
        
        from PyQt6.QtGui import QCursor, QPainter
        
        # Get cursor in viewport coords
        vp_pos = self.mapFromGlobal(QCursor.pos())
        
        # Convert to viewer coords
        viewer_pos = self.viewer.mapFrom(self.scroll_area.viewport(), vp_pos)
        
        # Convert to image coords
        scale = float(self.viewer.scale) if getattr(self.viewer, "scale", None) else 1.0
        img_x = int(viewer_pos.x() / scale)
        img_y = int(viewer_pos.y() / scale)
        
        # Draw
        p = QPainter(self)
        self.draw_crosshair_on_overlay(p, vp_pos, img_x, img_y)
    
    def draw_crosshair_on_overlay(self, p, vp_pos, img_x, img_y):
        from PyQt6.QtGui import QPainterPath, QFont, QPen
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QColor
        
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        
        size = self.main.crosshair_size
        pixel_scale = 16
        grab_pixels = max(5, int(size / pixel_scale))
        if grab_pixels % 2 == 0:
            grab_pixels += 1
        half = grab_pixels // 2
        pixel_size = int(size / grab_pixels)
        actual_draw_size = grab_pixels * pixel_size
        
        # Position with offset
        offset_x, offset_y = 40, 40
        draw_x = int(vp_pos.x() + offset_x)
        draw_y = int(vp_pos.y() + offset_y)
        
        if draw_x + actual_draw_size > self.width():
            draw_x = int(vp_pos.x() - actual_draw_size - 10)
        if draw_y + actual_draw_size > self.height():
            draw_y = int(vp_pos.y() - actual_draw_size - 10)
        
        # Circular clip
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        path = QPainterPath()
        path.addEllipse(draw_x, draw_y, actual_draw_size, actual_draw_size)
        p.setClipPath(path)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        
        p.fillRect(draw_x, draw_y, actual_draw_size, actual_draw_size, QColor(40, 40, 40))
        
        # Draw pixels
        if self.viewer.image:
            w, h = self.viewer.image.size
            start_x, start_y = img_x - half, img_y - half
            center_col, center_row = half, half
            has_alpha = self.viewer.image.mode in ('RGBA', 'LA', 'PA')
            
            for row in range(grab_pixels):
                for col in range(grab_pixels):
                    px_x, px_y = start_x + col, start_y + row
                    
                    # Sample pixel color
                    if 0 <= px_x < w and 0 <= px_y < h:
                        px = self.viewer.image.getpixel((px_x, px_y))
                        if isinstance(px, int):
                            r, g, b, a = px, px, px, 255
                        elif len(px) == 4:
                            r, g, b, a = int(px[0]), int(px[1]), int(px[2]), int(px[3])
                        elif len(px) >= 3:
                            r, g, b, a = int(px[0]), int(px[1]), int(px[2]), 255
                        else:
                            r = g = b = int(px[0]); a = 255
                        
                        # Composite against checkerboard if transparent
                        if a < 255 and has_alpha:
                            # Determine checkerboard color for this pixel
                            cs = 8  # checkerboard square size, matches main canvas
                            if (px_x // cs + px_y // cs) % 2 == 0:
                                bg_r, bg_g, bg_b = 255, 255, 255
                            else:
                                bg_r, bg_g, bg_b = 204, 204, 204
                            fa = a / 255.0
                            r = int(r * fa + bg_r * (1.0 - fa))
                            g = int(g * fa + bg_g * (1.0 - fa))
                            b = int(b * fa + bg_b * (1.0 - fa))
                    else:
                        r = g = b = 40
                    
                    # Highlight center row/column - blend with light blue like a translucent highlighter
                    if (row == center_row or col == center_col) and not (row == center_row and col == center_col):
                        a = 0.30
                        r = int(r * (1.0 - a) + 100 * a)
                        g = int(g * (1.0 - a) + 180 * a)
                        b = int(b * (1.0 - a) + 255 * a)
                    
                    p.fillRect(draw_x + col * pixel_size, draw_y + row * pixel_size, pixel_size, pixel_size, QColor(r, g, b))
            
            # Grid
            p.setPen(QPen(QColor(0, 0, 0), 1))
            for i in range(grab_pixels + 1):
                p.drawLine(draw_x + i * pixel_size, draw_y, draw_x + i * pixel_size, draw_y + actual_draw_size)
                p.drawLine(draw_x, draw_y + i * pixel_size, draw_x + actual_draw_size, draw_y + i * pixel_size)
        
        p.restore()
        
        # Circle
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        p.setPen(QPen(QColor(255, 255, 255), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(draw_x, draw_y, actual_draw_size, actual_draw_size)
        p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
        p.drawEllipse(draw_x + 1, draw_y + 1, actual_draw_size - 2, actual_draw_size - 2)
        
        # Center pixel border (black outline with white inner, all inside the pixel)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        center_pixel_x = draw_x + center_col * pixel_size
        center_pixel_y = draw_y + center_row * pixel_size
        
        # Black outer border (1 pixel from edge)
        p.setPen(QPen(QColor(0, 0, 0), 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRect(center_pixel_x + 1, center_pixel_y + 1, pixel_size - 2, pixel_size - 2)
        
        # White inner border (2 pixels from edge)
        p.setPen(QPen(QColor(255, 255, 255), 1))
        p.drawRect(center_pixel_x + 2, center_pixel_y + 2, pixel_size - 4, pixel_size - 4)
        
        # Text
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
        coord_text = f"X: {img_x} Y: {img_y}"
        font = QFont()
        font.setFamily("Arial")
        font.setPixelSize(13)
        font.setBold(True)
        font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
        p.setFont(font)
        
        text_x = draw_x + actual_draw_size // 2 - 30
        text_y = draw_y + actual_draw_size + 15
        
        outline_pen = QPen(QColor(0, 0, 0), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        for dx in [-1, 0, 1]:
            for dy in [-1, 0, 1]:
                if dx != 0 or dy != 0:
                    p.setPen(outline_pen)
                    p.drawText(text_x + dx, text_y + dy, coord_text)
        
        p.setPen(QPen(QColor(255, 255, 255), 1, Qt.PenStyle.SolidLine))
        p.drawText(text_x, text_y, coord_text)

# =========================================================
# Custom Toolbox ComboBox
# =========================================================

class ToolboxComboBox(QComboBox):
    """Custom combo box that resets to 'Select tool' position when opened"""
    def showPopup(self):
        # Reset to index 0 (Select tool) before showing popup
        if self.currentIndex() != 0:
            self.blockSignals(True)
            self.setCurrentIndex(0)
            self.blockSignals(False)
        super().showPopup()


class DropDownComboBox(QComboBox):
    """ComboBox that always drops downward.
    
    Uses editable + read-only trick: editable combos use a popup that
    always drops down from the top. Making the line edit read-only
    prevents user typing while keeping the drop-down behavior.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        # Make it look like a normal combo (not an editable text field)
        self.lineEdit().setStyleSheet("background: transparent;")
        self.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)

    def addItems(self, texts):
        """Override to recalculate minimum width after adding items."""
        super().addItems(texts)
        self._update_min_width()

    def addItem(self, *args, **kwargs):
        """Override to recalculate minimum width after adding an item."""
        super().addItem(*args, **kwargs)
        self._update_min_width()

    def _update_min_width(self):
        """Set minimum width to fit the longest item plus dropdown arrow."""
        fm = self.fontMetrics()
        max_w = 0
        for i in range(self.count()):
            w = fm.horizontalAdvance(self.itemText(i))
            if w > max_w:
                max_w = w
        # Add padding for the dropdown arrow and margins
        self.setMinimumWidth(max_w + 40)

# =========================================================
# Color Swatch Button with Checkmark
# =========================================================

from PyQt6.QtCore import pyqtSignal

class ColorSwatchButton(QLabel):
    """Color swatch button that can display a checkmark overlay when in use"""
    clicked = pyqtSignal()  # Custom clicked signal
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.show_checkmark = False
        self.is_editable = False
        self.color_rgba = (255, 255, 255, 255)  # Store color with alpha
        self.setFrameStyle(QLabel.Shape.Box)
        self.setLineWidth(1)
        
    def set_color(self, rgba):
        """Set the color (including alpha) for this button"""
        self.color_rgba = rgba
        self.update()
        
    def set_in_use(self, in_use):
        """Set whether this color is in use (shows checkmark)"""
        self.show_checkmark = in_use
        self.update()
    
    def set_editable(self, editable):
        """Set whether this color is editable (shows cyan border)"""
        self.is_editable = editable
        self.update()
    
    def mousePressEvent(self, event):
        """Handle clicks like a button"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
    
    def paintEvent(self, event):
        # Create painter
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Get dimensions
        width = self.width()
        height = self.height()
        rect = self.rect()
        
        # Draw checkerboard pattern if color has transparency
        if len(self.color_rgba) >= 4 and self.color_rgba[3] < 255:
            checker_size = 6  # Slightly larger boxes
            white = QColor(255, 255, 255)
            light_gray = QColor(204, 204, 204)
            
            for y in range(0, height, checker_size):
                for x in range(0, width, checker_size):
                    if ((x // checker_size) + (y // checker_size)) % 2 == 0:
                        painter.fillRect(x, y, checker_size, checker_size, white)
                    else:
                        painter.fillRect(x, y, checker_size, checker_size, light_gray)
        
        # Draw the color
        color = QColor(*self.color_rgba)
        painter.fillRect(rect, color)
        
        # Draw border
        pen = QPen()
        pen.setColor(QColor(102, 102, 102))
        pen.setWidth(1)
        painter.setPen(pen)
        painter.drawRect(rect.adjusted(0, 0, -1, -1))
        
        # Draw underline indicator if this is the active/editable slot
        if self.is_editable:
            parent = self.window()
            is_dark = getattr(parent, '_is_dark_mode', False) if parent else False
            if is_dark:
                # Dark mode: 1px black separator + white bar
                bar_h = 3
                painter.fillRect(0, height - bar_h - 1, width, 1, QColor(0, 0, 0))
                painter.fillRect(0, height - bar_h, width, bar_h, QColor(255, 255, 255))
            else:
                # Light mode: black outline bar + white inner bar (more visible)
                bar_h = 4
                painter.fillRect(0, height - bar_h - 1, width, bar_h + 1, QColor(0, 0, 0))
                painter.fillRect(1, height - bar_h, width - 2, bar_h - 1, QColor(255, 255, 255))
        
        # If in use, draw checkmark overlay
        if self.show_checkmark:
            # Calculate checkmark points
            x_offset = width * 0.2
            y_offset = height * 0.5
            x_mid = width * 0.4
            y_mid = height * 0.7
            x_end = width * 0.8
            y_end = height * 0.25
            
            # Draw the checkmark stroke
            path = QPainterPath()
            path.moveTo(x_offset, y_offset)
            path.lineTo(x_mid, y_mid)
            path.lineTo(x_end, y_end)
            
            # Draw black outline for contrast
            pen = QPen(QColor(0, 0, 0), 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.drawPath(path)
            
            # Draw white checkmark on top
            pen.setColor(QColor(255, 255, 255))
            pen.setWidth(3)
            painter.setPen(pen)
            painter.drawPath(path)

class PaletteButton(QLabel):
    """Small palette button with checkerboard support for transparency"""
    clicked = pyqtSignal()
    doubleClicked = pyqtSignal()
    
    def __init__(self, rgba, parent=None):
        super().__init__(parent)
        self.color_rgba = rgba
        self.setFrameStyle(QLabel.Shape.Box)
        self.setLineWidth(1)
        
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)
    
    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.doubleClicked.emit()
        super().mouseDoubleClickEvent(event)
    
    def paintEvent(self, event):
        painter = QPainter(self)
        
        width = self.width()
        height = self.height()
        rect = self.rect()
        
        # Draw checkerboard for transparent colors
        if len(self.color_rgba) >= 4 and self.color_rgba[3] < 255:
            checker_size = 3  # Smaller for 18x18 buttons
            white = QColor(255, 255, 255)
            light_gray = QColor(204, 204, 204)
            
            for y in range(0, height, checker_size):
                for x in range(0, width, checker_size):
                    if ((x // checker_size) + (y // checker_size)) % 2 == 0:
                        painter.fillRect(x, y, checker_size, checker_size, white)
                    else:
                        painter.fillRect(x, y, checker_size, checker_size, light_gray)
        
        # Draw color
        color = QColor(*self.color_rgba)
        painter.fillRect(rect, color)
        
        # Draw border
        pen = QPen(QColor(102, 102, 102), 1)
        painter.setPen(pen)
        painter.drawRect(rect.adjusted(0, 0, -1, -1))


class PaletteReorderButton(PaletteButton):
    """Palette swatch used in the palette editor: supports selection + drag-reorder."""
    def __init__(self, rgba, index, editor, parent=None):
        super().__init__(rgba, parent)
        self._editor = editor
        self.index = index
        self._selected = False
        self._drag_over = False
        self._press_pos = None
        self._drag_started = False
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMouseTracking(True)  # Enable mouse tracking for drag detection

    def set_selected(self, selected: bool):
        self._selected = bool(selected)
        self.update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._press_pos = event.pos()
            self._drag_started = False
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._press_pos is None:
            return
        if not (event.buttons() & Qt.MouseButton.LeftButton):
            return
        
        # Start drag if moved enough
        distance = (event.pos() - self._press_pos).manhattanLength()
        if distance < QApplication.startDragDistance():
            return
        
        if not self._drag_started:
            self._drag_started = True
            drag = QDrag(self)
            mime = QMimeData()
            # Encode position tuple as "row,col"
            position_str = f"{self.index[0]},{self.index[1]}"
            mime.setData("application/x-palette-index", QByteArray(position_str.encode("utf-8")))
            drag.setMimeData(mime)
            drag.setPixmap(self.grab())
            drag.setHotSpot(event.pos())
            drag.exec(Qt.DropAction.MoveAction)
            self._press_pos = None
            self._drag_started = False
    
    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            # Only emit clicked if we didn't start dragging
            if self._press_pos is not None and not self._drag_started:
                if (event.pos() - self._press_pos).manhattanLength() < QApplication.startDragDistance():
                    self.clicked.emit()
            self._press_pos = None
            self._drag_started = False
        super().mouseReleaseEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat("application/x-palette-index"):
            self._drag_over = True
            self.update()
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self._drag_over = False
        self.update()
        super().dragLeaveEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasFormat("application/x-palette-index"):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        self._drag_over = False
        self.update()

        if not event.mimeData().hasFormat("application/x-palette-index"):
            event.ignore()
            return

        try:
            # Parse "row,col" string back to tuple
            position_str = bytes(event.mimeData().data("application/x-palette-index")).decode("utf-8")
            row, col = position_str.split(',')
            src = (int(row), int(col))
        except Exception:
            event.ignore()
            return

        dst = self.index  # Already a tuple
        if self._editor is not None:
            self._editor.move_swatch(src, dst)

        event.acceptProposedAction()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        # Selection ring
        if self._selected:
            pen = QPen(QColor(80, 80, 208), 3)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(self.rect().adjusted(1, 1, -2, -2))

            # Small checkmark for extra clarity
            pen2 = QPen(QColor(255, 255, 255), 2)
            painter.setPen(pen2)
            r = self.rect().adjusted(6, 6, -6, -6)
            painter.drawLine(r.left(), r.center().y(), r.center().x() - 1, r.bottom())
            painter.drawLine(r.center().x() - 1, r.bottom(), r.right(), r.top() + 2)

        # Drag-over hint
        if self._drag_over:
            pen = QPen(QColor(255, 255, 255, 180), 2, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(self.rect().adjusted(2, 2, -3, -3))

class EmptyPalettePlaceholder(QLabel):
    """Empty placeholder slot that can receive dropped colors"""
    def __init__(self, index, editor, parent=None):
        super().__init__(parent)
        self._editor = editor
        self.index = index
        self._drag_over = False
        self.setFrameStyle(QLabel.Shape.Box)
        self.setLineWidth(1)
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMouseTracking(True)  # Enable mouse tracking
    
    def mousePressEvent(self, event):
        """Handle click to add color at this position"""
        if event.button() == Qt.MouseButton.LeftButton:
            if self._editor and hasattr(self._editor, 'adding_new_color') and self._editor.adding_new_color:
                # In add mode - add color here
                self._editor.add_color_at_position(self.index)
                event.accept()
                return
        super().mousePressEvent(event)
    
    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat("application/x-palette-index"):
            self._drag_over = True
            self.update()
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def dragLeaveEvent(self, event):
        self._drag_over = False
        self.update()
        super().dragLeaveEvent(event)
    
    def dragMoveEvent(self, event):
        if event.mimeData().hasFormat("application/x-palette-index"):
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def dropEvent(self, event):
        self._drag_over = False
        self.update()
        
        if not event.mimeData().hasFormat("application/x-palette-index"):
            event.ignore()
            return
        
        try:
            # Parse "row,col" string back to tuple
            position_str = bytes(event.mimeData().data("application/x-palette-index")).decode("utf-8")
            row, col = position_str.split(',')
            src = (int(row), int(col))
        except Exception:
            event.ignore()
            return
        
        dst = self.index  # Already a tuple
        if self._editor is not None:
            self._editor.move_swatch(src, dst)
        
        event.acceptProposedAction()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        
        # Draw empty dashed box
        if self._drag_over:
            pen = QPen(QColor(80, 80, 208), 2, Qt.PenStyle.DashLine)
            painter.setBrush(QBrush(QColor(240, 240, 255)))
        else:
            pen = QPen(QColor(180, 180, 180), 1, Qt.PenStyle.DashLine)
            painter.setBrush(QBrush(QColor(250, 250, 250)))
        
        painter.setPen(pen)
        painter.drawRect(self.rect().adjusted(1, 1, -2, -2))

# =========================================================
# Image Viewer
# =========================================================

class ImageViewer(QLabel):
    def __init__(self):
        super().__init__()
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("background:#1e1e1e; border:1px solid #333;")
        
        # Enable keyboard focus for text input
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        
        # Enable mouse tracking for status bar updates (cursor position/color even when not clicking)
        self.setMouseTracking(True)
        
        # Prevent the label from expanding when setting pixmap
        from PyQt6.QtWidgets import QSizePolicy
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.setScaledContents(False)
        
        # Track if we're in an active drag operation (for mouse capture)
        self.mouse_captured = False

        self.image = None
        self.history = []
        self.redo_stack = []
        self.scale = 1.0
        self.offset = QPoint()
        self.sel_start = None
        self.sel_end = None
        self.drag_mode = None
        self.selection_finalized = False  # Flag to prevent mouseMoveEvent from updating after release
        self._crop_moving = False
        self._crop_drag_start = None
        self._crop_original_rect = None
        
        # Rectangle tool state
        self.rectangles = []  # List of rectangles being edited
        self.current_rect = None  # Current rectangle being drawn (x1, y1, x2, y2)
        self.dragging_handle = None  # Which handle is being dragged
        self.handle_size = 8  # Size of resize handles
        self._handle_min = 3  # Minimum handle radius for very small shapes
        self._handle_max = 8  # Maximum handle radius (matches handle_size)
        self._handle_scale_threshold = 80  # Shape length at which handles reach full size
        
        # Oval tool state
        self.ovals = []  # List of ovals being edited
        self.current_oval = None  # Current oval being drawn (x1, y1, x2, y2)
        
        # Line tool state
        self.lines = []  # List of lines being edited
        self.current_line = None  # Current line being drawn (x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2) - now uses control points like arrow
        self.line_keep_straight = True  # When True, line stays straight when dragging endpoints
        
        # WYSIWYG shape preview system
        self.shape_preview_image = None   # PIL image with shape rendered on it
        self.shape_preview_pixmap = None  # QPixmap cache for display
        self._shape_preview_key = None    # Cache key to detect when shape coords change
        
        # Arrow tool state
        self.arrows = []  # List of arrows being edited
        self.current_arrow = None  # Current arrow being drawn - now stores (x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2) for Bezier curve
        self.arrow_control_points = 2  # Number of control points for curve
        self.arrow_keep_straight = True  # When True, arrow stays straight when dragging endpoints
        
        # Freehand tool state
        self.freehand_points = []  # List of points being drawn
        self.freehand_last_pos = None  # Last position for continuous drawing
        self._freehand_undo_image = None  # Pre-stroke image for undo
        self._freehand_live_qimg = None  # Live QImage during stroke (KolourPaint-style)
        self._freehand_smooth = False  # Cached smooth_drawing setting during stroke
        
        # Highlight tool state
        self.highlight_strokes = []  # List of completed strokes
        self.current_highlight_stroke = None  # Current stroke being drawn
        self.current_highlight_rect = None  # Current rectangle (x1, y1, x2, y2)
        
        # Pixelate tool state
        self.current_pixelate_rect = None  # Current rectangle (x1, y1, x2, y2)
        
        # Blur tool state
        self.current_blur_rect = None  # Current rectangle (x1, y1, x2, y2)
        
        # Outline tool state
        self.outline_preview_active = False
        
        # Remove Space tool state
        self.rspace_preview_image = None  # PIL image for preview
        
        # Magnify Inset tool state
        self.inset_source_rect = None  # Source selection (x1, y1, x2, y2) in screen coords
        self.inset_dest_pos = None  # Where the magnified inset is placed (x, y) in screen coords
        self.inset_dragging_dest = False  # Dragging the magnified inset
        self.inset_drag_offset = None  # Offset from click to inset top-left
        
        # Step Marker Annotation tool state
        # Each marker: (number, badge_x, badge_y, tail_x, tail_y, has_tail=True/False)
        self.step_markers = []  # List of finalized markers
        self.step_markers_redo = []  # Redo stack for undone markers
        self.current_marker = None  # Current marker being created/edited
        self.marker_counter = 1  # Next marker number to place
        self.active_marker_index = None  # Index of marker being hovered/edited (None if none active)
        self.dragging_badge = False  # Dragging the main badge circle
        self.dragging_tail_handle = False  # Dragging the tail endpoint handle
        self.placing_new_marker = False  # In the middle of placing a new marker
        
        # Text tool state
        self.current_text = None  # Current text being placed: (text, x1, y1, x2, y2)
        self.text_editing = False  # Whether actively typing in the text box
        self.text_cursor_visible = True  # Blinking cursor state
        self.text_cursor_timer = None  # Timer for cursor blink
        self.text_cursor_pos = 0  # Cursor position in text (character index)
        self.text_selection_start = None  # Selection start position (None if no selection)
        self.text_selection_end = None  # Selection end position
        self.selecting_text = False  # Currently dragging to select text
        self.dragging_text_box = False  # Dragging the entire text box
        self.text_click_start = None  # For detecting click vs drag
        
        # Cut/Paste tool state
        self.cutpaste_selection = None  # (x1, y1, x2, y2) in screen coords
        self.cutpaste_clipboard = None  # PIL Image of cut/copied area
        self.cutpaste_paste_pos = None  # Position where paste preview is shown
        self.cutpaste_dragging = False  # Whether we're dragging the pasted selection
        self.cutpaste_resizing = None   # Handle name if resizing paste ('tl','tc','tr','lc','rc','bl','bc','br')
        
        # Crosshair cursor state
        self.crosshair_mouse_pos = None  # Current mouse position for crosshair
        
        # Panning state (Ctrl+drag to pan when image is larger than viewport)
        self.panning = False  # Whether we're currently panning
        self.pan_start_pos = None  # Mouse position when panning started
        self.pan_start_scroll = None  # Scroll position when panning started

    def start_cursor_blink(self):
        """Start cursor blinking timer"""
        from PyQt6.QtCore import QTimer
        if self.text_cursor_timer:
            self.text_cursor_timer.stop()
        self.text_cursor_visible = True
        self.text_cursor_timer = QTimer()
        self.text_cursor_timer.timeout.connect(self.toggle_cursor)
        self.text_cursor_timer.start(500)  # Blink every 500ms
    
    def stop_cursor_blink(self):
        """Stop cursor blinking timer"""
        if self.text_cursor_timer:
            self.text_cursor_timer.stop()
            self.text_cursor_timer = None
    
    def toggle_cursor(self):
        """Toggle cursor visibility"""
        self.text_cursor_visible = not self.text_cursor_visible
        self.update()
    
    def clamp_to_canvas(self, pos):
        """Clamp a position to stay within the canvas bounds.
        
        Returns a QPoint clamped to the visible canvas area.
        """
        if not self.pixmap():
            return pos
        
        # Get canvas bounds (the pixmap area)
        canvas_width = self.pixmap().width()
        canvas_height = self.pixmap().height()
        
        # Clamp x and y to canvas bounds
        x = max(0, min(pos.x(), canvas_width - 1))
        y = max(0, min(pos.y(), canvas_height - 1))
        
        return QPoint(x, y)

    def set_image(self, img, push=True):
        if self.image and push:
            # Store image and current number counter in history
            self.history.append((self.image.copy(), self.marker_counter))
            # Clear redo stack when new change is made
            self.redo_stack = []
            # Limit history to last 20 states to prevent memory issues
            if len(self.history) > 20:
                self.history.pop(0)
            # Mark as having unsaved changes
            parent = self.window()
            if hasattr(parent, 'has_unsaved_changes'):
                parent.has_unsaved_changes = True
            # Update button states
            if hasattr(parent, 'update_tool_buttons_state'):
                parent.update_tool_buttons_state()
            # Update status bar
            if hasattr(parent, '_update_status_bar'):
                parent._update_status_bar()
        self.image = img
        self._cached_base_qimg = None  # Invalidate cached QImage for preview rendering
        # Don't reset zoom - preserve current zoom level
        # Only reset zoom when loading a new source image (handled separately)
        self.update_view()
        # Update status bar with new image size
        parent = self.window()
        if hasattr(parent, '_update_status_bar'):
            parent._update_status_bar()

    def undo(self):
        # Special handling for Step Marker tool - undo per-marker
        parent = self.window()
        if hasattr(parent, 'active_tool') and parent.active_tool == "step_marker":
            if self.current_marker:
                # Remove current (uncommitted) marker preview
                self.current_marker = None
                self.placing_new_marker = False
                self.dragging_badge = False
                self.dragging_tail_handle = False
                self.active_marker_index = None
                self.update()
                if hasattr(parent, 'update_tool_buttons_state'):
                    parent.update_tool_buttons_state()
                return
            elif self.step_markers:
                # Remove last placed (but not yet applied) marker
                removed = self.step_markers.pop()
                self.step_markers_redo.append(removed)
                self.marker_counter = max(1, self.marker_counter - 1)
                # Update toolbar start number to reflect current counter
                if hasattr(parent, 'step_marker_start_toolbar'):
                    parent.step_marker_start_toolbar.blockSignals(True)
                    parent.step_marker_start_toolbar.setValue(self.marker_counter)
                    parent.step_marker_start_toolbar.blockSignals(False)
                self.active_marker_index = None
                self.update()
                if hasattr(parent, 'update_tool_buttons_state'):
                    parent.update_tool_buttons_state()
                return
            elif self.history:
                # Save current state to redo stack before undoing
                self.redo_stack.append((self.image.copy() if self.image else None, self.marker_counter))
                
                # Undo last applied number by restoring image and decrementing counter
                last_entry = self.history.pop()
                # Handle both old format (just image) and new format (image, counter)
                if isinstance(last_entry, tuple):
                    self.image, self.marker_counter = last_entry
                else:
                    self.image = last_entry
                    # Decrement counter since we're undoing a number
                    self.marker_counter = max(1, self.marker_counter - 1)
                self.update_view()
                
                # Update button states
                if hasattr(parent, 'update_tool_buttons_state'):
                    parent.update_tool_buttons_state()
                return
        
        # Normal undo for other tools
        # First, apply any pending annotations (highlight strokes, shapes, etc.)
        # so they get their own undo entry rather than being lost
        parent = self.window()
        if hasattr(parent, '_apply_pending_annotations'):
            parent._apply_pending_annotations()
        
        if self.history:
            # Save current state to redo stack
            if self.image:
                self.redo_stack.append((self.image.copy(), self.marker_counter))
            
            last_entry = self.history.pop()
            # Handle both old format (just image) and new format (image, counter)
            if isinstance(last_entry, tuple):
                self.image, self.marker_counter = last_entry
            else:
                self.image = last_entry
            # Clear any active paste preview when undoing
            self.cutpaste_paste_pos = None
            self.cutpaste_clipboard = None
            self.cutpaste_selection = None
            self._cached_base_qimg = None  # Invalidate cached QImage
            self.update_view()
            
            # Update button states
            parent = self.window()
            if hasattr(parent, 'update_tool_buttons_state'):
                parent.update_tool_buttons_state()

    def redo(self):
        """Redo the last undone action"""
        parent = self.window()
        
        # Special handling for Step Marker tool - redo per-marker
        if hasattr(parent, 'active_tool') and parent.active_tool == "step_marker":
            if self.step_markers_redo:
                restored = self.step_markers_redo.pop()
                self.step_markers.append(restored)
                self.marker_counter += 1
                # Update toolbar start number
                if hasattr(parent, 'step_marker_start_toolbar'):
                    parent.step_marker_start_toolbar.blockSignals(True)
                    parent.step_marker_start_toolbar.setValue(self.marker_counter)
                    parent.step_marker_start_toolbar.blockSignals(False)
                self.update()
                if hasattr(parent, 'update_tool_buttons_state'):
                    parent.update_tool_buttons_state()
                return
        
        if self.redo_stack:
            # Save current state to history
            if self.image:
                self.history.append((self.image.copy(), self.marker_counter))
            
            # Restore from redo stack
            redo_entry = self.redo_stack.pop()
            if isinstance(redo_entry, tuple):
                self.image, self.marker_counter = redo_entry
            else:
                self.image = redo_entry
            
            self.update_view()
            
            # Update button states
            parent = self.window()
            if hasattr(parent, 'update_tool_buttons_state'):
                parent.update_tool_buttons_state()

    def update_view(self):
        if not self.image:
            return
        
        # Display image at current scale (1.0 = 100%)
        qimg = PilToQImage(self.image)
        
        # Create checkerboard background behind the image to show transparency
        w, h = qimg.width(), qimg.height()
        checker = QPixmap(w, h)
        cp = QPainter(checker)
        # Create a small checkerboard tile and tile it for performance
        checker_size = 8
        tile = QPixmap(checker_size * 2, checker_size * 2)
        tile.fill(QColor(255, 255, 255))
        tp = QPainter(tile)
        tp.fillRect(checker_size, 0, checker_size, checker_size, QColor(204, 204, 204))
        tp.fillRect(0, checker_size, checker_size, checker_size, QColor(204, 204, 204))
        tp.end()
        cp.drawTiledPixmap(0, 0, w, h, tile)
        # Draw image on top of checkerboard
        cp.drawImage(0, 0, qimg)
        cp.end()
        pix = checker
        
        if self.scale != 1.0:
            # Scale the image using nearest-neighbor for pixel-perfect display
            scaled_width = int(pix.width() * self.scale)
            scaled_height = int(pix.height() * self.scale)
            scaled = pix.scaled(
                scaled_width, scaled_height,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.FastTransformation  # Nearest-neighbor, not blurry
            )
        else:
            scaled = pix
        
        # Set offset to top-left (scrollbars handle positioning)
        self.offset = QPoint(0, 0)
        self.setPixmap(scaled)
        
        # Resize viewer to match image (scrollbars will appear if needed)
        self.setFixedSize(scaled.width(), scaled.height())
        
        # Force parent viewport repaint to clear any stale overlays
        # (e.g. dotted border from transform preview after apply/cancel)
        # The viewer is a child of the scroll area's viewport, so parent() is the viewport
        parent_widget = self.parent()
        if parent_widget:
            parent_widget.update()

    def _dynamic_handle_size(self, length):
        """Calculate handle dot size based on shape length.
        
        Returns a size in pixels that scales linearly from _handle_min
        to _handle_max as the shape grows from 0 to _handle_scale_threshold.
        Small shapes get small handles so they don't obscure the shape.
        """
        if length >= self._handle_scale_threshold:
            return self._handle_max
        t = max(0.0, length / self._handle_scale_threshold)
        return max(self._handle_min, int(self._handle_min + t * (self._handle_max - self._handle_min)))

    def sample_rgb_at(self, pos: QPoint):

        """Return (r,g,b) at the given widget position, or None if unavailable.

        If a cut/paste preview is currently shown, sample from that preview when the

        cursor is over it (so eyedropper/crosshair reflect what the user sees).

        """

        if not self.image:

            return None


        # 1) Prefer sampling from an active paste preview (if present)

        if getattr(self, 'cutpaste_paste_pos', None) and getattr(self, 'cutpaste_clipboard', None):

            try:

                px1, py1, px2, py2 = self.cutpaste_paste_pos

                left, right = (px1, px2) if px1 <= px2 else (px2, px1)

                top, bottom = (py1, py2) if py1 <= py2 else (py2, py1)

                if left <= pos.x() <= right and top <= pos.y() <= bottom:

                    rect_w = float(max(1, right - left))

                    rect_h = float(max(1, bottom - top))

                    rel_x = int(((pos.x() - left) / rect_w) * self.cutpaste_clipboard.width)

                    rel_y = int(((pos.y() - top) / rect_h) * self.cutpaste_clipboard.height)

                    rel_x = max(0, min(self.cutpaste_clipboard.width - 1, rel_x))

                    rel_y = max(0, min(self.cutpaste_clipboard.height - 1, rel_y))

                    px = self.cutpaste_clipboard.getpixel((rel_x, rel_y))

                    if isinstance(px, int):

                        return (px, px, px)

                    if isinstance(px, (tuple, list)):

                        if len(px) >= 3:

                            return (int(px[0]), int(px[1]), int(px[2]))

                        if len(px) == 2:

                            v = int(px[0])

                            return (v, v, v)

            except Exception:

                pass


        # 2) Fallback: sample from the committed canvas

        try:

            scale = float(self.scale) if self.scale else 1.0

        except Exception:

            scale = 1.0

        x = int(pos.x() / scale)

        y = int(pos.y() / scale)

        w, h = self.image.size

        if x < 0 or y < 0 or x >= w or y >= h:

            return None

        px = self.image.getpixel((x, y))

        if isinstance(px, int):

            return (px, px, px)

        if len(px) >= 3:

            return (int(px[0]), int(px[1]), int(px[2]))

        return None


    def mousePressEvent(self, e):
        parent = self.window()
        
        # Capture mouse on left button press to track drags outside canvas
        if e.button() == Qt.MouseButton.LeftButton:
            self.mouse_captured = True
            self.grabMouse()  # This should capture all mouse events to this widget

        # Ctrl+Left-click starts panning (scrolling the view)
        if e.button() == Qt.MouseButton.LeftButton and e.modifiers() & Qt.KeyboardModifier.ControlModifier:
            if hasattr(parent, 'scroll_area'):
                self.panning = True
                self.pan_start_pos = e.globalPosition().toPoint()
                h_bar = parent.scroll_area.horizontalScrollBar()
                v_bar = parent.scroll_area.verticalScrollBar()
                self.pan_start_scroll = (h_bar.value(), v_bar.value())
                self.setCursor(Qt.CursorShape.ClosedHandCursor)
                return

        # Eyedropper mode: pick a color from the canvas and return to the color dialog
        if getattr(parent, '_eyedropper_active', False):
            # Quick eyedropper mode (no dialog)
            if getattr(parent, '_quick_eyedropper', False):
                if e.button() == Qt.MouseButton.LeftButton:
                    rgb = self.sample_rgb_at(e.pos())
                    if rgb is not None:
                        parent._finish_quick_eyedropper(rgb)
                    else:
                        parent._finish_quick_eyedropper(None)
                elif e.button() == Qt.MouseButton.RightButton:
                    parent._finish_quick_eyedropper(None)
                return
            # Dialog eyedropper mode
            # Safety: if eyedropper is stuck with no dialog, force it off
            if not getattr(parent, '_eyedropper_dialog', None):
                parent._eyedropper_active = False
                parent._force_restore_cursor()
            else:
                if e.button() == Qt.MouseButton.LeftButton:
                    rgb = self.sample_rgb_at(e.pos())
                    if rgb is None:
                        # Clicked outside the image area -> abort picking (do not reopen dialog)
                        if hasattr(parent, '_abort_eyedropper'):
                            parent._abort_eyedropper()
                        else:
                            parent._cancel_eyedropper()
                    else:
                        parent._finish_eyedropper(rgb)
                elif e.button() == Qt.MouseButton.RightButton:
                    # Cancel picking
                    if hasattr(parent, '_abort_eyedropper'):
                        parent._abort_eyedropper()
                    else:
                        parent._cancel_eyedropper()
                return
        # If there's an active paste preview, let the user resize, drag it or click outside to apply
        # regardless of which tool is currently selected.
        if self.cutpaste_paste_pos and self.cutpaste_clipboard:
            if e.button() == Qt.MouseButton.LeftButton:
                px1, py1, px2, py2 = self.cutpaste_paste_pos
                
                # Check handles first (for resizing)
                handle = self.get_handle_at_pos(e.pos(), (px1, py1, px2, py2))
                if handle:
                    self.cutpaste_resizing = handle
                    return
                
                if px1 <= e.pos().x() <= px2 and py1 <= e.pos().y() <= py2:
                    self.cutpaste_dragging = True
                    self.sel_start = e.pos()
                    return
                else:
                    parent.apply_paste()
                    return
            elif e.button() == Qt.MouseButton.RightButton:
                # Cancel paste preview without applying
                self.cutpaste_paste_pos = None
                self.cutpaste_clipboard = None
                self.cutpaste_dragging = False
                self.sel_start = None
                self.sel_end = None
                self.update()
                # Update button states
                parent = self.window()
                if hasattr(parent, 'update_tool_buttons_state'):
                    parent.update_tool_buttons_state()
                return

        
        # Handle rectangle tool
        if hasattr(parent, 'active_tool') and parent.active_tool == "rectangle":
            # Right-click cancels current rectangle
            if e.button() == Qt.MouseButton.RightButton:
                if self.current_rect:
                    self.current_rect = None
                    self.sel_start = None
                    self.sel_end = None
                    self.clear_shape_preview()
                    self.update()
                return
            
            # Left-click for drawing
            if e.button() == Qt.MouseButton.LeftButton:
                # Check if clicking on a handle of current_rect
                if self.current_rect:
                    handle = self.get_handle_at_pos(e.pos(), self.current_rect)
                    if handle:
                        self.dragging_handle = handle
                        return
                    else:
                        # Clicked elsewhere - apply current rect immediately
                        parent.apply_pending_rectangles([self.current_rect])
                        self.current_rect = None
                        self.dragging_handle = None
                
                # Start new rectangle
                self.sel_start = e.pos()
                self.sel_end = e.pos()
                self.current_rect = None
        
        # Handle oval tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "oval":
            # Right-click cancels current oval
            if e.button() == Qt.MouseButton.RightButton:
                if self.current_oval:
                    self.current_oval = None
                    self.sel_start = None
                    self.sel_end = None
                    self.clear_shape_preview()
                    self.update()
                return
            
            # Left-click for drawing
            if e.button() == Qt.MouseButton.LeftButton:
                # Check if clicking on a handle of current_oval
                if self.current_oval:
                    handle = self.get_handle_at_pos(e.pos(), self.current_oval)
                    if handle:
                        self.dragging_handle = handle
                        return
                    else:
                        # Clicked elsewhere - apply current oval immediately
                        parent.apply_pending_ovals([self.current_oval])
                        self.current_oval = None
                        self.dragging_handle = None
                
                # Start new oval
                self.sel_start = e.pos()
                self.sel_end = e.pos()
                self.current_oval = None
        
        # Handle line tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "line":
            # Right-click cancels current line
            if e.button() == Qt.MouseButton.RightButton:
                if self.current_line:
                    self.current_line = None
                    self.line_keep_straight = True
                    self.sel_start = None
                    self.sel_end = None
                    self.clear_shape_preview()
                    self.update()
                return
            
            # Left-click for drawing
            if e.button() == Qt.MouseButton.LeftButton:
                # Check if clicking on a handle of current_line
                if self.current_line:
                    x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2 = self.current_line
                    # Check start point
                    if abs(e.pos().x() - x1) <= self.handle_size and abs(e.pos().y() - y1) <= self.handle_size:
                        self.dragging_handle = 'start'
                        return
                    # Check end point
                    elif abs(e.pos().x() - x2) <= self.handle_size and abs(e.pos().y() - y2) <= self.handle_size:
                        self.dragging_handle = 'end'
                        return
                    # Check control point 1
                    elif abs(e.pos().x() - cp1_x) <= self.handle_size and abs(e.pos().y() - cp1_y) <= self.handle_size:
                        self.dragging_handle = 'cp1'
                        # Disable straight-line mode when user touches an inner control point
                        self.line_keep_straight = False
                        return
                    # Check control point 2
                    elif abs(e.pos().x() - cp2_x) <= self.handle_size and abs(e.pos().y() - cp2_y) <= self.handle_size:
                        self.dragging_handle = 'cp2'
                        # Disable straight-line mode when user touches an inner control point
                        self.line_keep_straight = False
                        return
                    else:
                        # Clicked elsewhere - apply current line immediately
                        parent.apply_pending_lines([self.current_line])
                        self.current_line = None
                        self.line_keep_straight = True
                        self.dragging_handle = None
                
                # Start new line
                self.sel_start = e.pos()
                self.sel_end = e.pos()
                self.current_line = None
                self.line_keep_straight = True
        
        # Handle arrow tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "arrow":
            # Right-click cancels current arrow
            if e.button() == Qt.MouseButton.RightButton:
                if self.current_arrow:
                    self.current_arrow = None
                    self.arrow_keep_straight = True
                    self.sel_start = None
                    self.sel_end = None
                    self.clear_shape_preview()
                    self.update()
                return
            
            # Left-click for drawing
            if e.button() == Qt.MouseButton.LeftButton:
                # Check if clicking on a handle of current_arrow
                if self.current_arrow:
                    x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2 = self.current_arrow
                    # Check start point
                    if abs(e.pos().x() - x1) <= self.handle_size and abs(e.pos().y() - y1) <= self.handle_size:
                        self.dragging_handle = 'start'
                        return
                    # Check end point
                    elif abs(e.pos().x() - x2) <= self.handle_size and abs(e.pos().y() - y2) <= self.handle_size:
                        self.dragging_handle = 'end'
                        return
                    # Check control point 1
                    elif abs(e.pos().x() - cp1_x) <= self.handle_size and abs(e.pos().y() - cp1_y) <= self.handle_size:
                        self.dragging_handle = 'cp1'
                        # Disable straight-line mode when user touches an inner control point
                        self.arrow_keep_straight = False
                        return
                    # Check control point 2
                    elif abs(e.pos().x() - cp2_x) <= self.handle_size and abs(e.pos().y() - cp2_y) <= self.handle_size:
                        self.dragging_handle = 'cp2'
                        # Disable straight-line mode when user touches an inner control point
                        self.arrow_keep_straight = False
                        return
                    else:
                        # Clicked elsewhere - apply current arrow immediately
                        parent.apply_pending_arrows([self.current_arrow])
                        self.current_arrow = None
                        self.arrow_keep_straight = True
                        self.dragging_handle = None
                
                # Start new arrow
                self.sel_start = e.pos()
                self.sel_end = e.pos()
                self.current_arrow = None
                self.arrow_keep_straight = True
        
        # Handle freehand tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "freehand":
            if e.button() == Qt.MouseButton.LeftButton:
                # For flood fill, apply immediately on click
                if hasattr(parent, 'freehand_mode') and parent.freehand_mode == 'flood':
                    parent.apply_flood_fill(e.pos())
                    return
                
                # For color eraser, start tracking and apply on first point
                if hasattr(parent, 'freehand_mode') and parent.freehand_mode == 'color_eraser':
                    self.freehand_points = [e.pos()]
                    self.freehand_last_pos = e.pos()
                    parent.apply_color_eraser_realtime([e.pos()])
                    return
                
                # For other modes, start drawing in real-time
                self.freehand_points = [e.pos()]
                self.freehand_last_pos = e.pos()
                parent._freehand_begin_stroke()
                # Draw initial mark at click point
                mode = getattr(parent, 'freehand_mode', 'pen')
                if mode == 'spraycan':
                    parent._freehand_draw_segment_realtime(e.pos(), e.pos())
                else:
                    parent._freehand_draw_dot_realtime(e.pos())
        
        # Handle cut/paste tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "cutpaste":
            if e.button() == Qt.MouseButton.LeftButton:
                # Check if clicking on existing selection to drag it
                if self.cutpaste_selection and not self.cutpaste_paste_pos:
                    x1, y1, x2, y2 = self.cutpaste_selection
                    if x1 <= e.pos().x() <= x2 and y1 <= e.pos().y() <= y2:
                        # Start dragging the selection - cut it and prepare to paste
                        parent.cut_selection_for_move()
                        self.cutpaste_dragging = True
                        self.sel_start = e.pos()
                        return
                
                # Check if clicking on existing paste preview to resize or drag it
                if self.cutpaste_paste_pos and self.cutpaste_clipboard:
                    px1, py1, px2, py2 = self.cutpaste_paste_pos
                    
                    # Check handles first (for resizing)
                    handle = self.get_handle_at_pos(e.pos(), (px1, py1, px2, py2))
                    if handle:
                        self.cutpaste_resizing = handle
                        return
                    
                    if px1 <= e.pos().x() <= px2 and py1 <= e.pos().y() <= py2:
                        # Start dragging the pasted selection
                        self.cutpaste_dragging = True
                        self.sel_start = e.pos()
                        return
                    else:
                        # Clicked outside paste preview - apply it
                        parent.apply_paste()
                        return
                
                # Start new selection (clear any existing paste preview)
                self.cutpaste_paste_pos = None
                self.cutpaste_selection = None
                self.sel_start = e.pos()
                self.sel_end = e.pos()
            elif e.button() == Qt.MouseButton.RightButton:
                # Right-click clears selection or paste preview
                if self.cutpaste_paste_pos or self.cutpaste_selection:
                    self.cutpaste_paste_pos = None
                    self.cutpaste_clipboard = None
                    self.cutpaste_selection = None
                    self.sel_start = None
                    self.sel_end = None
                    self.update()
                    if hasattr(parent, 'update_tool_buttons_state'):
                        parent.update_tool_buttons_state()
        
        # Handle highlight tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "highlight":
            style = getattr(getattr(parent, 'highlight_style', None), 'currentText', lambda: 'Pen')()
            if e.button() == Qt.MouseButton.LeftButton:
                style = parent.highlight_style.currentText()
                if style == "Rectangle" or style == "Spotlight":
                    # Check if clicking on existing rectangle handle
                    if self.current_highlight_rect:
                        handle = self.get_handle_at_pos(e.pos(), self.current_highlight_rect)
                        if handle:
                            self.dragging_handle = handle
                            return
                        else:
                            # Clicking outside rectangle - check if inside or outside
                            x1, y1, x2, y2 = self.current_highlight_rect
                            if x1 <= e.pos().x() <= x2 and y1 <= e.pos().y() <= y2:
                                # Clicking inside - do nothing (maybe drag in future)
                                return
                            else:
                                # Clicking outside - apply and start new
                                parent.apply_all_highlights()
                    # Start new rectangle
                    self.current_highlight_rect = None
                    self.sel_start = e.pos()
                    self.sel_end = e.pos()
                else:
                    # Pen mode - start new stroke
                    self.highlight_strokes = getattr(self, 'highlight_strokes', [])
                    self.current_highlight_stroke = [e.pos()]
            elif e.button() == Qt.MouseButton.RightButton:
                # Right-click cancels current highlight rectangle
                if (style == "Rectangle" or style == "Spotlight") and self.current_highlight_rect:
                    self.current_highlight_rect = None
                    self.sel_start = None
                    self.sel_end = None
                    self.update()
        
        # Handle magnify inset tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "magnify_inset":
            if e.button() == Qt.MouseButton.LeftButton:
                # If inset is placed, check if clicking on the inset to drag it
                if self.inset_source_rect and self.inset_dest_pos:
                    zoom = int(parent.inset_zoom.currentText().replace('%', '')) / 100.0
                    src = self.inset_source_rect
                    sw = (src[2] - src[0]) * zoom
                    sh = (src[3] - src[1]) * zoom
                    dx, dy = self.inset_dest_pos
                    if dx <= e.pos().x() <= dx + sw and dy <= e.pos().y() <= dy + sh:
                        # Clicking inside inset - start dragging
                        self.inset_dragging_dest = True
                        self.inset_drag_offset = (e.pos().x() - dx, e.pos().y() - dy)
                        return
                    # Check if clicking on source handles
                    if self.inset_source_rect:
                        handle = self.get_handle_at_pos(e.pos(), self.inset_source_rect)
                        if handle:
                            self.dragging_handle = handle
                            return
                    # Clicking outside both - apply current, don't start new yet
                    parent._apply_magnify_inset()
                    return
                # Start new source selection (only if no active inset)
                self.inset_source_rect = None
                self.inset_dest_pos = None
                self.sel_start = e.pos()
                self.sel_end = e.pos()
            elif e.button() == Qt.MouseButton.RightButton:
                # Right-click cancels
                self.inset_source_rect = None
                self.inset_dest_pos = None
                self.sel_start = None
                self.sel_end = None
                self.update()
        
        # Handle pixelate tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "pixelate":
            if e.button() == Qt.MouseButton.LeftButton:
                # Check if clicking on existing rectangle handle
                if self.current_pixelate_rect:
                    handle = self.get_handle_at_pos(e.pos(), self.current_pixelate_rect)
                    if handle:
                        self.dragging_handle = handle
                        return
                    else:
                        # Clicking outside rectangle - apply and start new
                        x1, y1, x2, y2 = self.current_pixelate_rect
                        if x1 <= e.pos().x() <= x2 and y1 <= e.pos().y() <= y2:
                            # Clicking inside - do nothing
                            return
                        else:
                            # Clicking outside - apply and start new
                            parent.apply_pixelate()
                # Start new rectangle
                self.current_pixelate_rect = None
                self.sel_start = e.pos()
                self.sel_end = e.pos()
            elif e.button() == Qt.MouseButton.RightButton:
                # Right-click cancels current pixelate rectangle
                if self.current_pixelate_rect:
                    self.current_pixelate_rect = None
                    self.sel_start = None
                    self.sel_end = None
                    self.update()
        
        # Handle blur tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "blur":
            if e.button() == Qt.MouseButton.LeftButton:
                if self.current_blur_rect:
                    handle = self.get_handle_at_pos(e.pos(), self.current_blur_rect)
                    if handle:
                        self.dragging_handle = handle
                        return
                    else:
                        x1, y1, x2, y2 = self.current_blur_rect
                        if x1 <= e.pos().x() <= x2 and y1 <= e.pos().y() <= y2:
                            return
                        else:
                            parent.apply_blur()
                self.current_blur_rect = None
                self.sel_start = e.pos()
                self.sel_end = e.pos()
            elif e.button() == Qt.MouseButton.RightButton:
                if self.current_blur_rect:
                    self.current_blur_rect = None
                    self.sel_start = None
                    self.sel_end = None
                    self.update()
        
        # Handle step marker tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "step_marker":
            if e.button() == Qt.MouseButton.LeftButton:
                size = parent.step_marker_size.value() if hasattr(parent, 'step_marker_size') else 40
                radius = size // 2
                
                # Check if clicking on current marker being placed
                if self.current_marker:
                    num, bx, by, tx, ty, has_tail = self.current_marker
                    
                    # Check tail handle first (larger hit area for easier clicking - 10px radius)
                    if abs(e.pos().x() - tx) <= 10 and abs(e.pos().y() - ty) <= 10:
                        self.dragging_tail_handle = True
                        self.dragging_badge = False
                        self.update()
                        return
                    
                    # Check badge circle
                    if abs(e.pos().x() - bx) <= radius and abs(e.pos().y() - by) <= radius:
                        self.dragging_badge = True
                        self.dragging_tail_handle = False
                        self.update()
                        return
                    
                    # Clicking elsewhere - finalize current and start new
                    self.step_markers.append(self.current_marker)
                    self.marker_counter += 1
                    self.current_marker = None
                    self.placing_new_marker = False
                    self.active_marker_index = None
                    self.step_markers_redo.clear()  # New action clears redo
                    # Update undo button state
                    if hasattr(parent, 'update_tool_buttons_state'):
                        parent.update_tool_buttons_state()
                    # Fall through to create new marker below
                
                # Check if clicking on an existing marker
                clicked_marker_idx = None
                clicked_tail_handle = False
                
                # First check tail handles (higher priority - 10px hit radius)
                # Check ALL markers, not just those with has_tail=True
                for idx, marker in enumerate(self.step_markers):
                    num, bx, by, tx, ty, has_tail = marker
                    # Always check tail handle position, even if tail not drawn yet
                    if abs(e.pos().x() - tx) <= 10 and abs(e.pos().y() - ty) <= 10:
                        clicked_marker_idx = idx
                        clicked_tail_handle = True
                        break
                
                # Then check badge circles
                if clicked_marker_idx is None:
                    for idx, marker in enumerate(self.step_markers):
                        num, bx, by, tx, ty, has_tail = marker
                        if abs(e.pos().x() - bx) <= radius and abs(e.pos().y() - by) <= radius:
                            clicked_marker_idx = idx
                            break
                
                if clicked_marker_idx is not None:
                    # Editing existing marker
                    self.active_marker_index = clicked_marker_idx
                    
                    # If marker doesn't have a tail, position the handle for initial creation
                    marker = self.step_markers[clicked_marker_idx]
                    num, bx, by, tx, ty, has_tail = marker
                    if not has_tail:
                        # Position tail handle offset from badge for easy grabbing
                        import math
                        size = parent.step_marker_size.value() if hasattr(parent, 'step_marker_size') else 40
                        scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
                        scaled_radius = (size * scale) / 2
                        handle_radius = max(4, int(5 * scale))
                        offset_dist = scaled_radius + handle_radius
                        tx = bx + int(offset_dist * math.cos(math.radians(45)))
                        ty = by + int(offset_dist * math.sin(math.radians(45)))
                        self.step_markers[clicked_marker_idx] = (num, bx, by, tx, ty, has_tail)
                    
                    if clicked_tail_handle:
                        self.dragging_tail_handle = True
                    else:
                        self.dragging_badge = True
                    self.update()
                    return
                
                # Clicking empty space - create new marker
                # Badge at click point, white dot just outside
                import math as _m
                _scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
                _scaled_radius = (size * _scale) / 2
                _handle_radius = max(4, int(5 * _scale))
                _dist = _scaled_radius + _handle_radius
                _ox = int(_dist * _m.cos(_m.radians(45)))
                _oy = int(_dist * _m.sin(_m.radians(45)))
                self.current_marker = (self.marker_counter, e.pos().x(), e.pos().y(), 
                                     e.pos().x() + _ox, e.pos().y() + _oy, False)
                self.placing_new_marker = True
                self.dragging_badge = True
                self.active_marker_index = None
                self.update()
                if hasattr(parent, 'update_tool_buttons_state'):
                    parent.update_tool_buttons_state()
        
        # Handle text tool
        elif hasattr(parent, 'active_tool') and parent.active_tool == "text":
            if e.button() == Qt.MouseButton.LeftButton:
                # Check if clicking on existing text box
                if self.current_text:
                    text_str, x1, y1, x2, y2 = self.current_text
                    # Check if clicking on a handle
                    handle = self.get_handle_at_pos(e.pos(), (x1, y1, x2, y2))
                    if handle:
                        self.dragging_handle = handle
                        self.text_editing = False  # Stop editing while resizing
                        self.stop_cursor_blink()
                        return
                    # Check if clicking inside box
                    if x1 <= e.pos().x() <= x2 and y1 <= e.pos().y() <= y2:
                        if self.text_editing:
                            # In edit mode - position cursor or start selection
                            self.text_cursor_pos = self.get_cursor_pos_from_click(e.pos(), text_str, x1, y1, x2, y2, parent)
                            self.text_selection_start = self.text_cursor_pos
                            self.text_selection_end = None
                            self.selecting_text = True
                            self.sel_start = e.pos()
                        else:
                            # Not editing - prepare to drag box
                            self.sel_start = e.pos()
                        return
                    else:
                        # Clicking outside - apply current text if there's text
                        if text_str.strip():
                            parent.apply_text_to_image()
                        else:
                            # Empty text - just cancel
                            self.current_text = None
                            self.text_editing = False
                            self.stop_cursor_blink()
                            self.update()
                
                # Start drawing new text box
                self.sel_start = e.pos()
                self.sel_end = e.pos()
                self.text_editing = False  # Don't start editing until mouse released
            elif e.button() == Qt.MouseButton.RightButton:
                # Right-click cancels current text
                if self.current_text:
                    self.current_text = None
                    self.text_editing = False
                    self.stop_cursor_blink()
                    self.update()
        
        else:
            # For cutout/crop tools - handle existing selection interaction
            if hasattr(parent, 'active_tool') and parent.active_tool == "cutout":
                if self.selection_finalized and self.sel_start is not None and self.sel_end is not None:
                    if e.button() == Qt.MouseButton.LeftButton:
                        img_left = int(self.offset.x())
                        img_top = int(self.offset.y())
                        img_right = img_left + int(self.image.width * self.scale) if self.image else self.width()
                        img_bottom = img_top + int(self.image.height * self.scale) if self.image else self.height()
                        handle_size = self.handle_size
                        
                        if self.drag_mode == "horizontal":
                            y1, y2 = sorted([self.sel_start.y(), self.sel_end.y()])
                            mid_x = (img_left + img_right) / 2
                            # Check top edge handle
                            if abs(e.pos().y() - y1) <= handle_size and abs(e.pos().x() - mid_x) <= handle_size:
                                self.dragging_handle = 'tc'
                                self._crop_drag_start = e.pos()
                                self._crop_original_rect = (img_left, y1, img_right, y2)
                                return
                            # Check bottom edge handle
                            if abs(e.pos().y() - y2) <= handle_size and abs(e.pos().x() - mid_x) <= handle_size:
                                self.dragging_handle = 'bc'
                                self._crop_drag_start = e.pos()
                                self._crop_original_rect = (img_left, y1, img_right, y2)
                                return
                            # Check if inside strip - drag to move
                            if y1 <= e.pos().y() <= y2:
                                self._crop_moving = True
                                self._crop_drag_start = e.pos()
                                self._crop_original_rect = (img_left, y1, img_right, y2)
                                return
                        else:
                            x1, x2 = sorted([self.sel_start.x(), self.sel_end.x()])
                            mid_y = (img_top + img_bottom) / 2
                            # Check left edge handle
                            if abs(e.pos().x() - x1) <= handle_size and abs(e.pos().y() - mid_y) <= handle_size:
                                self.dragging_handle = 'lc'
                                self._crop_drag_start = e.pos()
                                self._crop_original_rect = (x1, img_top, x2, img_bottom)
                                return
                            # Check right edge handle
                            if abs(e.pos().x() - x2) <= handle_size and abs(e.pos().y() - mid_y) <= handle_size:
                                self.dragging_handle = 'rc'
                                self._crop_drag_start = e.pos()
                                self._crop_original_rect = (x1, img_top, x2, img_bottom)
                                return
                            # Check if inside strip - drag to move
                            if x1 <= e.pos().x() <= x2:
                                self._crop_moving = True
                                self._crop_drag_start = e.pos()
                                self._crop_original_rect = (x1, img_top, x2, img_bottom)
                                return
                        
                        # Clicked outside strip - clear and start new
                        self.selection_finalized = False
                        self.sel_start = self.sel_end = e.pos()
                        self.dragging_handle = None
                        self._crop_moving = False
                        parent.update_tool_buttons_state()
                        return
                    elif e.button() == Qt.MouseButton.RightButton:
                        # Right-click cancels
                        self.selection_finalized = False
                        self.sel_start = None
                        self.sel_end = None
                        self.dragging_handle = None
                        self._crop_moving = False
                        self.update()
                        parent.update_tool_buttons_state()
                        return
            
            elif hasattr(parent, 'active_tool') and parent.active_tool == "crop":
                if self.selection_finalized and self.sel_start is not None and self.sel_end is not None:
                    x1 = min(self.sel_start.x(), self.sel_end.x())
                    y1 = min(self.sel_start.y(), self.sel_end.y())
                    x2 = max(self.sel_start.x(), self.sel_end.x())
                    y2 = max(self.sel_start.y(), self.sel_end.y())
                    crop_rect = (x1, y1, x2, y2)
                    
                    # Check handles first
                    handle = self.get_handle_at_pos(e.pos(), crop_rect)
                    if handle:
                        self.dragging_handle = handle
                        self._crop_drag_start = e.pos()
                        self._crop_original_rect = crop_rect
                        return
                    
                    # Check if inside - drag to move
                    if x1 <= e.pos().x() <= x2 and y1 <= e.pos().y() <= y2:
                        self._crop_moving = True
                        self._crop_drag_start = e.pos()
                        self._crop_original_rect = crop_rect
                        return
                    
                    # Clicked outside - clear and start new
                    self.selection_finalized = False
                    self.sel_start = self.sel_end = e.pos()
                    self.dragging_handle = None
                    self._crop_moving = False
                    parent.update_tool_buttons_state()
                    return
            
            # Reset finalized flag when starting new selection
            self.selection_finalized = False
            self._crop_moving = False
            self.sel_start = self.sel_end = e.pos()

    def mouseMoveEvent(self, e):
        parent = self.window()
        
        # Get raw position
        raw_pos = e.pos()
        
        # Get the position, clamped to canvas bounds if we're in a drag operation
        pos = raw_pos
        if self.mouse_captured and self.pixmap():
            # Clamp to canvas bounds (0 to width-1, 0 to height-1)
            canvas_width = self.pixmap().width()
            canvas_height = self.pixmap().height()
            
            # Clamp X and Y to valid range
            clamped_x = max(0, min(raw_pos.x(), canvas_width - 1))
            clamped_y = max(0, min(raw_pos.y(), canvas_height - 1))
            pos = QPoint(clamped_x, clamped_y)
        
        # Check if left button is held down
        buttons = e.buttons()
        is_dragging = bool(buttons & Qt.MouseButton.LeftButton)
        
        # Handle panning (Ctrl+drag) - uses raw position for smooth panning
        if self.panning and self.pan_start_pos and hasattr(parent, 'scroll_area'):
            current_pos = e.globalPosition().toPoint()
            delta_x = self.pan_start_pos.x() - current_pos.x()
            delta_y = self.pan_start_pos.y() - current_pos.y()
            
            h_bar = parent.scroll_area.horizontalScrollBar()
            v_bar = parent.scroll_area.verticalScrollBar()
            
            h_bar.setValue(self.pan_start_scroll[0] + delta_x)
            v_bar.setValue(self.pan_start_scroll[1] + delta_y)
            return
        
        # Track mouse and update overlay
        if hasattr(parent, 'crosshair_enabled') and parent.crosshair_enabled:
            self.crosshair_mouse_pos = pos
            if hasattr(parent, 'crosshair_overlay'):
                parent.crosshair_overlay.update()
        
        # Update for guide lines if enabled
        if hasattr(parent, 'guide_lines_enabled') and parent.guide_lines_enabled:
            self.update()
        
        # Update status bar with cursor position and pixel color (use clamped pos)
        if hasattr(parent, '_update_status_cursor') and self.image:
            # Convert screen position to image coordinates
            scale = float(self.scale) if self.scale else 1.0
            img_x = int(pos.x() / scale)
            img_y = int(pos.y() / scale)
            
            # Clamp to image bounds for display
            w, h = self.image.size
            img_x = max(0, min(img_x, w - 1))
            img_y = max(0, min(img_y, h - 1))
            
            # Get pixel color
            try:
                pixel = self.image.getpixel((img_x, img_y))
                if isinstance(pixel, int):  # Grayscale
                    color = (pixel, pixel, pixel)
                elif len(pixel) >= 3:
                    color = pixel[:3]
                else:
                    color = None
            except:
                color = None
            parent._update_status_cursor(img_x, img_y, color)
        
        # Always update viewer for selection box drawing (cutout/crop/etc)
        self.update()

        # Eyedropper mode: ignore normal tool dragging while picking a color
        if getattr(parent, '_eyedropper_active', False):
            return

        # While a paste preview is being dragged, update its position even if we're not in cut/paste tool.
        if self.cutpaste_dragging and self.cutpaste_paste_pos and self.cutpaste_clipboard:
            dx = pos.x() - self.sel_start.x()
            dy = pos.y() - self.sel_start.y()
            x1, y1, x2, y2 = self.cutpaste_paste_pos
            self.cutpaste_paste_pos = (x1 + dx, y1 + dy, x2 + dx, y2 + dy)
            self.sel_start = pos
            self.update()
            return
        
        # While a paste preview is being resized via handle
        if self.cutpaste_resizing and self.cutpaste_paste_pos and self.cutpaste_clipboard:
            px1, py1, px2, py2 = self.cutpaste_paste_pos
            mx, my = pos.x(), pos.y()
            handle = self.cutpaste_resizing
            orig_w = px2 - px1
            orig_h = py2 - py1
            aspect = orig_w / orig_h if orig_h > 0 else 1.0
            
            # Check if Shift is held for free resize on corners
            shift_held = bool(QApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier)
            
            is_corner = handle in ('tl', 'tr', 'bl', 'br')
            
            if handle == 'tl':
                if is_corner and not shift_held:
                    new_w = max(20, px2 - mx)
                    new_h = new_w / aspect
                    px1 = px2 - new_w
                    py1 = py2 - new_h
                else:
                    px1 = min(mx, px2 - 20)
                    py1 = min(my, py2 - 20)
            elif handle == 'tr':
                if is_corner and not shift_held:
                    new_w = max(20, mx - px1)
                    new_h = new_w / aspect
                    px2 = px1 + new_w
                    py1 = py2 - new_h
                else:
                    px2 = max(mx, px1 + 20)
                    py1 = min(my, py2 - 20)
            elif handle == 'bl':
                if is_corner and not shift_held:
                    new_w = max(20, px2 - mx)
                    new_h = new_w / aspect
                    px1 = px2 - new_w
                    py2 = py1 + new_h
                else:
                    px1 = min(mx, px2 - 20)
                    py2 = max(my, py1 + 20)
            elif handle == 'br':
                if is_corner and not shift_held:
                    new_w = max(20, mx - px1)
                    new_h = new_w / aspect
                    px2 = px1 + new_w
                    py2 = py1 + new_h
                else:
                    px2 = max(mx, px1 + 20)
                    py2 = max(my, py1 + 20)
            elif handle == 'tc':
                py1 = min(my, py2 - 20)
            elif handle == 'bc':
                py2 = max(my, py1 + 20)
            elif handle == 'lc':
                px1 = min(mx, px2 - 20)
            elif handle == 'rc':
                px2 = max(mx, px1 + 20)
            
            self.cutpaste_paste_pos = (px1, py1, px2, py2)
            self.update()
            return
        if hasattr(parent, 'active_tool') and parent.active_tool == "rectangle":
            if self.dragging_handle and self.current_rect:
                # Resize the rectangle by moving the handle
                self.resize_shape_with_handle(pos, is_rect=True)
                self._shape_changed()
            elif self.sel_start is not None:
                # Drawing new rectangle
                self.sel_end = pos
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                self.current_rect = (x1, y1, x2, y2)
                self._shape_changed()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "oval":
            if self.dragging_handle and self.current_oval:
                # Resize the oval by moving the handle
                self.resize_shape_with_handle(pos, is_rect=False)
                self._shape_changed()
            elif self.sel_start is not None:
                # Drawing new oval
                self.sel_end = pos
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                self.current_oval = (x1, y1, x2, y2)
                self._shape_changed()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "line":
            if self.dragging_handle and self.current_line:
                # Resize the line by moving a point
                x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2 = self.current_line
                
                if self.dragging_handle == 'start':
                    # Moving start point
                    new_x1, new_y1 = pos.x(), pos.y()
                    
                    if self.line_keep_straight:
                        # Keep line straight - recalculate control points along the straight line
                        cp1_x = new_x1 + (x2 - new_x1) / 3
                        cp1_y = new_y1 + (y2 - new_y1) / 3
                        cp2_x = new_x1 + 2 * (x2 - new_x1) / 3
                        cp2_y = new_y1 + 2 * (y2 - new_y1) / 3
                    
                    self.current_line = (new_x1, new_y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2)
                    
                elif self.dragging_handle == 'end':
                    # Moving end point
                    new_x2, new_y2 = pos.x(), pos.y()
                    
                    if self.line_keep_straight:
                        # Keep line straight - recalculate control points along the straight line
                        cp1_x = x1 + (new_x2 - x1) / 3
                        cp1_y = y1 + (new_y2 - y1) / 3
                        cp2_x = x1 + 2 * (new_x2 - x1) / 3
                        cp2_y = y1 + 2 * (new_y2 - y1) / 3
                    
                    self.current_line = (x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, new_x2, new_y2)
                    
                elif self.dragging_handle == 'cp1':
                    # Moving control point 1 - straight mode already disabled
                    self.current_line = (x1, y1, pos.x(), pos.y(), cp2_x, cp2_y, x2, y2)
                    
                elif self.dragging_handle == 'cp2':
                    # Moving control point 2 - straight mode already disabled
                    self.current_line = (x1, y1, cp1_x, cp1_y, pos.x(), pos.y(), x2, y2)
                
                self._shape_changed()
            elif self.sel_start is not None:
                # Drawing new line - initialize with control points along the line
                self.sel_end = pos
                x1, y1 = self.sel_start.x(), self.sel_start.y()
                x2, y2 = self.sel_end.x(), self.sel_end.y()
                # Place control points at 1/3 and 2/3 along the line
                cp1_x = x1 + (x2 - x1) / 3
                cp1_y = y1 + (y2 - y1) / 3
                cp2_x = x1 + 2 * (x2 - x1) / 3
                cp2_y = y1 + 2 * (y2 - y1) / 3
                self.current_line = (x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2)
                self._shape_changed()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "arrow":
            if self.dragging_handle and self.current_arrow:
                # Resize the arrow by moving a point
                x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2 = self.current_arrow
                
                if self.dragging_handle == 'start':
                    # Moving start point
                    new_x1, new_y1 = pos.x(), pos.y()
                    
                    if self.arrow_keep_straight:
                        # Keep arrow straight - recalculate control points along the straight line
                        cp1_x = new_x1 + (x2 - new_x1) / 3
                        cp1_y = new_y1 + (y2 - new_y1) / 3
                        cp2_x = new_x1 + 2 * (x2 - new_x1) / 3
                        cp2_y = new_y1 + 2 * (y2 - new_y1) / 3
                    
                    self.current_arrow = (new_x1, new_y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2)
                    
                elif self.dragging_handle == 'end':
                    # Moving end point
                    new_x2, new_y2 = pos.x(), pos.y()
                    
                    if self.arrow_keep_straight:
                        # Keep arrow straight - recalculate control points along the straight line
                        cp1_x = x1 + (new_x2 - x1) / 3
                        cp1_y = y1 + (new_y2 - y1) / 3
                        cp2_x = x1 + 2 * (new_x2 - x1) / 3
                        cp2_y = y1 + 2 * (new_y2 - y1) / 3
                    
                    self.current_arrow = (x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, new_x2, new_y2)
                    
                elif self.dragging_handle == 'cp1':
                    # Moving control point 1 - straight mode already disabled
                    self.current_arrow = (x1, y1, pos.x(), pos.y(), cp2_x, cp2_y, x2, y2)
                    
                elif self.dragging_handle == 'cp2':
                    # Moving control point 2 - straight mode already disabled
                    self.current_arrow = (x1, y1, cp1_x, cp1_y, pos.x(), pos.y(), x2, y2)
                
                self._shape_changed()
            elif self.sel_start is not None:
                # Drawing new arrow - initialize with control points along the line
                self.sel_end = pos
                x1, y1 = self.sel_start.x(), self.sel_start.y()
                x2, y2 = self.sel_end.x(), self.sel_end.y()
                # Place control points at 1/3 and 2/3 along the line
                cp1_x = x1 + (x2 - x1) / 3
                cp1_y = y1 + (y2 - y1) / 3
                cp2_x = x1 + 2 * (x2 - x1) / 3
                cp2_y = y1 + 2 * (y2 - y1) / 3
                self.current_arrow = (x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2)
                self._shape_changed()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "freehand":
            if self.freehand_last_pos is not None:
                # For color eraser, apply in real-time
                if hasattr(parent, 'freehand_mode') and parent.freehand_mode == 'color_eraser':
                    # Apply the last few points immediately
                    self.freehand_points.append(pos)
                    if len(self.freehand_points) >= 3:
                        parent.apply_color_eraser_realtime([self.freehand_points[-1]])
                    self.freehand_last_pos = pos
                else:
                    # Real-time drawing: draw segment directly into image
                    prev = self.freehand_points[-1] if self.freehand_points else pos
                    self.freehand_points.append(pos)
                    self.freehand_last_pos = pos
                    parent._freehand_draw_segment_realtime(prev, pos)
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "cutpaste":
            if self.cutpaste_resizing and self.cutpaste_paste_pos:
                # Handled by the generic resize code above (already returned)
                pass
            elif self.cutpaste_dragging and self.cutpaste_paste_pos:
                # Drag the pasted selection
                dx = pos.x() - self.sel_start.x()
                dy = pos.y() - self.sel_start.y()
                x1, y1, x2, y2 = self.cutpaste_paste_pos
                self.cutpaste_paste_pos = (x1 + dx, y1 + dy, x2 + dx, y2 + dy)
                self.sel_start = pos
                self.update()
            elif self.sel_start is not None and not self.cutpaste_resizing:
                # Draw selection rectangle
                self.sel_end = pos
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "highlight":
            style = parent.highlight_style.currentText()
            if style == "Rectangle" or style == "Spotlight":
                # Rectangle mode with handle dragging
                if self.dragging_handle and self.current_highlight_rect:
                    self.update_rect_from_handle(pos, self.current_highlight_rect, self.dragging_handle)
                    self.update()
                elif self.sel_start is not None:
                    # Drawing new rectangle
                    self.sel_end = pos
                    x1 = min(self.sel_start.x(), self.sel_end.x())
                    y1 = min(self.sel_start.y(), self.sel_end.y())
                    x2 = max(self.sel_start.x(), self.sel_end.x())
                    y2 = max(self.sel_start.y(), self.sel_end.y())
                    self.current_highlight_rect = (x1, y1, x2, y2)
                    self.update()
            else:
                # Pen mode - only add points while left button is held
                if self.current_highlight_stroke is not None:
                    self.current_highlight_stroke.append(pos)
                    self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "magnify_inset":
            if self.inset_dragging_dest and self.inset_dest_pos:
                # Dragging the inset
                self.inset_dest_pos = (pos.x() - self.inset_drag_offset[0],
                                       pos.y() - self.inset_drag_offset[1])
                self.update()
            elif self.dragging_handle and self.inset_source_rect:
                # Resizing source rect via handle
                x1, y1, x2, y2 = self.inset_source_rect
                px, py = pos.x(), pos.y()
                if self.dragging_handle == 'tl':
                    x1, y1 = px, py
                elif self.dragging_handle == 'tc':
                    y1 = py
                elif self.dragging_handle == 'tr':
                    x2, y1 = px, py
                elif self.dragging_handle == 'rc':
                    x2 = px
                elif self.dragging_handle == 'br':
                    x2, y2 = px, py
                elif self.dragging_handle == 'bc':
                    y2 = py
                elif self.dragging_handle == 'bl':
                    x1, y2 = px, py
                elif self.dragging_handle == 'lc':
                    x1 = px
                self.inset_source_rect = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
                self.update()
            elif self.sel_start is not None:
                # Drawing new source selection
                self.sel_end = pos
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                self.inset_source_rect = (x1, y1, x2, y2)
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "pixelate":
            # Rectangle mode with handle dragging
            if self.dragging_handle and self.current_pixelate_rect:
                self.update_pixelate_rect_from_handle(pos, self.current_pixelate_rect, self.dragging_handle)
                self.update()
            elif self.sel_start is not None:
                # Drawing new rectangle
                self.sel_end = pos
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                self.current_pixelate_rect = (x1, y1, x2, y2)
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "blur":
            if self.dragging_handle and self.current_blur_rect:
                # Inline handle update for blur rect
                x1, y1, x2, y2 = self.current_blur_rect
                px, py = pos.x(), pos.y()
                h = self.dragging_handle
                if h == 'tl': x1, y1 = px, py
                elif h == 'tc': y1 = py
                elif h == 'tr': x2, y1 = px, py
                elif h == 'rc': x2 = px
                elif h == 'br': x2, y2 = px, py
                elif h == 'bc': y2 = py
                elif h == 'bl': x1, y2 = px, py
                elif h == 'lc': x1 = px
                self.current_blur_rect = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
                self.update()
            elif self.sel_start is not None:
                self.sel_end = pos
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                self.current_blur_rect = (x1, y1, x2, y2)
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "step_marker":
            # Dragging current marker being placed
            if self.current_marker:
                num, bx, by, tx, ty, has_tail = self.current_marker
                
                if self.dragging_badge:
                    # Move badge AND tail handle together
                    dx_move = pos.x() - bx
                    dy_move = pos.y() - by
                    self.current_marker = (num, pos.x(), pos.y(), tx + dx_move, ty + dy_move, has_tail)
                elif self.dragging_tail_handle:
                    # Move tail handle, badge stays put
                    self.current_marker = (num, bx, by, pos.x(), pos.y(), True)
                
                self.update()
            
            # Dragging existing marker
            elif self.active_marker_index is not None:
                marker = self.step_markers[self.active_marker_index]
                num, bx, by, tx, ty, has_tail = marker
                
                if self.dragging_badge:
                    # Move badge position, keep tail offset relative
                    dx = pos.x() - bx
                    dy = pos.y() - by
                    self.step_markers[self.active_marker_index] = (
                        num, pos.x(), pos.y(), tx + dx, ty + dy, has_tail
                    )
                elif self.dragging_tail_handle:
                    # Move tail handle only, badge stays put
                    self.step_markers[self.active_marker_index] = (
                        num, bx, by, pos.x(), pos.y(), True
                    )
                
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "text":
            # Check if we're drawing a new box
            if self.sel_start is not None and not self.current_text:
                # Drawing new text box
                self.sel_end = pos
                self.update()
            elif self.current_text:
                text_str, x1, y1, x2, y2 = self.current_text
                # Handle dragging
                if self.dragging_handle:
                    # Resize box via handle
                    px, py = pos.x(), pos.y()
                    handle = self.dragging_handle
                    
                    if handle == 'tl':
                        x1, y1 = px, py
                    elif handle == 'tc':
                        y1 = py
                    elif handle == 'tr':
                        x2, y1 = px, py
                    elif handle == 'rc':
                        x2 = px
                    elif handle == 'br':
                        x2, y2 = px, py
                    elif handle == 'bc':
                        y2 = py
                    elif handle == 'bl':
                        x1, y2 = px, py
                    elif handle == 'lc':
                        x1 = px
                    
                    # Ensure x1 < x2 and y1 < y2
                    x1, y1, x2, y2 = min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)
                    
                    # Constrain to image bounds
                    if self.image:
                        img_width = int(self.image.width * self.scale)
                        img_height = int(self.image.height * self.scale)
                        img_x1 = self.offset.x()
                        img_y1 = self.offset.y()
                        img_x2 = img_x1 + img_width
                        img_y2 = img_y1 + img_height
                        
                        x1 = max(img_x1, min(x1, img_x2))
                        y1 = max(img_y1, min(y1, img_y2))
                        x2 = max(img_x1, min(x2, img_x2))
                        y2 = max(img_y1, min(y2, img_y2))
                    
                    self.current_text = (text_str, x1, y1, x2, y2)
                    self.update()
                elif self.selecting_text:
                    # Update text selection end position
                    self.text_selection_end = self.get_cursor_pos_from_click(pos, text_str, x1, y1, x2, y2, parent)
                    self.text_cursor_pos = self.text_selection_end
                    self.update()
                elif self.sel_start is not None and not self.dragging_text_box and not self.text_editing:
                    # Start dragging if mouse moved
                    dx = abs(pos.x() - self.sel_start.x())
                    dy = abs(pos.y() - self.sel_start.y())
                    if dx > 2 or dy > 2:  # Movement threshold
                        self.dragging_text_box = True
                elif self.dragging_text_box:
                    # Move entire box
                    dx = pos.x() - self.sel_start.x()
                    dy = pos.y() - self.sel_start.y()
                    new_x1 = x1 + dx
                    new_y1 = y1 + dy
                    new_x2 = x2 + dx
                    new_y2 = y2 + dy
                    
                    # Constrain to image bounds
                    if self.image:
                        img_width = int(self.image.width * self.scale)
                        img_height = int(self.image.height * self.scale)
                        img_x1 = self.offset.x()
                        img_y1 = self.offset.y()
                        img_x2 = img_x1 + img_width
                        img_y2 = img_y1 + img_height
                        
                        box_width = new_x2 - new_x1
                        box_height = new_y2 - new_y1
                        
                        # Constrain left/right
                        if new_x1 < img_x1:
                            new_x1 = img_x1
                            new_x2 = new_x1 + box_width
                        elif new_x2 > img_x2:
                            new_x2 = img_x2
                            new_x1 = new_x2 - box_width
                        
                        # Constrain top/bottom
                        if new_y1 < img_y1:
                            new_y1 = img_y1
                            new_y2 = new_y1 + box_height
                        elif new_y2 > img_y2:
                            new_y2 = img_y2
                            new_y1 = new_y2 - box_height
                    
                    self.current_text = (text_str, new_x1, new_y1, new_x2, new_y2)
                    self.sel_start = pos
                    self.update()
        else:
            # Handle cutout selection resizing/moving when finalized
            if hasattr(parent, 'active_tool') and parent.active_tool == "cutout" and self.selection_finalized:
                img_left = int(self.offset.x())
                img_top = int(self.offset.y())
                img_right = img_left + int(self.image.width * self.scale) if self.image else self.width()
                img_bottom = img_top + int(self.image.height * self.scale) if self.image else self.height()
                
                if self.dragging_handle and self._crop_original_rect is not None:
                    ox1, oy1, ox2, oy2 = self._crop_original_rect
                    dx = pos.x() - self._crop_drag_start.x()
                    dy = pos.y() - self._crop_drag_start.y()
                    h = self.dragging_handle
                    
                    if self.drag_mode == "horizontal":
                        # Only move the affected edge vertically, clamped to image
                        ny1, ny2 = oy1, oy2
                        if h == 'tc':
                            ny1 = max(img_top, min(oy2 - 10, oy1 + dy))
                        elif h == 'bc':
                            ny2 = min(img_bottom, max(oy1 + 10, oy2 + dy))
                        self.sel_start = QPoint(self.sel_start.x(), ny1)
                        self.sel_end = QPoint(self.sel_end.x(), ny2)
                    else:
                        # Only move the affected edge horizontally, clamped to image
                        nx1, nx2 = ox1, ox2
                        if h == 'lc':
                            nx1 = max(img_left, min(ox2 - 10, ox1 + dx))
                        elif h == 'rc':
                            nx2 = min(img_right, max(ox1 + 10, ox2 + dx))
                        self.sel_start = QPoint(nx1, self.sel_start.y())
                        self.sel_end = QPoint(nx2, self.sel_end.y())
                    self.update()
                    return
                elif getattr(self, '_crop_moving', False) and self._crop_original_rect is not None:
                    ox1, oy1, ox2, oy2 = self._crop_original_rect
                    dx = pos.x() - self._crop_drag_start.x()
                    dy = pos.y() - self._crop_drag_start.y()
                    
                    if self.drag_mode == "horizontal":
                        # Move strip vertically only
                        ny1 = oy1 + dy
                        ny2 = oy2 + dy
                        if ny1 < img_top:
                            ny1, ny2 = img_top, img_top + (oy2 - oy1)
                        if ny2 > img_bottom:
                            ny2, ny1 = img_bottom, img_bottom - (oy2 - oy1)
                        self.sel_start = QPoint(self.sel_start.x(), ny1)
                        self.sel_end = QPoint(self.sel_end.x(), ny2)
                    else:
                        # Move strip horizontally only
                        nx1 = ox1 + dx
                        nx2 = ox2 + dx
                        if nx1 < img_left:
                            nx1, nx2 = img_left, img_left + (ox2 - ox1)
                        if nx2 > img_right:
                            nx2, nx1 = img_right, img_right - (ox2 - ox1)
                        self.sel_start = QPoint(nx1, self.sel_start.y())
                        self.sel_end = QPoint(nx2, self.sel_end.y())
                    self.update()
                    return
            
            # Handle crop selection resizing/moving when finalized
            elif hasattr(parent, 'active_tool') and parent.active_tool == "crop" and self.selection_finalized:
                # Image bounds in widget coordinates for clamping
                img_left = int(self.offset.x())
                img_top = int(self.offset.y())
                img_right = img_left + int(self.image.width * self.scale) if self.image else self.width()
                img_bottom = img_top + int(self.image.height * self.scale) if self.image else self.height()
                
                if self.dragging_handle and self._crop_original_rect is not None:
                    ox1, oy1, ox2, oy2 = self._crop_original_rect
                    dx = pos.x() - self._crop_drag_start.x()
                    dy = pos.y() - self._crop_drag_start.y()
                    h = self.dragging_handle
                    nx1, ny1, nx2, ny2 = ox1, oy1, ox2, oy2
                    # Handle names: tl, tc, tr, rc, br, bc, bl, lc
                    if h in ('tl', 'bl', 'lc'):
                        nx1 = max(img_left, ox1 + dx)
                    if h in ('tr', 'br', 'rc'):
                        nx2 = min(img_right, ox2 + dx)
                    if h in ('tl', 'tc', 'tr'):
                        ny1 = max(img_top, oy1 + dy)
                    if h in ('bl', 'bc', 'br'):
                        ny2 = min(img_bottom, oy2 + dy)
                    # Ensure min size
                    if nx2 - nx1 > 10 and ny2 - ny1 > 10:
                        self.sel_start = QPoint(nx1, ny1)
                        self.sel_end = QPoint(nx2, ny2)
                    self.update()
                    return
                elif getattr(self, '_crop_moving', False) and self._crop_original_rect is not None:
                    ox1, oy1, ox2, oy2 = self._crop_original_rect
                    dx = pos.x() - self._crop_drag_start.x()
                    dy = pos.y() - self._crop_drag_start.y()
                    # Clamp movement so selection stays within image bounds
                    nx1 = ox1 + dx
                    ny1 = oy1 + dy
                    nx2 = ox2 + dx
                    ny2 = oy2 + dy
                    if nx1 < img_left:
                        nx1, nx2 = img_left, img_left + (ox2 - ox1)
                    if nx2 > img_right:
                        nx2, nx1 = img_right, img_right - (ox2 - ox1)
                    if ny1 < img_top:
                        ny1, ny2 = img_top, img_top + (oy2 - oy1)
                    if ny2 > img_bottom:
                        ny2, ny1 = img_bottom, img_bottom - (oy2 - oy1)
                    self.sel_start = QPoint(nx1, ny1)
                    self.sel_end = QPoint(nx2, ny2)
                    self.update()
                    return
            
            # Only compute drag direction if a drag is actually in progress
            # and selection has not been finalized (for cutout/crop tools)
            if self.sel_start is None or self.selection_finalized:
                return
            self.sel_end = pos
            if hasattr(parent, 'active_tool') and parent.active_tool == "crop":
                self.drag_mode = "crop"
                # Clamp selection to image bounds
                if self.image:
                    il = int(self.offset.x())
                    it = int(self.offset.y())
                    ir = il + int(self.image.width * self.scale)
                    ib = it + int(self.image.height * self.scale)
                    cx = max(il, min(ir, self.sel_end.x()))
                    cy = max(it, min(ib, self.sel_end.y()))
                    self.sel_end = QPoint(cx, cy)
            else:
                dx = abs(self.sel_end.x() - self.sel_start.x())
                dy = abs(self.sel_end.y() - self.sel_start.y())
                self.drag_mode = "horizontal" if dy > dx else "vertical"
            self.update()

    def leaveEvent(self, e):
        """Handle mouse leaving the widget - keep tracking if dragging"""
        # Don't clear tracking data if we're in a drag operation
        if self.mouse_captured:
            # Mouse left but we're still dragging - keep the drag active
            # The mouseMoveEvent will continue to receive events due to grabMouse()
            return
        super().leaveEvent(e)

    def mouseDoubleClickEvent(self, e):
        """Handle double-click to enable inline text editing or select all"""
        parent = self.window()
        if hasattr(parent, 'active_tool') and parent.active_tool == "text":
            if e.button() == Qt.MouseButton.LeftButton and self.current_text:
                text_str, x1, y1, x2, y2 = self.current_text
                # Check if double-clicking inside box
                if x1 <= e.pos().x() <= x2 and y1 <= e.pos().y() <= y2:
                    if self.text_editing:
                        # Already editing - select all text
                        self.text_selection_start = 0
                        self.text_selection_end = len(text_str)
                        self.text_cursor_pos = len(text_str)
                    else:
                        # Not editing - enter edit mode and select all
                        self.text_editing = True
                        self.text_cursor_pos = len(text_str)
                        self.text_selection_start = 0
                        self.text_selection_end = len(text_str)
                        self.setFocus()
                        self.start_cursor_blink()
                    self.update()
    
    def wheelEvent(self, e):
        """Handle mouse wheel for zoom controls"""
        parent = self.window()
        
        # Get modifiers and delta
        modifiers = e.modifiers()
        delta = e.angleDelta().y()
        
        # Alt + Wheel: Change crosshair circle size if magnifier enabled, else scroll horizontally
        if modifiers & Qt.KeyboardModifier.AltModifier:
            if hasattr(parent, 'crosshair_enabled') and parent.crosshair_enabled:
                step = 10  # pixels per wheel notch
                if delta > 0:
                    parent.crosshair_size = min(320, parent.crosshair_size + step)
                else:
                    parent.crosshair_size = max(80, parent.crosshair_size - step)
                if hasattr(parent, '_update_magnifier_size_checks'):
                    parent._update_magnifier_size_checks()
                self.update()
            else:
                # Horizontal scroll
                if hasattr(parent, 'scroll_area'):
                    h_bar = parent.scroll_area.horizontalScrollBar()
                    h_bar.setValue(h_bar.value() - delta)
            e.accept()
            return
        
        # Ctrl + Wheel: Zoom canvas
        if modifiers & Qt.KeyboardModifier.ControlModifier:
            if delta > 0:
                parent.zoom_in()
            else:
                parent.zoom_out()
            e.accept()
            return
        
        # Default: pass to parent
        super().wheelEvent(e)

    def keyPressEvent(self, e):
        """Handle keyboard input for inline text editing"""
        parent = self.window()
        
        if hasattr(parent, 'active_tool') and parent.active_tool == "text" and self.text_editing and self.current_text:
            text_str, x1, y1, x2, y2 = self.current_text
            
            from PyQt6.QtCore import Qt
            
            # Handle selection deletion
            if self.text_selection_start is not None and self.text_selection_end is not None:
                sel_start = min(self.text_selection_start, self.text_selection_end)
                sel_end = max(self.text_selection_start, self.text_selection_end)
                
                if e.key() == Qt.Key.Key_Backspace or e.key() == Qt.Key.Key_Delete:
                    # Delete selection
                    text_str = text_str[:sel_start] + text_str[sel_end:]
                    self.text_cursor_pos = sel_start
                    self.text_selection_start = None
                    self.text_selection_end = None
                    self.current_text = (text_str, x1, y1, x2, y2)
                    self.update()
                    return
                elif e.text() and e.text().isprintable():
                    # Replace selection with typed character
                    text_str = text_str[:sel_start] + e.text() + text_str[sel_end:]
                    self.text_cursor_pos = sel_start + 1
                    self.text_selection_start = None
                    self.text_selection_end = None
                    self.current_text = (text_str, x1, y1, x2, y2)
                    self.update()
                    return
            
            if e.key() == Qt.Key.Key_Backspace:
                # Delete character before cursor
                if self.text_cursor_pos > 0:
                    text_str = text_str[:self.text_cursor_pos-1] + text_str[self.text_cursor_pos:]
                    self.text_cursor_pos -= 1
                    self.current_text = (text_str, x1, y1, x2, y2)
                    self.update()
            elif e.key() == Qt.Key.Key_Delete:
                # Delete character after cursor
                if self.text_cursor_pos < len(text_str):
                    text_str = text_str[:self.text_cursor_pos] + text_str[self.text_cursor_pos+1:]
                    self.current_text = (text_str, x1, y1, x2, y2)
                    self.update()
            elif e.key() == Qt.Key.Key_Left:
                # Move cursor left (with Shift = select)
                if e.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                    # Shift+Left = extend selection left
                    if self.text_selection_start is None:
                        self.text_selection_start = self.text_cursor_pos
                    if self.text_cursor_pos > 0:
                        self.text_cursor_pos -= 1
                    self.text_selection_end = self.text_cursor_pos
                    self.update()
                else:
                    # Plain Left = move cursor, clear selection
                    if self.text_cursor_pos > 0:
                        self.text_cursor_pos -= 1
                    self.text_selection_start = None
                    self.text_selection_end = None
                    self.update()
            elif e.key() == Qt.Key.Key_Right:
                # Move cursor right (with Shift = select)
                if e.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                    # Shift+Right = extend selection right
                    if self.text_selection_start is None:
                        self.text_selection_start = self.text_cursor_pos
                    if self.text_cursor_pos < len(text_str):
                        self.text_cursor_pos += 1
                    self.text_selection_end = self.text_cursor_pos
                    self.update()
                else:
                    # Plain Right = move cursor, clear selection
                    if self.text_cursor_pos < len(text_str):
                        self.text_cursor_pos += 1
                    self.text_selection_start = None
                    self.text_selection_end = None
                    self.update()
            elif e.key() == Qt.Key.Key_Home:
                # Move cursor to start
                self.text_cursor_pos = 0
                self.text_selection_start = None
                self.text_selection_end = None
                self.update()
            elif e.key() == Qt.Key.Key_End:
                # Move cursor to end
                self.text_cursor_pos = len(text_str)
                self.text_selection_start = None
                self.text_selection_end = None
                self.update()
            elif e.key() == Qt.Key.Key_Return or e.key() == Qt.Key.Key_Enter:
                # Finish editing
                if text_str.strip():
                    self.text_editing = False
                    self.stop_cursor_blink()
                    self.update()
                else:
                    # Empty text - cancel
                    self.current_text = None
                    self.text_editing = False
                    self.stop_cursor_blink()
                    self.update()
            elif e.key() == Qt.Key.Key_Escape:
                # Cancel editing
                self.current_text = None
                self.text_editing = False
                self.stop_cursor_blink()
                self.update()
            elif e.text() and e.text().isprintable():
                # Insert character at cursor position
                text_str = text_str[:self.text_cursor_pos] + e.text() + text_str[self.text_cursor_pos:]
                self.text_cursor_pos += 1
                self.current_text = (text_str, x1, y1, x2, y2)
                self.update()
        else:
            # Pass to parent for other key handling
            super().keyPressEvent(e)

    def get_cursor_pos_from_click(self, click_pos, text_str, x1, y1, x2, y2, parent):
        """Get cursor position from click location with proper hit-testing"""
        from PyQt6.QtGui import QFont, QFontMetrics
        
        # Get font settings
        font_name = parent.text_font.currentText() if hasattr(parent, 'text_font') else "DejaVu Sans"
        font_size = parent.text_size.value() if hasattr(parent, 'text_size') else 24
        alignment = parent.text_alignment if hasattr(parent, 'text_alignment') else "center"
        
        font = QFont(font_name, font_size)
        font.setBold(True)
        metrics = QFontMetrics(font)
        
        # Wrap text exactly like draw_text_preview does
        padding = 10
        box_width = x2 - x1
        box_height = y2 - y1
        available_width = box_width - padding * 2
        
        words = text_str.split()
        lines = []
        current_line = ""
        
        for word in words:
            test_line = current_line + (" " if current_line else "") + word
            test_width = metrics.horizontalAdvance(test_line)
            
            if test_width <= available_width:
                current_line = test_line
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        
        if current_line:
            lines.append(current_line)
        
        if not lines:
            return 0
        
        # Calculate line positions
        line_height = metrics.height()
        total_height = line_height * len(lines)
        start_y = y1 + (box_height - total_height) / 2 + line_height * 0.8
        
        # Find which line was clicked
        clicked_line = 0
        for i in range(len(lines)):
            line_y = start_y + i * line_height
            if click_pos.y() < line_y:
                clicked_line = max(0, i - 1)
                break
        else:
            clicked_line = len(lines) - 1
        
        # Get the clicked line
        line = lines[clicked_line]
        line_width = metrics.horizontalAdvance(line)
        
        # Calculate line X position based on alignment
        if alignment == "left":
            line_x = x1 + padding
        elif alignment == "right":
            line_x = x1 + box_width - line_width - padding
        else:  # center
            line_x = x1 + (box_width - line_width) / 2
        
        # Find character position within the line
        click_x = click_pos.x()
        char_pos = 0
        
        for i in range(len(line) + 1):
            text_to_here = line[:i]
            width_to_here = metrics.horizontalAdvance(text_to_here)
            
            if line_x + width_to_here > click_x:
                # Check if click is closer to previous or current character
                if i > 0:
                    prev_width = metrics.horizontalAdvance(line[:i-1])
                    if abs(click_x - (line_x + prev_width)) < abs(click_x - (line_x + width_to_here)):
                        char_pos = i - 1
                    else:
                        char_pos = i
                else:
                    char_pos = 0
                break
        else:
            char_pos = len(line)
        
        # Convert line+char position to absolute position in original text
        # Account for wrapped lines
        absolute_pos = 0
        for i in range(clicked_line):
            absolute_pos += len(lines[i]) + 1  # +1 for space between lines
        absolute_pos += char_pos
        
        return min(absolute_pos, len(text_str))

    def mouseReleaseEvent(self, e):
        parent = self.window()
        
        # Release mouse capture on left button release
        if e.button() == Qt.MouseButton.LeftButton and self.mouse_captured:
            self.mouse_captured = False
            self.releaseMouse()

        # End panning
        if self.panning:
            self.panning = False
            self.pan_start_pos = None
            self.pan_start_scroll = None
            self.unsetCursor()  # Restore default cursor
            return

        if getattr(parent, '_eyedropper_active', False):
            return

        # Finish dragging a paste preview regardless of the active tool
        if self.cutpaste_dragging and self.cutpaste_paste_pos and self.cutpaste_clipboard:
            self.cutpaste_dragging = False
            self.sel_start = None
            self.sel_end = None
            self.update()
            return
        
        # Finish resizing a paste preview
        if self.cutpaste_resizing and self.cutpaste_paste_pos:
            self.cutpaste_resizing = None
            self.sel_start = None
            self.update()
            return

        if hasattr(parent, 'active_tool') and parent.active_tool == "rectangle":
            if self.dragging_handle:
                self.dragging_handle = None
            elif self.sel_start is not None:
                # Finalize the rectangle dimensions
                self.sel_start = None
                self.sel_end = None
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "oval":
            if self.dragging_handle:
                self.dragging_handle = None
            elif self.sel_start is not None:
                # Finalize the oval dimensions
                self.sel_start = None
                self.sel_end = None
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "line":
            if self.dragging_handle:
                self.dragging_handle = None
            elif self.sel_start is not None:
                # Finalize the line dimensions
                self.sel_start = None
                self.sel_end = None
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "arrow":
            if self.dragging_handle:
                self.dragging_handle = None
            elif self.sel_start is not None:
                # Finalize the arrow dimensions
                self.sel_start = None
                self.sel_end = None
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "freehand":
            if self.freehand_points:
                # Apply for all modes (even single click should work)
                # Don't re-apply color eraser (already applied in real-time)
                if hasattr(parent, 'freehand_mode') and parent.freehand_mode == 'color_eraser':
                    self.freehand_points = []
                    self.freehand_last_pos = None
                elif hasattr(parent, 'freehand_mode') and parent.freehand_mode == 'flood':
                    # Flood fill already applied in mousePressEvent
                    self.freehand_points = []
                    self.freehand_last_pos = None
                else:
                    # Real-time stroke is already in the image - just finalize undo
                    parent._freehand_end_stroke()
                    self.freehand_points = []
                    self.freehand_last_pos = None
        elif hasattr(parent, 'active_tool') and parent.active_tool == "cutpaste":
            if self.cutpaste_dragging:
                # Finished dragging paste preview
                self.cutpaste_dragging = False
                self.sel_start = None
                self.sel_end = None
                self.update()
            elif self.sel_start is not None and self.sel_end is not None:
                # Calculate selection size
                width = abs(self.sel_end.x() - self.sel_start.x())
                height = abs(self.sel_end.y() - self.sel_start.y())
                
                # Only create selection if it's large enough (more than 5 pixels in either direction)
                if width > 5 or height > 5:
                    # Finished making selection
                    self.cutpaste_selection = (
                        min(self.sel_start.x(), self.sel_end.x()),
                        min(self.sel_start.y(), self.sel_end.y()),
                        max(self.sel_start.x(), self.sel_end.x()),
                        max(self.sel_start.y(), self.sel_end.y())
                    )
                    # Clear drag-selection state so we don't keep drawing a 'ghost' selection
                    self.sel_start = None
                    self.sel_end = None
                    self.update()
                    # Update button states now that we have a selection
                    parent.update_tool_buttons_state()
                else:
                    # Selection too small - clear it (user just clicked without dragging)
                    self.cutpaste_selection = None
                    self.sel_start = None
                    self.sel_end = None
                    self.update()
                    # Update button states since selection was cleared
                    parent.update_tool_buttons_state()
        elif hasattr(parent, 'active_tool') and (parent.active_tool == "cutout" or parent.active_tool == "crop"):
            # Stop handle/move dragging for cutout
            if parent.active_tool == "cutout" and (self.dragging_handle or getattr(self, '_crop_moving', False)):
                self.dragging_handle = None
                self._crop_moving = False
                self.selection_finalized = True
                self.update()
                parent.update_tool_buttons_state()
                return
            
            # Stop handle/move dragging for crop
            if parent.active_tool == "crop" and (self.dragging_handle or getattr(self, '_crop_moving', False)):
                self.dragging_handle = None
                self._crop_moving = False
                self.selection_finalized = True
                self.update()
                parent.update_tool_buttons_state()
                return
            
            # Finished making selection for cutout or crop.
            if self.sel_start is not None and self.sel_end is not None:
                # Check if selection is large enough (more than 5 pixels)
                width = abs(self.sel_end.x() - self.sel_start.x())
                height = abs(self.sel_end.y() - self.sel_start.y())
                
                if width > 5 or height > 5:
                    # IMPORTANT: keep sel_start/sel_end so Apply (Cut Out / Crop) buttons can use them.
                    # Set flag to prevent mouseMoveEvent from updating sel_end after release.
                    self.selection_finalized = True
                    self.update()
                    # Update button states now that we have a selection
                    parent.update_tool_buttons_state()
                else:
                    # Selection too small - clear it
                    self.sel_start = None
                    self.sel_end = None
                    self.selection_finalized = False
                    self.update()
                    # Update button states since selection was cleared
                    parent.update_tool_buttons_state()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "highlight":
            style = parent.highlight_style.currentText()
            if style == "Rectangle" or style == "Spotlight":
                # Finalize rectangle or stop handle dragging
                if self.dragging_handle:
                    self.dragging_handle = None
                elif self.sel_start is not None:
                    # Finalized rectangle dimensions
                    self.sel_start = None
                    self.sel_end = None
                    self.update()
            else:
                # Pen mode - apply stroke
                if hasattr(self, 'current_highlight_stroke') and self.current_highlight_stroke:
                    if not hasattr(self, 'highlight_strokes'):
                        self.highlight_strokes = []
                    self.highlight_strokes.append(self.current_highlight_stroke)
                    self.current_highlight_stroke = None
                    self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "magnify_inset":
            if self.inset_dragging_dest:
                self.inset_dragging_dest = False
                self.inset_drag_offset = None
            elif self.dragging_handle:
                self.dragging_handle = None
            elif self.sel_start is not None and self.inset_source_rect:
                # Finished drawing source selection - auto-place inset to the right
                x1, y1, x2, y2 = self.inset_source_rect
                sw = x2 - x1
                sh = y2 - y1
                if sw > 5 and sh > 5:
                    # Place inset to the right of source, offset by 20px
                    self.inset_dest_pos = (x2 + 20, y1)
                else:
                    self.inset_source_rect = None
                self.sel_start = None
                self.sel_end = None
            self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "pixelate":
            # Finalize rectangle or stop handle dragging
            if self.dragging_handle:
                self.dragging_handle = None
            elif self.sel_start is not None:
                # Finalized rectangle dimensions
                self.sel_start = None
                self.sel_end = None
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "blur":
            if self.dragging_handle:
                self.dragging_handle = None
            elif self.sel_start is not None:
                self.sel_start = None
                self.sel_end = None
                self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "step_marker":
            # Released after placing/dragging current marker
            if self.current_marker:
                if self.placing_new_marker and self.dragging_badge:
                    # Badge is now placed, tail stays at anchor
                    self.placing_new_marker = False
                
                # Stop any dragging
                self.dragging_badge = False
                self.dragging_tail_handle = False
            
            # Released after dragging existing marker
            elif self.active_marker_index is not None:
                self.dragging_badge = False
                self.dragging_tail_handle = False
                # Keep marker active for further editing
            
            self.update()
        elif hasattr(parent, 'active_tool') and parent.active_tool == "text":
            # Check if we were drawing a new box
            if self.sel_start is not None and self.sel_end is not None and not self.current_text:
                # Create text box from dragged rectangle
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                
                # Ensure minimum size
                min_width = 50
                min_height = 30
                if x2 - x1 < min_width:
                    x2 = x1 + min_width
                if y2 - y1 < min_height:
                    y2 = y1 + min_height
                
                # Constrain to image bounds
                if self.image:
                    img_width = int(self.image.width * self.scale)
                    img_height = int(self.image.height * self.scale)
                    img_x1 = self.offset.x()
                    img_y1 = self.offset.y()
                    img_x2 = img_x1 + img_width
                    img_y2 = img_y1 + img_height
                    
                    x1 = max(img_x1, min(x1, img_x2))
                    y1 = max(img_y1, min(y1, img_y2))
                    x2 = max(img_x1, min(x2, img_x2))
                    y2 = max(img_y1, min(y2, img_y2))
                
                # Create text box and start editing
                self.current_text = ("", x1, y1, x2, y2)
                self.text_editing = True
                self.text_cursor_pos = 0
                self.setFocus()
                self.start_cursor_blink()
                self.sel_start = None
                self.sel_end = None
                self.update()
            else:
                # Stop dragging/selecting
                if self.selecting_text:
                    # If selection start == end, clear selection
                    if self.text_selection_start == self.text_selection_end:
                        self.text_selection_start = None
                        self.text_selection_end = None
                    self.selecting_text = False
                
                self.dragging_text_box = False
                self.dragging_handle = None
                self.sel_start = None
                self.update()

    def get_handle_positions(self, rect):
        """Get positions of all 8 handles for a rectangle (x1, y1, x2, y2)"""
        x1, y1, x2, y2 = rect
        cx = (x1 + x2) / 2
        cy = (y1 + y2) / 2
        return {
            'tl': (x1, y1),      # Top-left
            'tc': (cx, y1),      # Top-center
            'tr': (x2, y1),      # Top-right
            'rc': (x2, cy),      # Right-center
            'br': (x2, y2),      # Bottom-right
            'bc': (cx, y2),      # Bottom-center
            'bl': (x1, y2),      # Bottom-left
            'lc': (x1, cy),      # Left-center
        }

    def _get_transparent_preview_brush(self, color):
        """Return a checkerboard QBrush tinted with the color for previewing transparent areas.
        Uses the same 8px white/gray(204) pattern as the canvas background checkerboard,
        scaled to match current zoom level.
        If color is fully opaque, returns a normal solid brush."""
        if isinstance(color, QColor) and color.alpha() < 255:
            tile = self._get_scaled_checker_tile()
            if color.alpha() > 0:
                # Create a tinted copy
                tinted = tile.copy()
                tp = QPainter(tinted)
                tp.fillRect(0, 0, tinted.width(), tinted.height(), color)
                tp.end()
                return QBrush(tinted)
            return QBrush(tile)
        return QBrush(color)

    def _get_checker_tile(self):
        """Return a cached 16x16 checkerboard QPixmap tile for transparency previews."""
        if not hasattr(self, '_checker_tile_cache') or self._checker_tile_cache is None:
            sz = 8
            tile = QPixmap(sz * 2, sz * 2)
            tile.fill(QColor(255, 255, 255))
            tp = QPainter(tile)
            tp.fillRect(sz, 0, sz, sz, QColor(204, 204, 204))
            tp.fillRect(0, sz, sz, sz, QColor(204, 204, 204))
            tp.end()
            self._checker_tile_cache = tile
        return self._checker_tile_cache

    def _get_scaled_checker_tile(self):
        """Return a checkerboard tile scaled to match current zoom level.
        This ensures the preview checkerboard aligns with the canvas background."""
        base = self._get_checker_tile()
        scaled_sz = max(2, int(8 * self.scale))
        total = scaled_sz * 2
        if total != base.width():
            return base.scaled(total, total, Qt.AspectRatioMode.IgnoreAspectRatio,
                              Qt.TransformationMode.FastTransformation)
        return base

    def _draw_transparent_stroke_preview(self, p, points, stroke_width, is_circles=False):
        """Draw a checkerboard preview along a freehand stroke path.
        
        Uses QPainterPath as clip region filled with cached checkerboard tile,
        aligned to image origin so it matches the canvas background exactly.
        """
        if not points:
            return
        
        # Build a path of the stroke shape
        stroke_path = QPainterPath()
        r = stroke_width / 2
        
        if is_circles or len(points) == 1:
            # Draw circles at each point
            for point in points:
                stroke_path.addEllipse(point.x() - r, point.y() - r, stroke_width, stroke_width)
        else:
            # Build a thick line path using QPainterPathStroker
            thin_path = QPainterPath()
            thin_path.moveTo(points[0].x(), points[0].y())
            for i in range(1, len(points)):
                thin_path.lineTo(points[i].x(), points[i].y())
            
            stroker = QPainterPathStroker()
            stroker.setWidth(stroke_width)
            stroker.setCapStyle(Qt.PenCapStyle.RoundCap)
            stroker.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            stroke_path = stroker.createStroke(thin_path)
        
        # Clip to the stroke shape and fill with checkerboard
        p.save()
        p.setClipPath(stroke_path)
        
        tile = self._get_scaled_checker_tile()
        bounds = stroke_path.boundingRect().toAlignedRect()
        p.drawTiledPixmap(bounds, tile)
        
        p.restore()

    def _shape_changed(self):
        """Call after shape coordinate change to update WYSIWYG preview and repaint.
        
        Throttles expensive preview generation to ~30fps during active drawing
        to avoid lag on large images.
        """
        if self.sel_start is not None:
            # During active drawing, throttle the expensive preview
            if not hasattr(self, '_shape_preview_timer'):
                from PyQt6.QtCore import QTimer
                self._shape_preview_timer = QTimer()
                self._shape_preview_timer.setSingleShot(True)
                self._shape_preview_timer.timeout.connect(self._deferred_shape_preview)
            if not self._shape_preview_timer.isActive():
                self._shape_preview_timer.start(33)  # ~30fps
            self.update()  # Repaint handles immediately
            return
        # Not actively drawing (handle drag or finalized) — update immediately
        self.shape_preview_image = None
        self.shape_preview_pixmap = None
        self._shape_preview_key = None
        parent = self.window()
        if hasattr(parent, '_update_shape_preview'):
            parent._update_shape_preview()
        self.update()
    
    def _deferred_shape_preview(self):
        """Generate the WYSIWYG preview after throttle delay."""
        self.shape_preview_image = None
        self.shape_preview_pixmap = None
        self._shape_preview_key = None
        parent = self.window()
        if hasattr(parent, '_update_shape_preview'):
            parent._update_shape_preview()
        self.update()

    def clear_shape_preview(self):
        """Clear any shape preview state"""
        self.shape_preview_image = None
        self.shape_preview_pixmap = None
        self._shape_preview_key = None

    def get_handle_at_pos(self, pos, shape):
        """Check if pos is over any handle of the given shape"""
        if not shape:
            return None
        
        handles = self.get_handle_positions(shape)
        for name, (hx, hy) in handles.items():
            if abs(pos.x() - hx) <= self.handle_size and abs(pos.y() - hy) <= self.handle_size:
                return name
        return None

    def resize_shape_with_handle(self, pos, is_rect=True):
        """Resize current shape (rect or oval) by dragging a handle"""
        current_shape = self.current_rect if is_rect else self.current_oval
        if not current_shape or not self.dragging_handle:
            return
        
        x1, y1, x2, y2 = current_shape
        px, py = pos.x(), pos.y()
        
        # Update shape based on which handle is being dragged
        if self.dragging_handle == 'tl':
            x1, y1 = px, py
        elif self.dragging_handle == 'tc':
            y1 = py
        elif self.dragging_handle == 'tr':
            x2, y1 = px, py
        elif self.dragging_handle == 'rc':
            x2 = px
        elif self.dragging_handle == 'br':
            x2, y2 = px, py
        elif self.dragging_handle == 'bc':
            y2 = py
        elif self.dragging_handle == 'bl':
            x1, y2 = px, py
        elif self.dragging_handle == 'lc':
            x1 = px
        
        # Ensure x1 < x2 and y1 < y2
        new_shape = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
        if is_rect:
            self.current_rect = new_shape
        else:
            self.current_oval = new_shape
    
    def update_rect_from_handle(self, pos, rect, handle):
        """Update rectangle by dragging a handle"""
        x1, y1, x2, y2 = rect
        px, py = pos.x(), pos.y()
        
        # Update rect based on which handle is being dragged
        if handle == 'tl':
            x1, y1 = px, py
        elif handle == 'tc':
            y1 = py
        elif handle == 'tr':
            x2, y1 = px, py
        elif handle == 'rc':
            x2 = px
        elif handle == 'br':
            x2, y2 = px, py
        elif handle == 'bc':
            y2 = py
        elif handle == 'bl':
            x1, y2 = px, py
        elif handle == 'lc':
            x1 = px
        
        # Ensure x1 < x2 and y1 < y2
        self.current_highlight_rect = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
    
    def update_pixelate_rect_from_handle(self, pos, rect, handle):
        """Update pixelate rectangle by dragging a handle"""
        x1, y1, x2, y2 = rect
        px, py = pos.x(), pos.y()
        
        # Update rect based on which handle is being dragged
        if handle == 'tl':
            x1, y1 = px, py
        elif handle == 'tc':
            y1 = py
        elif handle == 'tr':
            x2, y1 = px, py
        elif handle == 'rc':
            x2 = px
        elif handle == 'br':
            x2, y2 = px, py
        elif handle == 'bc':
            y2 = py
        elif handle == 'bl':
            x1, y2 = px, py
        elif handle == 'lc':
            x1 = px
        
        # Ensure x1 < x2 and y1 < y2
        self.current_pixelate_rect = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))

    def paintEvent(self, e):
        # During freehand stroke, draw live QImage directly instead of base pixmap
        if self._freehand_live_qimg is not None:
            # Let QLabel paint its background
            QWidget.paintEvent(self, e)
            p = QPainter(self)
            # Draw only the visible portion of the image at current scale
            visible = self.visibleRegion().boundingRect()
            # Source rect in image coordinates
            src_x = max(0, int(visible.x() / self.scale))
            src_y = max(0, int(visible.y() / self.scale))
            src_w = min(self._freehand_live_qimg.width() - src_x, int(visible.width() / self.scale) + 2)
            src_h = min(self._freehand_live_qimg.height() - src_y, int(visible.height() / self.scale) + 2)
            src_rect = QRectF(src_x, src_y, src_w, src_h)
            # Dest rect in widget coordinates
            dst_x = int(src_x * self.scale)
            dst_y = int(src_y * self.scale)
            dst_w = int(src_w * self.scale)
            dst_h = int(src_h * self.scale)
            dst_rect = QRectF(dst_x, dst_y, dst_w, dst_h)
            
            # Draw checkerboard behind image so transparency shows correctly
            if not hasattr(self, '_checker_tile') or self._checker_tile is None:
                cs = 8
                self._checker_tile = QPixmap(cs * 2, cs * 2)
                self._checker_tile.fill(QColor(255, 255, 255))
                tp = QPainter(self._checker_tile)
                tp.fillRect(cs, 0, cs, cs, QColor(204, 204, 204))
                tp.fillRect(0, cs, cs, cs, QColor(204, 204, 204))
                tp.end()
            p.drawTiledPixmap(int(dst_rect.x()), int(dst_rect.y()),
                              int(dst_rect.width()), int(dst_rect.height()),
                              self._checker_tile)
            
            p.drawImage(dst_rect, self._freehand_live_qimg, src_rect)
            
            # Draw pixel grid during freehand stroke too
            parent_fg = self.window()
            if (hasattr(parent_fg, 'pixel_grid_enabled') and parent_fg.pixel_grid_enabled 
                    and self.scale >= 3.0 and self._freehand_live_qimg is not None):
                grid_pen = QPen(QColor(128, 128, 128, 80), 1, Qt.PenStyle.SolidLine)
                p.setPen(grid_pen)
                img_w = self._freehand_live_qimg.width()
                img_h = self._freehand_live_qimg.height()
                visible = self.visibleRegion().boundingRect()
                ix0 = max(0, int(visible.x() / self.scale))
                iy0 = max(0, int(visible.y() / self.scale))
                ix1 = min(img_w, int((visible.x() + visible.width()) / self.scale) + 1)
                iy1 = min(img_h, int((visible.y() + visible.height()) / self.scale) + 1)
                s = self.scale
                for ix in range(ix0, ix1 + 1):
                    sx = int(ix * s)
                    p.drawLine(sx, int(iy0 * s), sx, int(iy1 * s))
                for iy in range(iy0, iy1 + 1):
                    sy = int(iy * s)
                    p.drawLine(int(ix0 * s), sy, int(ix1 * s), sy)
            
            p.end()
            return
        
        super().paintEvent(e)
        if not self.pixmap():
            return
        
        p = QPainter(self)
        
        # Display cached WYSIWYG shape preview image if available
        if self.shape_preview_image is not None:
            if self.shape_preview_pixmap is None:
                preview = self.shape_preview_image
                if preview.mode != 'RGBA':
                    preview = preview.convert('RGBA')
                data = preview.tobytes('raw', 'RGBA')
                qimg = QImage(data, preview.width, preview.height, preview.width * 4, QImage.Format.Format_RGBA8888)
                
                # Composite with checkerboard so transparency displays correctly
                w, h = preview.width, preview.height
                if not hasattr(self, '_checker_tile') or self._checker_tile is None:
                    cs = 8
                    self._checker_tile = QPixmap(cs * 2, cs * 2)
                    self._checker_tile.fill(QColor(255, 255, 255))
                    tp = QPainter(self._checker_tile)
                    tp.fillRect(cs, 0, cs, cs, QColor(204, 204, 204))
                    tp.fillRect(0, cs, cs, cs, QColor(204, 204, 204))
                    tp.end()
                composited = QPixmap(w, h)
                cp = QPainter(composited)
                cp.drawTiledPixmap(0, 0, w, h, self._checker_tile)
                cp.drawImage(0, 0, qimg)
                cp.end()
                self.shape_preview_pixmap = composited
            
            img_x = int(self.offset.x())
            img_y = int(self.offset.y())
            pw = int(self.shape_preview_image.width * self.scale)
            ph = int(self.shape_preview_image.height * self.scale)
            p.drawPixmap(img_x, img_y, pw, ph, self.shape_preview_pixmap)
        
        # Draw pixel grid when enabled and zoom >= 300%
        parent = self.window()
        if (hasattr(parent, 'pixel_grid_enabled') and parent.pixel_grid_enabled 
                and self.scale >= 3.0 and self.image):
            grid_pen = QPen(QColor(128, 128, 128, 80), 1, Qt.PenStyle.SolidLine)
            p.setPen(grid_pen)
            
            # Calculate visible area in image coordinates
            visible = self.visibleRegion().boundingRect()
            img_x0 = max(0, int(visible.x() / self.scale))
            img_y0 = max(0, int(visible.y() / self.scale))
            img_x1 = min(self.image.width, int((visible.x() + visible.width()) / self.scale) + 1)
            img_y1 = min(self.image.height, int((visible.y() + visible.height()) / self.scale) + 1)
            
            s = self.scale
            # Vertical lines
            for ix in range(img_x0, img_x1 + 1):
                sx = int(ix * s)
                p.drawLine(sx, int(img_y0 * s), sx, int(img_y1 * s))
            # Horizontal lines
            for iy in range(img_y0, img_y1 + 1):
                sy = int(iy * s)
                p.drawLine(int(img_x0 * s), sy, int(img_x1 * s), sy)
        
        # Use smooth drawing setting for anti-aliasing (cached on parent window)
        parent = self.window()
        smooth = getattr(parent, '_cached_smooth_drawing', False)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, smooth)
        
        # Draw selection rectangle ONLY for Crop and Cut Out tools
        if self.sel_start is not None and self.sel_end is not None:
            # Only show selection for Crop and Cut Out tools, and only if actually dragging
            # (start and end points are different)
            if hasattr(parent, 'active_tool') and parent.active_tool in ["crop", "cutout"]:
                # Check if there's actual dragging (points are more than 2 pixels apart)
                if abs(self.sel_end.x() - self.sel_start.x()) > 2 or abs(self.sel_end.y() - self.sel_start.y()) > 2:
                    if parent.active_tool == "cutout":
                        # Cut Out tool preview
                        img_left = self.offset.x()
                        img_top = self.offset.y()
                        img_width = self.pixmap().width()
                        img_height = self.pixmap().height()
                        
                        # Get cut parameters from parent
                        cut_style = parent.cut_style.currentText() if hasattr(parent, 'cut_style') else "Sawtooth"
                        saw_size = parent.saw.value() if hasattr(parent, 'saw') else 24
                        gap_pct = parent.gap.value() if hasattr(parent, 'gap') else 60
                        pr = getattr(parent, 'primary_color', (255, 255, 0, 255))
                        outline_alpha = int(pr[3]) if len(pr) > 3 else 255
                        outline = None if outline_alpha == 0 else (int(pr[0]), int(pr[1]), int(pr[2]), outline_alpha)
                        preview_mode = parent.cut_preview_type.currentText() if hasattr(parent, 'cut_preview_type') else "Outline"
                        
                        if self.drag_mode == "horizontal":
                            y1, y2 = sorted([self.sel_start.y(), self.sel_end.y()])
                            y1 = max(img_top, min(img_top + img_height, y1))
                            y2 = max(img_top, min(img_top + img_height, y2))
                            
                            img_y1 = max(0, min(self.image.height, int((y1 - img_top) / self.scale)))
                            img_y2 = max(0, min(self.image.height, int((y2 - img_top) / self.scale)))
                            
                            if preview_mode == "Result":
                                # Result mode: render actual cut and overlay it
                                cache_key = ('h_result', img_y1, img_y2, saw_size, gap_pct, outline, cut_style)
                                if getattr(self, '_cutout_preview_key', None) != cache_key:
                                    if img_y2 > img_y1:
                                        result_pil = horizontal_cut(self.image, img_y1, img_y2, saw_size, gap_pct, outline, cut_style)
                                        result_qimg = PilToQImage(result_pil)
                                        self._cutout_preview_pm = QPixmap.fromImage(result_qimg)
                                    else:
                                        self._cutout_preview_pm = None
                                    self._cutout_preview_key = cache_key
                                
                                if self._cutout_preview_pm is not None:
                                    sw = int(self._cutout_preview_pm.width() * self.scale)
                                    sh = int(self._cutout_preview_pm.height() * self.scale)
                                    overlay_color = QColor(0, 0, 0, 128)
                                    p.fillRect(int(img_left), int(y1), int(img_width), int(y2 - y1), overlay_color)
                                    p.save()
                                    p.setOpacity(0.85)
                                    p.drawPixmap(int(img_left), int(img_top), sw, sh, self._cutout_preview_pm)
                                    p.restore()
                            else:
                                # Outline mode: shaped dark overlay matching actual removal zone
                                overlay_color = QColor(0, 0, 0, 128)
                                
                                if cut_style == "Sawtooth" and img_y2 > img_y1:
                                    at_top = (img_y1 <= 0)
                                    at_bottom = (img_y2 >= self.image.height)
                                    amp = saw_size // 2
                                    step = saw_size
                                    s = self.scale
                                    w = self.image.width
                                    
                                    # Build top edge — exact same loop as horizontal_cut:
                                    # moveTo(0, y1); for x in range(0, w+step+step//2, step): lineTo(x, y1±amp)
                                    top_edge = QPainterPath()
                                    top_seam = None
                                    if not at_top:
                                        top_seam = QPainterPath()
                                        sx0 = img_left
                                        sy0 = img_top + img_y1 * s
                                        top_seam.moveTo(sx0, sy0)
                                        top_edge.moveTo(sx0, sy0)
                                        up_flag = True
                                        for x in range(0, w + step + (step // 2), step):
                                            tooth_y = img_y1 - amp if up_flag else img_y1 + amp
                                            sx = img_left + x * s
                                            sy = img_top + tooth_y * s
                                            top_edge.lineTo(sx, sy)
                                            top_seam.lineTo(sx, sy)
                                            up_flag = not up_flag
                                        top_edge.lineTo(img_left + img_width, y1)
                                    else:
                                        top_edge.moveTo(img_left, img_top)
                                        top_edge.lineTo(img_left + img_width, img_top)
                                    
                                    # Build bottom edge — same tooth phase as top so teeth align
                                    # Offset teeth outward by half the gap width since the gap
                                    # erodes into the kept area below the seam
                                    bottom_edge = QPainterPath()
                                    if not at_bottom:
                                        gap_half = max(2, int(step * (gap_pct / 100.0))) / 2.0
                                        bottom_points = []
                                        up_flag = True
                                        for x in range(0, w + step + (step // 2), step):
                                            tooth_y = img_y2 - amp if up_flag else img_y2 + amp
                                            tooth_y += gap_half  # push outward to cover gap erosion
                                            sx = img_left + x * s
                                            sy = img_top + tooth_y * s
                                            bottom_points.append((sx, sy))
                                            up_flag = not up_flag
                                        bottom_edge.moveTo(img_left + img_width, y2)
                                        for sx, sy in reversed(bottom_points):
                                            bottom_edge.lineTo(sx, sy)
                                        bottom_edge.lineTo(img_left, y2)
                                    else:
                                        bottom_edge.moveTo(img_left + img_width, img_top + img_height)
                                        bottom_edge.lineTo(img_left, img_top + img_height)
                                    
                                    # Combine into closed shape and draw
                                    removal_zone = QPainterPath(top_edge)
                                    removal_zone.connectPath(bottom_edge)
                                    removal_zone.closeSubpath()
                                    
                                    p.setPen(Qt.PenStyle.NoPen)
                                    p.setBrush(QBrush(overlay_color))
                                    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
                                    p.drawPath(removal_zone)
                                    
                                    # Draw seam line along top edge showing gap
                                    if top_seam and outline:
                                        gap_w = max(2, int(step * (gap_pct / 100.0))) * s
                                        p.setPen(QPen(QColor(*outline), gap_w,
                                                       Qt.PenStyle.SolidLine,
                                                       Qt.PenCapStyle.FlatCap,
                                                       Qt.PenJoinStyle.MiterJoin))
                                        p.setBrush(Qt.BrushStyle.NoBrush)
                                        p.drawPath(top_seam)
                                elif cut_style == "Line" and img_y2 > img_y1:
                                    # Line style: show the strip plus the line at seam
                                    p.fillRect(int(img_left), int(y1), int(img_width), int(y2 - y1), overlay_color)
                                    if outline:
                                        line_w = max(1, int(saw_size * self.scale))
                                        p.setPen(QPen(QColor(*outline), line_w, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap))
                                        p.drawLine(int(img_left), int(y1), int(img_left + img_width), int(y1))
                                else:
                                    # No effect: plain rectangle overlay
                                    p.fillRect(int(img_left), int(y1), int(img_width), int(y2 - y1), overlay_color)
                            
                            # Draw handles if finalized
                            if self.selection_finalized:
                                strip_h = abs(y2 - y1)
                                hs = self._dynamic_handle_size(strip_h)
                                mid_x = img_left + img_width / 2
                                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                                p.setBrush(QBrush(QColor(255, 255, 255)))
                                p.drawEllipse(int(mid_x - hs/2), int(y1 - hs/2),
                                              hs, hs)
                                p.drawEllipse(int(mid_x - hs/2), int(y2 - hs/2),
                                              hs, hs)
                            
                        else:
                            x1, x2 = sorted([self.sel_start.x(), self.sel_end.x()])
                            x1 = max(img_left, min(img_left + img_width, x1))
                            x2 = max(img_left, min(img_left + img_width, x2))
                            
                            img_x1 = max(0, min(self.image.width, int((x1 - img_left) / self.scale)))
                            img_x2 = max(0, min(self.image.width, int((x2 - img_left) / self.scale)))
                            
                            if preview_mode == "Result":
                                # Result mode: render actual cut and overlay it
                                cache_key = ('v_result', img_x1, img_x2, saw_size, gap_pct, outline, cut_style)
                                if getattr(self, '_cutout_preview_key', None) != cache_key:
                                    if img_x2 > img_x1:
                                        result_pil = vertical_cut(self.image, img_x1, img_x2, saw_size, gap_pct, outline, cut_style)
                                        result_qimg = PilToQImage(result_pil)
                                        self._cutout_preview_pm = QPixmap.fromImage(result_qimg)
                                    else:
                                        self._cutout_preview_pm = None
                                    self._cutout_preview_key = cache_key
                                
                                if self._cutout_preview_pm is not None:
                                    sw = int(self._cutout_preview_pm.width() * self.scale)
                                    sh = int(self._cutout_preview_pm.height() * self.scale)
                                    overlay_color = QColor(0, 0, 0, 128)
                                    p.fillRect(int(x1), int(img_top), int(x2 - x1), int(img_height), overlay_color)
                                    p.save()
                                    p.setOpacity(0.85)
                                    p.drawPixmap(int(img_left), int(img_top), sw, sh, self._cutout_preview_pm)
                                    p.restore()
                            else:
                                # Outline mode: shaped dark overlay matching actual removal zone
                                overlay_color = QColor(0, 0, 0, 128)
                                
                                if cut_style == "Sawtooth" and img_x2 > img_x1:
                                    at_left = (img_x1 <= 0)
                                    at_right = (img_x2 >= self.image.width)
                                    amp = saw_size // 2
                                    step = saw_size
                                    s = self.scale
                                    h = self.image.height
                                    
                                    # Build left edge — exact same loop as vertical_cut:
                                    # moveTo(x1, 0); for y in range(0, h+step+step//2, step): lineTo(x1±amp, y)
                                    left_edge = QPainterPath()
                                    left_seam = None
                                    if not at_left:
                                        left_seam = QPainterPath()
                                        sx0 = img_left + img_x1 * s
                                        sy0 = img_top
                                        left_seam.moveTo(sx0, sy0)
                                        left_edge.moveTo(sx0, sy0)
                                        up_flag = True
                                        for y in range(0, h + step + (step // 2), step):
                                            tooth_x = img_x1 - amp if up_flag else img_x1 + amp
                                            sx = img_left + tooth_x * s
                                            sy = img_top + y * s
                                            left_edge.lineTo(sx, sy)
                                            left_seam.lineTo(sx, sy)
                                            up_flag = not up_flag
                                        left_edge.lineTo(x1, img_top + img_height)
                                    else:
                                        left_edge.moveTo(img_left, img_top)
                                        left_edge.lineTo(img_left, img_top + img_height)
                                    
                                    # Build right edge — same tooth phase as left so teeth align
                                    # Offset teeth outward by half the gap width
                                    right_edge = QPainterPath()
                                    if not at_right:
                                        gap_half = max(2, int(step * (gap_pct / 100.0))) / 2.0
                                        right_points = []
                                        up_flag = True
                                        for y in range(0, h + step + (step // 2), step):
                                            tooth_x = img_x2 - amp if up_flag else img_x2 + amp
                                            tooth_x += gap_half  # push outward to cover gap erosion
                                            sx = img_left + tooth_x * s
                                            sy = img_top + y * s
                                            right_points.append((sx, sy))
                                            up_flag = not up_flag
                                        right_edge.moveTo(x2, img_top + img_height)
                                        for sx, sy in reversed(right_points):
                                            right_edge.lineTo(sx, sy)
                                        right_edge.lineTo(x2, img_top)
                                    else:
                                        right_edge.moveTo(img_left + img_width, img_top + img_height)
                                        right_edge.lineTo(img_left + img_width, img_top)
                                    
                                    # Combine into closed shape and draw
                                    removal_zone = QPainterPath(left_edge)
                                    removal_zone.connectPath(right_edge)
                                    removal_zone.closeSubpath()
                                    
                                    p.setPen(Qt.PenStyle.NoPen)
                                    p.setBrush(QBrush(overlay_color))
                                    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
                                    p.drawPath(removal_zone)
                                    
                                    # Draw seam line along left edge showing gap
                                    if left_seam and outline:
                                        gap_w = max(2, int(step * (gap_pct / 100.0))) * s
                                        p.setPen(QPen(QColor(*outline), gap_w,
                                                       Qt.PenStyle.SolidLine,
                                                       Qt.PenCapStyle.FlatCap,
                                                       Qt.PenJoinStyle.MiterJoin))
                                        p.setBrush(Qt.BrushStyle.NoBrush)
                                        p.drawPath(left_seam)
                                elif cut_style == "Line" and img_x2 > img_x1:
                                    p.fillRect(int(x1), int(img_top), int(x2 - x1), int(img_height), overlay_color)
                                    if outline:
                                        line_w = max(1, int(saw_size * self.scale))
                                        p.setPen(QPen(QColor(*outline), line_w, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap))
                                        p.drawLine(int(x1), int(img_top), int(x1), int(img_top + img_height))
                                else:
                                    p.fillRect(int(x1), int(img_top), int(x2 - x1), int(img_height), overlay_color)
                            
                            # Draw handles if finalized
                            if self.selection_finalized:
                                strip_w = abs(x2 - x1)
                                hs = self._dynamic_handle_size(strip_w)
                                mid_y = img_top + img_height / 2
                                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                                p.setBrush(QBrush(QColor(255, 255, 255)))
                                p.drawEllipse(int(x1 - hs/2), int(mid_y - hs/2),
                                              hs, hs)
                                p.drawEllipse(int(x2 - hs/2), int(mid_y - hs/2),
                                              hs, hs)
                    
                    elif self.drag_mode == "crop":
                        # Rectangular selection (for crop tool)
                        x1 = int(min(self.sel_start.x(), self.sel_end.x()))
                        y1 = int(min(self.sel_start.y(), self.sel_end.y()))
                        x2 = int(max(self.sel_start.x(), self.sel_end.x()))
                        y2 = int(max(self.sel_start.y(), self.sel_end.y()))
                        
                        # Draw dim overlay outside the crop area
                        img_left = int(self.offset.x())
                        img_top = int(self.offset.y())
                        img_w = int(self.pixmap().width())
                        img_h = int(self.pixmap().height())
                        overlay_color = QColor(0, 0, 0, 128)
                        
                        # Clamp crop rect to image bounds for overlay
                        cx1 = max(img_left, x1)
                        cy1 = max(img_top, y1)
                        cx2 = min(img_left + img_w, x2)
                        cy2 = min(img_top + img_h, y2)
                        
                        # Top strip
                        if cy1 > img_top:
                            p.fillRect(img_left, img_top,
                                       img_w, cy1 - img_top, overlay_color)
                        # Bottom strip
                        if cy2 < img_top + img_h:
                            p.fillRect(img_left, cy2,
                                       img_w, img_top + img_h - cy2, overlay_color)
                        # Left strip (between top and bottom)
                        if cx1 > img_left:
                            p.fillRect(img_left, cy1,
                                       cx1 - img_left, cy2 - cy1, overlay_color)
                        # Right strip (between top and bottom)
                        if cx2 < img_left + img_w:
                            p.fillRect(cx2, cy1,
                                       img_left + img_w - cx2, cy2 - cy1, overlay_color)
                        
                        # Draw crop border
                        p.setPen(QPen(QColor(60, 255, 60), 2, Qt.PenStyle.DashLine))
                        p.drawRect(x1, y1, x2 - x1, y2 - y1)
                        
                        # Draw pixel dimensions near the crop rectangle
                        crop_px_w = max(0, int(abs(x2 - x1) / self.scale))
                        crop_px_h = max(0, int(abs(y2 - y1) / self.scale))
                        dim_text = f"{crop_px_w} \u00d7 {crop_px_h} px"
                        font = p.font()
                        font.setPointSize(9)
                        p.setFont(font)
                        fm = p.fontMetrics()
                        tw = fm.horizontalAdvance(dim_text)
                        th = fm.height()
                        # Position label just below the crop rect, centered
                        lx = int((x1 + x2) / 2 - tw / 2)
                        ly = int(y2 + 4)
                        # If label would go off the bottom, put it above instead
                        if ly + th > int(img_top + img_h):
                            ly = int(y1 - th - 4)
                        # Draw background pill for readability
                        p.setPen(Qt.PenStyle.NoPen)
                        p.setBrush(QBrush(QColor(0, 0, 0, 180)))
                        p.drawRoundedRect(lx - 6, ly - 1, tw + 12, th + 2, 4, 4)
                        p.setPen(QColor(255, 255, 255))
                        p.drawText(lx, ly + fm.ascent(), dim_text)
                        
                        # Draw handles if selection is finalized
                        if self.selection_finalized:
                            diag = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
                            hs = self._dynamic_handle_size(diag)
                            handles = self.get_handle_positions((x1, y1, x2, y2))
                            p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                            p.setBrush(QBrush(QColor(255, 255, 255)))
                            for hx, hy in handles.values():
                                p.drawEllipse(
                                    int(hx - hs/2),
                                    int(hy - hs/2),
                                    hs, hs
                                )
        
        # Draw rectangle handles (shape itself is rendered in WYSIWYG preview image)
        if hasattr(parent, 'active_tool') and parent.active_tool == "rectangle":
            if self.current_rect:
                rx1, ry1, rx2, ry2 = self.current_rect
                diag = math.sqrt((rx2 - rx1)**2 + (ry2 - ry1)**2)
                hs = self._dynamic_handle_size(diag)
                handles = self.get_handle_positions(self.current_rect)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for hx, hy in handles.values():
                    p.drawEllipse(
                        int(hx - hs/2),
                        int(hy - hs/2),
                        hs,
                        hs
                    )
        
        # Draw oval handles (shape itself is rendered in WYSIWYG preview image)
        if hasattr(parent, 'active_tool') and parent.active_tool == "oval":
            if self.current_oval:
                ox1, oy1, ox2, oy2 = self.current_oval
                diag = math.sqrt((ox2 - ox1)**2 + (oy2 - oy1)**2)
                hs = self._dynamic_handle_size(diag)
                handles = self.get_handle_positions(self.current_oval)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for hx, hy in handles.values():
                    p.drawEllipse(
                        int(hx - hs/2),
                        int(hy - hs/2),
                        hs,
                        hs
                    )
        
        # Draw line handles (shape itself is rendered in WYSIWYG preview image)
        if hasattr(parent, 'active_tool') and parent.active_tool == "line":
            if self.current_line:
                x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2 = self.current_line
                line_len = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
                hs = self._dynamic_handle_size(line_len)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for hx, hy in [(x1, y1), (cp1_x, cp1_y), (cp2_x, cp2_y), (x2, y2)]:
                    p.drawEllipse(
                        int(hx - hs/2),
                        int(hy - hs/2),
                        hs,
                        hs
                    )
        
        # Draw arrow handles (shape itself is rendered in WYSIWYG preview image)
        if hasattr(parent, 'active_tool') and parent.active_tool == "arrow":
            if self.current_arrow:
                x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2 = self.current_arrow
                # Scale handles based on arrow length
                arrow_len = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
                hs = self._dynamic_handle_size(arrow_len)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for hx, hy in [(x1, y1), (cp1_x, cp1_y), (cp2_x, cp2_y), (x2, y2)]:
                    p.drawEllipse(
                        int(hx - hs/2),
                        int(hy - hs/2),
                        hs,
                        hs
                    )
        
        # Freehand preview: no longer needed - strokes are drawn directly into the image in real-time
        
        # Draw cut/paste selection and preview
        if hasattr(parent, 'active_tool') and parent.active_tool == "cutpaste":
            # Draw current selection rectangle
            if self.sel_start is not None and self.sel_end is not None and not self.cutpaste_dragging:
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                
                p.setPen(QPen(QColor(0, 255, 255), 2, Qt.PenStyle.DashLine))
                p.drawRect(x1, y1, x2 - x1, y2 - y1)
            
            # Draw selection rectangle (after releasing mouse)
            if self.cutpaste_selection:
                x1, y1, x2, y2 = self.cutpaste_selection
                p.setPen(QPen(QColor(0, 255, 255), 2, Qt.PenStyle.DashLine))
                p.drawRect(x1, y1, x2 - x1, y2 - y1)
        
        # Draw dotted border when transform rotation preview is active
        if getattr(self, '_transform_preview_active', False):
            img_x = int(self.offset.x())
            img_y = int(self.offset.y())
            if self.pixmap():
                pw = self.pixmap().width()
                ph = self.pixmap().height()
                p.setPen(QPen(QColor(0, 200, 255), 2, Qt.PenStyle.DashLine))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRect(img_x, img_y, pw, ph)
        
        # Draw paste preview - always draw if there's a paste pending (works with any tool or no tool)
        if self.cutpaste_paste_pos and self.cutpaste_clipboard:
            px1, py1, px2, py2 = self.cutpaste_paste_pos
            
            # Draw the pasted image (scale to match current view scale/selection box)
            qimg = PilToQImage(self.cutpaste_clipboard)
            w = max(1, int(px2 - px1))
            h = max(1, int(py2 - py1))
            pm = QPixmap.fromImage(qimg).scaled(w, h, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.FastTransformation)
            p.drawPixmap(int(px1), int(py1), pm)
            
            # Draw cyan dashed border around paste (inset by 1px so border is visible at edges)
            p.setPen(QPen(QColor(0, 255, 255), 2, Qt.PenStyle.DashLine))
            p.drawRect(int(px1) + 1, int(py1) + 1, int(px2 - px1) - 2, int(py2 - py1) - 2)
            
            # Draw resize handles (inset to match the cyan border)
            paste_diag = math.sqrt((px2 - px1)**2 + (py2 - py1)**2)
            hs = self._dynamic_handle_size(paste_diag)
            handles = self.get_handle_positions((px1 + 1, py1 + 1, px2 - 1, py2 - 1))
            p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
            p.setBrush(QBrush(QColor(255, 255, 255)))
            for hx, hy in handles.values():
                p.drawEllipse(
                    int(hx - hs/2),
                    int(hy - hs/2),
                    hs,
                    hs
                )
        # Draw highlight tool preview
        if hasattr(parent, 'active_tool') and parent.active_tool == "highlight":
            style = parent.highlight_style.currentText() if hasattr(parent, 'highlight_style') else "Rectangle"
            size = parent.highlight_size.value() if hasattr(parent, 'highlight_size') else 15
            # Use Primary color (opaque)
            pr = getattr(parent, 'primary_color', (255, 255, 0, 255))
            highlight_color = QColor(pr[0], pr[1], pr[2], 255)

            if style == "Spotlight":
                # Spotlight mode: dim everything outside the rectangle
                if self.current_highlight_rect:
                    x1, y1, x2, y2 = self.current_highlight_rect
                    opacity = parent.spotlight_opacity.value() if hasattr(parent, 'spotlight_opacity') else 60
                    feather_pct = parent.spotlight_feather.value() if hasattr(parent, 'spotlight_feather') else 0
                    dim_alpha = int(255 * opacity / 100)
                    
                    if feather_pct > 0:
                        # Convert percentage to screen pixels
                        # Feather = percentage of half the shortest side of the spotlight rect
                        rect_w = x2 - x1
                        rect_h = y2 - y1
                        half_short = min(rect_w, rect_h) / 2.0
                        f = half_short * feather_pct / 100.0
                        
                        if f > 0:
                            # Build gradient overlay using numpy
                            import numpy as np
                            widget_rect = self.rect()
                            ww, wh = widget_rect.width(), widget_rect.height()
                            
                            ys = np.arange(wh).reshape(-1, 1).astype(np.float32)
                            xs = np.arange(ww).reshape(1, -1).astype(np.float32)
                            
                            # Distance inward from spotlight rect edges
                            dx = np.minimum(xs - x1, x2 - 1 - xs)
                            dy = np.minimum(ys - y1, y2 - 1 - ys)
                            d = np.minimum(dx, dy)
                            
                            # d >= f → inside spotlight (alpha=0), d < 0 → outside (alpha=dim), 0..f → gradient
                            alpha = np.full((wh, ww), dim_alpha, dtype=np.float32)
                            inside = d >= f
                            alpha[inside] = 0
                            feather_zone = (d >= 0) & (d < f)
                            alpha[feather_zone] = dim_alpha * (1.0 - d[feather_zone] / f)
                            
                            # Build ARGB32 overlay
                            alpha_u8 = alpha.astype(np.uint8)
                            zeros = np.zeros((wh, ww), dtype=np.uint8)
                            rgba = np.stack([zeros, zeros, zeros, alpha_u8], axis=-1)
                            overlay_img = QImage(rgba.data, ww, wh, ww * 4, QImage.Format.Format_RGBA8888)
                            overlay_img._buf = rgba  # prevent GC
                            p.drawImage(0, 0, overlay_img)
                        else:
                            # Feather too small, use hard edge
                            dim_color = QColor(0, 0, 0, dim_alpha)
                            widget_rect = self.rect()
                            p.setPen(Qt.PenStyle.NoPen)
                            p.setBrush(QBrush(dim_color))
                            p.drawRect(widget_rect.x(), widget_rect.y(), widget_rect.width(), int(y1) - widget_rect.y())
                            p.drawRect(widget_rect.x(), int(y2), widget_rect.width(), widget_rect.bottom() - int(y2))
                            p.drawRect(widget_rect.x(), int(y1), int(x1) - widget_rect.x(), int(y2 - y1))
                            p.drawRect(int(x2), int(y1), widget_rect.right() - int(x2), int(y2 - y1))
                    else:
                        # Hard edge spotlight (original behavior)
                        dim_color = QColor(0, 0, 0, dim_alpha)
                        widget_rect = self.rect()
                        
                        p.setPen(Qt.PenStyle.NoPen)
                        p.setBrush(QBrush(dim_color))
                        # Top
                        p.drawRect(widget_rect.x(), widget_rect.y(), widget_rect.width(), int(y1) - widget_rect.y())
                        # Bottom
                        p.drawRect(widget_rect.x(), int(y2), widget_rect.width(), widget_rect.bottom() - int(y2))
                        # Left
                        p.drawRect(widget_rect.x(), int(y1), int(x1) - widget_rect.x(), int(y2 - y1))
                        # Right
                        p.drawRect(int(x2), int(y1), widget_rect.right() - int(x2), int(y2 - y1))
            else:
                # Pen and Rectangle highlight modes
                if hasattr(self, 'highlight_strokes') or hasattr(self, 'current_highlight_stroke') or self.current_highlight_rect:
                    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Multiply)
                    p.setPen(QPen(highlight_color, size, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                    p.setBrush(QBrush(highlight_color))

                    if hasattr(self, 'highlight_strokes'):
                        for stroke in self.highlight_strokes:
                            if len(stroke) > 1:
                                for i in range(len(stroke) - 1):
                                    p.drawLine(stroke[i], stroke[i + 1])

                    if hasattr(self, 'current_highlight_stroke') and self.current_highlight_stroke:
                        if len(self.current_highlight_stroke) > 1:
                            for i in range(len(self.current_highlight_stroke) - 1):
                                p.drawLine(self.current_highlight_stroke[i], self.current_highlight_stroke[i + 1])

                    if self.current_highlight_rect:
                        x1, y1, x2, y2 = self.current_highlight_rect
                        p.setPen(Qt.PenStyle.NoPen)
                        p.drawRect(x1, y1, x2 - x1, y2 - y1)

                    p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)

            if self.current_highlight_rect:
                x1, y1, x2, y2 = self.current_highlight_rect
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.DashLine))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRect(x1, y1, x2 - x1, y2 - y1)

                handles = self.get_handle_positions(self.current_highlight_rect)
                diag = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
                hs = self._dynamic_handle_size(diag)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for handle_pos in handles.values():
                    hx, hy = handle_pos
                    p.drawEllipse(int(hx - hs/2), int(hy - hs/2), hs, hs)

        # Draw pixelate tool preview
        if hasattr(parent, 'active_tool') and parent.active_tool == "pixelate":
            if self.current_pixelate_rect:
                x1, y1, x2, y2 = self.current_pixelate_rect
                
                # Live pixelation preview
                if self.image and x2 > x1 and y2 > y1:
                    from PIL import Image as PILImage
                    block_size = parent.pixelate_size.value() if hasattr(parent, 'pixelate_size') else 10
                    
                    # Convert screen coords to image coords
                    scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
                    offset = self.offset if hasattr(self, 'offset') else type('', (), {'x': lambda s: 0, 'y': lambda s: 0})()
                    ix1 = int((x1 - offset.x()) / scale)
                    iy1 = int((y1 - offset.y()) / scale)
                    ix2 = int((x2 - offset.x()) / scale)
                    iy2 = int((y2 - offset.y()) / scale)
                    
                    # Clamp to image bounds
                    ix1 = max(0, min(self.image.width, ix1))
                    iy1 = max(0, min(self.image.height, iy1))
                    ix2 = max(0, min(self.image.width, ix2))
                    iy2 = max(0, min(self.image.height, iy2))
                    
                    if ix2 > ix1 and iy2 > iy1:
                        # Pixelate using BOX averaging + NEAREST upscale (ShareX-style)
                        region = self.image.crop((ix1, iy1, ix2, iy2))
                        rw, rh = region.size
                        # BOX filter averages all pixels in each cell (no subpixel color bleed)
                        small_w = max(1, rw // block_size)
                        small_h = max(1, rh // block_size)
                        small = region.resize((small_w, small_h), PILImage.Resampling.BOX)
                        pixelated = small.resize((rw, rh), PILImage.Resampling.NEAREST)
                        
                        # Convert to QImage and draw at screen position
                        if pixelated.mode != 'RGBA':
                            pixelated = pixelated.convert('RGBA')
                        data = pixelated.tobytes('raw', 'RGBA')
                        qimg = QImage(data, pixelated.width, pixelated.height, pixelated.width * 4, QImage.Format.Format_RGBA8888)
                        # Scale to screen size and draw
                        screen_w = x2 - x1
                        screen_h = y2 - y1
                        pixmap = QPixmap.fromImage(qimg).scaled(screen_w, screen_h, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.FastTransformation)
                        p.drawPixmap(x1, y1, pixmap)
                
                # Draw dashed border
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.DashLine))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRect(x1, y1, x2 - x1, y2 - y1)
                
                # Draw handles
                handles = self.get_handle_positions(self.current_pixelate_rect)
                diag = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
                hs = self._dynamic_handle_size(diag)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for handle_pos in handles.values():
                    hx, hy = handle_pos
                    p.drawEllipse(
                        int(hx - hs/2),
                        int(hy - hs/2),
                        hs,
                        hs
                    )
        
        # Draw blur tool preview
        if hasattr(parent, 'active_tool') and parent.active_tool == "blur":
            if self.current_blur_rect:
                x1, y1, x2, y2 = self.current_blur_rect
                
                # Live blur preview
                if self.image and x2 > x1 and y2 > y1:
                    from PIL import Image as PILImage
                    from PIL import ImageFilter
                    blur_radius = parent.blur_radius.value() if hasattr(parent, 'blur_radius') else 5
                    blur_inside = parent.blur_inside.currentText() == "Inside" if hasattr(parent, 'blur_inside') else True
                    feather_pct = parent.blur_feather.value() if hasattr(parent, 'blur_feather') else 0
                    
                    scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
                    offset = self.offset
                    
                    if blur_inside:
                        # Blur inside the rectangle
                        ix1 = max(0, min(self.image.width, int((x1 - offset.x()) / scale)))
                        iy1 = max(0, min(self.image.height, int((y1 - offset.y()) / scale)))
                        ix2 = max(0, min(self.image.width, int((x2 - offset.x()) / scale)))
                        iy2 = max(0, min(self.image.height, int((y2 - offset.y()) / scale)))
                        
                        # Convert feather percentage to image pixels
                        half_short = min(ix2 - ix1, iy2 - iy1) / 2.0 if (ix2 > ix1 and iy2 > iy1) else 0
                        feather = int(half_short * feather_pct / 100.0)
                        
                        if ix2 > ix1 and iy2 > iy1:
                            if feather > 0:
                                # Feathered: expand, blur, composite with gradient mask
                                import numpy as np
                                w, h = self.image.width, self.image.height
                                ex1 = max(0, ix1 - feather)
                                ey1 = max(0, iy1 - feather)
                                ex2 = min(w, ix2 + feather)
                                ey2 = min(h, iy2 + feather)
                                
                                expanded = self.image.crop((ex1, ey1, ex2, ey2))
                                blurred_exp = expanded.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                                
                                ew, eh = ex2 - ex1, ey2 - ey1
                                ys = np.arange(eh).reshape(-1, 1)
                                xs = np.arange(ew).reshape(1, -1)
                                dx = np.minimum(xs - (ix1 - ex1), (ix2 - ex1) - 1 - xs)
                                dy = np.minimum(ys - (iy1 - ey1), (iy2 - ey1) - 1 - ys)
                                d = np.minimum(dx, dy).astype(np.float32)
                                alpha = np.clip(d / feather, 0.0, 1.0) * 255
                                mask = PILImage.fromarray(alpha.astype(np.uint8), mode='L')
                                
                                composited = PILImage.composite(blurred_exp, expanded, mask)
                                if composited.mode != 'RGBA':
                                    composited = composited.convert('RGBA')
                                data = composited.tobytes('raw', 'RGBA')
                                qimg = QImage(data, composited.width, composited.height, composited.width * 4, QImage.Format.Format_RGBA8888)
                                # Map expanded region to screen coordinates
                                sx1 = int(offset.x() + ex1 * scale)
                                sy1 = int(offset.y() + ey1 * scale)
                                sw = int((ex2 - ex1) * scale)
                                sh = int((ey2 - ey1) * scale)
                                pixmap = QPixmap.fromImage(qimg).scaled(sw, sh, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
                                p.drawPixmap(sx1, sy1, pixmap)
                            else:
                                region = self.image.crop((ix1, iy1, ix2, iy2))
                                blurred = region.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                                if blurred.mode != 'RGBA':
                                    blurred = blurred.convert('RGBA')
                                data = blurred.tobytes('raw', 'RGBA')
                                qimg = QImage(data, blurred.width, blurred.height, blurred.width * 4, QImage.Format.Format_RGBA8888)
                                screen_w = x2 - x1
                                screen_h = y2 - y1
                                pixmap = QPixmap.fromImage(qimg).scaled(screen_w, screen_h, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
                                p.drawPixmap(x1, y1, pixmap)
                    else:
                        # Blur outside the rectangle
                        ix1 = max(0, min(self.image.width, int((x1 - offset.x()) / scale)))
                        iy1 = max(0, min(self.image.height, int((y1 - offset.y()) / scale)))
                        ix2 = max(0, min(self.image.width, int((x2 - offset.x()) / scale)))
                        iy2 = max(0, min(self.image.height, int((y2 - offset.y()) / scale)))
                        
                        # Convert feather percentage to image pixels
                        half_short = min(ix2 - ix1, iy2 - iy1) / 2.0 if (ix2 > ix1 and iy2 > iy1) else 0
                        feather = int(half_short * feather_pct / 100.0)
                        
                        if feather > 0:
                            
                            full_blurred = self.image.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                            
                            ys = np.arange(h).reshape(-1, 1)
                            xs = np.arange(w).reshape(1, -1)
                            dx = np.minimum(xs - ix1, ix2 - 1 - xs)
                            dy = np.minimum(ys - iy1, iy2 - 1 - ys)
                            d = np.minimum(dx, dy).astype(np.float32)
                            alpha_arr = np.clip((feather - d) / feather, 0.0, 1.0) * 255
                            outside = (dx < 0) | (dy < 0)
                            alpha_arr[outside] = 255
                            mask = PILImage.fromarray(alpha_arr.astype(np.uint8), mode='L')
                            
                            composited = PILImage.composite(full_blurred, self.image, mask)
                            if composited.mode != 'RGBA':
                                composited = composited.convert('RGBA')
                            data = composited.tobytes('raw', 'RGBA')
                            qimg = QImage(data, composited.width, composited.height, composited.width * 4, QImage.Format.Format_RGBA8888)
                            img_w = int(w * scale)
                            img_h = int(h * scale)
                            pixmap = QPixmap.fromImage(qimg).scaled(img_w, img_h, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
                            p.drawPixmap(int(offset.x()), int(offset.y()), pixmap)
                        else:
                            full_blurred = self.image.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                            if full_blurred.mode != 'RGBA':
                                full_blurred = full_blurred.convert('RGBA')
                            data = full_blurred.tobytes('raw', 'RGBA')
                            qimg = QImage(data, full_blurred.width, full_blurred.height, full_blurred.width * 4, QImage.Format.Format_RGBA8888)
                            img_w = int(self.image.width * scale)
                            img_h = int(self.image.height * scale)
                            pixmap = QPixmap.fromImage(qimg).scaled(img_w, img_h, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
                            p.drawPixmap(int(offset.x()), int(offset.y()), pixmap)
                            
                            # Draw the unblurred rectangle region on top
                            ix1 = max(0, min(self.image.width, int((x1 - offset.x()) / scale)))
                            iy1 = max(0, min(self.image.height, int((y1 - offset.y()) / scale)))
                            ix2 = max(0, min(self.image.width, int((x2 - offset.x()) / scale)))
                            iy2 = max(0, min(self.image.height, int((y2 - offset.y()) / scale)))
                            if ix2 > ix1 and iy2 > iy1:
                                region = self.image.crop((ix1, iy1, ix2, iy2))
                                if region.mode != 'RGBA':
                                    region = region.convert('RGBA')
                                data = region.tobytes('raw', 'RGBA')
                                qimg2 = QImage(data, region.width, region.height, region.width * 4, QImage.Format.Format_RGBA8888)
                                screen_w = x2 - x1
                                screen_h = y2 - y1
                                pxm = QPixmap.fromImage(qimg2).scaled(screen_w, screen_h, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
                                p.drawPixmap(x1, y1, pxm)
                
                # Draw dashed border
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.DashLine))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRect(x1, y1, x2 - x1, y2 - y1)
                
                # Draw handles
                handles = self.get_handle_positions(self.current_blur_rect)
                diag = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
                hs = self._dynamic_handle_size(diag)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for handle_pos in handles.values():
                    hx, hy = handle_pos
                    p.drawEllipse(int(hx - hs/2), int(hy - hs/2), hs, hs)
        
        # Draw outline tool preview
        if hasattr(parent, 'active_tool') and parent.active_tool == "outline":
            if self.outline_preview_active and self.image:
                thickness = parent.outline_thickness.value() if hasattr(parent, 'outline_thickness') else 2
                corner_radius = parent.outline_corner_radius.value() if hasattr(parent, 'outline_corner_radius') else 0
                color = QColor(*parent.primary_color)
                scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
                offset = self.offset
                
                # Calculate screen-space values
                screen_t = max(1, int(thickness * scale))
                screen_r = int(corner_radius * scale)
                
                # Image area on screen
                img_x = int(offset.x())
                img_y = int(offset.y())
                img_w = int(self.image.width * scale)
                img_h = int(self.image.height * scale)
                
                if screen_r > 0:
                    # Rounded corners preview
                    # Draw checkerboard in corner regions to show transparency
                    checker_size = 6
                    white_c = QColor(255, 255, 255)
                    gray_c = QColor(192, 192, 192)
                    
                    # Build a path for the area outside the rounded rect (corner cutoffs)
                    full_rect_path = QPainterPath()
                    full_rect_path.addRect(float(img_x), float(img_y), float(img_w), float(img_h))
                    rounded_path = QPainterPath()
                    rounded_path.addRoundedRect(float(img_x), float(img_y), float(img_w), float(img_h), float(screen_r), float(screen_r))
                    corner_path = full_rect_path - rounded_path
                    
                    # Draw checkerboard behind corners
                    p.save()
                    p.setClipPath(corner_path)
                    for cy in range(img_y, img_y + img_h, checker_size):
                        for cx in range(img_x, img_x + img_w, checker_size):
                            c = white_c if ((cx // checker_size) + (cy // checker_size)) % 2 == 0 else gray_c
                            p.fillRect(cx, cy, checker_size, checker_size, c)
                    p.restore()
                    
                    # Draw the border as a rounded rect stroke
                    if thickness > 0:
                        half_t = screen_t / 2.0
                        # Build the actual inset border path that matches what we'll draw
                        inset_path = QPainterPath()
                        inset_path.addRoundedRect(QRectF(img_x + half_t, img_y + half_t, img_w - screen_t, img_h - screen_t), max(0, screen_r - half_t), max(0, screen_r - half_t))
                        
                        # Draw checkerboard behind border if color has transparency
                        if color.alpha() < 255:
                            p.save()
                            # Create clip from the actual inset border stroke area
                            stroker = QPainterPathStroker()
                            stroker.setWidth(screen_t)
                            border_stroke_path = stroker.createStroke(inset_path)
                            p.setClipPath(border_stroke_path)
                            for cy in range(img_y - screen_t, img_y + img_h + screen_t, checker_size):
                                for cx in range(img_x - screen_t, img_x + img_w + screen_t, checker_size):
                                    cc = white_c if ((cx // checker_size) + (cy // checker_size)) % 2 == 0 else gray_c
                                    p.fillRect(cx, cy, checker_size, checker_size, cc)
                            p.restore()
                        
                        border_pen = QPen(color, screen_t, Qt.PenStyle.SolidLine, Qt.PenCapStyle.SquareCap, Qt.PenJoinStyle.RoundJoin)
                        p.setPen(border_pen)
                        p.setBrush(Qt.BrushStyle.NoBrush)
                        p.drawRoundedRect(QRectF(img_x + half_t, img_y + half_t, img_w - screen_t, img_h - screen_t), max(0, screen_r - half_t), max(0, screen_r - half_t))
                else:
                    # Original square corners preview
                    # Define the 4 border rects
                    border_rects = [
                        (img_x, img_y, img_w, screen_t),                        # Top
                        (img_x, img_y + img_h - screen_t, img_w, screen_t),     # Bottom
                        (img_x, img_y, screen_t, img_h),                        # Left
                        (img_x + img_w - screen_t, img_y, screen_t, img_h),     # Right
                    ]
                    
                    # Draw checkerboard behind if color has transparency
                    if color.alpha() < 255:
                        checker_size = 6
                        white = QColor(255, 255, 255)
                        gray = QColor(192, 192, 192)
                        for rx, ry, rw, rh in border_rects:
                            p.save()
                            p.setClipRect(rx, ry, rw, rh)
                            for cy in range(ry, ry + rh, checker_size):
                                for cx in range(rx, rx + rw, checker_size):
                                    c = white if ((cx // checker_size) + (cy // checker_size)) % 2 == 0 else gray
                                    p.fillRect(cx, cy, checker_size, checker_size, c)
                            p.restore()
                    
                    # Draw the color on top
                    p.setPen(Qt.PenStyle.NoPen)
                    p.setBrush(QBrush(color))
                    for rx, ry, rw, rh in border_rects:
                        p.drawRect(rx, ry, rw, rh)
        
        # Draw remove space preview (replace the normal image display)
        if hasattr(parent, 'active_tool') and parent.active_tool == "remove_space":
            if self.rspace_preview_image is not None:
                from PIL import Image as PILImage
                preview = self.rspace_preview_image
                if preview.mode != 'RGBA':
                    preview = preview.convert('RGBA')
                data = preview.tobytes('raw', 'RGBA')
                qimg = QImage(data, preview.width, preview.height, preview.width * 4, QImage.Format.Format_RGBA8888)
                
                scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
                offset = self.offset
                img_x = int(offset.x())
                img_y = int(offset.y())
                orig_w = int(self.image.width * scale)
                orig_h = int(self.image.height * scale)
                pw = int(preview.width * scale)
                ph = int(preview.height * scale)
                
                # Dim the entire original image area first
                p.setBrush(QBrush(QColor(0, 0, 0, 120)))
                p.setPen(Qt.PenStyle.NoPen)
                p.drawRect(img_x, img_y, orig_w, orig_h)
                
                # Draw checkerboard background for the preview area
                checker_size = 8
                tile = QPixmap(checker_size * 2, checker_size * 2)
                tile.fill(QColor(255, 255, 255))
                tp2 = QPainter(tile)
                tp2.fillRect(checker_size, 0, checker_size, checker_size, QColor(204, 204, 204))
                tp2.fillRect(0, checker_size, checker_size, checker_size, QColor(204, 204, 204))
                tp2.end()
                
                p.drawTiledPixmap(img_x, img_y, pw, ph, tile)
                
                # Draw preview image on top
                preview_pixmap = QPixmap.fromImage(qimg).scaled(pw, ph, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.FastTransformation)
                p.drawPixmap(img_x, img_y, preview_pixmap)
                
                # Draw border around the preview to show new size
                p.setPen(QPen(QColor(0, 180, 0), 2, Qt.PenStyle.DashLine))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRect(img_x, img_y, pw, ph)
                
                # Show size info with background for readability (inside preview, bottom-left)
                size_text = f"{preview.width}×{preview.height} (was {self.image.width}×{self.image.height})"
                font = p.font()
                font.setPixelSize(14)
                font.setBold(True)
                p.setFont(font)
                from PyQt6.QtGui import QFontMetrics
                fm = QFontMetrics(font)
                text_rect = fm.boundingRect(size_text)
                text_w = text_rect.width() + 16
                text_h = text_rect.height() + 8
                text_x = img_x + 4
                text_y = img_y + ph - text_h - 4  # Inside bottom of preview
                # Draw background pill
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QBrush(QColor(0, 0, 0, 180)))
                p.drawRoundedRect(text_x, text_y, text_w, text_h, 4, 4)
                # Draw text
                p.setPen(QPen(QColor(80, 255, 80)))
                p.drawText(text_x + 8, text_y + text_h - 6, size_text)
        
        # Draw magnify inset tool preview
        if hasattr(parent, 'active_tool') and parent.active_tool == "magnify_inset":
            # Draw source selection rectangle (while drawing or after placed)
            src = self.inset_source_rect
            if src:
                x1, y1, x2, y2 = src
                sw = x2 - x1
                sh = y2 - y1
                
                is_oval = hasattr(parent, 'inset_shape') and parent.inset_shape.currentText() == "Oval"
                
                if not self.inset_dest_pos:
                    # Source highlight border (only during initial selection)
                    p.setPen(QPen(QColor(0, 120, 215), 2, Qt.PenStyle.DashLine))
                    p.setBrush(QBrush(QColor(0, 120, 215, 30)))
                    if is_oval:
                        p.drawEllipse(x1, y1, sw, sh)
                    else:
                        p.drawRect(x1, y1, sw, sh)
                
                # Draw handles on source
                sx1, sy1, sx2, sy2 = src
                diag = math.sqrt((sx2 - sx1)**2 + (sy2 - sy1)**2)
                hs = self._dynamic_handle_size(diag)
                handles = self.get_handle_positions(src)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for hx, hy in handles.values():
                    p.drawEllipse(int(hx - hs/2), int(hy - hs/2),
                                  hs, hs)
                
                # Draw magnified inset if placed
                if self.inset_dest_pos and self.image and sw > 5 and sh > 5:
                    from PIL import Image as PILImage
                    
                    zoom = int(parent.inset_zoom.currentText().replace('%', '')) / 100.0
                    border_w = parent.inset_border.value() if hasattr(parent, 'inset_border') else 3
                    
                    # Convert source screen coords to image coords
                    scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
                    offset = self.offset
                    ix1 = int((x1 - offset.x()) / scale)
                    iy1 = int((y1 - offset.y()) / scale)
                    ix2 = int((x2 - offset.x()) / scale)
                    iy2 = int((y2 - offset.y()) / scale)
                    
                    # Clamp to image bounds
                    ix1 = max(0, min(self.image.width, ix1))
                    iy1 = max(0, min(self.image.height, iy1))
                    ix2 = max(0, min(self.image.width, ix2))
                    iy2 = max(0, min(self.image.height, iy2))
                    
                    if ix2 > ix1 and iy2 > iy1:
                        # Crop and scale the source region
                        region = self.image.crop((ix1, iy1, ix2, iy2))
                        new_w = int(region.width * zoom)
                        new_h = int(region.height * zoom)
                        if new_w > 0 and new_h > 0:
                            scaled = region.resize((new_w, new_h), PILImage.Resampling.LANCZOS)
                            
                            # Convert to QPixmap
                            if scaled.mode != 'RGBA':
                                scaled = scaled.convert('RGBA')
                            data = scaled.tobytes('raw', 'RGBA')
                            qimg = QImage(data, scaled.width, scaled.height, 
                                         scaled.width * 4, QImage.Format.Format_RGBA8888)
                            
                            # Scale to screen size
                            dest_sw = int(sw * zoom)
                            dest_sh = int(sh * zoom)
                            pixmap = QPixmap.fromImage(qimg).scaled(
                                dest_sw, dest_sh, 
                                Qt.AspectRatioMode.IgnoreAspectRatio,
                                Qt.TransformationMode.SmoothTransformation)
                            
                            dx, dy = self.inset_dest_pos
                            
                            # Build clip region that excludes the inset area
                            inset_path = QPainterPath()
                            if is_oval:
                                inset_path.addEllipse(float(dx), float(dy), float(dest_sw), float(dest_sh))
                            else:
                                inset_path.addRect(float(dx), float(dy), float(dest_sw), float(dest_sh))
                            
                            # -- 1. Connection between source and inset (inset area erased) --
                            conn_mode = parent.inset_connection.currentText() if hasattr(parent, 'inset_connection') else "Yes"
                            
                            if conn_mode == "Yes":
                                import math as _math
                                from PyQt6.QtCore import QPointF
                                from PyQt6.QtGui import QPolygonF
                                
                                border_col = QColor(*parent.primary_color[:3])
                                fill_col = QColor(border_col.red(), border_col.green(), border_col.blue(), 40)
                                line_col = QColor(border_col.red(), border_col.green(), border_col.blue(), 120)
                                conn_pen = QPen(line_col, max(1, border_w // 2), Qt.PenStyle.SolidLine)
                                
                                src_cx = (x1 + x2) / 2
                                src_cy = (y1 + y2) / 2
                                dst_cx = dx + dest_sw / 2
                                dst_cy = dy + dest_sh / 2
                                
                                tmp_conn = QPixmap(self.size())
                                tmp_conn.fill(QColor(0, 0, 0, 0))
                                tc = QPainter(tmp_conn)
                                tc.setRenderHint(QPainter.RenderHint.Antialiasing)
                                
                                if is_oval:
                                    src_rx, src_ry = sw / 2, sh / 2
                                    dst_rx, dst_ry = dest_sw / 2, dest_sh / 2
                                    
                                    d = _math.sqrt((dst_cx - src_cx)**2 + (dst_cy - src_cy)**2)
                                    angle = _math.atan2(dst_cy - src_cy, dst_cx - src_cx)
                                    
                                    if d > 1:
                                        r1 = (src_rx + src_ry) / 2
                                        r2 = (dst_rx + dst_ry) / 2
                                        ratio = max(-1.0, min(1.0, (r2 - r1) / d))
                                        off = _math.asin(ratio)
                                        tp1 = angle + _math.pi/2 + off
                                        tp2 = angle - _math.pi/2 - off
                                        
                                        # Build cylinder: source arc (near side) -> line -> dest arc (far side) -> line
                                        n_seg = 32
                                        pts = []
                                        
                                        # Source arc: from tp1 to tp2 going the SHORT way (near side, facing dest)
                                        # This is the arc that faces the destination
                                        src_sweep = tp2 - tp1
                                        # Normalize to go the short way (through the side facing dest)
                                        if src_sweep > _math.pi:
                                            src_sweep -= 2 * _math.pi
                                        elif src_sweep < -_math.pi:
                                            src_sweep += 2 * _math.pi
                                        for i in range(n_seg + 1):
                                            a = tp1 + (i / n_seg) * src_sweep
                                            pts.append(QPointF(src_cx + src_rx * _math.cos(a),
                                                               src_cy + src_ry * _math.sin(a)))
                                        
                                        # Dest arc: from tp2 to tp1 going the LONG way (far side, away from source)
                                        # This wraps around the back of the destination circle
                                        dst_sweep = tp1 - tp2
                                        # Normalize to go the long way (around the back)
                                        if dst_sweep > 0:
                                            dst_sweep -= 2 * _math.pi
                                        elif dst_sweep < -2 * _math.pi:
                                            dst_sweep += 2 * _math.pi
                                        for i in range(n_seg + 1):
                                            a = tp2 + (i / n_seg) * dst_sweep
                                            pts.append(QPointF(dst_cx + dst_rx * _math.cos(a),
                                                               dst_cy + dst_ry * _math.sin(a)))
                                        
                                        tc.setPen(conn_pen)
                                        tc.setBrush(QBrush(fill_col))
                                        tc.drawPolygon(QPolygonF(pts))
                                else:
                                    # Rectangle: cube/box connection - 4 faces from source to inset corners
                                    # Source corners
                                    stl = QPointF(x1, y1)  # top-left
                                    str_ = QPointF(x2, y1)  # top-right
                                    sbr = QPointF(x2, y2)  # bottom-right
                                    sbl = QPointF(x1, y2)  # bottom-left
                                    # Dest corners
                                    dtl = QPointF(dx, dy)
                                    dtr = QPointF(dx + dest_sw, dy)
                                    dbr = QPointF(dx + dest_sw, dy + dest_sh)
                                    dbl = QPointF(dx, dy + dest_sh)
                                    
                                    # Draw all 4 side faces
                                    faces = [
                                        QPolygonF([stl, str_, dtr, dtl]),  # top face
                                        QPolygonF([str_, sbr, dbr, dtr]),  # right face
                                        QPolygonF([sbr, sbl, dbl, dbr]),  # bottom face
                                        QPolygonF([sbl, stl, dtl, dbl]),  # left face
                                    ]
                                    for face in faces:
                                        tc.setPen(conn_pen)
                                        tc.setBrush(QBrush(fill_col))
                                        tc.drawPolygon(face)
                                
                                tc.end()
                                p.drawPixmap(0, 0, tmp_conn)
                            
                            # -- 2. Draw the magnified image --
                            if is_oval:
                                p.save()
                                p.setClipPath(inset_path)
                                p.drawPixmap(int(dx), int(dy), pixmap)
                                p.restore()
                            else:
                                p.drawPixmap(int(dx), int(dy), pixmap)
                            
                            # -- 4. Inset border --
                            if border_w > 0:
                                p.setPen(QPen(QColor(*parent.primary_color), border_w, Qt.PenStyle.SolidLine))
                                p.setBrush(Qt.BrushStyle.NoBrush)
                                if is_oval:
                                    p.drawEllipse(int(dx), int(dy), dest_sw, dest_sh)
                                else:
                                    p.drawRect(int(dx), int(dy), dest_sw, dest_sh)
                            
                            # -- 5. Source outline (back face, hidden behind inset) --
                            if border_w > 0:
                                tmp_src = QPixmap(self.size())
                                tmp_src.fill(QColor(0, 0, 0, 0))
                                ts = QPainter(tmp_src)
                                ts.setRenderHint(QPainter.RenderHint.Antialiasing)
                                ts.setPen(QPen(QColor(*parent.primary_color), max(1, border_w // 2), Qt.PenStyle.SolidLine))
                                ts.setBrush(Qt.BrushStyle.NoBrush)
                                if is_oval:
                                    ts.drawEllipse(x1, y1, sw, sh)
                                else:
                                    ts.drawRect(x1, y1, sw, sh)
                                # Erase where inset covers it
                                ts.setCompositionMode(QPainter.CompositionMode.CompositionMode_DestinationOut)
                                ts.setPen(Qt.PenStyle.NoPen)
                                ts.setBrush(QBrush(QColor(0, 0, 0, 255)))
                                if is_oval:
                                    ts.drawEllipse(QRectF(float(dx), float(dy), float(dest_sw), float(dest_sh)))
                                else:
                                    ts.drawRect(QRectF(float(dx), float(dy), float(dest_sw), float(dest_sh)))
                                ts.end()
                                p.drawPixmap(0, 0, tmp_src)
                            
                            # -- 6. Zoom label --
                            zoom_text = parent.inset_zoom.currentText()
                            font = p.font()
                            font.setPixelSize(max(10, int(12 * scale)))
                            font.setBold(True)
                            p.setFont(font)
                            p.setPen(QPen(QColor(0, 0, 0), 2))
                            p.drawText(int(dx) + 5, int(dy) + dest_sh - 5, zoom_text)
                            p.setPen(QPen(QColor(255, 255, 255)))
                            p.drawText(int(dx) + 5, int(dy) + dest_sh - 5, zoom_text)
        
        # Draw step marker tool preview
        if hasattr(parent, 'active_tool') and parent.active_tool == "step_marker":
            size = parent.step_marker_size.value() if hasattr(parent, 'step_marker_size') else 40
            
            # Get colors - primary = badge, secondary = text
            badge_color = QColor(*parent.primary_color) if hasattr(parent, 'primary_color') else QColor(220, 50, 50, 255)
            text_color = QColor(*parent.secondary_color) if hasattr(parent, 'secondary_color') else QColor(255, 255, 255)
            
            # Draw all finalized markers (no handles unless active)
            for idx, marker in enumerate(self.step_markers):
                num, bx, by, tx, ty, has_tail = marker
                is_active = (idx == self.active_marker_index)
                show_handle = is_active  # Always show handle when active, even without tail
                self.draw_step_marker(p, num, bx, by, tx, ty, size, has_tail, show_handle, is_active, badge_color, text_color)
            
            # Draw current marker being placed (always show handle)
            if self.current_marker:
                num, bx, by, tx, ty, has_tail = self.current_marker
                self.draw_step_marker(p, num, bx, by, tx, ty, size, has_tail, 
                                    show_handle=True, is_active=False, badge_color=badge_color, text_color=text_color)
        
        # Draw text tool preview (WYSIWYG - rendered into image via shape preview system)
        if hasattr(parent, 'active_tool') and parent.active_tool == "text":
            # Draw box being created (before text box exists)
            if self.sel_start is not None and self.sel_end is not None and not self.current_text:
                x1 = min(self.sel_start.x(), self.sel_end.x())
                y1 = min(self.sel_start.y(), self.sel_end.y())
                x2 = max(self.sel_start.x(), self.sel_end.x())
                y2 = max(self.sel_start.y(), self.sel_end.y())
                
                # Draw dotted preview box
                p.setPen(QPen(QColor(0, 120, 215), 2, Qt.PenStyle.DashLine))
                p.setBrush(QBrush(QColor(0, 120, 215, 30)))
                p.drawRect(int(x1), int(y1), int(x2 - x1), int(y2 - y1))
            
            if self.current_text:
                # Trigger WYSIWYG preview generation (text is rendered in shape preview image)
                if hasattr(parent, '_update_shape_preview'):
                    parent._update_shape_preview()
                
                text_str, x1, y1, x2, y2 = self.current_text
                
                # Draw dotted box (UI overlay)
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.DashLine))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRect(int(x1), int(y1), int(x2 - x1), int(y2 - y1))
                
                # Draw handles (UI overlay)
                diag = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
                hs = self._dynamic_handle_size(diag)
                handles = self.get_handle_positions((x1, y1, x2, y2))
                p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
                p.setBrush(QBrush(QColor(255, 255, 255)))
                for handle_pos in handles.values():
                    hx, hy = handle_pos
                    p.drawEllipse(
                        int(hx - hs/2),
                        int(hy - hs/2),
                        hs,
                        hs
                    )
                
                # Draw blinking cursor (UI overlay)
                if self.text_editing and self.text_cursor_visible:
                    try:
                        from PyQt6.QtGui import QFont
                        font_name = parent.text_font.currentText() if hasattr(parent, 'text_font') else "DejaVu Sans"
                        font_size = parent.text_size.value() if hasattr(parent, 'text_size') else 14
                        alignment = parent.text_alignment if hasattr(parent, 'text_alignment') else "center"
                        
                        # Set up font at image scale to calculate cursor position
                        font = QFont(font_name)
                        font.setPixelSize(font_size)
                        font.setBold(parent.text_bold.isChecked() if hasattr(parent, 'text_bold') else False)
                        font.setItalic(parent.text_italic.isChecked() if hasattr(parent, 'text_italic') else False)
                        font.setUnderline(parent.text_underline.isChecked() if hasattr(parent, 'text_underline') else False)
                        p.setFont(font)
                        metrics = p.fontMetrics()
                        
                        # Convert box to image coords for text layout
                        box_x1 = int((x1 - self.offset.x()) / self.scale)
                        box_y1 = int((y1 - self.offset.y()) / self.scale)
                        box_w = int((x2 - x1) / self.scale)
                        box_h = int((y2 - y1) / self.scale)
                        padding = 10
                        available_width = box_w - padding * 2
                        
                        # Word wrap (same as render)
                        lines = []
                        line_char_starts = [0]
                        current_line = ""
                        current_start = 0
                        last_break = -1
                        last_break_line = ""
                        for ci, ch in enumerate(text_str):
                            current_line += ch
                            if ch == ' ':
                                last_break = ci
                                last_break_line = current_line
                            if metrics.horizontalAdvance(current_line) > available_width and len(current_line) > 1:
                                if last_break > current_start:
                                    lines.append(last_break_line.rstrip(' '))
                                    current_start = last_break + 1
                                    current_line = text_str[current_start:ci + 1]
                                    last_break = -1
                                    last_break_line = ""
                                else:
                                    lines.append(current_line[:-1])
                                    current_start = ci
                                    current_line = ch
                                    last_break = -1
                                    last_break_line = ""
                                line_char_starts.append(current_start)
                        if current_line:
                            lines.append(current_line)
                        if not lines:
                            lines = [text_str]
                        
                        line_height = metrics.height()
                        total_height = line_height * len(lines)
                        start_y_img = box_y1 + (box_h - total_height) / 2 + line_height * 0.8
                        
                        cursor_pos = self.text_cursor_pos
                        
                        # Find cursor line and position
                        cursor_line = len(lines) - 1
                        cursor_pos_in_line = cursor_pos - line_char_starts[cursor_line] if cursor_line < len(line_char_starts) else len(lines[-1])
                        for i, start in enumerate(line_char_starts):
                            end = start + len(lines[i])
                            if cursor_pos <= end:
                                cursor_line = i
                                cursor_pos_in_line = cursor_pos - start
                                break
                        
                        if lines:
                            line_text = lines[cursor_line]
                            cursor_pos_in_line = min(cursor_pos_in_line, len(line_text))
                            text_before = line_text[:cursor_pos_in_line]
                            cursor_offset = metrics.horizontalAdvance(text_before)
                            
                            lw = metrics.horizontalAdvance(line_text)
                            if alignment == "left":
                                lx = box_x1 + padding
                            elif alignment == "right":
                                lx = box_x1 + box_w - lw - padding
                            else:
                                lx = box_x1 + (box_w - lw) / 2
                            
                            cx_img = lx + cursor_offset
                            cy_img = start_y_img + cursor_line * line_height
                        else:
                            cy_img = box_y1 + box_h / 2
                            if alignment == "left":
                                cx_img = box_x1 + padding
                            elif alignment == "right":
                                cx_img = box_x1 + box_w - padding
                            else:
                                cx_img = box_x1 + box_w / 2
                        
                        # Convert image coords to screen coords
                        cx_scr = cx_img * self.scale + self.offset.x()
                        cy_scr = cy_img * self.scale + self.offset.y()
                        ch_scr = (line_height * 0.8 if lines else 20) * self.scale
                        
                        p.setPen(QPen(QColor(0, 0, 0), 2, Qt.PenStyle.SolidLine))
                        p.drawLine(int(cx_scr), int(cy_scr - ch_scr * 0.8), int(cx_scr), int(cy_scr + ch_scr * 0.2))
                    except Exception:
                        pass
        
        # Draw guide lines (ruler-style crosshair) if enabled
        if hasattr(parent, 'guide_lines_enabled') and parent.guide_lines_enabled:
            self.draw_guide_lines(p, parent)
        
        # Crosshair now drawn by overlay (not here)

    def draw_step_marker(self, p, number, badge_x, badge_y, tail_x, tail_y, size, has_tail, show_handle=True, is_active=False, badge_color=None, text_color=None):
        """Draw a step marker with numbered badge and optional pointer tail
        
        Components:
        1. Badge: Colored circle with number (always drawn)
        2. Tail: Colored tapered triangle from badge edge to tail point (only if has_tail or tail moved)
        3. Handle: Small white circle at tail endpoint (only when active/editing)
        """
        import math
        from PyQt6.QtCore import Qt
        
        # Default colors
        if badge_color is None:
            badge_color = QColor(220, 50, 50, 255)
        if text_color is None:
            text_color = QColor(255, 255, 255)
        
        # Get zoom scale from parent
        parent = self.window()
        scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
        
        # Scale the size with zoom level
        scaled_size = int(size * scale)
        radius = scaled_size // 2
        
        # Calculate if tail should be drawn (moved from initial position)
        dx = tail_x - badge_x
        dy = tail_y - badge_y
        distance = math.sqrt(dx * dx + dy * dy)
        draw_tail = has_tail and distance > radius * 0.4
        
        if draw_tail:
            # Draw complete teardrop as ONE unified path
            from PyQt6.QtGui import QPainterPath
            from PyQt6.QtCore import QPointF
            
            angle = math.atan2(dy, dx)
            
            # Dynamic spread based on distance - when point is close, narrow the tail
            # so the triangle sides form straight lines to the point
            # At far distances: wide spread (85°). As point approaches circle edge: narrow down.
            max_spread = 85.0
            min_spread = 20.0
            # Normalize distance: 1.0 = at circle edge, larger = farther away
            norm_dist = distance / radius if radius > 0 else 1.0
            # Smoothly interpolate: full spread at 3x radius+, narrowing as it gets closer
            t = max(0.0, min(1.0, (norm_dist - 1.0) / 2.0))
            spread = math.radians(min_spread + (max_spread - min_spread) * t)
            
            # Calculate points on circle edge where tail connects
            left_angle = angle - spread
            right_angle = angle + spread
            
            left_x = badge_x + math.cos(left_angle) * radius
            left_y = badge_y + math.sin(left_angle) * radius
            
            right_x = badge_x + math.cos(right_angle) * radius
            right_y = badge_y + math.sin(right_angle) * radius
            
            # Create complete teardrop path
            path = QPainterPath()
            
            # Start with the full circle
            path.addEllipse(
                badge_x - radius,
                badge_y - radius,
                radius * 2,
                radius * 2
            )
            
            # Add the tail triangle
            tail_path = QPainterPath()
            tail_path.moveTo(left_x, left_y)
            tail_path.lineTo(tail_x, tail_y)
            tail_path.lineTo(right_x, right_y)
            tail_path.closeSubpath()
            
            # Unite the circle and tail
            path = path.united(tail_path)
            
            # Draw unified teardrop
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(badge_color))
            p.drawPath(path)
        else:
            # No tail - just draw circle
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(badge_color))
            p.drawEllipse(
                int(badge_x - radius),
                int(badge_y - radius),
                int(radius * 2),
                int(radius * 2)
            )
        
        # Draw dotted outline if marker is active
        if is_active:
            p.setPen(QPen(QColor(0, 120, 215), 2, Qt.PenStyle.DotLine))
            p.setBrush(Qt.BrushStyle.NoBrush)
            outline_radius = radius + 4
            p.drawEllipse(
                int(badge_x - outline_radius),
                int(badge_y - outline_radius),
                int(outline_radius * 2),
                int(outline_radius * 2)
            )
        
        # Draw number on badge - better centered
        p.setPen(text_color)
        from PyQt6.QtGui import QFont
        font = QFont()
        font.setPixelSize(int(scaled_size * 0.6))  # Prominent number size
        font.setBold(True)
        p.setFont(font)
        text = str(number)
        
        # Use Qt's alignment for better centering
        from PyQt6.QtCore import Qt
        text_rect = p.fontMetrics().boundingRect(text)
        text_x = int(badge_x - text_rect.width() / 2)
        text_y = int(badge_y + text_rect.height() / 2 - text_rect.height() / 6)  # Better vertical centering
        p.drawText(text_x, text_y, text)
        
        # Draw tail handle (small white dot) when active
        if show_handle:
            p.setPen(QPen(QColor(0, 0, 0), 2, Qt.PenStyle.SolidLine))
            p.setBrush(QBrush(QColor(255, 255, 255)))
            handle_size = max(8, int(10 * scale))
            p.drawEllipse(
                int(tail_x - handle_size // 2),
                int(tail_y - handle_size // 2),
                handle_size,
                handle_size
            )
    
    def draw_guide_lines(self, p, parent):
        """Draw ruler-style guide lines that follow the mouse cursor across the canvas"""
        from PyQt6.QtGui import QCursor
        
        if not self.pixmap():
            return
        
        # Get current mouse position
        mouse_pos = self.mapFromGlobal(QCursor.pos())
        mx, my = mouse_pos.x(), mouse_pos.y()
        
        # Get image bounds
        img_left = self.offset.x()
        img_top = self.offset.y()
        img_right = img_left + self.pixmap().width()
        img_bottom = img_top + self.pixmap().height()
        
        # Only draw if mouse is within the image area
        if not (img_left <= mx <= img_right and img_top <= my <= img_bottom):
            return
        
        # Set up pen for faint guide lines
        guide_color = QColor(100, 150, 255, 120)  # Light blue, semi-transparent
        pen = QPen(guide_color, 1, Qt.PenStyle.SolidLine)
        p.setPen(pen)
        
        # Draw vertical line (full height of image)
        p.drawLine(int(mx), int(img_top), int(mx), int(img_bottom))
        
        # Draw horizontal line (full width of image)
        p.drawLine(int(img_left), int(my), int(img_right), int(my))
        
        # Optional: Draw small crosshair at cursor position for precision
        cross_size = 10
        darker_color = QColor(80, 120, 220, 180)
        p.setPen(QPen(darker_color, 1, Qt.PenStyle.SolidLine))
        
        # Small cross marks at intersection
        p.drawLine(int(mx - cross_size), int(my), int(mx - 3), int(my))
        p.drawLine(int(mx + 3), int(my), int(mx + cross_size), int(my))
        p.drawLine(int(mx), int(my - cross_size), int(mx), int(my - 3))
        p.drawLine(int(mx), int(my + 3), int(mx), int(my + cross_size))
    
    def draw_crosshair(self, p, parent):
        """Draw magnified crosshair cursor overlay (ShareX style with fixed magnification)"""
        if not self.crosshair_mouse_pos:
            return
        
        # CRITICAL: Disable anti-aliasing for crisp pixel-perfect rendering
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        
        # Get crosshair settings
        size = parent.crosshair_size  # Circle diameter (changes with Alt+Wheel)
        pixel_scale = 16  # Larger pixels (was 12, now 16 for bigger look)
        pos = self.crosshair_mouse_pos
        
        # Calculate how many pixels to sample based on circle size and fixed magnification
        grab_pixels = max(5, int(size / pixel_scale))
        if grab_pixels % 2 == 0:
            grab_pixels += 1  # Keep odd so there's a true center pixel
        half = grab_pixels // 2
        
        # Convert screen position to image coordinates
        try:
            scale = float(self.scale) if self.scale else 1.0
        except Exception:
            scale = 1.0
        
        img_x = int(pos.x() / scale)
        img_y = int(pos.y() / scale)
        
        # Calculate pixel size in the magnified view - use integer for pixel-perfect alignment
        pixel_size = int(size / grab_pixels)
        
        # Recalculate actual drawing size to avoid black gaps
        actual_draw_size = grab_pixels * pixel_size
        
        # Position magnifier OFFSET from cursor (below and to the right)
        offset_x = 40  # Offset to the right
        offset_y = 40  # Offset down
        draw_x = int(pos.x() + offset_x)
        draw_y = int(pos.y() + offset_y)
        
        # Keep on screen by adjusting offset if needed
        if draw_x + actual_draw_size > self.width():
            draw_x = int(pos.x() - actual_draw_size - 10)  # Move to left of cursor
        if draw_y + actual_draw_size > self.height():
            draw_y = int(pos.y() - actual_draw_size - 10)  # Move above cursor
        
        # Create circular clip path (re-enable AA just for the circle edge)
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        from PyQt6.QtGui import QPainterPath
        path = QPainterPath()
        path.addEllipse(draw_x, draw_y, actual_draw_size, actual_draw_size)
        p.setClipPath(path)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)  # Back to no AA
        
        # Fill background with dark gray (in case we're sampling outside image)
        p.fillRect(draw_x, draw_y, actual_draw_size, actual_draw_size, QColor(40, 40, 40))
        
        # Draw pixel grid
        if self.image:
            w, h = self.image.size
            
            # Calculate which pixels to show (centered on cursor)
            start_x = img_x - half
            start_y = img_y - half
            
            # Center indices for crosshair overlay
            center_col = half
            center_row = half
            
            for row in range(grab_pixels):
                for col in range(grab_pixels):
                    px_x = start_x + col
                    px_y = start_y + row
                    
                    # Get pixel color (or default if outside bounds)
                    if 0 <= px_x < w and 0 <= px_y < h:
                        try:
                            px_color = self.image.getpixel((px_x, px_y))
                            if isinstance(px_color, int):
                                # Grayscale
                                r = g = b = px_color
                            elif len(px_color) >= 3:
                                r, g, b = int(px_color[0]), int(px_color[1]), int(px_color[2])
                            else:
                                r = g = b = 40
                        except:
                            r = g = b = 40
                    else:
                        # Outside image bounds - use dark gray
                        r = g = b = 40
                    
                    # Draw the pixel - use exact integer coordinates
                    px_draw_x = draw_x + col * pixel_size
                    px_draw_y = draw_y + row * pixel_size
                    
                    # Check if this pixel is on the crosshair (center row or col, but not center pixel)
                    is_crosshair = (row == center_row or col == center_col) and not (row == center_row and col == center_col)
                    
                    if is_crosshair:
                        # Manual alpha blend: mix pixel color with light blue (80, 160, 255) at 30%
                        br, bg, bb = 80, 160, 255
                        a = 0.30
                        r = int(r * (1.0 - a) + br * a)
                        g = int(g * (1.0 - a) + bg * a)
                        b = int(b * (1.0 - a) + bb * a)
                    
                    p.fillRect(px_draw_x, px_draw_y, pixel_size, pixel_size, QColor(r, g, b))
            
            
            # Draw grid lines (thin black lines) - pixel-perfect positioning
            p.setPen(QPen(QColor(0, 0, 0), 1))
            for i in range(grab_pixels + 1):
                # Vertical lines - align to exact pixel boundaries
                line_x = draw_x + i * pixel_size
                p.drawLine(line_x, draw_y, line_x, draw_y + actual_draw_size)
                # Horizontal lines - align to exact pixel boundaries
                line_y = draw_y + i * pixel_size
                p.drawLine(draw_x, line_y, draw_x + actual_draw_size, line_y)
        
        p.restore()
        
        # Draw circle border (white outer, black inner) - use high quality AA
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        
        # White outer circle - thinner for cleaner look
        p.setPen(QPen(QColor(255, 255, 255), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(draw_x, draw_y, actual_draw_size, actual_draw_size)
        
        # Black inner circle for contrast
        p.setPen(QPen(QColor(0, 0, 0), 1, Qt.PenStyle.SolidLine))
        p.drawEllipse(draw_x + 1, draw_y + 1, actual_draw_size - 2, actual_draw_size - 2)
        
        # Highlight center pixel with a small white square (just the border, not filled)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)  # No AA for pixel border
        center_pixel_x = draw_x + center_col * pixel_size
        center_pixel_y = draw_y + center_row * pixel_size
        p.setPen(QPen(QColor(255, 255, 255), 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        # Draw inner border to avoid covering the pixel
        p.drawRect(center_pixel_x + 1, center_pixel_y + 1, pixel_size - 2, pixel_size - 2)
        
        # Draw coordinate text below the circle - high quality text rendering
        if self.image:
            p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
            
            coord_text = f"X: {img_x} Y: {img_y}"
            
            from PyQt6.QtGui import QFont
            font = QFont()
            font.setFamily("Arial")  # Use clean font
            font.setPixelSize(13)
            font.setBold(True)
            font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
            p.setFont(font)
            
            # Calculate text position
            text_x = draw_x + actual_draw_size // 2 - 30
            text_y = draw_y + actual_draw_size + 15
            
            # Draw text with thick black outline for maximum contrast
            outline_pen = QPen(QColor(0, 0, 0), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
            
            # Black outline (thicker)
            for dx in [-1, 0, 1]:
                for dy in [-1, 0, 1]:
                    if dx != 0 or dy != 0:
                        p.setPen(outline_pen)
                        p.drawText(text_x + dx, text_y + dy, coord_text)
            
            # White text on top
            p.setPen(QPen(QColor(255, 255, 255), 1, Qt.PenStyle.SolidLine))
            p.drawText(text_x, text_y, coord_text)
    
    def draw_text_preview(self, p, text_str, x1, y1, box_width, box_height, font_name, font_size, color, outline_enabled, outline_color, outline_thickness, shadow_enabled, alignment="center"):
        """Draw text preview with wrapping, outline, shadow and alignment within a box"""
        from PyQt6.QtGui import QFont, QPainterPath
        # Get color
        colors = {
            "Black": QColor(0, 0, 0),
            "White": QColor(255, 255, 255),
            "Red": QColor(255, 0, 0),
            "Green": QColor(0, 200, 0),
            "Blue": QColor(0, 100, 255),
            "Yellow": QColor(255, 255, 0),
            "Orange": QColor(255, 140, 0),
            "Pink": QColor(255, 0, 255),
            "Purple": QColor(160, 32, 240),
            "Gray": QColor(128, 128, 128)
        }

        def _as_qcolor(val, default=QColor(0, 0, 0)):
            if isinstance(val, (tuple, list)) and len(val) >= 3:
                r, g, b = int(val[0]), int(val[1]), int(val[2])
                a = int(val[3]) if len(val) >= 4 else 255
                return QColor(r, g, b, a)
            if isinstance(val, QColor):
                return val
            if isinstance(val, str):
                return colors.get(val, default)
            return default

        text_color = _as_qcolor(color, QColor(0, 0, 0))
        
        # Setup font with style options
        # font_size is in image pixels, scale to screen pixels for preview
        font = QFont(font_name)
        scale = self.scale if hasattr(self, 'scale') and self.scale else 1.0
        font.setPixelSize(max(1, int(font_size * scale)))
        parent = self.window()
        font.setBold(parent.text_bold.isChecked() if hasattr(parent, 'text_bold') else True)
        font.setItalic(parent.text_italic.isChecked() if hasattr(parent, 'text_italic') else False)
        font.setUnderline(parent.text_underline.isChecked() if hasattr(parent, 'text_underline') else False)
        p.setFont(font)
        metrics = p.fontMetrics()
        
        # Wrap text to fit box width (preserves exact spacing)
        padding = max(1, int(10 * scale))
        available_width = box_width - padding * 2
        lines = []
        line_char_starts = []  # Start index in text_str for each line
        current_line = ""
        current_start = 0
        last_break = -1  # Last valid break point (after a space)
        last_break_line = ""  # Line text up to last break
        
        for i, ch in enumerate(text_str):
            current_line += ch
            if ch == ' ':
                last_break = i
                last_break_line = current_line
            
            if metrics.horizontalAdvance(current_line) > available_width and len(current_line) > 1:
                if last_break > current_start:
                    # Break at last space
                    lines.append(last_break_line.rstrip(' '))
                    line_char_starts.append(current_start)
                    current_start = last_break + 1
                    current_line = text_str[current_start:i + 1]
                    last_break = -1
                    last_break_line = ""
                else:
                    # No space to break at, break at current char
                    lines.append(current_line[:-1])
                    line_char_starts.append(current_start)
                    current_start = i
                    current_line = ch
                    last_break = -1
                    last_break_line = ""
        
        if current_line:
            lines.append(current_line)
            line_char_starts.append(current_start)
        
        # If no lines, use the text as-is
        if not lines:
            lines = [text_str]
            line_char_starts = [0]
        
        # Calculate total height and starting position to center vertically
        line_height = metrics.height()
        total_height = line_height * len(lines)
        start_y = y1 + (box_height - total_height) / 2 + line_height * 0.8
        
        # Draw each line
        for i, line in enumerate(lines):
            line_width = metrics.horizontalAdvance(line)
            
            # Calculate x position based on alignment
            if alignment == "left":
                x = x1 + padding
            elif alignment == "right":
                x = x1 + box_width - line_width - padding
            else:  # center
                x = x1 + (box_width - line_width) / 2
            
            y = start_y + i * line_height
            
            # Draw selection highlight if any
            if (hasattr(self, 'text_selection_start') and hasattr(self, 'text_selection_end') and 
                self.text_selection_start is not None and self.text_selection_end is not None):
                
                sel_start = min(self.text_selection_start, self.text_selection_end)
                sel_end = max(self.text_selection_start, self.text_selection_end)
                
                # Calculate character positions for this line
                char_count_before = sum(len(lines[j]) + 1 for j in range(i))
                char_count_after = char_count_before + len(line)
                
                # Check if selection overlaps this line
                if sel_start <= char_count_after and sel_end >= char_count_before:
                    # Calculate selection range within this line
                    line_sel_start = max(0, sel_start - char_count_before)
                    line_sel_end = min(len(line), sel_end - char_count_before)
                    
                    # Get text segments
                    text_before = line[:line_sel_start]
                    text_selected = line[line_sel_start:line_sel_end]
                    
                    # Calculate positions
                    offset_before = metrics.horizontalAdvance(text_before)
                    width_selected = metrics.horizontalAdvance(text_selected)
                    
                    # Draw selection rectangle
                    sel_x = x + offset_before
                    sel_y = y - line_height * 0.8
                    p.fillRect(int(sel_x), int(sel_y), int(width_selected), int(line_height), QColor(0, 120, 215, 100))
            
            # Draw shadow first (if enabled)
            if shadow_enabled:
                shadow_path = QPainterPath()
                shadow_path.addText(x, y, font, line)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(0, 0, 0, 150))
                p.save()
                p.translate(2, 2)
                p.drawPath(shadow_path)
                p.restore()
            
            # Use QPainterPath for both outline and fill to ensure alignment
            text_path = QPainterPath()
            text_path.addText(x, y, font, line)
            
            # Draw outline (if enabled)
            if outline_enabled:
                outline_col = _as_qcolor(outline_color, QColor(0, 0, 0))
                p.setPen(QPen(outline_col, outline_thickness, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawPath(text_path)
            
            # Draw main text fill
            if text_color.alpha() < 255:
                # Transparent text - show checkerboard
                p.save()
                p.setClipPath(text_path)
                tile = self._get_scaled_checker_tile()
                bounds = text_path.boundingRect().toAlignedRect()
                p.drawTiledPixmap(bounds, tile)
                p.restore()
            else:
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(text_color)
                p.drawPath(text_path)
        
        # Draw blinking cursor if editing
        if hasattr(self, 'text_editing') and self.text_editing and self.text_cursor_visible:
            # Calculate cursor position
            cursor_pos = self.text_cursor_pos if hasattr(self, 'text_cursor_pos') else len(text_str)
            
            # Find which line and position in that line
            char_count = 0
            cursor_line = 0
            cursor_pos_in_line = 0
            
            if lines:
                # Use accurate line_char_starts for cursor mapping
                cursor_line = len(lines) - 1
                cursor_pos_in_line = cursor_pos - line_char_starts[cursor_line] if cursor_line < len(line_char_starts) else len(lines[-1])
                
                for i, start in enumerate(line_char_starts):
                    end = start + len(lines[i])
                    if cursor_pos <= end:
                        cursor_line = i
                        cursor_pos_in_line = cursor_pos - start
                        break
                
                # Get text up to cursor in this line
                line_text = lines[cursor_line]
                cursor_pos_in_line = min(cursor_pos_in_line, len(line_text))
                text_before_cursor = line_text[:cursor_pos_in_line]
                cursor_offset = metrics.horizontalAdvance(text_before_cursor)
                
                # Calculate x based on alignment
                line_width = metrics.horizontalAdvance(line_text)
                if alignment == "left":
                    line_x = x1 + padding
                elif alignment == "right":
                    line_x = x1 + box_width - line_width - padding
                else:  # center
                    line_x = x1 + (box_width - line_width) / 2
                
                cursor_x = line_x + cursor_offset
                cursor_y = start_y + cursor_line * line_height
            else:
                # No text yet, draw at appropriate position based on alignment
                cursor_y = y1 + box_height / 2
                if alignment == "left":
                    cursor_x = x1 + padding
                elif alignment == "right":
                    cursor_x = x1 + box_width - padding
                else:  # center
                    cursor_x = x1 + box_width / 2
            
            # Draw cursor line
            p.setPen(QPen(text_color, 2, Qt.PenStyle.SolidLine))
            cursor_height = line_height * 0.8 if lines else 20
            p.drawLine(int(cursor_x), int(cursor_y - cursor_height * 0.8), int(cursor_x), int(cursor_y + cursor_height * 0.2))

    def draw_arrowhead(self, painter, x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2, color, line_width, is_straight=False):
        """Draw a curved arrow with arrowhead at the shortened endpoint using Bezier curve"""
        import math
        from PyQt6.QtGui import QPainterPath, QPolygonF
        from PyQt6.QtCore import QPointF
        
        # Arrowhead size based on line width
        arrow_length = max(10, line_width * 3)
        
        if is_straight:
            dx = x2 - x1
            dy = y2 - y1
            angle = math.atan2(dy, dx)
            backup_distance = arrow_length * 0.3
            total_dist = math.sqrt(dx*dx + dy*dy)
            if total_dist > 0:
                frac = max(0, 1.0 - backup_distance / total_dist)
            else:
                frac = 0.95
            curve_end_x = int(x1 + frac * dx)
            curve_end_y = int(y1 + frac * dy)
            painter.drawLine(int(x1), int(y1), curve_end_x, curve_end_y)
        else:
            dx = 3 * (x2 - cp2_x)
            dy = 3 * (y2 - cp2_y)
            if math.sqrt(dx*dx + dy*dy) < 1:
                dx = 3 * (x2 - cp1_x)
                dy = 3 * (y2 - cp1_y)
            angle = math.atan2(dy, dx)
            
            backup_distance = arrow_length * 0.3
            total_dist = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
            if total_dist > 0:
                t_end = max(0.85, 1.0 - (backup_distance / total_dist))
            else:
                t_end = 0.95
            t_end_inv = 1 - t_end
            curve_end_x = (t_end_inv**3 * x1 + 3 * t_end_inv**2 * t_end * cp1_x + 
                           3 * t_end_inv * t_end**2 * cp2_x + t_end**3 * x2)
            curve_end_y = (t_end_inv**3 * y1 + 3 * t_end_inv**2 * t_end * cp1_y + 
                           3 * t_end_inv * t_end**2 * cp2_y + t_end**3 * y2)
            path = QPainterPath()
            path.moveTo(x1, y1)
            path.cubicTo(cp1_x, cp1_y, cp2_x, cp2_y, curve_end_x, curve_end_y)
            painter.drawPath(path)
        
        # Calculate arrowhead points anchored at the ORIGINAL endpoint (x2, y2)
        base_angle1 = angle + math.pi - math.pi/6  # 150 degrees offset
        base_angle2 = angle + math.pi + math.pi/6  # 210 degrees offset
        
        p1_x = x2 + arrow_length * math.cos(base_angle1)
        p1_y = y2 + arrow_length * math.sin(base_angle1)
        p2_x = x2 + arrow_length * math.cos(base_angle2)
        p2_y = y2 + arrow_length * math.sin(base_angle2)
        
        # Draw filled arrowhead with tip at original endpoint
        arrow_head = QPolygonF([
            QPointF(x2, y2),  # Tip at original endpoint
            QPointF(p1_x, p1_y),
            QPointF(p2_x, p2_y)
        ])
        
        painter.setBrush(QBrush(color))
        painter.setPen(QPen(color, 1, Qt.PenStyle.SolidLine))
        painter.drawPolygon(arrow_head)

# =========================================================
# Color Palette Editor Dialog
# =========================================================

class CompactColorPicker(QWidget):
    """Compact color picker widget: SV square + hue bar + alpha bar + inputs.

    Replaces the bulky QColorDialog with a focused ~350x280 widget.
    Emits colorChanged(QColor) on every interactive change.

    Performance: The SV square uses two overlaid QLinearGradients
    (white->hue horizontal, then transparent->black vertical) instead of
    per-pixel QImage generation — GPU-composited by Qt, <1 ms repaints.
    """
    colorChanged = pyqtSignal(QColor)

    def __init__(self, parent=None, initial_color=None):
        super().__init__(parent)
        self._block_signals = False
        self._hue = 0.0
        self._sat = 1.0
        self._val = 1.0
        self._alpha = 1.0
        self._build_ui()
        if initial_color:
            self.setColor(QColor(*initial_color) if isinstance(initial_color, (tuple, list)) else initial_color)
        else:
            self.setColor(QColor(255, 0, 0, 255))

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        top_row = QHBoxLayout()
        top_row.setSpacing(6)
        self._sv_widget = _SVSquare(self)
        self._sv_widget.setFixedSize(200, 200)
        self._sv_widget.svChanged.connect(self._on_sv_changed)
        top_row.addWidget(self._sv_widget)
        self._hue_bar = _HueBar(self)
        self._hue_bar.setFixedSize(24, 200)
        self._hue_bar.hueChanged.connect(self._on_hue_changed)
        top_row.addWidget(self._hue_bar)
        right_col = QVBoxLayout()
        right_col.setSpacing(6)
        preview_container = QWidget()
        preview_container.setFixedSize(60, 60)
        preview_layout = QVBoxLayout(preview_container)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.setSpacing(0)
        self._preview_old = _ColorPreviewSwatch()
        self._preview_old.setFixedHeight(30)
        self._preview_old.setToolTip("Original color")
        self._preview_new = _ColorPreviewSwatch()
        self._preview_new.setFixedHeight(30)
        self._preview_new.setToolTip("New color")
        preview_layout.addWidget(self._preview_old)
        preview_layout.addWidget(self._preview_new)
        right_col.addWidget(preview_container)
        right_col.addStretch()
        alpha_label = QLabel("A")
        alpha_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_col.addWidget(alpha_label)
        self._alpha_bar = _AlphaBar(self)
        self._alpha_bar.setFixedSize(60, 24)
        self._alpha_bar.alphaChanged.connect(self._on_alpha_changed)
        right_col.addWidget(self._alpha_bar)
        top_row.addLayout(right_col)
        layout.addLayout(top_row)
        input_row = QHBoxLayout()
        input_row.setSpacing(4)
        hex_label = QLabel("#")
        input_row.addWidget(hex_label)
        self._hex_edit = QLineEdit()
        self._hex_edit.setFixedWidth(72)
        self._hex_edit.setMaxLength(8)
        self._hex_edit.setToolTip("Hex color (RRGGBB or RRGGBBAA)")
        self._hex_edit.editingFinished.connect(self._on_hex_edited)
        input_row.addWidget(self._hex_edit)
        input_row.addSpacing(4)
        for label_text, attr_name in [("R", "_spin_r"), ("G", "_spin_g"), ("B", "_spin_b"), ("A", "_spin_a")]:
            lbl = QLabel(label_text)
            input_row.addWidget(lbl)
            spin = QSpinBox()
            spin.setRange(0, 255)
            spin.setFixedWidth(52)
            spin.setButtonSymbols(QSpinBox.ButtonSymbols.NoButtons)
            spin.valueChanged.connect(self._on_spin_changed)
            setattr(self, attr_name, spin)
            input_row.addWidget(spin)
        input_row.addStretch()
        layout.addLayout(input_row)

    def setColor(self, qcolor):
        self._block_signals = True
        h = qcolor.hsvHueF()
        s = qcolor.hsvSaturationF()
        v = qcolor.valueF()
        a = qcolor.alphaF()
        if h < 0:
            h = self._hue / 360.0
        self._hue = h * 360.0
        self._sat = s
        self._val = v
        self._alpha = a
        self._sync_all_widgets()
        self._block_signals = False

    def setOriginalColor(self, qcolor):
        self._preview_old.set_color(qcolor)

    def currentColor(self):
        c = QColor.fromHsvF(self._hue / 360.0, self._sat, self._val)
        c.setAlphaF(self._alpha)
        return c

    def _on_hue_changed(self, hue):
        self._hue = hue
        self._sv_widget.set_hue(hue)
        self._sync_inputs()
        self._emit_color()

    def _on_sv_changed(self, s, v):
        self._sat = s
        self._val = v
        self._sync_inputs()
        self._emit_color()

    def _on_alpha_changed(self, a):
        self._alpha = a
        self._sync_inputs()
        self._emit_color()

    def _on_spin_changed(self):
        if self._block_signals:
            return
        r, g, b, a = self._spin_r.value(), self._spin_g.value(), self._spin_b.value(), self._spin_a.value()
        qc = QColor(r, g, b, a)
        self._block_signals = True
        h = qc.hsvHueF()
        if h >= 0:
            self._hue = h * 360.0
        self._sat = qc.hsvSaturationF()
        self._val = qc.valueF()
        self._alpha = a / 255.0
        self._sync_all_widgets()
        self._block_signals = False
        self._emit_color()

    def _on_hex_edited(self):
        if self._block_signals:
            return
        txt = self._hex_edit.text().strip().lstrip('#')
        if len(txt) == 6:
            txt += 'ff'
        if len(txt) != 8:
            return
        try:
            r, g, b, a = int(txt[0:2], 16), int(txt[2:4], 16), int(txt[4:6], 16), int(txt[6:8], 16)
        except ValueError:
            return
        qc = QColor(r, g, b, a)
        self._block_signals = True
        h = qc.hsvHueF()
        if h >= 0:
            self._hue = h * 360.0
        self._sat = qc.hsvSaturationF()
        self._val = qc.valueF()
        self._alpha = a / 255.0
        self._sync_all_widgets()
        self._block_signals = False
        self._emit_color()

    def _sync_all_widgets(self):
        self._hue_bar.set_hue(self._hue)
        self._sv_widget.set_hue(self._hue)
        self._sv_widget.set_sv(self._sat, self._val)
        self._alpha_bar.set_alpha(self._alpha)
        self._alpha_bar.set_base_color(QColor.fromHsvF(self._hue / 360.0, self._sat, self._val))
        self._sync_inputs()

    def _sync_inputs(self):
        c = self.currentColor()
        old_block = self._block_signals
        self._block_signals = True
        self._spin_r.setValue(c.red())
        self._spin_g.setValue(c.green())
        self._spin_b.setValue(c.blue())
        self._spin_a.setValue(c.alpha())
        hex_str = f"{c.red():02x}{c.green():02x}{c.blue():02x}"
        if c.alpha() < 255:
            hex_str += f"{c.alpha():02x}"
        self._hex_edit.setText(hex_str)
        self._preview_new.set_color(c)
        self._alpha_bar.set_base_color(QColor.fromHsvF(self._hue / 360.0, self._sat, self._val))
        self._block_signals = old_block

    def _emit_color(self):
        if not self._block_signals:
            self.colorChanged.emit(self.currentColor())


class _ColorPreviewSwatch(QWidget):
    """Small swatch showing a color with checkerboard behind transparency."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._color = QColor(255, 255, 255)

    def set_color(self, qcolor):
        self._color = QColor(qcolor)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        r = self.rect()
        cs = 6
        for y in range(0, r.height(), cs):
            for x in range(0, r.width(), cs):
                c = QColor(255, 255, 255) if ((x // cs) + (y // cs)) % 2 == 0 else QColor(204, 204, 204)
                p.fillRect(x, y, cs, cs, c)
        p.fillRect(r, self._color)
        p.setPen(QPen(QColor(128, 128, 128), 1))
        p.drawRect(r.adjusted(0, 0, -1, -1))


class _SVSquare(QWidget):
    """Saturation (x) / Value (y) square using two overlaid QLinearGradients."""
    svChanged = pyqtSignal(float, float)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hue = 0.0
        self._sat = 1.0
        self._val = 1.0
        self._dragging = False

    def set_hue(self, hue):
        self._hue = hue
        self.update()

    def set_sv(self, s, v):
        self._sat = s
        self._val = v
        self.update()

    def paintEvent(self, event):
        from PyQt6.QtGui import QLinearGradient
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        w, h = self.width(), self.height()
        rect = self.rect()
        hue_color = QColor.fromHsvF(self._hue / 360.0, 1.0, 1.0)
        sat_grad = QLinearGradient(0, 0, w, 0)
        sat_grad.setColorAt(0, QColor(255, 255, 255))
        sat_grad.setColorAt(1, hue_color)
        p.fillRect(rect, sat_grad)
        val_grad = QLinearGradient(0, 0, 0, h)
        val_grad.setColorAt(0, QColor(0, 0, 0, 0))
        val_grad.setColorAt(1, QColor(0, 0, 0, 255))
        p.fillRect(rect, val_grad)
        cx = int(self._sat * (w - 1))
        cy = int((1.0 - self._val) * (h - 1))
        p.setPen(QPen(QColor(0, 0, 0), 2))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QPoint(cx, cy), 6, 6)
        p.setPen(QPen(QColor(255, 255, 255), 1))
        p.drawEllipse(QPoint(cx, cy), 5, 5)

    def _pos_to_sv(self, pos):
        w, h = self.width(), self.height()
        s = max(0.0, min(1.0, pos.x() / max(w - 1, 1)))
        v = max(0.0, min(1.0, 1.0 - pos.y() / max(h - 1, 1)))
        return s, v

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._sat, self._val = self._pos_to_sv(e.pos())
            self.update()
            self.svChanged.emit(self._sat, self._val)

    def mouseMoveEvent(self, e):
        if self._dragging:
            self._sat, self._val = self._pos_to_sv(e.pos())
            self.update()
            self.svChanged.emit(self._sat, self._val)

    def mouseReleaseEvent(self, e):
        self._dragging = False


class _HueBar(QWidget):
    """Vertical hue bar. Pre-renders rainbow gradient into QPixmap cache."""
    hueChanged = pyqtSignal(float)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hue = 0.0
        self._dragging = False
        self._bg_cache = None
        self._cache_size = None

    def set_hue(self, hue):
        self._hue = hue
        self.update()

    def paintEvent(self, event):
        from PyQt6.QtGui import QLinearGradient
        p = QPainter(self)
        w, h = self.width(), self.height()
        if self._bg_cache is None or self._cache_size != (w, h):
            pm = QPixmap(w, h)
            pp = QPainter(pm)
            grad = QLinearGradient(0, 0, 0, h)
            for i in range(7):
                frac = i / 6.0
                grad.setColorAt(frac, QColor.fromHsvF(frac, 1.0, 1.0))
            pp.fillRect(0, 0, w, h, grad)
            pp.end()
            self._bg_cache = pm
            self._cache_size = (w, h)
        p.drawPixmap(0, 0, self._bg_cache)
        y = int((self._hue / 360.0) * (h - 1))
        p.setPen(QPen(QColor(0, 0, 0), 2))
        p.drawLine(0, y, w - 1, y)
        p.setPen(QPen(QColor(255, 255, 255), 1))
        p.drawLine(1, y, w - 2, y)

    def _pos_to_hue(self, pos):
        h = self.height()
        return max(0.0, min(360.0, (pos.y() / max(h - 1, 1)) * 360.0))

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._hue = self._pos_to_hue(e.pos())
            self.update()
            self.hueChanged.emit(self._hue)

    def mouseMoveEvent(self, e):
        if self._dragging:
            self._hue = self._pos_to_hue(e.pos())
            self.update()
            self.hueChanged.emit(self._hue)

    def mouseReleaseEvent(self, e):
        self._dragging = False


class _AlphaBar(QWidget):
    """Horizontal alpha selection bar (0.0-1.0)."""
    alphaChanged = pyqtSignal(float)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alpha = 1.0
        self._base_color = QColor(255, 0, 0)
        self._dragging = False

    def set_alpha(self, alpha):
        self._alpha = alpha
        self.update()

    def set_base_color(self, qcolor):
        self._base_color = QColor(qcolor)
        self._base_color.setAlpha(255)
        self.update()

    def paintEvent(self, event):
        from PyQt6.QtGui import QLinearGradient
        p = QPainter(self)
        w, h = self.width(), self.height()
        cs = 6
        for y in range(0, h, cs):
            for x in range(0, w, cs):
                c = QColor(255, 255, 255) if ((x // cs) + (y // cs)) % 2 == 0 else QColor(204, 204, 204)
                p.fillRect(x, y, cs, cs, c)
        transparent = QColor(self._base_color)
        transparent.setAlpha(0)
        grad = QLinearGradient(0, 0, w, 0)
        grad.setColorAt(0, transparent)
        grad.setColorAt(1, self._base_color)
        p.fillRect(self.rect(), grad)
        p.setPen(QPen(QColor(128, 128, 128), 1))
        p.drawRect(self.rect().adjusted(0, 0, -1, -1))
        x = int(self._alpha * (w - 1))
        p.setPen(QPen(QColor(0, 0, 0), 2))
        p.drawLine(x, 0, x, h - 1)
        p.setPen(QPen(QColor(255, 255, 255), 1))
        p.drawLine(x, 1, x, h - 2)

    def _pos_to_alpha(self, pos):
        return max(0.0, min(1.0, pos.x() / max(self.width() - 1, 1)))

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._alpha = self._pos_to_alpha(e.pos())
            self.update()
            self.alphaChanged.emit(self._alpha)

    def mouseMoveEvent(self, e):
        if self._dragging:
            self._alpha = self._pos_to_alpha(e.pos())
            self.update()
            self.alphaChanged.emit(self._alpha)

    def mouseReleaseEvent(self, e):
        self._dragging = False


class ColorPaletteEditorDialog(QDialog):
    """Simplified palette editor: compact swatch grid + inline color picker.

    Design:
    - Click a swatch to select+edit immediately. No modes.
    - Color changes are live — picker updates the swatch in-place (no flicker).
    - Single OK/Cancel at dialog level. Cancel reverts all changes.
    - Drag-and-drop reorder preserved.

    IMPORTANT: Uses non-modal QEventLoop pattern for eyedropper hide/show.
    """

    def __init__(self, parent=None, current_palette=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Color Palette")
        self.setWindowModality(Qt.WindowModality.NonModal)
        self._user_accepted = False
        self.setMinimumWidth(400)
        self.resize(420, 520)

        self.palette_positions = {}
        if current_palette:
            if isinstance(current_palette, dict):
                self.palette_positions = current_palette.copy()
            else:
                palette_list = self._normalize_palette(list(current_palette))
                for i, rgba in enumerate(palette_list):
                    self.palette_positions[(i // 10, i % 10)] = rgba
        else:
            default = self.get_default_palette()
            for i, rgba in enumerate(default):
                self.palette_positions[(i // 10, i % 10)] = rgba

        self._snapshot = self.palette_positions.copy()
        self.selected_position = None
        self.adding_new_color = False

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        palette_group = QGroupBox("Palette")
        palette_inner = QVBoxLayout(palette_group)
        palette_inner.setContentsMargins(6, 6, 6, 6)
        palette_inner.setSpacing(4)

        swatch_container = QWidget()
        self.palette_grid = QGridLayout(swatch_container)
        self.palette_grid.setContentsMargins(0, 0, 0, 0)
        self.palette_grid.setSpacing(2)
        from PyQt6.QtWidgets import QLayout
        self.palette_grid.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)
        self.palette_grid.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        swatch_container.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self._swatch_scroll = QScrollArea()
        self._swatch_scroll.setWidgetResizable(True)
        self._swatch_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._swatch_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._swatch_scroll.setWidget(swatch_container)
        palette_inner.addWidget(self._swatch_scroll)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        add_btn = QPushButton("+ Add")
        add_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        add_btn.setToolTip("Add a new color to the palette")
        add_btn.clicked.connect(self.add_color)
        btn_row.addWidget(add_btn)
        remove_btn = QPushButton("Remove")
        remove_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        remove_btn.setToolTip("Remove the selected color")
        remove_btn.clicked.connect(self.remove_selected)
        btn_row.addWidget(remove_btn)
        reset_btn = QPushButton("Reset to Default")
        reset_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        reset_btn.clicked.connect(self.reset_to_default)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()
        palette_inner.addLayout(btn_row)

        palette_group.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        main_layout.addWidget(palette_group)

        editor_group = QGroupBox("Color Editor")
        editor_inner = QVBoxLayout(editor_group)
        editor_inner.setContentsMargins(6, 6, 6, 6)
        editor_inner.setSpacing(4)

        self._color_picker = CompactColorPicker(self)
        self._color_picker.colorChanged.connect(self._on_picker_color_changed)
        editor_inner.addWidget(self._color_picker)

        self._pick_canvas_btn = QPushButton("Pick Color from Canvas")
        self._pick_canvas_btn.setToolTip("Click to pick a color from your canvas/image")
        self._pick_canvas_btn.setMinimumHeight(28)
        self._pick_canvas_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._pick_canvas_btn.clicked.connect(self._pick_from_canvas)
        self._pick_canvas_btn.setEnabled(self.parent() is not None and hasattr(self.parent(), '_start_eyedropper'))
        editor_inner.addWidget(self._pick_canvas_btn)

        self._editor_group = editor_group
        self._set_editor_enabled(False)
        main_layout.addWidget(editor_group)

        dialog_buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        dialog_buttons.accepted.connect(self._on_accept)
        dialog_buttons.rejected.connect(self._on_reject)
        for btn in dialog_buttons.buttons():
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        main_layout.addWidget(dialog_buttons)
        self._dialog_buttons = dialog_buttons
        self.rebuild_palette_display()

    def _set_editor_enabled(self, enabled):
        self._color_picker.setEnabled(enabled)
        self._pick_canvas_btn.setEnabled(
            enabled and self.parent() is not None and hasattr(self.parent(), '_start_eyedropper')
        )
        self._editor_group.setTitle("Color Editor" if enabled else "Color Editor (select a color above)")

    def _on_accept(self):
        self._commit_current_edit()
        self._user_accepted = True
        self.close()

    def _on_reject(self):
        self.palette_positions = self._snapshot.copy()
        self._user_accepted = False
        self.close()

    def run(self):
        self._user_accepted = False
        loop = QEventLoop()
        self.destroyed.connect(loop.quit)
        self.finished.connect(lambda _: loop.quit())
        self.show()
        self.raise_()
        self.activateWindow()
        loop.exec()
        return QDialog.DialogCode.Accepted if self._user_accepted else QDialog.DialogCode.Rejected

    def get_default_palette(self):
        return [
            (0, 0, 0, 0), (255, 255, 255, 255), (0, 0, 0, 255),
            (192, 192, 192, 255), (128, 128, 128, 255), (255, 0, 0, 255),
            (255, 165, 0, 255), (255, 255, 0, 255), (0, 255, 0, 255),
            (0, 255, 255, 255), (0, 0, 255, 255), (157, 0, 255, 255),
        ]

    @staticmethod
    def calculate_palette_grid_layout(palette_size, for_dialog=False):
        if for_dialog:
            cols = 10
            if palette_size <= 20:    rows = 2
            elif palette_size <= 40:  rows = 3
            elif palette_size <= 60:  rows = 4
            else:                     rows = ((palette_size - 1) // 20) + 2
            return (cols, rows, rows * cols)
        else:
            if palette_size <= 0:
                return (6, 2, 0)
            if palette_size <= 20:    rows = 2
            elif palette_size <= 40:  rows = 3
            elif palette_size <= 60:  rows = 4
            else:                     rows = ((palette_size - 1) // 20) + 2
            cols = (palette_size + rows - 1) // rows
            return (cols, rows, palette_size)

    def _normalize_palette(self, palette):
        normalized = []
        if not palette:
            return normalized
        for item in palette:
            if item is None:
                continue
            try:
                if isinstance(item, QColor):
                    r, g, b, a = item.getRgb()
                    normalized.append((int(r), int(g), int(b), int(a)))
                    continue
            except Exception:
                pass
            if isinstance(item, (list, tuple)):
                if len(item) == 3:
                    r, g, b = item; a = 255
                elif len(item) == 4:
                    r, g, b, a = item
                else:
                    continue
                try:
                    r = int(r); g = int(g); b = int(b); a = int(a)
                except Exception:
                    continue
                r = max(0, min(255, r)); g = max(0, min(255, g))
                b = max(0, min(255, b)); a = max(0, min(255, a))
                normalized.append((r, g, b, a))
        return normalized

    def get_palette(self):
        return self.palette_positions.copy()

    def rebuild_palette_display(self):
        while self.palette_grid.count():
            item = self.palette_grid.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
                w.deleteLater()
        from PyQt6.QtCore import QCoreApplication
        QCoreApplication.processEvents()
        if not self.palette_positions:
            return
        max_row = max((pos[0] for pos in self.palette_positions.keys()), default=0)
        color_count = len(self.palette_positions)
        rows = max(2, max_row + 1)
        if color_count > 20: rows = max(rows, 3)
        if color_count > 40: rows = max(rows, 4)
        cols = 10
        swatch_size = 32
        for row in range(rows):
            for col in range(cols):
                pos = (row, col)
                if pos in self.palette_positions:
                    rgba = self.palette_positions[pos]
                    swatch = PaletteReorderButton(rgba, index=pos, editor=self)
                    swatch.setFixedSize(swatch_size, swatch_size)
                    swatch.setToolTip(
                        "Transparent" if rgba[3] == 0 else
                        f"R:{rgba[0]} G:{rgba[1]} B:{rgba[2]} A:{rgba[3]}"
                    )
                    swatch.clicked.connect(lambda p=pos: self.select_color(p))
                    swatch.doubleClicked.connect(lambda p=pos: self.select_color(p))
                    swatch.set_selected(pos == self.selected_position)
                    self.palette_grid.addWidget(swatch, row, col)
                else:
                    placeholder = EmptyPalettePlaceholder(index=pos, editor=self)
                    placeholder.setFixedSize(swatch_size, swatch_size)
                    placeholder.setToolTip("Empty slot — drag a color here or click after '+ Add'")
                    self.palette_grid.addWidget(placeholder, row, col)
        visible_cap = 6
        eff = min(rows, visible_cap)
        sp = self.palette_grid.spacing()
        self._swatch_scroll.setFixedHeight(eff * swatch_size + max(0, eff - 1) * sp + 4)

    def _find_swatch_widget(self, position):
        for i in range(self.palette_grid.count()):
            item = self.palette_grid.itemAt(i)
            w = item.widget() if item else None
            if w and isinstance(w, PaletteReorderButton) and hasattr(w, 'index') and w.index == position:
                return w
        return None

    def _update_swatch_color(self, position, rgba):
        swatch = self._find_swatch_widget(position)
        if swatch is not None:
            swatch.color_rgba = rgba
            swatch.setToolTip(
                "Transparent" if rgba[3] == 0 else
                f"R:{rgba[0]} G:{rgba[1]} B:{rgba[2]} A:{rgba[3]}"
            )
            swatch.update()

    def _commit_current_edit(self):
        if self.selected_position is not None and self.selected_position in self.palette_positions:
            c = self._color_picker.currentColor()
            self.palette_positions[self.selected_position] = (c.red(), c.green(), c.blue(), c.alpha())

    def select_color(self, position):
        if position is None or position not in self.palette_positions:
            return
        if self.selected_position is not None and self.selected_position != position:
            self._commit_current_edit()
        self.selected_position = position
        rgba = self.palette_positions[position]
        self._set_editor_enabled(True)
        qc = QColor(*rgba)
        self._color_picker.setOriginalColor(qc)
        self._color_picker.setColor(qc)
        self.rebuild_palette_display()

    def _on_picker_color_changed(self, qcolor):
        if self.selected_position is not None and self.selected_position in self.palette_positions:
            rgba = (qcolor.red(), qcolor.green(), qcolor.blue(), qcolor.alpha())
            self.palette_positions[self.selected_position] = rgba
            self._update_swatch_color(self.selected_position, rgba)

    def move_swatch(self, src_pos, dst_pos):
        if src_pos == dst_pos:
            return
        if src_pos not in self.palette_positions:
            return
        src_color = self.palette_positions[src_pos]
        if dst_pos in self.palette_positions:
            dst_color = self.palette_positions[dst_pos]
            self.palette_positions[dst_pos] = src_color
            self.palette_positions[src_pos] = dst_color
        else:
            self.palette_positions[dst_pos] = src_color
            del self.palette_positions[src_pos]
        if self.selected_position == src_pos:
            self.selected_position = dst_pos
        self.rebuild_palette_display()

    def add_color(self):
        max_row = max((pos[0] for pos in self.palette_positions.keys()), default=0)
        rows = max(2, max_row + 1)
        cols = 10
        target = None
        for row in range(rows + 1):
            for col in range(cols):
                if (row, col) not in self.palette_positions:
                    target = (row, col)
                    break
            if target:
                break
        if target is None:
            target = (rows, 0)
        self.palette_positions[target] = (255, 255, 255, 255)
        self.adding_new_color = False
        self.rebuild_palette_display()
        self.select_color(target)

    def add_color_at_position(self, position):
        if position in self.palette_positions:
            self.select_color(position)
            return
        self.palette_positions[position] = (255, 255, 255, 255)
        self.adding_new_color = False
        self.rebuild_palette_display()
        self.select_color(position)

    def remove_selected(self):
        if self.selected_position is None:
            QMessageBox.information(self, "No Selection", "Select a color first.")
            return
        if len(self.palette_positions) <= 1:
            QMessageBox.information(self, "Cannot Remove", "Palette must contain at least one color.")
            return
        del self.palette_positions[self.selected_position]
        self.selected_position = None
        self._set_editor_enabled(False)
        self.rebuild_palette_display()

    def reset_to_default(self):
        reply = QMessageBox.question(
            self, "Reset Palette", "Reset the color palette to default colors?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            default = self.get_default_palette()
            self.palette_positions = {}
            for i, rgba in enumerate(default):
                self.palette_positions[(i // 6, i % 6)] = rgba
            self.selected_position = None
            self._set_editor_enabled(False)
            self.rebuild_palette_display()

    def _pick_from_canvas(self):
        parent = self.parent()
        if not parent or not hasattr(parent, '_start_eyedropper'):
            QMessageBox.information(self, "Not Available", "Canvas eyedropper is not available.")
            return
        self.hide()
        dummy_dlg = QDialog(parent)
        dummy_dlg.setWindowFlags(Qt.WindowType.Tool)
        dummy_dlg.setModal(False)
        original_finish = parent._finish_eyedropper

        def finish_with_restore(rgb):
            original_finish(rgb)
            if rgb and self.selected_position is not None:
                qc = QColor(*rgb)
                self._color_picker.setColor(qc)
                self.palette_positions[self.selected_position] = (qc.red(), qc.green(), qc.blue(), qc.alpha())
            parent._finish_eyedropper = original_finish
            try:
                dummy_dlg.close()
                dummy_dlg.setParent(None)
                from PyQt6.QtCore import QCoreApplication
                QCoreApplication.processEvents()
            except Exception:
                pass
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(10, lambda: (self.show(), self.raise_(), self.activateWindow(), self.rebuild_palette_display()))

        parent._finish_eyedropper = finish_with_restore
        parent._start_eyedropper(dummy_dlg, None)

# =========================================================
# FTP Settings Dialog
# =========================================================

class ToolboxEditorDialog(QDialog):
    """Dialog for customizing which tools appear in the toolbox dropdown and their order"""
    
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Toolbox")
        self.setMinimumWidth(600)
        self.setMinimumHeight(500)
        self.config = config or load_config()
        
        # All available tools with their display names
        self.all_tools = {
            "arrow": "Arrow",
            "blur": "Blur",
            "color_light": "Color & Light",
            "crop": "Crop",
            "cutout": "Cut Out",
            "cutpaste": "Cut/Paste",
            "freehand": "Freehand",
            "highlight": "Highlight",
            "line": "Line",
            "magnify_inset": "Magnify Inset",
            "step_marker": "Step Marker",
            "oval": "Oval",
            "outline": "Outline",
            "pixelate": "Pixelate",
            "rectangle": "Rectangle",
            "remove_space": "Remove Space",
            "text": "Text",
            "transform": "Transform"
        }
        
        layout = QVBoxLayout(self)
        
        # Instructions
        info_label = QLabel(
            "Organize tools for the Toolbox dropdown. Tools are always shown alphabetically in the Tools menu.\n"
            "Select a tool and use the ← → arrows to move between sections. Drag and drop to reorder within a section."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Main content area with three sections
        content_layout = QHBoxLayout()
        
        # Most Used Tools section
        most_used_layout = QVBoxLayout()
        most_used_layout.addWidget(QLabel("<b>Most Used Tools</b>"))
        self.most_used_list = QListWidget()
        self.most_used_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        most_used_layout.addWidget(self.most_used_list)
        
        content_layout.addLayout(most_used_layout)
        
        # Less Used Tools section
        less_used_layout = QVBoxLayout()
        less_used_layout.addWidget(QLabel("<b>Less Used Tools</b>"))
        self.less_used_list = QListWidget()
        self.less_used_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        less_used_layout.addWidget(self.less_used_list)
        
        content_layout.addLayout(less_used_layout)
        
        # Hidden Tools section
        hidden_layout = QVBoxLayout()
        hidden_layout.addWidget(QLabel("<b>Hidden Tools</b>"))
        self.hidden_list = QListWidget()
        self.hidden_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        hidden_layout.addWidget(self.hidden_list)
        
        content_layout.addLayout(hidden_layout)
        
        layout.addLayout(content_layout)
        
        # Arrow buttons (centered at bottom)
        arrow_layout = QHBoxLayout()
        arrow_layout.addStretch()
        
        self.btn_move_left = QPushButton("←")
        self.btn_move_left.setFixedWidth(60)
        self.btn_move_left.setToolTip("Move selected tool to the left section")
        self.btn_move_left.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_move_left.clicked.connect(self.move_left)
        
        self.btn_move_right = QPushButton("→")
        self.btn_move_right.setFixedWidth(60)
        self.btn_move_right.setToolTip("Move selected tool to the right section")
        self.btn_move_right.clicked.connect(self.move_right)
        self.btn_move_right.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        
        arrow_layout.addWidget(self.btn_move_left)
        arrow_layout.addWidget(self.btn_move_right)
        arrow_layout.addStretch()
        
        layout.addLayout(arrow_layout)
        
        # Reset and dialog buttons
        button_layout = QHBoxLayout()
        reset_btn = QPushButton("Reset to Default")
        reset_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        reset_btn.clicked.connect(self.reset_to_default)
        button_layout.addWidget(reset_btn)
        button_layout.addStretch()
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.save_and_close)
        ok_btn.setDefault(True)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Load current configuration
        self.load_current_config()
    
    def load_current_config(self):
        """Load current toolbox organization from config"""
        most_used = self.config.get("toolbox_most_used", [])
        less_used = self.config.get("toolbox_less_used", [])
        hidden = self.config.get("toolbox_hidden", [])
        
        # If no customization exists, put all tools in most_used (alphabetically)
        if not most_used and not less_used and not hidden:
            most_used = sorted(self.all_tools.keys())
        
        # Set single selection mode for all lists
        for lw in (self.most_used_list, self.less_used_list, self.hidden_list):
            lw.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
            lw.itemClicked.connect(self._on_list_item_clicked)
        
        # Populate lists
        for tool_id in most_used:
            if tool_id in self.all_tools:
                item = QListWidgetItem(self.all_tools[tool_id])
                item.setData(Qt.ItemDataRole.UserRole, tool_id)
                self.most_used_list.addItem(item)
        
        for tool_id in less_used:
            if tool_id in self.all_tools:
                item = QListWidgetItem(self.all_tools[tool_id])
                item.setData(Qt.ItemDataRole.UserRole, tool_id)
                self.less_used_list.addItem(item)
        
        for tool_id in hidden:
            if tool_id in self.all_tools:
                item = QListWidgetItem(self.all_tools[tool_id])
                item.setData(Qt.ItemDataRole.UserRole, tool_id)
                self.hidden_list.addItem(item)
    
    def _select_exclusively(self, target_list, item):
        """Ensure only one item is selected across all lists"""
        for lw in (self.most_used_list, self.less_used_list, self.hidden_list):
            if lw is not target_list:
                lw.blockSignals(True)
                lw.clearSelection()
                lw.blockSignals(False)
        
        target_list.setCurrentItem(item)
        item.setSelected(True)
    
    def _on_list_item_clicked(self, item):
        """Handle item click to enforce exclusive selection"""
        lw = item.listWidget()
        self._select_exclusively(lw, item)
    
    def get_active_list(self):
        """Get the currently active list widget"""
        if self.most_used_list.hasFocus() or self.most_used_list.selectedItems():
            return self.most_used_list
        elif self.less_used_list.hasFocus() or self.less_used_list.selectedItems():
            return self.less_used_list
        elif self.hidden_list.hasFocus() or self.hidden_list.selectedItems():
            return self.hidden_list
        return None
    
    def move_left(self):
        """Move selected tool to the left section"""
        active_list = self.get_active_list()
        if not active_list:
            return
        
        selected_items = active_list.selectedItems()
        if not selected_items:
            return
        
        # Determine destination based on current list
        if active_list == self.less_used_list:
            dest_list = self.most_used_list
        elif active_list == self.hidden_list:
            dest_list = self.less_used_list
        else:
            return  # Already at leftmost
        
        self._move_items(active_list, dest_list)
    
    def move_right(self):
        """Move selected tool to the right section"""
        active_list = self.get_active_list()
        if not active_list:
            return
        
        selected_items = active_list.selectedItems()
        if not selected_items:
            return
        
        # Determine destination based on current list
        if active_list == self.most_used_list:
            dest_list = self.less_used_list
        elif active_list == self.less_used_list:
            dest_list = self.hidden_list
        else:
            return  # Already at rightmost
        
        self._move_items(active_list, dest_list)
    
    def _move_items(self, source_list, dest_list):
        """Move selected items from source list to destination list"""
        item = source_list.currentItem()
        if not item:
            return
        
        # Remove from source
        source_list.takeItem(source_list.row(item))
        
        # Add to destination
        dest_list.addItem(item)
        
        # Ensure exclusive selection on the moved item
        self._select_exclusively(dest_list, item)
        dest_list.setFocus()
    
    def reset_to_default(self):
        """Reset to default configuration (all tools alphabetically in most used)"""
        self.most_used_list.clear()
        self.less_used_list.clear()
        self.hidden_list.clear()
        
        # Add all tools to most used in alphabetical order
        for tool_id in sorted(self.all_tools.keys()):
            item = QListWidgetItem(self.all_tools[tool_id])
            item.setData(Qt.ItemDataRole.UserRole, tool_id)
            self.most_used_list.addItem(item)
    
    def save_and_close(self):
        """Save configuration and close dialog"""
        # Collect tool IDs from each list
        most_used = []
        for i in range(self.most_used_list.count()):
            item = self.most_used_list.item(i)
            most_used.append(item.data(Qt.ItemDataRole.UserRole))
        
        less_used = []
        for i in range(self.less_used_list.count()):
            item = self.less_used_list.item(i)
            less_used.append(item.data(Qt.ItemDataRole.UserRole))
        
        hidden = []
        for i in range(self.hidden_list.count()):
            item = self.hidden_list.item(i)
            hidden.append(item.data(Qt.ItemDataRole.UserRole))
        
        # Update config
        self.config["toolbox_most_used"] = most_used
        self.config["toolbox_less_used"] = less_used
        self.config["toolbox_hidden"] = hidden
        
        # Save to file
        save_config(self.config)
        
        self.accept()


class ToolbarEditorDialog(QDialog):
    """Dialog for customizing which tools appear in the toolbar and their order"""
    
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Toolbar")
        self.setMinimumWidth(600)
        self.setMinimumHeight(500)
        self.config = config or load_config()
        
        # All available tools with their display names
        self.all_tools = {
            "arrow": "Arrow",
            "blur": "Blur",
            "color_light": "Color & Light",
            "crop": "Crop",
            "cutout": "Cut Out",
            "cutpaste": "Cut/Paste",
            "freehand": "Freehand",
            "highlight": "Highlight",
            "line": "Line",
            "magnify_inset": "Magnify Inset",
            "step_marker": "Step Marker",
            "oval": "Oval",
            "outline": "Outline",
            "pixelate": "Pixelate",
            "rectangle": "Rectangle",
            "remove_space": "Remove Space",
            "text": "Text",
            "transform": "Transform"
        }
        
        layout = QVBoxLayout(self)
        
        # Instructions
        info_label = QLabel(
            "Organize tools for the Toolbar. Most Used tools appear on the left, Less Used on the right (separated by a divider), and Hidden tools won't appear.\n"
            "Select a tool and use the ← → arrows to move between sections. Drag and drop to reorder within a section."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Main content area with three sections
        content_layout = QHBoxLayout()
        
        # Most Used Tools section (left side of divider)
        most_used_layout = QVBoxLayout()
        most_used_layout.addWidget(QLabel("<b>Most Used (Top)</b>"))
        self.most_used_list = QListWidget()
        self.most_used_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        most_used_layout.addWidget(self.most_used_list)
        
        content_layout.addLayout(most_used_layout)
        
        # Less Used Tools section (right side of divider)
        less_used_layout = QVBoxLayout()
        less_used_layout.addWidget(QLabel("<b>Less Used (Bottom)</b>"))
        self.less_used_list = QListWidget()
        self.less_used_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        less_used_layout.addWidget(self.less_used_list)
        
        content_layout.addLayout(less_used_layout)
        
        # Hidden Tools section
        hidden_layout = QVBoxLayout()
        hidden_layout.addWidget(QLabel("<b>Hidden</b>"))
        self.hidden_list = QListWidget()
        self.hidden_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        hidden_layout.addWidget(self.hidden_list)
        
        content_layout.addLayout(hidden_layout)
        
        layout.addLayout(content_layout)
        
        # Arrow buttons (centered at bottom)
        arrow_layout = QHBoxLayout()
        arrow_layout.addStretch()
        
        self.btn_move_left = QPushButton("←")
        self.btn_move_left.setFixedWidth(60)
        self.btn_move_left.setToolTip("Move selected tool to the left section")
        self.btn_move_left.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_move_left.clicked.connect(self.move_left)
        
        self.btn_move_right = QPushButton("→")
        self.btn_move_right.setFixedWidth(60)
        self.btn_move_right.setToolTip("Move selected tool to the right section")
        self.btn_move_right.clicked.connect(self.move_right)
        self.btn_move_right.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        
        arrow_layout.addWidget(self.btn_move_left)
        arrow_layout.addWidget(self.btn_move_right)
        arrow_layout.addStretch()
        
        layout.addLayout(arrow_layout)
        
        # Reset and dialog buttons
        button_layout = QHBoxLayout()
        reset_btn = QPushButton("Reset to Default")
        reset_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        reset_btn.clicked.connect(self.reset_to_default)
        button_layout.addWidget(reset_btn)
        button_layout.addStretch()
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.save_and_close)
        ok_btn.setDefault(True)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Load current configuration
        self.load_current_config()
    
    def load_current_config(self):
        """Load current toolbar organization from config"""
        most_used = self.config.get("toolbar_most_used", [])
        less_used = self.config.get("toolbar_less_used", [])
        hidden = self.config.get("toolbar_hidden", [])
        
        # If no customization exists, put all tools in most_used (alphabetically)
        if not most_used and not less_used and not hidden:
            most_used = sorted(self.all_tools.keys())
        
        # Set single selection mode for all lists
        for lw in (self.most_used_list, self.less_used_list, self.hidden_list):
            lw.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
            lw.itemClicked.connect(self._on_list_item_clicked)
        
        # Populate lists
        for tool_id in most_used:
            if tool_id in self.all_tools:
                item = QListWidgetItem(self.all_tools[tool_id])
                item.setData(Qt.ItemDataRole.UserRole, tool_id)
                self.most_used_list.addItem(item)
        
        for tool_id in less_used:
            if tool_id in self.all_tools:
                item = QListWidgetItem(self.all_tools[tool_id])
                item.setData(Qt.ItemDataRole.UserRole, tool_id)
                self.less_used_list.addItem(item)
        
        for tool_id in hidden:
            if tool_id in self.all_tools:
                item = QListWidgetItem(self.all_tools[tool_id])
                item.setData(Qt.ItemDataRole.UserRole, tool_id)
                self.hidden_list.addItem(item)
    
    def _select_exclusively(self, target_list, item):
        """Ensure only one item is selected across all lists"""
        for lw in (self.most_used_list, self.less_used_list, self.hidden_list):
            if lw is not target_list:
                lw.blockSignals(True)
                lw.clearSelection()
                lw.blockSignals(False)
        
        target_list.setCurrentItem(item)
        item.setSelected(True)
    
    def _on_list_item_clicked(self, item):
        """Handle item click to enforce exclusive selection"""
        lw = item.listWidget()
        self._select_exclusively(lw, item)
    
    def get_active_list(self):
        """Get the currently active list widget"""
        if self.most_used_list.hasFocus() or self.most_used_list.selectedItems():
            return self.most_used_list
        elif self.less_used_list.hasFocus() or self.less_used_list.selectedItems():
            return self.less_used_list
        elif self.hidden_list.hasFocus() or self.hidden_list.selectedItems():
            return self.hidden_list
        return None
    
    def move_left(self):
        """Move selected tool to the left section"""
        active_list = self.get_active_list()
        if not active_list:
            return
        
        selected_items = active_list.selectedItems()
        if not selected_items:
            return
        
        # Determine destination based on current list
        if active_list == self.less_used_list:
            dest_list = self.most_used_list
        elif active_list == self.hidden_list:
            dest_list = self.less_used_list
        else:
            return  # Already at leftmost
        
        self._move_items(active_list, dest_list)
    
    def move_right(self):
        """Move selected tool to the right section"""
        active_list = self.get_active_list()
        if not active_list:
            return
        
        selected_items = active_list.selectedItems()
        if not selected_items:
            return
        
        # Determine destination based on current list
        if active_list == self.most_used_list:
            dest_list = self.less_used_list
        elif active_list == self.less_used_list:
            dest_list = self.hidden_list
        else:
            return  # Already at rightmost
        
        self._move_items(active_list, dest_list)
    
    def _move_items(self, source_list, dest_list):
        """Move selected items from source list to destination list"""
        item = source_list.currentItem()
        if not item:
            return
        
        # Remove from source
        source_list.takeItem(source_list.row(item))
        
        # Add to destination
        dest_list.addItem(item)
        
        # Ensure exclusive selection on the moved item
        self._select_exclusively(dest_list, item)
        dest_list.setFocus()
    
    def reset_to_default(self):
        """Reset to default configuration (all tools alphabetically in most used)"""
        self.most_used_list.clear()
        self.less_used_list.clear()
        self.hidden_list.clear()
        
        # Add all tools to most used in alphabetical order
        for tool_id in sorted(self.all_tools.keys()):
            item = QListWidgetItem(self.all_tools[tool_id])
            item.setData(Qt.ItemDataRole.UserRole, tool_id)
            self.most_used_list.addItem(item)
    
    def save_and_close(self):
        """Save configuration and close dialog"""
        # Collect tool IDs from each list
        most_used = []
        for i in range(self.most_used_list.count()):
            item = self.most_used_list.item(i)
            most_used.append(item.data(Qt.ItemDataRole.UserRole))
        
        less_used = []
        for i in range(self.less_used_list.count()):
            item = self.less_used_list.item(i)
            less_used.append(item.data(Qt.ItemDataRole.UserRole))
        
        hidden = []
        for i in range(self.hidden_list.count()):
            item = self.hidden_list.item(i)
            hidden.append(item.data(Qt.ItemDataRole.UserRole))
        
        # Update config
        self.config["toolbar_most_used"] = most_used
        self.config["toolbar_less_used"] = less_used
        self.config["toolbar_hidden"] = hidden
        
        # Save to file
        save_config(self.config)
        
        self.accept()


class ToolDefaultsDialog(QDialog):
    """Dialog for configuring default settings for each tool"""
    
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Tool Defaults")
        self.setMinimumWidth(550)
        self.setMinimumHeight(500)
        self.config = config or load_config()
        self.parent_window = parent
        
        # Get current tool defaults from config
        self.tool_defaults = self.config.get("tool_defaults", {})
        
        layout = QVBoxLayout(self)
        
        # Instructions
        info_label = QLabel(
            "Configure default settings for each tool. Choose 'Remember Last' to restore "
            "the last used value, or set a specific default."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Scroll area for tool settings
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.StyledPanel)  # Add border around scroll area
        
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Create settings groups for each tool
        self._create_rectangle_group(scroll_layout)
        self._create_oval_group(scroll_layout)
        self._create_line_group(scroll_layout)
        self._create_arrow_group(scroll_layout)
        self._create_freehand_group(scroll_layout)
        self._create_highlight_group(scroll_layout)
        self._create_pixelate_group(scroll_layout)
        self._create_blur_group(scroll_layout)
        self._create_magnify_inset_group(scroll_layout)
        self._create_outline_group(scroll_layout)
        self._create_numbers_group(scroll_layout)
        self._create_text_group(scroll_layout)
        self._create_colors_group(scroll_layout)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        # Button row
        button_layout = QHBoxLayout()
        
        reset_btn = QPushButton("Reset All to Defaults")
        reset_btn.clicked.connect(self.reset_all)
        button_layout.addWidget(reset_btn)
        
        button_layout.addStretch()
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.save_and_close)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
    
    def _create_no_wheel_combo(self):
        """Create a combo box that ignores mouse wheel events when not focused"""
        combo = QComboBox()
        combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        # Override wheel event to ignore it (scroll passes to parent)
        combo.wheelEvent = lambda e: e.ignore()
        return combo
    
    def _create_mode_combo(self, key, options, default_idx=0):
        """Create a combo box for choosing between 'Default', 'Remember Last', or specific value"""
        combo = self._create_no_wheel_combo()
        combo.addItems(["Default", "Remember Last"] + options)
        
        # Load saved setting
        saved = self.tool_defaults.get(key, {})
        mode = saved.get("mode", "default")
        value = saved.get("value", None)
        
        if mode == "default":
            combo.setCurrentIndex(0)
        elif mode == "remember":
            combo.setCurrentIndex(1)
        elif mode == "specific" and value is not None:
            # Find the value in options
            idx = combo.findText(str(value))
            if idx >= 0:
                combo.setCurrentIndex(idx)
            else:
                combo.setCurrentIndex(0)
        
        return combo
    
    def _create_bool_combo(self, key):
        """Create a combo for boolean settings"""
        combo = self._create_no_wheel_combo()
        combo.addItems(["Default", "Remember Last", "On", "Off"])
        
        saved = self.tool_defaults.get(key, {})
        mode = saved.get("mode", "default")
        value = saved.get("value", None)
        
        if mode == "default":
            combo.setCurrentIndex(0)
        elif mode == "remember":
            combo.setCurrentIndex(1)
        elif mode == "specific":
            combo.setCurrentIndex(2 if value else 3)
        
        return combo
    
    def _create_rectangle_group(self, layout):
        group = QGroupBox("Rectangle")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Line Width:"), 0, 0)
        self.rect_width_combo = self._create_mode_combo(
            "rect_width", [str(i) for i in range(1, 21)])
        grid.addWidget(self.rect_width_combo, 0, 1)
        
        grid.addWidget(QLabel("Rounded Corners:"), 1, 0)
        self.rect_rounded_combo = self._create_mode_combo(
            "rect_rounded", ["0", "5", "10", "15", "20", "25", "30"])
        grid.addWidget(self.rect_rounded_combo, 1, 1)
        
        grid.addWidget(QLabel("Fill Enabled:"), 2, 0)
        self.rect_fill_combo = self._create_bool_combo("rect_fill")
        grid.addWidget(self.rect_fill_combo, 2, 1)
        
        layout.addWidget(group)
    
    def _create_oval_group(self, layout):
        group = QGroupBox("Oval")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Line Width:"), 0, 0)
        self.oval_width_combo = self._create_mode_combo(
            "oval_width", [str(i) for i in range(1, 21)])
        grid.addWidget(self.oval_width_combo, 0, 1)
        
        grid.addWidget(QLabel("Fill Enabled:"), 1, 0)
        self.oval_fill_combo = self._create_bool_combo("oval_fill")
        grid.addWidget(self.oval_fill_combo, 1, 1)
        
        layout.addWidget(group)
    
    def _create_line_group(self, layout):
        group = QGroupBox("Line")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Line Width:"), 0, 0)
        self.line_width_combo = self._create_mode_combo(
            "line_width", [str(i) for i in range(1, 21)])
        grid.addWidget(self.line_width_combo, 0, 1)
        
        grid.addWidget(QLabel("Rounded Ends:"), 1, 0)
        self.line_rounded_combo = self._create_bool_combo("line_rounded")
        grid.addWidget(self.line_rounded_combo, 1, 1)
        
        layout.addWidget(group)
    
    def _create_arrow_group(self, layout):
        group = QGroupBox("Arrow")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Line Width:"), 0, 0)
        self.arrow_width_combo = self._create_mode_combo(
            "arrow_width", [str(i) for i in range(1, 21)])
        grid.addWidget(self.arrow_width_combo, 0, 1)
        
        grid.addWidget(QLabel("Rounded:"), 1, 0)
        self.arrow_rounded_combo = self._create_bool_combo("arrow_rounded")
        grid.addWidget(self.arrow_rounded_combo, 1, 1)
        
        layout.addWidget(group)
    
    def _create_freehand_group(self, layout):
        group = QGroupBox("Freehand")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Mode:"), 0, 0)
        self.freehand_mode_combo = self._create_mode_combo(
            "freehand_mode", ["Pen", "Brush", "Spray Can", "Flood Fill", "Color Eraser", "Eraser"])
        grid.addWidget(self.freehand_mode_combo, 0, 1)
        
        grid.addWidget(QLabel("Size:"), 1, 0)
        self.freehand_size_combo = self._create_mode_combo(
            "freehand_size", [str(i) for i in range(1, 21)])
        grid.addWidget(self.freehand_size_combo, 1, 1)
        
        layout.addWidget(group)
    
    def _create_highlight_group(self, layout):
        group = QGroupBox("Highlight")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Style:"), 0, 0)
        self.highlight_style_combo = self._create_mode_combo(
            "highlight_style", ["Pen", "Rectangle", "Spotlight"])
        grid.addWidget(self.highlight_style_combo, 0, 1)
        
        grid.addWidget(QLabel("Size:"), 1, 0)
        self.highlight_size_combo = self._create_mode_combo(
            "highlight_size", [str(i) for i in range(5, 51, 5)])
        grid.addWidget(self.highlight_size_combo, 1, 1)
        
        layout.addWidget(group)
    
    def _create_pixelate_group(self, layout):
        group = QGroupBox("Pixelate")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Block Size:"), 0, 0)
        self.pixelate_size_combo = self._create_mode_combo(
            "pixelate_size", [str(i) for i in list(range(1, 21)) + list(range(25, 51, 5))])
        grid.addWidget(self.pixelate_size_combo, 0, 1)
        
        layout.addWidget(group)
    
    def _create_blur_group(self, layout):
        group = QGroupBox("Blur")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Area:"), 0, 0)
        self.blur_area_combo = self._create_mode_combo(
            "blur_area", ["Inside", "Outside"])
        grid.addWidget(self.blur_area_combo, 0, 1)
        
        grid.addWidget(QLabel("Radius:"), 0, 2)
        self.blur_radius_combo = self._create_mode_combo(
            "blur_radius", [str(i) for i in list(range(1, 21)) + list(range(25, 51, 5))])
        grid.addWidget(self.blur_radius_combo, 0, 3)
        
        layout.addWidget(group)
    
    def _create_magnify_inset_group(self, layout):
        group = QGroupBox("Magnify Inset")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Shape:"), 0, 0)
        self.inset_shape_combo = self._create_mode_combo(
            "inset_shape", ["Rectangle", "Oval"])
        grid.addWidget(self.inset_shape_combo, 0, 1)
        
        grid.addWidget(QLabel("Zoom:"), 0, 2)
        self.inset_zoom_combo = self._create_mode_combo(
            "inset_zoom", ["125%", "150%", "175%", "200%", "225%", "250%", "275%", "300%"])
        grid.addWidget(self.inset_zoom_combo, 0, 3)
        
        grid.addWidget(QLabel("Border:"), 1, 0)
        self.inset_border_combo = self._create_mode_combo(
            "inset_border", [str(i) for i in range(0, 11)])
        grid.addWidget(self.inset_border_combo, 1, 1)
        
        grid.addWidget(QLabel("Connection:"), 1, 2)
        self.inset_connection_combo = self._create_mode_combo(
            "inset_connection", ["No", "Yes"])
        grid.addWidget(self.inset_connection_combo, 1, 3)
        
        layout.addWidget(group)
    
    def _create_outline_group(self, layout):
        group = QGroupBox("Outline")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Thickness:"), 0, 0)
        self.outline_thickness_combo = self._create_mode_combo(
            "outline_thickness", [str(i) for i in range(1, 51)])
        grid.addWidget(self.outline_thickness_combo, 0, 1)
        
        grid.addWidget(QLabel("Corner Radius:"), 1, 0)
        self.outline_corner_radius_combo = self._create_mode_combo(
            "outline_corner_radius", [str(i) for i in range(0, 201, 5)])
        grid.addWidget(self.outline_corner_radius_combo, 1, 1)
        
        layout.addWidget(group)
    
    def _create_numbers_group(self, layout):
        group = QGroupBox("Step Marker")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Size:"), 0, 0)
        self.step_marker_size_combo = self._create_mode_combo(
            "step_marker_size", [str(i) for i in range(20, 101, 10)])
        grid.addWidget(self.step_marker_size_combo, 0, 1)
        
        grid.addWidget(QLabel("Start #:"), 0, 2)
        self.step_marker_start = QSpinBox()
        self.step_marker_start.setMinimum(1)
        self.step_marker_start.setMaximum(999)
        self.step_marker_start.setValue(1)
        self.step_marker_start.valueChanged.connect(self._on_start_number_changed)
        grid.addWidget(self.step_marker_start, 0, 3)
        
        color_hint = QLabel("Primary = badge, Secondary = number")
        color_hint.setStyleSheet("color: #888; font-size: 10px;")
        grid.addWidget(color_hint, 1, 0, 1, 4)
        
        layout.addWidget(group)
    
    def _on_start_number_changed(self, value):
        """Update marker counter when start number changes"""
        # self.parent() is the CutoutTool main window
        main_win = self.parent()
        if main_win and hasattr(main_win, 'viewer'):
            main_win.viewer.marker_counter = value
        # Sync toolbar spinbox on main window
        if main_win and hasattr(main_win, 'step_marker_start_toolbar'):
            main_win.step_marker_start_toolbar.blockSignals(True)
            main_win.step_marker_start_toolbar.setValue(value)
            main_win.step_marker_start_toolbar.blockSignals(False)
        # Sync this dialog's own spinbox
        if hasattr(self, 'step_marker_start'):
            self.step_marker_start.blockSignals(True)
            self.step_marker_start.setValue(value)
            self.step_marker_start.blockSignals(False)
    
    def _create_text_group(self, layout):
        group = QGroupBox("Text")
        grid = QGridLayout(group)
        
        import platform
        from PyQt6.QtGui import QFontDatabase
        available = set(QFontDatabase.families())
        
        if platform.system() == 'Windows':
            preferred = ["Arial", "Calibri", "Cambria", "Consolas", "Comic Sans MS",
                         "Courier New", "Georgia", "Impact", "Lucida Console",
                         "Segoe UI", "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana"]
        elif platform.system() == 'Darwin':
            preferred = ["Helvetica", "Helvetica Neue", "Arial", "Menlo", "Monaco",
                         "San Francisco", "Avenir", "Georgia", "Courier New", "Times New Roman"]
        else:
            preferred = ["DejaVu Sans", "DejaVu Sans Mono", "DejaVu Serif",
                         "Liberation Sans", "Liberation Mono", "Liberation Serif",
                         "Ubuntu", "Ubuntu Mono", "Noto Sans", "Noto Serif", "Noto Mono"]
        
        fonts = [f for f in preferred if f in available]
        if not fonts:
            fonts = sorted(available)[:15]
        
        grid.addWidget(QLabel("Font:"), 0, 0)
        self.text_font_combo = self._create_mode_combo("text_font", fonts)
        grid.addWidget(self.text_font_combo, 0, 1)
        
        grid.addWidget(QLabel("Size:"), 1, 0)
        self.text_size_combo = self._create_mode_combo(
            "text_size", [str(i) for i in [8, 10, 12, 14, 16, 18, 20, 24, 28, 32, 36, 48, 64, 72, 96]])
        grid.addWidget(self.text_size_combo, 1, 1)
        
        grid.addWidget(QLabel("Outline:"), 2, 0)
        self.text_outline_combo = self._create_bool_combo("text_outline")
        grid.addWidget(self.text_outline_combo, 2, 1)
        
        grid.addWidget(QLabel("Outline Thickness:"), 3, 0)
        self.text_outline_thickness_combo = self._create_mode_combo(
            "text_outline_thickness", [str(i) for i in range(1, 11)])
        grid.addWidget(self.text_outline_thickness_combo, 3, 1)
        
        grid.addWidget(QLabel("Shadow:"), 4, 0)
        self.text_shadow_combo = self._create_bool_combo("text_shadow")
        grid.addWidget(self.text_shadow_combo, 4, 1)
        
        grid.addWidget(QLabel("Alignment:"), 5, 0)
        self.text_align_combo = self._create_mode_combo(
            "text_alignment", ["Left", "Center", "Right"])
        grid.addWidget(self.text_align_combo, 5, 1)
        
        layout.addWidget(group)
    
    def _create_colors_group(self, layout):
        group = QGroupBox("Colors")
        main_layout = QVBoxLayout(group)
        
        # Load the current palette
        self._load_palette_for_dialog()
        
        # --- Primary Color ---
        primary_layout = QHBoxLayout()
        primary_layout.addWidget(QLabel("Primary Color:"))
        
        self.primary_color_combo = self._create_no_wheel_combo()
        self.primary_color_combo.addItems(["Default (Black)", "Remember Last", "From Palette", "Custom Color"])
        self.primary_color_combo.currentIndexChanged.connect(self._on_primary_mode_changed)
        primary_layout.addWidget(self.primary_color_combo)
        
        # Color preview button (also used for custom color picking)
        self.primary_color_btn = QPushButton()
        self.primary_color_btn.setFixedSize(30, 30)
        self.primary_color_btn.setToolTip("Click to pick custom color")
        self.primary_color_btn.clicked.connect(self._pick_primary_color)
        primary_layout.addWidget(self.primary_color_btn)
        
        primary_layout.addStretch()
        main_layout.addLayout(primary_layout)
        
        # Primary palette selector (shown when "From Palette" is selected)
        self.primary_palette_widget = self._create_mini_palette("primary")
        main_layout.addWidget(self.primary_palette_widget)
        
        main_layout.addSpacing(10)
        
        # --- Secondary Color ---
        secondary_layout = QHBoxLayout()
        secondary_layout.addWidget(QLabel("Secondary Color:"))
        
        self.secondary_color_combo = self._create_no_wheel_combo()
        self.secondary_color_combo.addItems(["Default (White)", "Remember Last", "From Palette", "Custom Color"])
        self.secondary_color_combo.currentIndexChanged.connect(self._on_secondary_mode_changed)
        secondary_layout.addWidget(self.secondary_color_combo)
        
        # Color preview button
        self.secondary_color_btn = QPushButton()
        self.secondary_color_btn.setFixedSize(30, 30)
        self.secondary_color_btn.setToolTip("Click to pick custom color")
        self.secondary_color_btn.clicked.connect(self._pick_secondary_color)
        secondary_layout.addWidget(self.secondary_color_btn)
        
        secondary_layout.addStretch()
        main_layout.addLayout(secondary_layout)
        
        # Secondary palette selector
        self.secondary_palette_widget = self._create_mini_palette("secondary")
        main_layout.addWidget(self.secondary_palette_widget)
        
        # Load saved settings
        self._load_color_settings()
        
        layout.addWidget(group)
    
    def _load_palette_for_dialog(self):
        """Load the color palette for use in this dialog"""
        config = load_config()
        custom_palette = config.get('custom_palette', None)
        
        if custom_palette and isinstance(custom_palette, dict):
            # Convert string keys back to tuples if needed
            self._dialog_palette = {}
            for key, value in custom_palette.items():
                try:
                    if isinstance(key, str):
                        parsed = ast.literal_eval(key)
                        if not (isinstance(parsed, tuple) and len(parsed) == 2):
                            continue
                        row, col = int(parsed[0]), int(parsed[1])
                    else:
                        row, col = key
                    rgba = tuple(int(v) for v in value)
                    if len(rgba) < 3:
                        continue
                    self._dialog_palette[(row, col)] = rgba
                except (ValueError, TypeError, SyntaxError):
                    continue
        else:
            # Default palette
            default_list = [
                (0, 0, 0, 0), (255, 255, 255, 255), (0, 0, 0, 255),
                (192, 192, 192, 255), (128, 128, 128, 255), (255, 0, 0, 255),
                (255, 165, 0, 255), (255, 255, 0, 255), (0, 255, 0, 255),
                (0, 255, 255, 255), (0, 0, 255, 255), (157, 0, 255, 255),
            ]
            self._dialog_palette = {}
            for i, rgba in enumerate(default_list):
                row, col = i // 6, i % 6
                self._dialog_palette[(row, col)] = rgba
    
    def _create_mini_palette(self, color_type):
        """Create a mini palette widget for color selection"""
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(20, 5, 5, 5)
        
        label = QLabel("Select from palette:")
        label.setStyleSheet("color: #666;")
        container_layout.addWidget(label)
        
        # Create grid of color swatches
        palette_widget = QWidget()
        grid = QGridLayout(palette_widget)
        grid.setSpacing(2)
        grid.setContentsMargins(0, 0, 0, 0)
        
        # Find palette dimensions
        if self._dialog_palette:
            max_row = max((pos[0] for pos in self._dialog_palette.keys()), default=1)
            max_col = max((pos[1] for pos in self._dialog_palette.keys()), default=5)
        else:
            max_row, max_col = 1, 5
        
        # Store swatch buttons for this color type
        swatches = {}
        
        for row in range(max_row + 1):
            for col in range(max_col + 1):
                pos = (row, col)
                rgba = self._dialog_palette.get(pos)
                
                btn = QPushButton()
                btn.setFixedSize(24, 24)
                btn.setCheckable(True)
                
                if rgba:
                    r, g, b, a = rgba
                    if a == 0:
                        # Transparent - show checkerboard pattern
                        btn.setStyleSheet("""
                            QPushButton {
                                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                    stop:0 #ccc, stop:0.5 #ccc, stop:0.5 #fff, stop:1 #fff);
                                border: 1px solid #888;
                            }
                            QPushButton:checked { border: 2px solid #00f; }
                        """)
                    else:
                        btn.setStyleSheet(f"""
                            QPushButton {{
                                background-color: rgb({r},{g},{b});
                                border: 1px solid #888;
                            }}
                            QPushButton:checked {{ border: 2px solid #00f; }}
                        """)
                    btn.setToolTip(f"RGB({r},{g},{b})")
                    btn.clicked.connect(lambda checked, p=pos, ct=color_type: self._on_palette_color_selected(p, ct))
                    swatches[pos] = btn
                else:
                    btn.setEnabled(False)
                    btn.setStyleSheet("background-color: #f0f0f0; border: 1px solid #ddd;")
                
                grid.addWidget(btn, row, col)
        
        # Store swatches reference
        if color_type == "primary":
            self._primary_palette_swatches = swatches
        else:
            self._secondary_palette_swatches = swatches
        
        container_layout.addWidget(palette_widget)
        container.setVisible(False)  # Hidden by default
        return container
    
    def _on_palette_color_selected(self, pos, color_type):
        """Handle palette color selection"""
        rgba = self._dialog_palette.get(pos)
        if not rgba:
            return
        
        if color_type == "primary":
            self._primary_custom_color = rgba
            self._primary_palette_pos = pos
            self._update_color_button(self.primary_color_btn, rgba)
            # Uncheck other swatches
            for p, btn in self._primary_palette_swatches.items():
                btn.setChecked(p == pos)
        else:
            self._secondary_custom_color = rgba
            self._secondary_palette_pos = pos
            self._update_color_button(self.secondary_color_btn, rgba)
            # Uncheck other swatches
            for p, btn in self._secondary_palette_swatches.items():
                btn.setChecked(p == pos)
    
    def _on_primary_mode_changed(self, index):
        """Handle primary color mode change"""
        # Show/hide palette selector
        self.primary_palette_widget.setVisible(index == 2)  # "From Palette"
        
        # Update color preview based on mode
        if index == 0:  # Default (Black)
            self._update_color_button(self.primary_color_btn, (0, 0, 0, 255))
        elif index == 1:  # Remember Last
            self._update_color_button(self.primary_color_btn, (128, 128, 128, 255))  # Gray to indicate "varies"
        # For palette and custom, keep current color
    
    def _on_secondary_mode_changed(self, index):
        """Handle secondary color mode change"""
        # Show/hide palette selector
        self.secondary_palette_widget.setVisible(index == 2)  # "From Palette"
        
        # Update color preview based on mode
        if index == 0:  # Default (White)
            self._update_color_button(self.secondary_color_btn, (255, 255, 255, 255))
        elif index == 1:  # Remember Last
            self._update_color_button(self.secondary_color_btn, (128, 128, 128, 255))  # Gray to indicate "varies"
        # For palette and custom, keep current color
    
    def _load_color_settings(self):
        """Load saved color settings"""
        # Primary color
        saved = self.tool_defaults.get("primary_color", {})
        mode = saved.get("mode", "default")
        
        self._primary_palette_pos = None
        
        if mode == "default":
            self.primary_color_combo.setCurrentIndex(0)
            self._primary_custom_color = (0, 0, 0, 255)
        elif mode == "remember":
            self.primary_color_combo.setCurrentIndex(1)
            self._primary_custom_color = (128, 128, 128, 255)
        elif mode == "palette":
            self.primary_color_combo.setCurrentIndex(2)
            pos = saved.get("palette_pos")
            if pos:
                self._primary_palette_pos = tuple(pos)
                rgba = self._dialog_palette.get(self._primary_palette_pos)
                self._primary_custom_color = rgba if rgba else (0, 0, 0, 255)
                # Check the corresponding swatch
                if hasattr(self, '_primary_palette_swatches') and self._primary_palette_pos in self._primary_palette_swatches:
                    self._primary_palette_swatches[self._primary_palette_pos].setChecked(True)
            else:
                self._primary_custom_color = (0, 0, 0, 255)
            self.primary_palette_widget.setVisible(True)
        else:  # specific/custom
            self.primary_color_combo.setCurrentIndex(3)
            val = saved.get("value")
            self._primary_custom_color = tuple(val) if val else (0, 0, 0, 255)
        
        self._update_color_button(self.primary_color_btn, self._primary_custom_color)
        
        # Secondary color
        saved2 = self.tool_defaults.get("secondary_color", {})
        mode2 = saved2.get("mode", "default")
        
        self._secondary_palette_pos = None
        
        if mode2 == "default":
            self.secondary_color_combo.setCurrentIndex(0)
            self._secondary_custom_color = (255, 255, 255, 255)
        elif mode2 == "remember":
            self.secondary_color_combo.setCurrentIndex(1)
            self._secondary_custom_color = (128, 128, 128, 255)
        elif mode2 == "palette":
            self.secondary_color_combo.setCurrentIndex(2)
            pos = saved2.get("palette_pos")
            if pos:
                self._secondary_palette_pos = tuple(pos)
                rgba = self._dialog_palette.get(self._secondary_palette_pos)
                self._secondary_custom_color = rgba if rgba else (255, 255, 255, 255)
                # Check the corresponding swatch
                if hasattr(self, '_secondary_palette_swatches') and self._secondary_palette_pos in self._secondary_palette_swatches:
                    self._secondary_palette_swatches[self._secondary_palette_pos].setChecked(True)
            else:
                self._secondary_custom_color = (255, 255, 255, 255)
            self.secondary_palette_widget.setVisible(True)
        else:  # specific/custom
            self.secondary_color_combo.setCurrentIndex(3)
            val = saved2.get("value")
            self._secondary_custom_color = tuple(val) if val else (255, 255, 255, 255)
        
        self._update_color_button(self.secondary_color_btn, self._secondary_custom_color)
    
    def _update_color_button(self, btn, color):
        """Update button background to show the color"""
        if isinstance(color, (list, tuple)) and len(color) >= 3:
            r, g, b = color[0], color[1], color[2]
            btn.setStyleSheet(f"background-color: rgb({r},{g},{b}); border: 1px solid #888;")
    
    def _pick_primary_color(self):
        """Open color picker for primary color"""
        if not self._primary_custom_color:
            self._primary_custom_color = (0, 0, 0, 255)
        initial = QColor(self._primary_custom_color[0], self._primary_custom_color[1], self._primary_custom_color[2])
        color = QColorDialog.getColor(initial, self, "Select Primary Color")
        if color.isValid():
            self._primary_custom_color = (color.red(), color.green(), color.blue(), 255)
            self._update_color_button(self.primary_color_btn, self._primary_custom_color)
            self.primary_color_combo.setCurrentIndex(3)  # Set to Custom
            self._primary_palette_pos = None  # Clear palette position
    
    def _pick_secondary_color(self):
        """Open color picker for secondary color"""
        if not self._secondary_custom_color:
            self._secondary_custom_color = (255, 255, 255, 255)
        initial = QColor(self._secondary_custom_color[0], self._secondary_custom_color[1], self._secondary_custom_color[2])
        color = QColorDialog.getColor(initial, self, "Select Secondary Color")
        if color.isValid():
            self._secondary_custom_color = (color.red(), color.green(), color.blue(), 255)
            self._update_color_button(self.secondary_color_btn, self._secondary_custom_color)
            self.secondary_color_combo.setCurrentIndex(3)  # Set to Custom
            self._secondary_palette_pos = None  # Clear palette position
    
    def _get_combo_setting(self, combo, key):
        """Extract mode and value from a combo box"""
        idx = combo.currentIndex()
        text = combo.currentText()
        
        if idx == 0:
            return {"mode": "default", "value": None}
        elif idx == 1:
            return {"mode": "remember", "value": None}
        else:
            return {"mode": "specific", "value": text}
    
    def _get_bool_combo_setting(self, combo, key):
        """Extract mode and value from a boolean combo box"""
        idx = combo.currentIndex()
        
        if idx == 0:
            return {"mode": "default", "value": None}
        elif idx == 1:
            return {"mode": "remember", "value": None}
        elif idx == 2:
            return {"mode": "specific", "value": True}
        else:
            return {"mode": "specific", "value": False}
    
    def reset_all(self):
        """Reset all settings to defaults"""
        # Reset all combos to index 0 (Default)
        for combo in [self.rect_width_combo, self.rect_rounded_combo, self.rect_fill_combo,
                      self.oval_width_combo, self.oval_fill_combo,
                      self.line_width_combo, self.line_rounded_combo,
                      self.arrow_width_combo, self.arrow_rounded_combo,
                      self.freehand_mode_combo, self.freehand_size_combo,
                      self.highlight_style_combo, self.highlight_size_combo,
                      self.pixelate_size_combo, self.blur_area_combo, self.blur_radius_combo,
                      self.inset_shape_combo, self.inset_zoom_combo, self.inset_border_combo, self.inset_connection_combo,
                      self.outline_thickness_combo, self.outline_corner_radius_combo,
                      self.step_marker_size_combo,
                      self.text_font_combo, self.text_size_combo, self.text_outline_combo,
                      self.text_outline_thickness_combo, self.text_shadow_combo, self.text_align_combo,
                      self.primary_color_combo, self.secondary_color_combo]:
            combo.setCurrentIndex(0)
        
        # Reset color buttons and hide palette selectors
        self._primary_custom_color = (0, 0, 0, 255)
        self._secondary_custom_color = (255, 255, 255, 255)
        self._primary_palette_pos = None
        self._secondary_palette_pos = None
        self._update_color_button(self.primary_color_btn, self._primary_custom_color)
        self._update_color_button(self.secondary_color_btn, self._secondary_custom_color)
        self.primary_palette_widget.setVisible(False)
        self.secondary_palette_widget.setVisible(False)
        
        # Uncheck all palette swatches
        if hasattr(self, '_primary_palette_swatches'):
            for btn in self._primary_palette_swatches.values():
                btn.setChecked(False)
        if hasattr(self, '_secondary_palette_swatches'):
            for btn in self._secondary_palette_swatches.values():
                btn.setChecked(False)
    
    def save_and_close(self):
        """Save all settings and close"""
        defaults = {}
        
        # Rectangle
        defaults["rect_width"] = self._get_combo_setting(self.rect_width_combo, "rect_width")
        defaults["rect_rounded"] = self._get_combo_setting(self.rect_rounded_combo, "rect_rounded")
        defaults["rect_fill"] = self._get_bool_combo_setting(self.rect_fill_combo, "rect_fill")
        
        # Oval
        defaults["oval_width"] = self._get_combo_setting(self.oval_width_combo, "oval_width")
        defaults["oval_fill"] = self._get_bool_combo_setting(self.oval_fill_combo, "oval_fill")
        
        # Line
        defaults["line_width"] = self._get_combo_setting(self.line_width_combo, "line_width")
        defaults["line_rounded"] = self._get_bool_combo_setting(self.line_rounded_combo, "line_rounded")
        
        # Arrow
        defaults["arrow_width"] = self._get_combo_setting(self.arrow_width_combo, "arrow_width")
        defaults["arrow_rounded"] = self._get_bool_combo_setting(self.arrow_rounded_combo, "arrow_rounded")
        
        # Freehand
        defaults["freehand_mode"] = self._get_combo_setting(self.freehand_mode_combo, "freehand_mode")
        defaults["freehand_size"] = self._get_combo_setting(self.freehand_size_combo, "freehand_size")
        
        # Highlight
        defaults["highlight_style"] = self._get_combo_setting(self.highlight_style_combo, "highlight_style")
        defaults["highlight_size"] = self._get_combo_setting(self.highlight_size_combo, "highlight_size")
        
        # Pixelate
        defaults["pixelate_size"] = self._get_combo_setting(self.pixelate_size_combo, "pixelate_size")
        
        # Blur
        defaults["blur_area"] = self._get_combo_setting(self.blur_area_combo, "blur_area")
        defaults["blur_radius"] = self._get_combo_setting(self.blur_radius_combo, "blur_radius")
        
        # Magnify Inset
        defaults["inset_shape"] = self._get_combo_setting(self.inset_shape_combo, "inset_shape")
        defaults["inset_zoom"] = self._get_combo_setting(self.inset_zoom_combo, "inset_zoom")
        defaults["inset_border"] = self._get_combo_setting(self.inset_border_combo, "inset_border")
        defaults["inset_connection"] = self._get_combo_setting(self.inset_connection_combo, "inset_connection")
        
        # Outline
        defaults["outline_thickness"] = self._get_combo_setting(self.outline_thickness_combo, "outline_thickness")
        defaults["outline_corner_radius"] = self._get_combo_setting(self.outline_corner_radius_combo, "outline_corner_radius")
        
        # Numbers
        defaults["step_marker_size"] = self._get_combo_setting(self.step_marker_size_combo, "step_marker_size")
        
        # Text
        defaults["text_font"] = self._get_combo_setting(self.text_font_combo, "text_font")
        defaults["text_size"] = self._get_combo_setting(self.text_size_combo, "text_size")
        defaults["text_outline"] = self._get_bool_combo_setting(self.text_outline_combo, "text_outline")
        defaults["text_outline_thickness"] = self._get_combo_setting(self.text_outline_thickness_combo, "text_outline_thickness")
        defaults["text_shadow"] = self._get_bool_combo_setting(self.text_shadow_combo, "text_shadow")
        defaults["text_alignment"] = self._get_combo_setting(self.text_align_combo, "text_alignment")
        
        # Colors - now with palette support
        primary_idx = self.primary_color_combo.currentIndex()
        if primary_idx == 0:  # Default
            defaults["primary_color"] = {"mode": "default", "value": None}
        elif primary_idx == 1:  # Remember Last
            defaults["primary_color"] = {"mode": "remember", "value": None}
        elif primary_idx == 2:  # From Palette
            defaults["primary_color"] = {
                "mode": "palette",
                "palette_pos": list(self._primary_palette_pos) if self._primary_palette_pos else None,
                "value": list(self._primary_custom_color) if self._primary_custom_color else None
            }
        else:  # Custom Color
            defaults["primary_color"] = {"mode": "specific", "value": list(self._primary_custom_color) if self._primary_custom_color else None}
        
        secondary_idx = self.secondary_color_combo.currentIndex()
        if secondary_idx == 0:  # Default
            defaults["secondary_color"] = {"mode": "default", "value": None}
        elif secondary_idx == 1:  # Remember Last
            defaults["secondary_color"] = {"mode": "remember", "value": None}
        elif secondary_idx == 2:  # From Palette
            defaults["secondary_color"] = {
                "mode": "palette",
                "palette_pos": list(self._secondary_palette_pos) if self._secondary_palette_pos else None,
                "value": list(self._secondary_custom_color) if self._secondary_custom_color else None
            }
        else:  # Custom Color
            defaults["secondary_color"] = {"mode": "specific", "value": list(self._secondary_custom_color) if self._secondary_custom_color else None}
        
        # Save to config
        self.config["tool_defaults"] = defaults
        save_config(self.config)
        
        self.accept()


class ImageSettingsDialog(QDialog):
    """Dialog for configuring image handling settings"""
    
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Image Settings")
        self.setMinimumWidth(500)
        self.config = config or load_config()
        
        layout = QVBoxLayout(self)
        
        # Large Image Detection group
        detection_group = QGroupBox("Large Image Detection")
        detection_layout = QVBoxLayout(detection_group)
        
        # Enable checkbox
        self.check_image_size_checkbox = QCheckBox("Prompt when opening large images")
        self.check_image_size_checkbox.setChecked(self.config.get("check_image_size", True))
        self.check_image_size_checkbox.setToolTip("Show a dialog when opening/pasting images larger than the maximum dimension")
        detection_layout.addWidget(self.check_image_size_checkbox)
        
        detection_layout.addSpacing(10)
        
        # Maximum dimension input
        max_dim_layout = QHBoxLayout()
        max_dim_label = QLabel("Maximum dimension (width or height):")
        self.max_dimension_spin = QSpinBox()
        self.max_dimension_spin.setRange(800, 5000)
        self.max_dimension_spin.setSingleStep(100)
        self.max_dimension_spin.setValue(self.config.get("max_image_dimension", 1920))
        self.max_dimension_spin.setSuffix(" px")
        self.max_dimension_spin.setToolTip("Images larger than this will trigger the prompt")
        max_dim_layout.addWidget(max_dim_label)
        max_dim_layout.addWidget(self.max_dimension_spin)
        max_dim_layout.addStretch()
        detection_layout.addLayout(max_dim_layout)
        
        detection_layout.addSpacing(10)
        
        # Action dropdown
        action_layout = QHBoxLayout()
        action_label = QLabel("Action for large images:")
        self.large_image_action_combo = QComboBox()
        self.large_image_action_combo.addItems(["Prompt user", "Always resize", "Ignore (no prompt)"])
        current_action = self.config.get("large_image_action", "prompt")
        if current_action == "prompt":
            self.large_image_action_combo.setCurrentIndex(0)
        elif current_action == "always_resize":
            self.large_image_action_combo.setCurrentIndex(1)
        elif current_action == "ignore":
            self.large_image_action_combo.setCurrentIndex(2)
        self.large_image_action_combo.setToolTip("Choose what happens when a large image is detected")
        action_layout.addWidget(action_label)
        action_layout.addWidget(self.large_image_action_combo)
        action_layout.addStretch()
        detection_layout.addLayout(action_layout)
        
        layout.addWidget(detection_group)
        
        layout.addStretch()
        
        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.save_and_accept)
        button_box.rejected.connect(self.reject)
        button_box.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for btn in button_box.buttons():
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(button_box)
    
    def save_and_accept(self):
        """Save config and close dialog"""
        # Map combo box selection to action value
        action_index = self.large_image_action_combo.currentIndex()
        action_map = {0: "prompt", 1: "always_resize", 2: "ignore"}
        
        # Update only the image settings
        self.config.update({
            "check_image_size": self.check_image_size_checkbox.isChecked(),
            "max_image_dimension": self.max_dimension_spin.value(),
            "large_image_action": action_map[action_index]
        })
        
        save_config(self.config)
        self.accept()


class ImportSettingsDialog(QDialog):
    """Dialog for selecting which settings categories to import"""
    
    def __init__(self, parent=None, import_config=None):
        super().__init__(parent)
        self.setWindowTitle("Import Settings")
        self.setMinimumWidth(400)
        self.import_config = import_config or {}
        
        layout = QVBoxLayout(self)
        
        # Show export info if available
        export_info = self.import_config.get("_export_info", {})
        if export_info:
            info_text = f"Settings file from: {export_info.get('app', 'Unknown')}"
            if export_info.get("export_date"):
                try:
                    from datetime import datetime
                    date_str = export_info["export_date"][:10]  # Just the date part
                    info_text += f"\nExported: {date_str}"
                except:
                    pass
            info_label = QLabel(info_text)
            info_label.setStyleSheet("color: #666; padding: 5px;")
            layout.addWidget(info_label)
        
        # Instructions
        layout.addWidget(QLabel("Select which settings to import:"))
        
        # Checkboxes for each category
        self.checkboxes = {}
        
        categories = [
            ("toolbox", "Toolbox Organization", 
             self._has_setting(["toolbox_most_used", "toolbox_less_used", "toolbox_hidden"])),
            ("toolbar", "Toolbar Organization",
             self._has_setting(["toolbar_most_used", "toolbar_less_used", "toolbar_hidden"])),
            ("tool_defaults", "Tool Defaults",
             self._has_setting(["tool_defaults"])),
            ("palette", "Color Palette",
             self._has_setting(["custom_palette"])),
            ("image_settings", "Image Settings",
             self._has_setting(["check_image_size", "max_image_dimension"])),
            ("ftp_settings", "FTP Settings",
             self._has_setting(["ftp_host", "destinations"])),
        ]
        
        group = QGroupBox()
        group_layout = QVBoxLayout(group)
        
        for key, label, available in categories:
            cb = QCheckBox(label)
            cb.setChecked(available)
            cb.setEnabled(available)
            if not available:
                cb.setToolTip("Not found in import file")
            self.checkboxes[key] = cb
            group_layout.addWidget(cb)
        
        layout.addWidget(group)
        
        # Select all / none buttons
        btn_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self._select_all)
        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(self._select_none)
        btn_layout.addWidget(select_all_btn)
        btn_layout.addWidget(select_none_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # Warning about overwriting
        warning_label = QLabel(
            "⚠️ Warning: Importing will overwrite your current settings\n"
            "for the selected categories."
        )
        warning_label.setStyleSheet("color: #c00; padding: 10px;")
        layout.addWidget(warning_label)
        
        layout.addStretch()
        
        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        for btn in button_box.buttons():
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(button_box)
    
    def _has_setting(self, keys):
        """Check if any of the given keys exist in the import config"""
        for key in keys:
            if key in self.import_config:
                val = self.import_config[key]
                # Check if it has actual content
                if val is not None:
                    if isinstance(val, (list, dict)):
                        if len(val) > 0:
                            return True
                    else:
                        return True
        return False
    
    def _select_all(self):
        """Select all available checkboxes"""
        for cb in self.checkboxes.values():
            if cb.isEnabled():
                cb.setChecked(True)
    
    def _select_none(self):
        """Deselect all checkboxes"""
        for cb in self.checkboxes.values():
            cb.setChecked(False)
    
    def get_selected_categories(self):
        """Return list of selected category keys"""
        return [key for key, cb in self.checkboxes.items() if cb.isChecked()]


# =========================================================
# Upload protocol helpers (FTP / FTPS / SFTP)
# =========================================================

def _create_upload_connection(protocol, host, user, password, parent_widget=None):
    """Create and return a connected upload client for the given protocol.
    
    Args:
        parent_widget: Optional QWidget for host-key confirmation dialogs (SFTP).
    Returns:
        ftplib.FTP, ftplib.FTP_TLS, or paramiko.SFTPClient
    Raises:
        Exception with user-friendly message on failure.
    """
    protocol = protocol.upper()
    
    if protocol == "FTP":
        conn = ftplib.FTP(host, timeout=10)
        conn.login(user, password)
        return conn
    
    elif protocol == "FTPS":
        import ssl
        ctx = ssl.create_default_context()
        conn = ftplib.FTP_TLS(host, timeout=10, context=ctx)
        conn.login(user, password)
        conn.prot_p()  # switch to encrypted data channel
        return conn
    
    elif protocol == "SFTP":
        try:
            import paramiko
        except ImportError:
            raise RuntimeError(
                "SFTP requires the 'paramiko' package.\n\n"
                "Install it with:  pip install paramiko"
            )
        
        # Use SSHClient for host key verification
        client = paramiko.SSHClient()
        
        # Load system known hosts
        try:
            client.load_system_host_keys()
        except Exception:
            pass
        
        # Load Magpie-specific known_hosts
        pannex_known_hosts = get_config_dir() / "known_hosts"
        if pannex_known_hosts.exists():
            try:
                client.load_host_keys(str(pannex_known_hosts))
            except Exception:
                pass
        
        # Reject unknown keys by default
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        
        try:
            client.connect(host, port=22, username=user, password=password, timeout=10)
        except paramiko.SSHException as e:
            if "not found in known_hosts" in str(e) or "Server" in str(e):
                # Retrieve the host key to show the user
                try:
                    transport = paramiko.Transport((host, 22))
                    transport.connect()
                    host_key = transport.get_remote_server_key()
                    transport.close()
                except Exception:
                    raise RuntimeError(
                        f"Cannot verify the SSH host key for '{host}'.\n\n"
                        "Connect to this server via SSH first, or add its key\n"
                        "to your system known_hosts file."
                    )
                
                key_type = host_key.get_name()
                fingerprint = ":".join(f"{b:02x}" for b in host_key.get_fingerprint())
                
                # Prompt user if we have a parent widget
                if parent_widget is not None:
                    reply = QMessageBox.question(
                        parent_widget,
                        "Unknown SSH Host Key",
                        f"The server '{host}' presented an unknown host key.\n\n"
                        f"Type: {key_type}\n"
                        f"Fingerprint: {fingerprint}\n\n"
                        "Do you want to trust this key and continue?\n"
                        "(The key will be saved for future connections.)",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.No
                    )
                    if reply != QMessageBox.StandardButton.Yes:
                        raise RuntimeError("Connection cancelled — host key not trusted.")
                else:
                    raise RuntimeError(
                        f"Unknown SSH host key for '{host}'.\n"
                        f"Fingerprint: {fingerprint}\n\n"
                        "Connect via SSH first to trust this server."
                    )
                
                # User accepted — save key and retry
                try:
                    pannex_known_hosts.parent.mkdir(parents=True, exist_ok=True)
                    host_keys = paramiko.HostKeys()
                    if pannex_known_hosts.exists():
                        host_keys.load(str(pannex_known_hosts))
                    host_keys.add(host, key_type, host_key)
                    host_keys.save(str(pannex_known_hosts))
                except Exception:
                    pass
                
                # Retry with the now-trusted key
                client2 = paramiko.SSHClient()
                try:
                    client2.load_system_host_keys()
                except Exception:
                    pass
                if pannex_known_hosts.exists():
                    try:
                        client2.load_host_keys(str(pannex_known_hosts))
                    except Exception:
                        pass
                client2.set_missing_host_key_policy(paramiko.RejectPolicy())
                client2.connect(host, port=22, username=user, password=password, timeout=10)
                sftp = client2.open_sftp()
                sftp._ssh_client_ref = client2
                return sftp
            else:
                raise
        
        sftp = client.open_sftp()
        sftp._ssh_client_ref = client
        return sftp
    
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def _close_upload_connection(conn, protocol):
    """Cleanly close an upload connection."""
    protocol = protocol.upper()
    try:
        if protocol in ("FTP", "FTPS"):
            conn.quit()
        elif protocol == "SFTP":
            conn.close()
            if hasattr(conn, '_ssh_client_ref'):
                conn._ssh_client_ref.close()
            elif hasattr(conn, '_transport_ref'):
                conn._transport_ref.close()
    except Exception:
        pass


class FTPSettingsDialog(QDialog):
    """Dialog for configuring FTP/FTPS/SFTP connection and destinations"""
    
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("Upload Settings")
        self.setMinimumWidth(550)
        self.setMinimumHeight(550)
        self.config = config or load_config()
        
        layout = QVBoxLayout(self)
        
        # Connection settings group
        conn_group = QGroupBox("Connection")
        conn_layout = QFormLayout(conn_group)
        
        # Protocol selector
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["FTP", "FTPS", "SFTP"])
        current_protocol = self.config.get("upload_protocol", "FTP")
        idx = self.protocol_combo.findText(current_protocol)
        if idx >= 0:
            self.protocol_combo.setCurrentIndex(idx)
        self.protocol_combo.setToolTip(
            "FTP: Standard (unencrypted)\n"
            "FTPS: FTP over TLS (encrypted)\n"
            "SFTP: SSH File Transfer (encrypted, requires paramiko)"
        )
        conn_layout.addRow("Protocol:", self.protocol_combo)
        
        self.host_edit = QLineEdit(self.config.get("ftp_host", ""))
        self.host_edit.setPlaceholderText("ftp.example.com")
        conn_layout.addRow("Host:", self.host_edit)
        
        self.ftp_url_edit = QLineEdit(self.config.get("ftp_url", ""))
        self.ftp_url_edit.setPlaceholderText("https://ftp.example.com")
        self.ftp_url_edit.setToolTip("Base URL for uploaded files (used to construct clipboard URL)")
        conn_layout.addRow("URL:", self.ftp_url_edit)
        
        self.user_edit = QLineEdit(self.config.get("ftp_user", ""))
        self.user_edit.setPlaceholderText("username")
        conn_layout.addRow("Username:", self.user_edit)
        
        # Load password: try keyring first, fall back to base64 in config
        stored_pass = load_password(
            self.config.get("ftp_user", ""),
            self.config.get("ftp_pass_encoded", "")
        )
        self.pass_edit = QLineEdit(stored_pass)
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("password")
        conn_layout.addRow("Password:", self.pass_edit)
        
        # Keyring status hint
        if _keyring_available:
            kr_label = QLabel("🔒 Password secured by OS credential manager")
            kr_label.setStyleSheet("color: #888; font-size: 10px;")
            kr_label.setWordWrap(True)
            conn_layout.addRow("", kr_label)
        else:
            kr_label = QLabel("⚠ No secure credential storage available — password will not be saved between sessions")
            kr_label.setStyleSheet("color: #cc8800; font-size: 10px;")
            kr_label.setWordWrap(True)
            conn_layout.addRow("", kr_label)
        
        layout.addWidget(conn_group)
        
        # Connection buttons
        conn_btn_layout = QHBoxLayout()
        test_btn = QPushButton("Test Connection")
        test_btn.clicked.connect(self.test_connection)
        clear_conn_btn = QPushButton("Clear Connection")
        clear_conn_btn.clicked.connect(self.clear_connection)
        clear_conn_btn.setToolTip("Clear all FTP connection settings")
        conn_btn_layout.addWidget(test_btn)
        conn_btn_layout.addWidget(clear_conn_btn)
        conn_btn_layout.addStretch()
        layout.addLayout(conn_btn_layout)
        
        # Destinations group
        dest_group = QGroupBox("Destinations (Client Folders)")
        dest_layout = QVBoxLayout(dest_group)
        
        self.dest_list = QListWidget()
        for dest in self.config.get("destinations", []):
            item = QListWidgetItem(f"{dest['name']} → {dest['path']}")
            item.setData(Qt.ItemDataRole.UserRole, dest)
            self.dest_list.addItem(item)
        dest_layout.addWidget(self.dest_list)
        
        dest_btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_destination)
        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(self.edit_destination)
        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(self.remove_destination)
        dest_btn_layout.addWidget(add_btn)
        dest_btn_layout.addWidget(edit_btn)
        dest_btn_layout.addWidget(remove_btn)
        dest_btn_layout.addStretch()
        dest_layout.addLayout(dest_btn_layout)
        
        # Bulk import row
        bulk_btn_layout = QHBoxLayout()
        import_csv_btn = QPushButton("Import from CSV...")
        import_csv_btn.clicked.connect(self.import_from_csv)
        import_csv_btn.setToolTip("Import destinations from a CSV file (name,path)")
        export_btn = QPushButton("Export to CSV...")
        export_btn.clicked.connect(self.export_to_csv)
        export_btn.setToolTip("Export current destinations to a CSV file")
        bulk_btn_layout.addWidget(import_csv_btn)
        bulk_btn_layout.addWidget(export_btn)
        bulk_btn_layout.addStretch()
        dest_layout.addLayout(bulk_btn_layout)
        
        # Remember last folder checkbox
        self.remember_folder_checkbox = QCheckBox("Remember last folder per destination")
        self.remember_folder_checkbox.setChecked(self.config.get("remember_last_folder", True))
        self.remember_folder_checkbox.setToolTip("When enabled, each destination remembers the last folder you navigated to")
        dest_layout.addWidget(self.remember_folder_checkbox)
        
        layout.addWidget(dest_group)
        
        # Clipboard options group
        clipboard_group = QGroupBox("After Upload")
        clipboard_layout = QVBoxLayout(clipboard_group)
        
        self.copy_url_checkbox = QCheckBox("Copy URL to clipboard after upload")
        self.copy_url_checkbox.setChecked(self.config.get("copy_url_after_upload", True))
        clipboard_layout.addWidget(self.copy_url_checkbox)
        
        # Public URL prefix
        web_url_layout = QFormLayout()
        self.web_url_base_edit = QLineEdit(self.config.get("web_url_base", ""))
        self.web_url_base_edit.setPlaceholderText("https://yoursite.com/images/")
        self.web_url_base_edit.setToolTip("The uploaded filename is appended to this to build the public URL")
        web_url_layout.addRow("Public URL prefix:", self.web_url_base_edit)
        clipboard_layout.addLayout(web_url_layout)
        
        web_url_help = QLabel("The filename is appended to this prefix. Leave blank to use the FTP host.")
        web_url_help.setStyleSheet("color: #888; font-size: 10px;")
        web_url_help.setWordWrap(True)
        clipboard_layout.addWidget(web_url_help)
        
        # Clipboard format
        clipboard_layout.addSpacing(4)
        template_label = QLabel("Clipboard format:")
        clipboard_layout.addWidget(template_label)
        
        self.url_template_edit = QLineEdit(self.config.get("url_template", ""))
        self.url_template_edit.setPlaceholderText("{url}")
        clipboard_layout.addWidget(self.url_template_edit)
        
        template_help = QLabel("Use {url} for the full URL, or {path} for just the file path. Leave blank for the full URL.")
        template_help.setStyleSheet("color: #888; font-size: 10px;")
        template_help.setWordWrap(True)
        clipboard_layout.addWidget(template_help)
        
        layout.addWidget(clipboard_group)
        
        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.save_and_accept)
        button_box.rejected.connect(self.reject)
        button_box.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for btn in button_box.buttons():
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(button_box)
    
    def test_connection(self):
        """Test connection with current settings"""
        host = self.host_edit.text().strip()
        user = self.user_edit.text().strip()
        password = self.pass_edit.text()
        protocol = self.protocol_combo.currentText()
        
        if not host or not user:
            QMessageBox.warning(self, "Missing Info", "Please enter host and username.")
            return
        
        try:
            conn = _create_upload_connection(protocol, host, user, password, parent_widget=self)
            _close_upload_connection(conn, protocol)
            QMessageBox.information(self, "Success", f"{protocol} connection successful!")
        except Exception as e:
            QMessageBox.critical(self, "Connection Failed", f"Could not connect via {protocol}:\n{e}")
    
    def clear_connection(self):
        """Clear all connection settings"""
        reply = QMessageBox.question(
            self,
            "Clear Connection",
            "This will clear the host, URL, username, and password.\n\nAre you sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            # Remove password from keyring if stored
            old_user = self.user_edit.text().strip()
            if old_user:
                delete_password(old_user)
            self.host_edit.clear()
            self.ftp_url_edit.clear()
            self.user_edit.clear()
            self.pass_edit.clear()
    
    def add_destination(self):
        """Add a new destination"""
        name, ok1 = QInputDialog.getText(self, "Add Destination", "Client/Destination name:")
        if not ok1 or not name.strip():
            return
        
        path, ok2 = QInputDialog.getText(self, "Add Destination", "FTP folder path:", text="/")
        if not ok2:
            return
        
        dest = {"name": name.strip(), "path": path.strip() or "/"}
        item = QListWidgetItem(f"{dest['name']} → {dest['path']}")
        item.setData(Qt.ItemDataRole.UserRole, dest)
        self.dest_list.addItem(item)
    
    def edit_destination(self):
        """Edit selected destination"""
        current = self.dest_list.currentItem()
        if not current:
            return
        
        dest = current.data(Qt.ItemDataRole.UserRole)
        
        name, ok1 = QInputDialog.getText(self, "Edit Destination", "Client/Destination name:", text=dest["name"])
        if not ok1 or not name.strip():
            return
        
        path, ok2 = QInputDialog.getText(self, "Edit Destination", "FTP folder path:", text=dest["path"])
        if not ok2:
            return
        
        dest = {"name": name.strip(), "path": path.strip() or "/"}
        current.setText(f"{dest['name']} → {dest['path']}")
        current.setData(Qt.ItemDataRole.UserRole, dest)
    
    def remove_destination(self):
        """Remove selected destination"""
        current = self.dest_list.currentRow()
        if current >= 0:
            self.dest_list.takeItem(current)
    
    def save_and_accept(self):
        """Save config and close dialog"""
        # Gather destinations
        destinations = []
        for i in range(self.dest_list.count()):
            item = self.dest_list.item(i)
            destinations.append(item.data(Qt.ItemDataRole.UserRole))
        
        username = self.user_edit.text().strip()
        password = self.pass_edit.text()
        
        # Save password to keyring (returns "" if stored in keyring,
        # or base64 string if keyring unavailable)
        pass_for_config = save_password(username, password)
        
        # Update only the settings managed by this dialog
        self.config.update({
            "upload_protocol": self.protocol_combo.currentText(),
            "ftp_host": self.host_edit.text().strip(),
            "ftp_url": self.ftp_url_edit.text().strip(),
            "ftp_user": username,
            "ftp_pass_encoded": pass_for_config,
            "web_url_base": self.web_url_base_edit.text().strip(),
            "url_template": self.url_template_edit.text(),
            "destinations": destinations,
            "remember_last_folder": self.remember_folder_checkbox.isChecked(),
            "copy_url_after_upload": self.copy_url_checkbox.isChecked()
        })
        
        save_config(self.config)
        self.accept()
    
    def parse_destinations_text(self, text):
        """Parse text into destinations list. Format: name,path per line"""
        destinations = []
        for line in text.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):  # Skip empty lines and comments
                continue
            
            # Try comma-separated first, then tab-separated
            if ',' in line:
                parts = line.split(',', 1)
            elif '\t' in line:
                parts = line.split('\t', 1)
            else:
                continue  # Skip invalid lines
            
            if len(parts) >= 2:
                name = parts[0].strip().strip('"\'')
                path = parts[1].strip().strip('"\'')
                if name and path:
                    # Ensure path starts with /
                    if not path.startswith('/'):
                        path = '/' + path
                    destinations.append({"name": name, "path": path})
        
        return destinations
    
    def import_from_csv(self):
        """Import destinations from a CSV file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Destinations", "",
            "CSV Files (*.csv);;Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    text = f.read()
                
                new_dests = self.parse_destinations_text(text)
                
                if new_dests:
                    # Ask if they want to replace or append
                    if self.dest_list.count() > 0:
                        reply = QMessageBox.question(
                            self,
                            "Import Destinations",
                            f"Found {len(new_dests)} destinations.\n\nDo you want to replace existing destinations or add to them?",
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
                        )
                        reply_btn = reply
                        if reply_btn == QMessageBox.StandardButton.Cancel:
                            return
                        if reply_btn == QMessageBox.StandardButton.Yes:
                            # Replace - clear existing
                            self.dest_list.clear()
                    
                    # Add new destinations
                    for dest in new_dests:
                        item = QListWidgetItem(f"{dest['name']} → {dest['path']}")
                        item.setData(Qt.ItemDataRole.UserRole, dest)
                        self.dest_list.addItem(item)
                    
                    QMessageBox.information(self, "Import Complete", f"Imported {len(new_dests)} destinations.")
                else:
                    QMessageBox.warning(self, "Import Failed", "No valid destinations found in file.\n\nFormat should be: name,path (one per line)")
                    
            except Exception as e:
                QMessageBox.warning(self, "Import Error", f"Could not read file:\n{e}")
    
    def import_from_clipboard(self):
        """Import destinations from clipboard text"""
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        
        if not text.strip():
            QMessageBox.warning(self, "Empty Clipboard", "No text found in clipboard.\n\nCopy text in format: name,path (one per line)")
            return
        
        new_dests = self.parse_destinations_text(text)
        
        if new_dests:
            # Ask if they want to replace or append
            if self.dest_list.count() > 0:
                reply = QMessageBox.question(
                    self,
                    "Import Destinations",
                    f"Found {len(new_dests)} destinations in clipboard.\n\nYes = Replace existing\nNo = Add to existing",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
                )
                if reply == QMessageBox.StandardButton.Cancel:
                    return
                if reply == QMessageBox.StandardButton.Yes:
                    self.dest_list.clear()
            
            # Add new destinations
            for dest in new_dests:
                item = QListWidgetItem(f"{dest['name']} → {dest['path']}")
                item.setData(Qt.ItemDataRole.UserRole, dest)
                self.dest_list.addItem(item)
            
            QMessageBox.information(self, "Import Complete", f"Imported {len(new_dests)} destinations.")
        else:
            QMessageBox.warning(self, "Import Failed", "No valid destinations found in clipboard.\n\nFormat should be: name,path (one per line)")
    
    def export_to_csv(self):
        """Export current destinations to a CSV file"""
        if self.dest_list.count() == 0:
            QMessageBox.warning(self, "Nothing to Export", "No destinations to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Destinations", "destinations.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("# Destination Name, FTP Path\n")
                    for i in range(self.dest_list.count()):
                        item = self.dest_list.item(i)
                        dest = item.data(Qt.ItemDataRole.UserRole)
                        f.write(f"{dest['name']},{dest['path']}\n")
                
                QMessageBox.information(self, "Export Complete", f"Exported {self.dest_list.count()} destinations to:\n{file_path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Error", f"Could not write file:\n{e}")

# =========================================================
# FTP Upload Dialog
# =========================================================

class _NetworkWorker(QThread):
    """Run a callable off the UI thread; emit result or error."""
    finished = pyqtSignal(object)   # result on success
    errored = pyqtSignal(str)       # error message on failure

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            result = self._fn()
            self.finished.emit(result)
        except Exception as e:
            self.errored.emit(str(e))


class _SFTPConnectWorker(QThread):
    """Connect via SFTP in background; pause for host-key trust if needed."""
    finished = pyqtSignal(object)       # connected SFTPClient
    errored = pyqtSignal(str)           # error message
    host_key_prompt = pyqtSignal(str, str, str)  # host, key_type, fingerprint

    def __init__(self, host, user, password, parent=None):
        super().__init__(parent)
        self._host = host
        self._user = user
        self._password = password
        # Threading event — worker waits on this while UI shows the dialog
        import threading
        self._trust_event = threading.Event()
        self._trust_accepted = False

    def accept_host_key(self):
        """Called from main thread when user accepts the key."""
        self._trust_accepted = True
        self._trust_event.set()

    def reject_host_key(self):
        """Called from main thread when user rejects the key."""
        self._trust_accepted = False
        self._trust_event.set()

    def run(self):
        try:
            import paramiko
        except ImportError:
            self.errored.emit(
                "SFTP requires the 'paramiko' package.\n\n"
                "Install it with:  pip install paramiko"
            )
            return

        host = self._host
        pannex_known_hosts = get_config_dir() / "known_hosts"

        def _make_client():
            client = paramiko.SSHClient()
            try:
                client.load_system_host_keys()
            except Exception:
                pass
            if pannex_known_hosts.exists():
                try:
                    client.load_host_keys(str(pannex_known_hosts))
                except Exception:
                    pass
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            return client

        try:
            client = _make_client()
            try:
                client.connect(host, port=22, username=self._user,
                               password=self._password, timeout=10)
            except paramiko.SSHException as e:
                if "not found in known_hosts" not in str(e) and "Server" not in str(e):
                    raise

                # Unknown host key — fetch it and ask the UI thread
                try:
                    transport = paramiko.Transport((host, 22))
                    transport.connect()
                    host_key = transport.get_remote_server_key()
                    transport.close()
                except Exception:
                    self.errored.emit(
                        f"Cannot retrieve SSH host key for '{host}'.\n"
                        "Check the hostname and try again."
                    )
                    return

                key_type = host_key.get_name()
                fingerprint = ":".join(f"{b:02x}" for b in host_key.get_fingerprint())

                # Signal main thread and wait
                self.host_key_prompt.emit(host, key_type, fingerprint)
                self._trust_event.wait()

                if not self._trust_accepted:
                    self.errored.emit("Connection cancelled — host key not trusted.")
                    return

                # Save the accepted key
                try:
                    pannex_known_hosts.parent.mkdir(parents=True, exist_ok=True)
                    host_keys = paramiko.HostKeys()
                    if pannex_known_hosts.exists():
                        host_keys.load(str(pannex_known_hosts))
                    host_keys.add(host, key_type, host_key)
                    host_keys.save(str(pannex_known_hosts))
                except Exception:
                    pass

                # Retry with the now-trusted key
                client = _make_client()
                client.connect(host, port=22, username=self._user,
                               password=self._password, timeout=10)

            sftp = client.open_sftp()
            sftp._ssh_client_ref = client
            self.finished.emit(sftp)

        except Exception as e:
            self.errored.emit(str(e))


class FTPUploadDialog(QDialog):
    """Dialog for publishing image to FTP"""
    
    def __init__(self, parent=None, config=None, destination_name=None):
        super().__init__(parent)
        self.setWindowTitle("Upload to FTP")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)
        self.config = config or load_config()
        self.ftp = None
        self._network_busy = False
        self.current_path = "/"
        self.current_destination_name = destination_name
        self.destination_base_path = "/"  # Can't navigate above this
        self.current_files = []  # List of files in current directory
        
        # Navigation history
        self.history_back = []
        self.history_forward = []
        
        layout = QVBoxLayout(self)
        
        # Destination dropdown
        dest_layout = QHBoxLayout()
        dest_layout.addWidget(QLabel("Destination:"))
        self.dest_combo = QComboBox()
        self.dest_combo.addItem("Browse...", None)
        for dest in self.config.get("destinations", []):
            self.dest_combo.addItem(dest["name"], dest)
        
        # Select specified destination or last used
        target_dest = destination_name or self.config.get("last_destination", "")
        for i in range(self.dest_combo.count()):
            data = self.dest_combo.itemData(i)
            if data and data.get("name") == target_dest:
                self.dest_combo.setCurrentIndex(i)
                break
        
        self.dest_combo.currentIndexChanged.connect(self.on_destination_changed)
        dest_layout.addWidget(self.dest_combo, 1)
        
        settings_btn = QPushButton("⚙")
        settings_btn.setFixedWidth(30)
        settings_btn.setToolTip("FTP Settings")
        settings_btn.clicked.connect(self.open_settings)
        dest_layout.addWidget(settings_btn)
        
        layout.addLayout(dest_layout)
        
        # Navigation buttons and path display
        path_layout = QHBoxLayout()
        
        # Back button
        self.back_btn = QPushButton("◀")
        self.back_btn.setFixedWidth(30)
        self.back_btn.setToolTip("Go back")
        self.back_btn.clicked.connect(self.go_back)
        self.back_btn.setEnabled(False)
        path_layout.addWidget(self.back_btn)
        
        # Forward button
        self.forward_btn = QPushButton("▶")
        self.forward_btn.setFixedWidth(30)
        self.forward_btn.setToolTip("Go forward")
        self.forward_btn.clicked.connect(self.go_forward)
        self.forward_btn.setEnabled(False)
        path_layout.addWidget(self.forward_btn)
        
        # Up button
        self.folder_up_btn = QPushButton("⬆")
        self.folder_up_btn.setFixedWidth(30)
        self.folder_up_btn.setToolTip("Go up one folder")
        self.folder_up_btn.clicked.connect(self.go_folder_up)
        path_layout.addWidget(self.folder_up_btn)
        
        # New folder button
        self.new_folder_btn = QPushButton("📁+")
        self.new_folder_btn.setFixedWidth(35)
        self.new_folder_btn.setToolTip("Create new folder")
        self.new_folder_btn.clicked.connect(self.create_new_folder)
        path_layout.addWidget(self.new_folder_btn)
        
        path_layout.addWidget(QLabel("Path:"))
        self.path_label = QLabel("/")
        self.path_label.setStyleSheet("color: #888; padding: 4px;")
        path_layout.addWidget(self.path_label, 1)
        layout.addLayout(path_layout)
        
        # Folder/file browser
        self.folder_list = QListWidget()
        self.folder_list.itemDoubleClicked.connect(self.on_item_double_click)
        self.folder_list.itemClicked.connect(self.on_item_clicked)
        layout.addWidget(self.folder_list)
        
        # Filename
        filename_layout = QHBoxLayout()
        filename_layout.addWidget(QLabel("Filename:"))
        from datetime import datetime
        default_name = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        self.filename_edit = QLineEdit(default_name)
        filename_layout.addWidget(self.filename_edit, 1)
        layout.addLayout(filename_layout)
        
        # Copy URL checkbox
        self.copy_url_checkbox = QCheckBox("Copy URL to clipboard")
        self.copy_url_checkbox.setChecked(self.config.get("copy_url_after_upload", True))
        layout.addWidget(self.copy_url_checkbox)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #888;")
        layout.addWidget(self.status_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.upload_btn = QPushButton("Upload")
        self.upload_btn.clicked.connect(self.do_upload)
        self.upload_btn.setDefault(True)  # Make Upload the default button (triggered by Enter)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(self.upload_btn)
        layout.addLayout(button_layout)
        
        # Initialize
        self.uploaded_url = None
        self.check_config()
        
        # Set focus to filename field and select all text for easy editing
        self.filename_edit.setFocus()
        self.filename_edit.selectAll()
    
    def check_config(self):
        """Check if FTP is configured"""
        if not self.config.get("ftp_host"):
            self.status_label.setText("⚠ FTP not configured - click ⚙ to set up")
            self.upload_btn.setEnabled(False)
            self.folder_list.setEnabled(False)
            self.folder_up_btn.setEnabled(False)
            self.back_btn.setEnabled(False)
            self.forward_btn.setEnabled(False)
            self.new_folder_btn.setEnabled(False)
        else:
            self.connect_ftp()
    
    def _set_ui_busy(self, busy):
        """Disable or enable all interactive controls during network operations."""
        enabled = not busy
        self.dest_combo.setEnabled(enabled)
        self.folder_list.setEnabled(enabled)
        self.upload_btn.setEnabled(enabled)
        self.filename_edit.setEnabled(enabled)
        self.new_folder_btn.setEnabled(enabled)
        if busy:
            self.back_btn.setEnabled(False)
            self.forward_btn.setEnabled(False)
            self.folder_up_btn.setEnabled(False)
        else:
            self.update_nav_buttons()

    def connect_ftp(self):
        """Connect to server using configured protocol (threaded)"""
        if self._network_busy:
            return
        self._network_busy = True
        self.status_label.setText("Connecting...")
        self._set_ui_busy(True)

        protocol = self.config.get("upload_protocol", "FTP")
        host = self.config["ftp_host"]
        user = self.config["ftp_user"]
        password = load_password(user, self.config.get("ftp_pass_encoded", ""))

        if protocol == "SFTP":
            worker = _SFTPConnectWorker(host, user, password, self)
            worker.finished.connect(lambda conn: self._on_connected(conn, protocol))
            worker.errored.connect(self._on_connect_error)
            worker.host_key_prompt.connect(self._on_sftp_host_key_prompt)
            self._connect_worker = worker
            worker.start()
        else:
            def do_connect():
                return _create_upload_connection(protocol, host, user, password)
            worker = _NetworkWorker(do_connect, self)
            worker.finished.connect(lambda conn: self._on_connected(conn, protocol))
            worker.errored.connect(self._on_connect_error)
            self._connect_worker = worker
            worker.start()

    def _on_sftp_host_key_prompt(self, host, key_type, fingerprint):
        """Show host-key trust dialog on the main thread."""
        reply = QMessageBox.question(
            self,
            "Unknown SSH Host Key",
            f"The server '{host}' presented an unknown host key.\n\n"
            f"Type: {key_type}\n"
            f"Fingerprint: {fingerprint}\n\n"
            "Do you want to trust this key and continue?\n"
            "(The key will be saved for future connections.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        worker = self._connect_worker
        if isinstance(worker, _SFTPConnectWorker):
            if reply == QMessageBox.StandardButton.Yes:
                worker.accept_host_key()
            else:
                worker.reject_host_key()

    def _on_connected(self, conn, protocol):
        """Handle successful connection (runs on UI thread)."""
        self._network_busy = False
        self.ftp = conn
        self._upload_protocol = protocol
        self.status_label.setText(f"Connected ({protocol})")
        self._set_ui_busy(False)

        if self.dest_combo.currentIndex() > 0:
            self.on_destination_changed(self.dest_combo.currentIndex())
        else:
            self.destination_base_path = "/"
            self.browse_path("/", add_to_history=False)

    def _on_connect_error(self, message):
        """Handle connection failure (runs on UI thread)."""
        self._network_busy = False
        self.status_label.setText(f"Connection failed: {message}")
        self._set_ui_busy(False)
        # Keep upload-related controls disabled since we're not connected
        self.upload_btn.setEnabled(False)
        self.folder_list.setEnabled(False)
    
    def browse_path(self, path, add_to_history=True):
        """Browse to a path and list contents (FTP/FTPS/SFTP) — threaded"""
        if not self.ftp or self._network_busy:
            return
        self._network_busy = True
        self._set_ui_busy(True)
        self.status_label.setText("Loading...")
        protocol = getattr(self, '_upload_protocol', 'FTP')
        ftp = self.ftp

        def do_browse():
            if protocol == "SFTP":
                ftp.chdir(path)
                resolved = ftp.normalize(".")
            else:
                ftp.cwd(path)
                resolved = ftp.pwd()

            folders = []
            files = []
            if protocol == "SFTP":
                import stat
                for attr in ftp.listdir_attr("."):
                    name = attr.filename
                    if name in ('.', '..'):
                        continue
                    if stat.S_ISDIR(attr.st_mode):
                        folders.append(name)
                    else:
                        files.append(name)
            else:
                items = []
                ftp.retrlines('LIST', lambda x: items.append(x))
                for item_str in items:
                    parts = item_str.split()
                    if len(parts) >= 9:
                        name = " ".join(parts[8:])
                        is_dir = item_str.startswith('d')
                        if name in ('.', '..'):
                            continue
                        if is_dir:
                            folders.append(name)
                        else:
                            files.append(name)
            return {"resolved": resolved, "folders": folders, "files": files}

        def on_success(result):
            old_path = self.current_path
            self.current_path = result["resolved"]
            self.path_label.setText(self.current_path)

            if add_to_history and old_path != self.current_path:
                self.history_back.append(old_path)
                self.history_forward.clear()

            self.update_nav_buttons()
            self.folder_list.clear()
            self.current_files = []

            for name in sorted(result["folders"]):
                item = QListWidgetItem(f"📁 {name}")
                item.setData(Qt.ItemDataRole.UserRole, ("folder", name))
                self.folder_list.addItem(item)

            for name in sorted(result["files"]):
                lower_name = name.lower()
                if lower_name.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp')):
                    icon = "🖼"
                else:
                    icon = "📄"
                item = QListWidgetItem(f"{icon} {name}")
                item.setData(Qt.ItemDataRole.UserRole, ("file", name))
                self.folder_list.addItem(item)
                self.current_files.append(name)

            self._network_busy = False
            self._set_ui_busy(False)
            self.status_label.setText(f"Connected ({protocol})")

        def on_error(msg):
            self._network_busy = False
            self._set_ui_busy(False)
            self.status_label.setText(f"Browse failed: {msg}")

        worker = _NetworkWorker(do_browse, self)
        worker.finished.connect(on_success)
        worker.errored.connect(on_error)
        self._browse_worker = worker
        worker.start()
    
    def update_nav_buttons(self):
        """Update navigation button enabled states"""
        # Back button
        self.back_btn.setEnabled(len(self.history_back) > 0)
        
        # Forward button
        self.forward_btn.setEnabled(len(self.history_forward) > 0)
        
        # Up button - disabled if at destination base path or root
        can_go_up = (self.current_path != "/" and 
                     self.current_path != self.destination_base_path and
                     self.current_path.startswith(self.destination_base_path))
        self.folder_up_btn.setEnabled(can_go_up)
    
    def go_back(self):
        """Navigate back in history"""
        if self.history_back:
            self.history_forward.append(self.current_path)
            path = self.history_back.pop()
            self.browse_path(path, add_to_history=False)
    
    def go_forward(self):
        """Navigate forward in history"""
        if self.history_forward:
            self.history_back.append(self.current_path)
            path = self.history_forward.pop()
            self.browse_path(path, add_to_history=False)
    
    def go_folder_up(self):
        """Navigate up one folder (but not above destination base)"""
        if self.current_path != "/" and self.current_path != self.destination_base_path:
            parent = "/".join(self.current_path.rstrip("/").split("/")[:-1]) or "/"
            # Don't go above destination base path
            if parent.startswith(self.destination_base_path.rstrip("/")) or self.destination_base_path == "/":
                self.browse_path(parent)
    
    def create_new_folder(self):
        """Create a new folder in the current directory"""
        if not self.ftp:
            return
        
        folder_name, ok = QInputDialog.getText(
            self, 
            "New Folder", 
            "Enter folder name:"
        )
        
        if ok and folder_name.strip():
            folder_name = folder_name.strip()
            # Remove any invalid characters
            folder_name = folder_name.replace("/", "").replace("\\", "")
            
            if not folder_name:
                QMessageBox.warning(self, "Invalid Name", "Please enter a valid folder name.")
                return
            
            try:
                new_path = self.current_path.rstrip("/") + "/" + folder_name
                protocol = getattr(self, '_upload_protocol', 'FTP')
                if protocol == "SFTP":
                    self.ftp.mkdir(new_path)
                else:
                    self.ftp.mkd(new_path)
                self.status_label.setText(f"Created folder: {folder_name}")
                # Refresh current directory and navigate into the new folder
                self.browse_path(new_path)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not create folder:\n{e}")
    
    def on_item_double_click(self, item):
        """Navigate into folder on double-click, or select file"""
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            item_type, name = data
            if item_type == "folder":
                self.browse_path(self.current_path.rstrip("/") + "/" + name)
            elif item_type == "file":
                # Double-click on file sets it as filename
                self.filename_edit.setText(name)
    
    def on_item_clicked(self, item):
        """Single click on file sets filename"""
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            item_type, name = data
            if item_type == "file":
                self.filename_edit.setText(name)
    
    def on_destination_changed(self, index):
        """Handle destination selection"""
        dest = self.dest_combo.itemData(index)
        if dest:
            self.current_destination_name = dest["name"]
            self.destination_base_path = dest["path"]
            
            # Clear history when changing destinations
            self.history_back.clear()
            self.history_forward.clear()
            
            # Check if we should use remembered path
            if self.config.get("remember_last_folder", True):
                last_paths = self.config.get("destination_last_paths", {})
                remembered_path = last_paths.get(dest["name"])
                if remembered_path:
                    # Try to navigate to remembered path, fall back to base path
                    try:
                        self.browse_path(remembered_path, add_to_history=False)
                    except:
                        self.browse_path(dest["path"], add_to_history=False)
                else:
                    self.browse_path(dest["path"], add_to_history=False)
            else:
                # Always start at destination base path
                self.browse_path(dest["path"], add_to_history=False)
        else:
            # Browse mode - can go anywhere
            self.destination_base_path = "/"
            self.history_back.clear()
            self.history_forward.clear()
    
    def open_settings(self):
        """Open settings dialog"""
        dialog = FTPSettingsDialog(self, self.config)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.config = dialog.config
            self.check_config()
            
            # Refresh destinations dropdown
            self.dest_combo.clear()
            self.dest_combo.addItem("Browse...", None)
            for dest in self.config.get("destinations", []):
                self.dest_combo.addItem(dest["name"], dest)
    
    def do_upload(self):
        """Upload the image via FTP/FTPS/SFTP — threaded"""
        if not self.ftp or self._network_busy:
            return
        
        filename = self.filename_edit.text().strip()
        if not filename:
            QMessageBox.warning(self, "Missing Filename", "Please enter a filename.")
            return
        
        # Sanitize: strip any path components to prevent directory traversal
        filename = os.path.basename(filename)
        if not filename:
            QMessageBox.warning(self, "Invalid Filename", "Please enter a valid filename.")
            return
        
        # Ensure .png extension
        if not filename.lower().endswith('.png'):
            filename += '.png'
        
        # Check if file already exists
        if filename in self.current_files:
            reply = QMessageBox.question(
                self, 
                "File Exists",
                f"'{filename}' already exists in this folder.\n\nDo you want to overwrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        self.status_label.setText("Uploading...")
        self._network_busy = True
        self._set_ui_busy(True)
        
        # Prepare buffer on UI thread (needs parent.viewer.image)
        parent = self.parent()
        if not parent or not parent.viewer.image:
            self._network_busy = False
            self._set_ui_busy(False)
            self.status_label.setText("No image to upload")
            return
        
        buffer = BytesIO()
        parent.viewer.image.save(buffer, "PNG")
        buffer.seek(0)
        
        protocol = getattr(self, '_upload_protocol', 'FTP')
        remote_path = self.current_path.rstrip("/") + "/" + filename
        ftp = self.ftp

        def do_transfer():
            if protocol == "SFTP":
                ftp.putfo(buffer, remote_path)
            else:
                ftp.storbinary(f"STOR {filename}", buffer)
            return remote_path

        def on_success(rpath):
            # Construct the file path
            path_part = rpath
            
            # Construct full URL
            web_url_base = self.config.get("web_url_base", "").strip().rstrip("/")
            if not web_url_base:
                ftp_url = self.config.get("ftp_url", "").strip().rstrip("/")
                if ftp_url:
                    web_url_base = ftp_url
                else:
                    ftp_host = self.config.get("ftp_host", "").strip()
                    web_url_base = f"https://{ftp_host}" if ftp_host else ""
            self.uploaded_url = f"{web_url_base}{path_part}"
            
            # Copy to clipboard if requested
            if self.copy_url_checkbox.isChecked():
                url_template = self.config.get("url_template", "").strip()
                if url_template:
                    clipboard_text = url_template.replace("{url}", self.uploaded_url).replace("{path}", path_part)
                else:
                    clipboard_text = self.uploaded_url
                QApplication.clipboard().setText(clipboard_text)
            
            # Remember last destination and the full path used
            if self.current_destination_name:
                self.config["last_destination"] = self.current_destination_name
                if "destination_last_paths" not in self.config:
                    self.config["destination_last_paths"] = {}
                self.config["destination_last_paths"][self.current_destination_name] = self.current_path
                save_config(self.config)
            
            self.status_label.setText(f"✓ Uploaded successfully!")
            
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(1000, self.accept)

        def on_error(msg):
            self._network_busy = False
            self._set_ui_busy(False)
            self.status_label.setText(f"Upload failed: {msg}")

        worker = _NetworkWorker(do_transfer, self)
        worker.finished.connect(on_success)
        worker.errored.connect(on_error)
        self._upload_worker = worker
        worker.start()
    
    def _stop_workers(self):
        """Wait for any active network workers to finish."""
        for attr in ('_connect_worker', '_browse_worker', '_upload_worker'):
            worker = getattr(self, attr, None)
            if worker is not None and worker.isRunning():
                worker.wait(3000)  # wait up to 3 seconds
                if worker.isRunning():
                    worker.terminate()
                    worker.wait(1000)

    def closeEvent(self, event):
        """Clean up workers and connection"""
        self._stop_workers()
        if self.ftp:
            try:
                protocol = getattr(self, '_upload_protocol', 'FTP')
                _close_upload_connection(self.ftp, protocol)
            except Exception:
                pass
        super().closeEvent(event)

# =========================================================
# Main Window
# =========================================================

class CutoutTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Magpie v{APP_VERSION}")
        self.resize(1200, 850)
        self.setAcceptDrops(True)  # Enable drag-and-drop file opening

        self.active_tool = None  # Start with no tool selected
        self.viewer = ImageViewer()
        self.current_path = None
        
        # Default save directory - Pictures folder, remembered within session only
        _pictures = os.path.join(str(Path.home()), "Pictures")
        if not os.path.isdir(_pictures):
            _pictures = str(Path.home())
        self._session_save_dir = _pictures

        # Default freehand mode (used by pen/brush/eraser/spray/flood/color eraser)
        self.freehand_mode = 'pen'
        
        # Previous image snapshot (for "Restore Previous" feature)
        self.previous_image_snapshot = None  # Stores (image_copy, path, undo_stack)
        
        # Session preference for large images
        self.session_large_image_preference = None  # "resize" or "keep" for this session

        # Eyedropper (pick color from canvas) state
        self._eyedropper_active = False
        self._eyedropper_dialog = None
        self._eyedropper_restore_modality = None
        self._eyedropper_restore_modal = None
        self._eyedropper_button = None  # Track which button is being picked for
        self._eyedropper_spinner_angle = 0
        
        # Spinner timer for eyedropper animation
        from PyQt6.QtCore import QTimer
        self._eyedropper_timer = QTimer(self)
        self._eyedropper_timer.timeout.connect(self._update_eyedropper_spinner)
        self._eyedropper_timer.setInterval(50)  # 20 FPS
        
        # Crosshair state (magnifier)
        self.crosshair_enabled = False
        self.crosshair_pixel_scale = 8  # Fixed magnification level (constant)
        self.crosshair_size = 140  # Size of crosshair circle in pixels (dynamic with Alt+Wheel)
        
        # Guide lines state (ruler-style crosshair lines)
        self.guide_lines_enabled = False
        
        # Pixel grid state (gridlines between pixels at high zoom)
        self.pixel_grid_enabled = False
        
        # Dark mode detection (from saved preference or system palette)
        config = load_config()
        theme_mode = config.get("theme_mode", "system")
        if theme_mode == "dark":
            self._is_dark_mode = True
        elif theme_mode == "light":
            self._is_dark_mode = False
        else:
            palette = QApplication.instance().palette()
            self._is_dark_mode = palette.color(palette.ColorRole.Window).lightness() < 128
        
        # Remember last blank image size
        self.last_blank_width = 800
        self.last_blank_height = 600
        
        # Track whether a source is loaded
        self.source_loaded = False
        
        # Track unsaved changes
        self.has_unsaved_changes = False
        self.original_image_hash = None  # To detect if image was modified
        
        # Toolbar visibility state
        self.toolbar_visible = True  # Toolbar visible by default
        self._transform_updating = False  # Guard for transform spinbox cross-updates
        self._transform_aspect = 1.0  # Aspect ratio for locked resize

        # ============== Menu Bar ==============
        self.create_menu_bar()

        main = QWidget()
        self.setCentralWidget(main)
        root = QVBoxLayout(main)

        # ---------------- Row 1: Global ----------------
        global_bar = QHBoxLayout()

        # Set as Image button (crops canvas to pasted content)
        self.btn_crop_canvas = QPushButton("Set as Image")
        self.btn_crop_canvas.setToolTip("Set pasted content as the new image")
        self.btn_crop_canvas.clicked.connect(self.crop_to_content)
        self.btn_crop_canvas.setEnabled(False)  # Initially disabled
        self.btn_crop_canvas.setMinimumHeight(28)

        # Undo/Redo section
        self.btn_undo = QPushButton()
        self.btn_undo.setToolTip("Undo (Ctrl+Z)")
        self.btn_undo.setFixedSize(30, 28)
        self.btn_undo.clicked.connect(self.viewer.undo)
        self.btn_undo.setEnabled(False)

        self.btn_redo = QPushButton()
        self.btn_redo.setToolTip("Redo (Ctrl+Y)")
        self.btn_redo.setFixedSize(30, 28)
        self.btn_redo.clicked.connect(self.viewer.redo)
        self.btn_redo.setEnabled(False)

        # Zoom section
        zoom_label = QLabel("Zoom:")
        
        self._bar_btn_zoom_out = QPushButton()
        self._bar_btn_zoom_out.setToolTip("Zoom Out")
        self._bar_btn_zoom_out.setFixedSize(30, 28)
        self._bar_btn_zoom_out.clicked.connect(self.zoom_out)

        self._bar_btn_zoom_in = QPushButton()
        self._bar_btn_zoom_in.setToolTip("Zoom In")
        self._bar_btn_zoom_in.setFixedSize(30, 28)
        self._bar_btn_zoom_in.clicked.connect(self.zoom_in)

        # Zoom percentage dropdown
        self.zoom_combo = QComboBox()
        self.zoom_combo.addItems(["25%", "50%", "75%", "100%", "125%", "150%", "200%", "300%", "400%", "500%", "600%", "800%", "1000%"])
        self.zoom_combo.setCurrentText("100%")
        self.zoom_combo.setEditable(True)
        self.zoom_combo.setMinimumHeight(28)
        self.zoom_combo.currentTextChanged.connect(self.zoom_combo_changed)
        # Override wheel event so scrolling over the combo matches canvas zoom direction
        def _zoom_combo_wheel(e):
            if e.angleDelta().y() > 0:
                self.zoom_in()
            else:
                self.zoom_out()
            e.accept()
        self.zoom_combo.wheelEvent = _zoom_combo_wheel

        # Output section
        self._bar_btn_new = QPushButton("New")
        self._bar_btn_new.setToolTip("New blank image")
        self._bar_btn_new.setMinimumHeight(34)
        self._bar_btn_new.clicked.connect(self.new_blank_image)

        self._bar_btn_copy = QPushButton("Copy")
        self._bar_btn_copy.setToolTip("Copy to clipboard (Ctrl+C)")
        self._bar_btn_copy.setMinimumHeight(34)
        self._bar_btn_copy.clicked.connect(self.copy)

        self._bar_btn_save = QPushButton("Save")
        self._bar_btn_save.setToolTip("Save (Ctrl+S)")
        self._bar_btn_save.setMinimumHeight(34)
        self._bar_btn_save.clicked.connect(self.save)

        self._bar_btn_save_as = QPushButton("Save As")
        self._bar_btn_save_as.setToolTip("Save As (Ctrl+Shift+S)")
        self._bar_btn_save_as.setMinimumHeight(34)
        self._bar_btn_save_as.clicked.connect(self.save_as)

        # Apply custom SVG icons to bar buttons if available
        self._bar_icon_map = {
            "undo": self.btn_undo,
            "redo": self.btn_redo,
            "minus": self._bar_btn_zoom_out,
            "plus": self._bar_btn_zoom_in,
            "new": self._bar_btn_new,
            "copy": self._bar_btn_copy,
            "save": self._bar_btn_save,
            "saveas": self._bar_btn_save_as,
        }
        self._refresh_bar_icons()

        # Upload button (opens FTP upload dialog)
        self.btn_publish = QPushButton("Upload")
        self.btn_publish.setToolTip("Upload to FTP server")
        self.btn_publish.setMinimumHeight(34)
        self.btn_publish.clicked.connect(self.publish)
        self._bar_icon_map["ftp"] = self.btn_publish
        self._refresh_bar_icons()

        # Toolbox selector (hidden — kept for internal tool sync)
        self.tool_combo = ToolboxComboBox()
        self.tool_combo.setMinimumWidth(140)
        # Populate from config (will add "Select tool" and all configured tools)
        self.update_toolbox_dropdown()
        self.tool_combo.currentIndexChanged.connect(self.on_tool_combo_changed)
        # Not added to layout — tools are selected via sidebar and Tools menu
        self.tool_combo.setVisible(False)
        
        global_bar.addWidget(self._bar_btn_new)
        global_bar.addWidget(self._bar_btn_copy)
        global_bar.addWidget(self._bar_btn_save)
        global_bar.addWidget(self._bar_btn_save_as)
        global_bar.addWidget(self.btn_publish)
        
        # Apply button visibility from config (hidden by default)
        config = load_config()
        self.btn_publish.setVisible(config.get("ftp_button_visible", False))
        
        global_bar.addSpacing(20)
        
        global_bar.addWidget(self.btn_crop_canvas)
        
        global_bar.addSpacing(20)  # Space before undo/redo
        
        global_bar.addWidget(self.btn_undo)
        global_bar.addWidget(self.btn_redo)

        global_bar.addSpacing(20)  # Space before zoom
        
        global_bar.addWidget(zoom_label)
        global_bar.addWidget(self._bar_btn_zoom_out)
        global_bar.addWidget(self._bar_btn_zoom_in)
        global_bar.addWidget(self.zoom_combo)
        
        global_bar.addSpacing(20)  # Space before color palette
        
        # Color selector will be inserted here after it's built
        self._global_bar = global_bar
        self._global_bar_stretch = None  # placeholder for addStretch

        root.addLayout(global_bar)
        
        # Add horizontal separator line
        self.toolbar_separator1 = QWidget()
        self.toolbar_separator1.setFixedHeight(1)
        self.toolbar_separator1.setStyleSheet("background-color: #555;" if self._is_dark_mode else "background-color: #808080;")
        root.addWidget(self.toolbar_separator1)
        
        # ---------------- Toolbar (vertical sidebar using QToolBar) ----------------
        from PyQt6.QtWidgets import QToolBar, QToolButton
        from PyQt6.QtGui import QAction, QActionGroup
        
        self.toolbar_widget = QToolBar()
        self.toolbar_widget.setOrientation(Qt.Orientation.Vertical)
        self.toolbar_widget.setMovable(False)
        self.toolbar_widget.setFloatable(False)
        self.toolbar_widget.setIconSize(QSize(28, 28))
        self.toolbar_widget.setFixedWidth(44)
        self.toolbar_widget.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        self.toolbar_widget.setContentsMargins(0, 0, 0, 0)
        
        if self._is_dark_mode:
            self.toolbar_widget.setStyleSheet("""
                QToolBar { background-color: #2d2d2d; border-right: 1px solid #555; spacing: 0px; padding: 4px 2px 0px 2px; margin: 0px; }
                QToolButton { min-width: 36px; max-width: 36px; min-height: 36px; max-height: 36px; border: 1px solid transparent; border-radius: 4px; padding: 0px; margin: 1px 0px; background-color: transparent; }
                QToolButton:hover { background-color: #444; border: 1px solid #666; }
                QToolButton:checked { background-color: #3a4570; border: 2px solid #6a6adc; }
                QToolBar::separator { height: 2px; margin: 3px 4px; background-color: #555; }
            """)
        else:
            self.toolbar_widget.setStyleSheet("""
                QToolBar { background-color: #f0f0f0; border-right: 1px solid #808080; spacing: 0px; padding: 4px 2px 0px 2px; margin: 0px; }
                QToolButton { min-width: 36px; max-width: 36px; min-height: 36px; max-height: 36px; border: 1px solid transparent; border-radius: 4px; padding: 0px; margin: 1px 0px; background-color: transparent; }
                QToolButton:hover { background-color: #e0e0e0; border: 1px solid #aaa; }
                QToolButton:checked { background-color: #d0d8ff; border: 2px solid #5050d0; }
                QToolBar::separator { height: 2px; margin: 3px 4px; background-color: #606060; }
            """)
        
        self._toolbar_action_group = QActionGroup(self)
        self._toolbar_action_group.setExclusive(True)
        
        # Tool definitions (id -> tooltip)
        self.toolbar_tool_definitions = {
            "arrow": "Arrow",
            "blur": "Blur",
            "color_light": "Color & Light",
            "crop": "Crop",
            "cutout": "Cut Out",
            "cutpaste": "Cut/Paste",
            "freehand": "Freehand",
            "highlight": "Highlight",
            "line": "Line",
            "magnify_inset": "Magnify Inset",
            "step_marker": "Step Marker",
            "oval": "Oval",
            "outline": "Outline",
            "pixelate": "Pixelate",
            "rectangle": "Rectangle",
            "remove_space": "Remove Space",
            "text": "Text",
            "transform": "Transform",
        }
        
        # Build toolbar from config
        self.tool_buttons = {}
        self._populate_toolbar()
        
        # No separator needed - toolbar is now a sidebar

        # ---------------- Row 2: Tools ----------------
        # ---------------- Row 2: Tool options + Global colors ----------------
        self.tool_bar_layout = QHBoxLayout()  # Store reference for rebuild_palette
        
        # Tool options will be shown in a stacked widget inline
        self.tool_stack = QStackedWidget()
        self.tool_stack.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.tool_bar_layout.addWidget(self.tool_stack, 1)  # stretch factor 1 - takes available space
        
        # Second row for overflow tool options (auto-shows when tool has row 2)
        self.tool_stack_row2 = QStackedWidget()
        self.tool_stack_row2.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.tool_stack_row2.setVisible(False)  # Hidden by default
        # ---- Global color selector (Paint-style) ----
        # Primary = used by most tools; Secondary = rectangle/oval fill + text outline.
        self.primary_color = (0, 0, 0, 255)       # black
        self.secondary_color = (255, 255, 255, 255)  # white
        # Back-compat: some legacy code paths (e.g., Color Eraser) still reference a
        # stored "target color". With the global selector, use Primary as that target.
        self.selected_freehand_color = (self.primary_color[0], self.primary_color[1], self.primary_color[2])
        self._active_color_slot = "primary"  # which slot the palette edits

        self._global_palette = self.load_palette_from_config()

        self._color_selector_widget = self._build_global_color_selector()
        self._bar_icon_map["custom"] = self._custom_color_btn
        self._bar_icon_map["picker"] = self._eyedropper_indicator
        self._refresh_bar_icons()
        self._global_bar.addWidget(self._color_selector_widget)
        self._global_bar.addStretch()  # Push everything to the left
        
        # Empty panel for "Select tool" placeholder
        empty_panel = QWidget()
        empty_layout = QHBoxLayout(empty_panel)
        empty_layout.setContentsMargins(0, 0, 0, 0)
        empty_layout.addWidget(QLabel("Open or paste an image, then select a tool to begin. Use View → Help Panel for guidance."))
        empty_layout.addStretch()

        # --- Cut Out panel ---
        cutout_panel = QWidget()
        cutout_layout = QHBoxLayout(cutout_panel)
        cutout_layout.setContentsMargins(0, 0, 0, 0)

        self.cut_style = DropDownComboBox()
        self.cut_style.addItems(["Sawtooth", "Line", "No effect"])
        self.cut_style.currentIndexChanged.connect(self._refresh_color_selector_ui)
        self.cut_style.currentIndexChanged.connect(lambda: self._invalidate_cutout_preview())

        self.saw = QSpinBox()
        self.saw.setRange(6, 120)
        self.saw.setValue(24)
        self.saw.valueChanged.connect(lambda: self._invalidate_cutout_preview())

        self.gap = QSpinBox()
        self.gap.setRange(10, 150)   # percent
        self.gap.setValue(60)        # ShareX-like default
        self.gap.valueChanged.connect(lambda: self._invalidate_cutout_preview())

        self.cut_preview_type = DropDownComboBox()
        self.cut_preview_type.addItems(["Outline", "Result"])
        self.cut_preview_type.setToolTip("Outline: shaped overlay showing removal zone\nResult: actual cut output preview")
        self.cut_preview_type.currentIndexChanged.connect(lambda: self._invalidate_cutout_preview())

        btn_apply = QPushButton("Apply Cut")
        btn_apply.clicked.connect(self.apply_cut)

        self._gap_label = QLabel("Gap:")
        self._gap_pct_label = QLabel("%")
        
        for w in [
            QLabel("Cut Style:"), self.cut_style,
            QLabel("Size:"), self.saw,
            self._gap_label, self.gap, self._gap_pct_label,
            QLabel("Preview:"), self.cut_preview_type,
            btn_apply
        ]:
            cutout_layout.addWidget(w)
        cutout_layout.addStretch()
        
        # Enable/disable gap controls based on cut style
        self.cut_style.currentIndexChanged.connect(self._update_cutout_controls)
        self._update_cutout_controls()

        # --- Crop panel ---
        crop_panel = QWidget()
        crop_layout = QHBoxLayout(crop_panel)
        crop_layout.setContentsMargins(0, 0, 0, 0)

        self.btn_crop_apply = QPushButton("Apply Crop")
        self.btn_crop_apply.clicked.connect(self.apply_crop)
        self.btn_crop_apply.setEnabled(False)  # Initially disabled

        self.btn_crop_cancel = QPushButton("Cancel")
        self.btn_crop_cancel.clicked.connect(self.cancel_selection)
        self.btn_crop_cancel.setEnabled(False)  # Initially disabled

        crop_layout.addWidget(self.btn_crop_apply)
        crop_layout.addWidget(self.btn_crop_cancel)
        crop_layout.addStretch()

        # --- Rectangle panel ---
        rect_panel = QWidget()
        rect_layout = QHBoxLayout(rect_panel)
        rect_layout.setContentsMargins(0, 0, 0, 0)
        
        # Line width
        rect_layout.addWidget(QLabel("Line Width:"))
        self.rect_width = DropDownComboBox()
        self.rect_width.setEditable(True)
        self.rect_width.setFixedWidth(50)
        for i in range(1, 21):
            self.rect_width.addItem(str(i))
        self.rect_width.setCurrentText("2")
        self.rect_width.currentTextChanged.connect(self.update_rect_preview)
        rect_layout.addWidget(self.rect_width)
        
        # Rounded corners
        rect_layout.addWidget(QLabel("Rounded:"))
        self.rect_rounded = DropDownComboBox()
        self.rect_rounded.setEditable(True)
        self.rect_rounded.setFixedWidth(50)
        self.rect_rounded.addItems(["0", "5", "10", "15", "20", "25", "30"])
        self.rect_rounded.setCurrentText("0")
        self.rect_rounded.currentTextChanged.connect(self.update_rect_preview)
        rect_layout.addWidget(self.rect_rounded)

        # Fill checkbox and color picker
        rect_layout.addWidget(QLabel("Fill:"))
        self.fill_enabled = QCheckBox()
        self.fill_enabled.setChecked(False)  # Unchecked by default
        self.fill_enabled.stateChanged.connect(self.update_rect_preview)
        self.fill_enabled.stateChanged.connect(self._update_active_color_slot_from_tool)
        rect_layout.addWidget(self.fill_enabled)
        
        rect_layout.addStretch()

        # Add panels to tool_stack in alphabetical order to match dropdown
        # Index 0: empty panel (for "Select tool")
        self.tool_stack.addWidget(empty_panel)
        # Index 1: Arrow
        # Index 2: Crop  
        # Index 3: Cut Out
        # Index 4: Cut/Paste
        # Index 5: Freehand
        # Index 6: Highlight
        # Index 7: Line
        # Index 8: Step Marker
        # Index 9: Oval
        # Index 10: Pixelate
        # Index 11: Rectangle
        # Index 12: Text
        # (panels added after they're created below)
        
        # ---------------- Oval Tool ----------------
        oval_panel = QWidget()
        oval_layout = QHBoxLayout(oval_panel)
        oval_layout.setContentsMargins(0, 0, 0, 0)
        
        # Line width
        oval_layout.addWidget(QLabel("Line Width:"))
        self.oval_width = DropDownComboBox()
        self.oval_width.setEditable(True)
        self.oval_width.setFixedWidth(50)
        for i in range(1, 21):
            self.oval_width.addItem(str(i))
        self.oval_width.setCurrentText("2")
        self.oval_width.currentTextChanged.connect(self.update_oval_preview)
        oval_layout.addWidget(self.oval_width)

        # Fill checkbox and color picker
        oval_layout.addWidget(QLabel("Fill:"))
        self.oval_fill_enabled = QCheckBox()
        self.oval_fill_enabled.setChecked(False)  # Unchecked by default
        self.oval_fill_enabled.stateChanged.connect(self.update_oval_preview)
        self.oval_fill_enabled.stateChanged.connect(self._update_active_color_slot_from_tool)
        oval_layout.addWidget(self.oval_fill_enabled)
        
        oval_layout.addStretch()
        
        
        # ---------------- Line Tool ----------------
        line_panel = QWidget()
        line_layout = QHBoxLayout(line_panel)
        line_layout.setContentsMargins(0, 0, 0, 0)
        
        # Line width
        line_layout.addWidget(QLabel("Line Width:"))
        self.line_width_combo = DropDownComboBox()
        self.line_width_combo.setEditable(True)
        self.line_width_combo.setFixedWidth(50)
        for i in range(1, 21):
            self.line_width_combo.addItem(str(i))
        self.line_width_combo.setCurrentText("2")
        self.line_width_combo.currentTextChanged.connect(self.update_line_preview)
        line_layout.addWidget(self.line_width_combo)
        
        # Rounded checkbox
        line_layout.addWidget(QLabel("Rounded:"))
        self.line_rounded = QCheckBox()
        self.line_rounded.setChecked(True)  # Checked by default
        self.line_rounded.stateChanged.connect(self.update_line_preview)
        line_layout.addWidget(self.line_rounded)

        line_layout.addStretch()
        
        
        # ---------------- Arrow Tool ----------------
        arrow_panel = QWidget()
        arrow_layout = QHBoxLayout(arrow_panel)
        arrow_layout.setContentsMargins(0, 0, 0, 0)
        
        # Line width
        arrow_layout.addWidget(QLabel("Line Width:"))
        self.arrow_width_combo = DropDownComboBox()
        self.arrow_width_combo.setEditable(True)
        self.arrow_width_combo.setFixedWidth(50)
        for i in range(1, 21):
            self.arrow_width_combo.addItem(str(i))
        self.arrow_width_combo.setCurrentText("2")
        self.arrow_width_combo.currentTextChanged.connect(self.update_arrow_preview)
        arrow_layout.addWidget(self.arrow_width_combo)
        
        # Rounded checkbox
        arrow_layout.addWidget(QLabel("Rounded:"))
        self.arrow_rounded = QCheckBox()
        self.arrow_rounded.setChecked(True)  # Checked by default
        self.arrow_rounded.stateChanged.connect(self.update_arrow_preview)
        arrow_layout.addWidget(self.arrow_rounded)

        arrow_layout.addStretch()
        
        
        # ---------------- Freehand Tool ----------------
        freehand_panel = QWidget()
        freehand_layout = QHBoxLayout(freehand_panel)
        freehand_layout.setContentsMargins(0, 0, 0, 0)
        
        # Mode dropdown (replaces checkboxes)
        freehand_layout.addWidget(QLabel("Mode:"))
        self.freehand_mode_dropdown = DropDownComboBox()
        self.freehand_mode_dropdown.addItems(["Pen", "Brush", "Spray Can", "Flood Fill", "Color Eraser", "Eraser"])
        self.freehand_mode_dropdown.currentTextChanged.connect(self._on_freehand_mode_changed)
        freehand_layout.addWidget(self.freehand_mode_dropdown)
        
        # Size dropdown
        freehand_layout.addWidget(QLabel("Size:"))
        self.freehand_size = DropDownComboBox()
        self.freehand_size.setEditable(True)
        self.freehand_size.setFixedWidth(50)
        for i in range(1, 51):
            self.freehand_size.addItem(str(i))
        self.freehand_size.setCurrentText("3")
        freehand_layout.addWidget(self.freehand_size)
        
        # Tolerance (only for Color Eraser)
        self._tolerance_label = QLabel("Tolerance:")
        freehand_layout.addWidget(self._tolerance_label)
        self.color_eraser_tolerance = QSpinBox()
        self.color_eraser_tolerance.setRange(0, 255)
        self.color_eraser_tolerance.setValue(50)
        self.color_eraser_tolerance.setToolTip("Color match tolerance (0=exact, higher=more forgiving)")
        self.color_eraser_tolerance.setFixedWidth(55)
        freehand_layout.addWidget(self.color_eraser_tolerance)

        freehand_layout.addStretch()
        
        # Initialize tolerance as disabled (Pen is default)
        self._tolerance_label.setEnabled(False)
        self.color_eraser_tolerance.setEnabled(False)
        
        
        # ---------------- Cut/Paste Tool ----------------
        cutpaste_panel = QWidget()
        cutpaste_layout = QHBoxLayout(cutpaste_panel)
        cutpaste_layout.setContentsMargins(0, 0, 0, 0)
        
        self.btn_copy = QPushButton("Copy")
        self.btn_copy.clicked.connect(self.copy_selection)
        self.btn_copy.setEnabled(False)  # Initially disabled
        cutpaste_layout.addWidget(self.btn_copy)
        
        self.btn_cut = QPushButton("Cut")
        self.btn_cut.clicked.connect(self.cut_selection)
        self.btn_cut.setEnabled(False)  # Initially disabled
        cutpaste_layout.addWidget(self.btn_cut)
        
        self.btn_paste = QPushButton("Paste")
        self.btn_paste.clicked.connect(self.paste_selection)
        cutpaste_layout.addWidget(self.btn_paste)
        
        self.btn_import = QPushButton("Import")
        self.btn_import.clicked.connect(self.import_image)
        cutpaste_layout.addWidget(self.btn_import)
        
        self.btn_cutpaste_crop = QPushButton("Crop")
        self.btn_cutpaste_crop.clicked.connect(self.crop_to_selection)
        self.btn_cutpaste_crop.setEnabled(False)  # Initially disabled
        self.btn_cutpaste_crop.setToolTip("Crop canvas to selected area")
        cutpaste_layout.addWidget(self.btn_cutpaste_crop)
        
        cutpaste_layout.addStretch()
        

        # Highlight panel
        highlight_panel = QWidget()
        highlight_layout = QHBoxLayout(highlight_panel)
        highlight_layout.setContentsMargins(0, 0, 0, 0)
        
        highlight_layout.addWidget(QLabel("Style:"))
        self.highlight_style = DropDownComboBox()
        self.highlight_style.addItems(["Pen", "Rectangle", "Spotlight"])
        self.highlight_style.setCurrentIndex(1)  # Set Rectangle as default
        highlight_layout.addWidget(self.highlight_style)
        
        self._highlight_size_label = QLabel("Size:")
        highlight_layout.addWidget(self._highlight_size_label)
        self.highlight_size = QSpinBox()
        self.highlight_size.setRange(5, 50)
        self.highlight_size.setValue(15)
        self.highlight_size.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        highlight_layout.addWidget(self.highlight_size)
        
        # Spotlight dim (percentage in steps of 5)
        self._spotlight_dim_label = QLabel("Dim:")
        highlight_layout.addWidget(self._spotlight_dim_label)
        self.spotlight_opacity = QSpinBox()
        self.spotlight_opacity.setRange(20, 90)
        self.spotlight_opacity.setValue(60)
        self.spotlight_opacity.setSingleStep(5)
        self.spotlight_opacity.setSuffix("%")
        self.spotlight_opacity.setToolTip("How much to darken the area outside the spotlight")
        self.spotlight_opacity.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        highlight_layout.addWidget(self.spotlight_opacity)
        
        # Spotlight feather
        self._spotlight_feather_label = QLabel("Feather:")
        highlight_layout.addWidget(self._spotlight_feather_label)
        self.spotlight_feather = QSpinBox()
        self.spotlight_feather.setRange(0, 50)
        self.spotlight_feather.setValue(0)
        self.spotlight_feather.setSingleStep(5)
        self.spotlight_feather.setSuffix("%")
        self.spotlight_feather.setToolTip("Feather percentage — fades the spotlight edge (% of half the shortest side)")
        self.spotlight_feather.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        highlight_layout.addWidget(self.spotlight_feather)
        
        # Enable/disable controls based on style
        def _on_highlight_style_changed():
            style = self.highlight_style.currentText()
            is_pen = (style == "Pen")
            is_spotlight = (style == "Spotlight")
            # Size: only for Pen
            self._highlight_size_label.setEnabled(is_pen)
            self.highlight_size.setEnabled(is_pen)
            # Dim and Feather: only for Spotlight
            self._spotlight_dim_label.setEnabled(is_spotlight)
            self.spotlight_opacity.setEnabled(is_spotlight)
            self._spotlight_feather_label.setEnabled(is_spotlight)
            self.spotlight_feather.setEnabled(is_spotlight)
            self.viewer.update()
        self.highlight_style.currentTextChanged.connect(lambda: _on_highlight_style_changed())
        _on_highlight_style_changed()
        
        highlight_layout.addStretch()
        

        # Pixelate panel
        pixelate_panel = QWidget()
        pixelate_layout = QHBoxLayout(pixelate_panel)
        pixelate_layout.setContentsMargins(0, 0, 0, 0)
        
        pixelate_layout.addWidget(QLabel("Block Size:"))
        self.pixelate_size = QSpinBox()
        self.pixelate_size.setRange(1, 50)
        self.pixelate_size.setValue(10)
        self.pixelate_size.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        pixelate_layout.addWidget(self.pixelate_size)
        
        pixelate_layout.addStretch()
        
        # Blur panel
        blur_panel = QWidget()
        blur_layout = QHBoxLayout(blur_panel)
        blur_layout.setContentsMargins(0, 0, 0, 0)
        
        blur_layout.addWidget(QLabel("Area:"))
        self.blur_inside = DropDownComboBox()
        self.blur_inside.addItems(["Inside", "Outside"])
        self.blur_inside.currentTextChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        blur_layout.addWidget(self.blur_inside)
        
        blur_layout.addWidget(QLabel("Radius:"))
        self.blur_radius = QSpinBox()
        self.blur_radius.setRange(1, 50)
        self.blur_radius.setValue(5)
        self.blur_radius.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        blur_layout.addWidget(self.blur_radius)
        
        blur_layout.addWidget(QLabel("Feather:"))
        self.blur_feather = QSpinBox()
        self.blur_feather.setRange(0, 50)
        self.blur_feather.setValue(0)
        self.blur_feather.setSingleStep(5)
        self.blur_feather.setSuffix("%")
        self.blur_feather.setToolTip("Feather percentage — blends the blur edge (% of half the shortest side)")
        self.blur_feather.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        blur_layout.addWidget(self.blur_feather)
        
        blur_layout.addStretch()
        
        # Outline panel
        outline_panel = QWidget()
        outline_layout = QHBoxLayout(outline_panel)
        outline_layout.setContentsMargins(0, 0, 0, 0)
        
        outline_layout.addWidget(QLabel("Thickness:"))
        self.outline_thickness = QSpinBox()
        self.outline_thickness.setRange(1, 50)
        self.outline_thickness.setValue(2)
        self.outline_thickness.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        outline_layout.addWidget(self.outline_thickness)
        
        outline_layout.addWidget(QLabel("Corner Radius:"))
        self.outline_corner_radius = QSpinBox()
        self.outline_corner_radius.setRange(0, 200)
        self.outline_corner_radius.setValue(0)
        self.outline_corner_radius.setSuffix("px")
        self.outline_corner_radius.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        outline_layout.addWidget(self.outline_corner_radius)
        
        self.outline_preview_btn = QPushButton("Preview")
        self.outline_preview_btn.clicked.connect(self._toggle_outline_preview)
        outline_layout.addWidget(self.outline_preview_btn)
        
        self.outline_apply_btn = QPushButton("Apply")
        self.outline_apply_btn.clicked.connect(self.apply_outline)
        self.outline_apply_btn.setEnabled(False)
        outline_layout.addWidget(self.outline_apply_btn)
        
        outline_layout.addStretch()
        
        # Remove Space panel - Row 1 (Direction, Detect, buttons)
        rspace_panel = QWidget()
        rspace_layout = QHBoxLayout(rspace_panel)
        rspace_layout.setContentsMargins(0, 0, 0, 0)
        
        rspace_layout.addWidget(QLabel("Direction:"))
        self.rspace_direction = DropDownComboBox()
        self.rspace_direction.addItems(["Both", "Vertical", "Horizontal"])
        self.rspace_direction.currentTextChanged.connect(self._rspace_live_update)
        rspace_layout.addWidget(self.rspace_direction)
        
        rspace_layout.addWidget(QLabel("Detect:"))
        self.rspace_detect = DropDownComboBox()
        self.rspace_detect.addItems(["White/Near-white", "Auto-detect", "Pick Color", "Duplicate Lines"])
        self.rspace_detect.currentTextChanged.connect(self._rspace_live_update)
        rspace_layout.addWidget(self.rspace_detect)
        
        self.rspace_preview_btn = QPushButton("Preview")
        self.rspace_preview_btn.clicked.connect(self._preview_remove_space)
        rspace_layout.addWidget(self.rspace_preview_btn)
        
        self.rspace_apply_btn = QPushButton("Apply")
        self.rspace_apply_btn.clicked.connect(self._apply_remove_space)
        self.rspace_apply_btn.setEnabled(False)
        rspace_layout.addWidget(self.rspace_apply_btn)
        
        self.rspace_cancel_btn = QPushButton("Cancel")
        self.rspace_cancel_btn.clicked.connect(self._cancel_remove_space)
        self.rspace_cancel_btn.setEnabled(False)
        rspace_layout.addWidget(self.rspace_cancel_btn)
        
        rspace_layout.addStretch()
        
        # Remove Space panel - Row 2 (Keep, Min Gap, Tolerance sliders)
        rspace_panel_row2 = QWidget()
        rspace_layout2 = QHBoxLayout(rspace_panel_row2)
        rspace_layout2.setContentsMargins(0, 0, 0, 0)
        
        rspace_layout2.addWidget(QLabel("Keep:"))
        self.rspace_keep_slider = QSlider(Qt.Orientation.Horizontal)
        self.rspace_keep_slider.setRange(0, 100)
        self.rspace_keep_slider.setValue(4)
        self.rspace_keep_slider.setFixedWidth(140)
        self.rspace_keep_slider.setToolTip("Pixels of gap to keep where empty space was removed")
        self.rspace_keep_slider.valueChanged.connect(self._rspace_keep_slider_changed)
        rspace_layout2.addWidget(self.rspace_keep_slider)
        self.rspace_keep_label = QLabel("4")
        self.rspace_keep_label.setFixedWidth(24)
        rspace_layout2.addWidget(self.rspace_keep_label)
        
        rspace_layout2.addWidget(QLabel("Min Gap:"))
        self.rspace_min_gap_slider = QSlider(Qt.Orientation.Horizontal)
        self.rspace_min_gap_slider.setRange(1, 200)
        self.rspace_min_gap_slider.setValue(30)
        self.rspace_min_gap_slider.setFixedWidth(140)
        self.rspace_min_gap_slider.setToolTip("Only remove empty areas wider than this many pixels")
        self.rspace_min_gap_slider.valueChanged.connect(self._rspace_min_gap_slider_changed)
        rspace_layout2.addWidget(self.rspace_min_gap_slider)
        self.rspace_min_gap_label = QLabel("30")
        self.rspace_min_gap_label.setFixedWidth(24)
        rspace_layout2.addWidget(self.rspace_min_gap_label)
        
        rspace_layout2.addWidget(QLabel("Tolerance:"))
        self.rspace_tolerance_slider = QSlider(Qt.Orientation.Horizontal)
        self.rspace_tolerance_slider.setRange(0, 50)
        self.rspace_tolerance_slider.setValue(10)
        self.rspace_tolerance_slider.setFixedWidth(140)
        self.rspace_tolerance_slider.setToolTip("How close to target color counts as empty (0=exact)")
        self.rspace_tolerance_slider.valueChanged.connect(self._rspace_tolerance_slider_changed)
        rspace_layout2.addWidget(self.rspace_tolerance_slider)
        self.rspace_tolerance_label = QLabel("10")
        self.rspace_tolerance_label.setFixedWidth(24)
        rspace_layout2.addWidget(self.rspace_tolerance_label)
        
        rspace_layout2.addStretch()
        
        # Magnify Inset panel
        inset_panel = QWidget()
        inset_layout = QHBoxLayout(inset_panel)
        inset_layout.setContentsMargins(0, 0, 0, 0)
        
        inset_layout.addWidget(QLabel("Shape:"))
        self.inset_shape = DropDownComboBox()
        self.inset_shape.addItems(["Rectangle", "Oval"])
        inset_layout.addWidget(self.inset_shape)
        
        inset_layout.addWidget(QLabel("Zoom:"))
        self.inset_zoom = DropDownComboBox()
        for pct in ["125%", "150%", "175%", "200%", "225%", "250%", "275%", "300%"]:
            self.inset_zoom.addItem(pct)
        self.inset_zoom.setCurrentText("200%")
        self.inset_zoom.currentTextChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        inset_layout.addWidget(self.inset_zoom)
        
        inset_layout.addWidget(QLabel("Border:"))
        self.inset_border = QSpinBox()
        self.inset_border.setRange(0, 10)
        self.inset_border.setValue(3)
        self.inset_border.valueChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        inset_layout.addWidget(self.inset_border)
        
        inset_layout.addWidget(QLabel("Connected:"))
        self.inset_connection = DropDownComboBox()
        self.inset_connection.addItems(["Yes", "No"])
        self.inset_connection.setCurrentText("Yes")
        self.inset_connection.currentTextChanged.connect(lambda: self.viewer.update() if hasattr(self, 'viewer') else None)
        inset_layout.addWidget(self.inset_connection)
        
        self.inset_apply_btn = QPushButton("Apply")
        self.inset_apply_btn.clicked.connect(self._apply_magnify_inset)
        inset_layout.addWidget(self.inset_apply_btn)
        
        inset_layout.addStretch()

        # Step Marker panel
        step_marker_panel = QWidget()
        numbers_layout = QHBoxLayout(step_marker_panel)
        numbers_layout.setContentsMargins(0, 0, 0, 0)
        
        numbers_layout.addWidget(QLabel("Size:"))
        self.step_marker_size = QSpinBox()
        self.step_marker_size.setRange(20, 100)
        self.step_marker_size.setValue(40)
        numbers_layout.addWidget(self.step_marker_size)
        
        numbers_layout.addWidget(QLabel("Start #:"))
        self.step_marker_start_toolbar = QSpinBox()
        self.step_marker_start_toolbar.setRange(1, 999)
        self.step_marker_start_toolbar.setValue(1)
        self.step_marker_start_toolbar.valueChanged.connect(
            lambda v: setattr(self.viewer, 'marker_counter', v) if hasattr(self, 'viewer') else None)
        numbers_layout.addWidget(self.step_marker_start_toolbar)
        
        numbers_layout.addStretch()
        

        # Text panel
        text_panel = QWidget()
        text_layout = QHBoxLayout(text_panel)
        text_layout.setContentsMargins(0, 0, 0, 0)
        
        text_layout.addWidget(QLabel("Font:"))
        self.text_font = DropDownComboBox()
        # Detect OS and provide appropriate font list, filtered to what's installed
        import platform
        from PyQt6.QtGui import QFontDatabase
        available = set(QFontDatabase.families())
        
        if platform.system() == 'Windows':
            preferred = [
                "Arial", "Calibri", "Cambria", "Consolas", "Comic Sans MS",
                "Courier New", "Georgia", "Impact", "Lucida Console",
                "Segoe UI", "Tahoma", "Times New Roman", "Trebuchet MS",
                "Verdana", "Wingdings"
            ]
            default_font = "Arial"
        elif platform.system() == 'Darwin':
            preferred = [
                "Helvetica", "Helvetica Neue", "Arial", "Menlo", "Monaco",
                "San Francisco", "Avenir", "Georgia", "Courier New",
                "Times New Roman", "Futura", "Gill Sans"
            ]
            default_font = "Helvetica"
        else:
            preferred = [
                "DejaVu Sans", "DejaVu Sans Mono", "DejaVu Serif",
                "Liberation Sans", "Liberation Mono", "Liberation Serif",
                "Ubuntu", "Ubuntu Mono",
                "Noto Sans", "Noto Serif", "Noto Mono"
            ]
            default_font = "DejaVu Sans"
        
        # Add preferred fonts that are actually installed
        font_list = [f for f in preferred if f in available]
        # If none found, fall back to whatever is available
        if not font_list:
            font_list = sorted(available)[:15]
        self.text_font.addItems(font_list)
        # Set default
        idx = self.text_font.findText(default_font)
        if idx >= 0:
            self.text_font.setCurrentIndex(idx)
        text_layout.addWidget(self.text_font)
        
        text_layout.addWidget(QLabel("Size:"))
        self.text_size = QSpinBox()
        self.text_size.setRange(8, 200)
        self.text_size.setValue(24)
        text_layout.addWidget(self.text_size)
        
        # Alignment dropdown
        text_layout.addWidget(QLabel("Align:"))
        self.text_align_combo = QComboBox()
        self.text_align_combo.addItems(["Left", "Center", "Right"])
        self.text_align_combo.setCurrentText("Center")
        self.text_align_combo.currentTextChanged.connect(lambda t: self.set_text_alignment(t.lower()))
        text_layout.addWidget(self.text_align_combo)
        
        # Store current alignment
        self.text_alignment = "center"
        
        # Bold / Italic / Underline toggle buttons
        self.text_bold = QPushButton("B")
        self.text_bold.setFixedSize(28, 28)
        self.text_bold.setCheckable(True)
        self.text_bold.setChecked(True)  # Default bold on (matches old behavior)
        self.text_bold.setToolTip("Bold")
        self.text_bold.setStyleSheet("QPushButton { font-weight: bold; } QPushButton:checked { background-color: #00bfff; }")
        text_layout.addWidget(self.text_bold)
        
        self.text_italic = QPushButton("I")
        self.text_italic.setFixedSize(28, 28)
        self.text_italic.setCheckable(True)
        self.text_italic.setToolTip("Italic")
        self.text_italic.setStyleSheet("QPushButton { font-style: italic; } QPushButton:checked { background-color: #00bfff; }")
        text_layout.addWidget(self.text_italic)
        
        self.text_underline = QPushButton("U")
        self.text_underline.setFixedSize(28, 28)
        self.text_underline.setCheckable(True)
        self.text_underline.setToolTip("Underline")
        self.text_underline.setStyleSheet("QPushButton { text-decoration: underline; } QPushButton:checked { background-color: #00bfff; }")
        text_layout.addWidget(self.text_underline)
        
        # Shadow checkbox
        self.text_shadow = QCheckBox("Shadow")
        text_layout.addWidget(self.text_shadow)
        
        # Outline checkbox
        self.text_outline = QCheckBox("Outline")
        text_layout.addWidget(self.text_outline)
        
        # Thickness (grayed out when Outline not checked)
        self._text_thickness_label = QLabel("Thickness:")
        text_layout.addWidget(self._text_thickness_label)
        self.text_outline_thickness = QSpinBox()
        self.text_outline_thickness.setRange(1, 10)
        self.text_outline_thickness.setValue(3)
        text_layout.addWidget(self.text_outline_thickness)
        
        # Gray out thickness when outline is unchecked
        def _on_outline_changed():
            enabled = self.text_outline.isChecked()
            self._text_thickness_label.setEnabled(enabled)
            self.text_outline_thickness.setEnabled(enabled)
        self.text_outline.stateChanged.connect(lambda: _on_outline_changed())
        _on_outline_changed()  # Set initial state
        
        # Connect signals to update preview in real-time
        self.text_font.currentTextChanged.connect(self.update_text_preview)
        self.text_size.valueChanged.connect(self.update_text_preview)
        self.text_bold.toggled.connect(self.update_text_preview)
        self.text_italic.toggled.connect(self.update_text_preview)
        self.text_underline.toggled.connect(self.update_text_preview)
        self.text_outline.stateChanged.connect(self.update_text_preview)
        self.text_outline.stateChanged.connect(self._update_active_color_slot_from_tool)
        self.text_outline_thickness.valueChanged.connect(self.update_text_preview)
        self.text_shadow.stateChanged.connect(self.update_text_preview)
        
        text_layout.addStretch()
        
        # Transform panel - Row 1 (Rotate/Flip)
        transform_panel = QWidget()
        transform_layout = QHBoxLayout(transform_panel)
        transform_layout.setContentsMargins(0, 0, 0, 0)
        
        self.btn_rotate_ccw = QPushButton("↺ 90°")
        self.btn_rotate_ccw.setToolTip("Rotate 90° counter-clockwise")
        self.btn_rotate_ccw.clicked.connect(lambda: self._transform_rotate(-90))
        transform_layout.addWidget(self.btn_rotate_ccw)
        
        self.btn_rotate_cw = QPushButton("↻ 90°")
        self.btn_rotate_cw.setToolTip("Rotate 90° clockwise")
        self.btn_rotate_cw.clicked.connect(lambda: self._transform_rotate(90))
        transform_layout.addWidget(self.btn_rotate_cw)
        
        # Separator between 90° rotations and custom angle
        tsep_angle = QFrame()
        tsep_angle.setFrameShape(QFrame.Shape.VLine)
        tsep_angle.setStyleSheet("QFrame { background-color: #606060; }")
        tsep_angle.setFixedWidth(2)
        tsep_angle.setFixedHeight(22)
        transform_layout.addWidget(tsep_angle)
        
        transform_layout.addWidget(QLabel("Angle:"))
        self.transform_angle = QDoubleSpinBox()
        self.transform_angle.setRange(-359, 359)
        self.transform_angle.setValue(0)
        self.transform_angle.setSingleStep(0.5)
        self.transform_angle.setDecimals(1)
        self.transform_angle.setSuffix("°")
        self.transform_angle.setToolTip("Custom rotation angle (positive = clockwise)")
        self.transform_angle.valueChanged.connect(self._transform_live_preview)
        transform_layout.addWidget(self.transform_angle)
        
        self.btn_rotate_reset = QPushButton("Reset")
        self.btn_rotate_reset.setToolTip("Cancel rotation preview")
        self.btn_rotate_reset.clicked.connect(self._transform_cancel_preview)
        self.btn_rotate_reset.setEnabled(False)
        transform_layout.addWidget(self.btn_rotate_reset)
        
        self.btn_rotate_apply = QPushButton("Apply")
        self.btn_rotate_apply.setToolTip("Apply rotation permanently")
        self.btn_rotate_apply.clicked.connect(self._transform_rotate_custom)
        self.btn_rotate_apply.setEnabled(False)
        transform_layout.addWidget(self.btn_rotate_apply)
        
        # Separator
        tsep1 = QFrame()
        tsep1.setFrameShape(QFrame.Shape.VLine)
        tsep1.setStyleSheet("QFrame { background-color: #606060; }")
        tsep1.setFixedWidth(2)
        tsep1.setFixedHeight(22)
        transform_layout.addWidget(tsep1)
        
        self.btn_flip_h = QPushButton("⇔ Flip H")
        self.btn_flip_h.setToolTip("Flip horizontally (mirror)")
        self.btn_flip_h.clicked.connect(self._transform_flip_h)
        transform_layout.addWidget(self.btn_flip_h)
        
        self.btn_flip_v = QPushButton("⇕ Flip V")
        self.btn_flip_v.setToolTip("Flip vertically")
        self.btn_flip_v.clicked.connect(self._transform_flip_v)
        transform_layout.addWidget(self.btn_flip_v)
        
        transform_layout.addStretch()
        
        # Transform panel - Row 2 (Resize)
        transform_panel_row2 = QWidget()
        transform_layout2 = QHBoxLayout(transform_panel_row2)
        transform_layout2.setContentsMargins(0, 0, 0, 0)
        
        transform_layout2.addWidget(QLabel("W:"))
        self.transform_w = QSpinBox()
        self.transform_w.setRange(1, 99999)
        self.transform_w.setValue(0)
        self.transform_w.setToolTip("New width in pixels")
        self.transform_w.valueChanged.connect(self._transform_w_changed)
        transform_layout2.addWidget(self.transform_w)
        
        transform_layout2.addWidget(QLabel("H:"))
        self.transform_h = QSpinBox()
        self.transform_h.setRange(1, 99999)
        self.transform_h.setValue(0)
        self.transform_h.setToolTip("New height in pixels")
        self.transform_h.valueChanged.connect(self._transform_h_changed)
        transform_layout2.addWidget(self.transform_h)
        
        self.transform_lock_ratio = QCheckBox("Lock Ratio")
        self.transform_lock_ratio.setChecked(True)
        self.transform_lock_ratio.setToolTip("Keep aspect ratio when changing width or height")
        transform_layout2.addWidget(self.transform_lock_ratio)
        
        # Separator
        tsep2 = QFrame()
        tsep2.setFrameShape(QFrame.Shape.VLine)
        tsep2.setStyleSheet("QFrame { background-color: #606060; }")
        tsep2.setFixedWidth(2)
        tsep2.setFixedHeight(22)
        transform_layout2.addWidget(tsep2)
        
        transform_layout2.addWidget(QLabel("Scale:"))
        self.transform_pct = QSpinBox()
        self.transform_pct.setRange(1, 1000)
        self.transform_pct.setValue(100)
        self.transform_pct.setSuffix("%")
        self.transform_pct.setToolTip("Scale by percentage")
        self.transform_pct.valueChanged.connect(self._transform_pct_changed)
        transform_layout2.addWidget(self.transform_pct)
        
        self.btn_resize_reset = QPushButton("Reset")
        self.btn_resize_reset.setToolTip("Reset to original image dimensions")
        self.btn_resize_reset.clicked.connect(self._transform_resize_cancel)
        self.btn_resize_reset.setEnabled(False)
        transform_layout2.addWidget(self.btn_resize_reset)
        
        self.btn_resize = QPushButton("Apply")
        self.btn_resize.setToolTip("Apply resize permanently")
        self.btn_resize.clicked.connect(self._transform_resize)
        self.btn_resize.setEnabled(False)
        transform_layout2.addWidget(self.btn_resize)
        
        transform_layout2.addStretch()
        
        # --- Color & Light panel ---
        color_light_panel = QWidget()
        cl_layout = QHBoxLayout(color_light_panel)
        cl_layout.setContentsMargins(0, 0, 0, 0)
        
        cl_layout.addWidget(QLabel("Brightness:"))
        self.cl_brightness = QSlider(Qt.Orientation.Horizontal)
        self.cl_brightness.setRange(-100, 100)
        self.cl_brightness.setValue(0)
        self.cl_brightness.setFixedWidth(80)
        self.cl_brightness.setToolTip("Brightness adjustment (-100 to +100)")
        self.cl_brightness.valueChanged.connect(self._color_light_preview)
        cl_layout.addWidget(self.cl_brightness)
        
        cl_layout.addWidget(QLabel("Contrast:"))
        self.cl_contrast = QSlider(Qt.Orientation.Horizontal)
        self.cl_contrast.setRange(-100, 100)
        self.cl_contrast.setValue(0)
        self.cl_contrast.setFixedWidth(80)
        self.cl_contrast.setToolTip("Contrast adjustment (-100 to +100)")
        self.cl_contrast.valueChanged.connect(self._color_light_preview)
        cl_layout.addWidget(self.cl_contrast)
        
        cl_layout.addWidget(QLabel("Hue:"))
        self.cl_hue = QSlider(Qt.Orientation.Horizontal)
        self.cl_hue.setRange(-180, 180)
        self.cl_hue.setValue(0)
        self.cl_hue.setFixedWidth(80)
        self.cl_hue.setToolTip("Hue rotation in degrees (-180 to +180)")
        self.cl_hue.valueChanged.connect(self._color_light_preview)
        cl_layout.addWidget(self.cl_hue)
        
        cl_layout.addWidget(QLabel("Sharpness:"))
        self.cl_sharpness = QSlider(Qt.Orientation.Horizontal)
        self.cl_sharpness.setRange(-100, 100)
        self.cl_sharpness.setValue(0)
        self.cl_sharpness.setFixedWidth(80)
        self.cl_sharpness.setToolTip("Sharpness adjustment (-100=blur, 0=original, +100=sharpen)")
        self.cl_sharpness.valueChanged.connect(self._color_light_preview)
        cl_layout.addWidget(self.cl_sharpness)
        
        self.btn_cl_reset = QPushButton("Reset")
        self.btn_cl_reset.setToolTip("Reset all adjustments")
        self.btn_cl_reset.clicked.connect(self._color_light_cancel)
        self.btn_cl_reset.setEnabled(False)
        cl_layout.addWidget(self.btn_cl_reset)
        
        self.btn_cl_apply = QPushButton("Apply")
        self.btn_cl_apply.setToolTip("Apply adjustments permanently")
        self.btn_cl_apply.clicked.connect(self._color_light_apply)
        self.btn_cl_apply.setEnabled(False)
        cl_layout.addWidget(self.btn_cl_apply)
        
        cl_layout.addStretch()
        
        # Add panels to tool_stack in alphabetical order to match dropdown
        # Index 0: empty panel (for "Select tool") - already added
        self.tool_stack.addWidget(arrow_panel)      # Index 1: Arrow
        self.tool_stack.addWidget(blur_panel)       # Index 2: Blur
        self.tool_stack.addWidget(color_light_panel)  # Index 3: Color & Light
        self.tool_stack.addWidget(crop_panel)       # Index 4: Crop
        self.tool_stack.addWidget(cutout_panel)     # Index 5: Cut Out
        self.tool_stack.addWidget(cutpaste_panel)   # Index 6: Cut/Paste
        self.tool_stack.addWidget(freehand_panel)   # Index 7: Freehand
        self.tool_stack.addWidget(highlight_panel)  # Index 8: Highlight
        self.tool_stack.addWidget(line_panel)       # Index 9: Line
        self.tool_stack.addWidget(inset_panel)      # Index 10: Magnify Inset
        self.tool_stack.addWidget(step_marker_panel)    # Index 11: Step Marker
        self.tool_stack.addWidget(oval_panel)       # Index 12: Oval
        self.tool_stack.addWidget(outline_panel)    # Index 13: Outline
        self.tool_stack.addWidget(pixelate_panel)   # Index 14: Pixelate
        self.tool_stack.addWidget(rect_panel)       # Index 15: Rectangle
        self.tool_stack.addWidget(rspace_panel)     # Index 16: Remove Space
        self.tool_stack.addWidget(text_panel)       # Index 17: Text
        self.tool_stack.addWidget(transform_panel)  # Index 18: Transform

        # Add row 2 panels for tools that need overflow
        # Empty placeholder for tools without a second row
        self._row2_empty = QWidget()
        self.tool_stack_row2.addWidget(self._row2_empty)     # Index 0: empty
        self.tool_stack_row2.addWidget(rspace_panel_row2)    # Index 1: Remove Space row 2
        self.tool_stack_row2.addWidget(transform_panel_row2) # Index 2: Transform row 2
        
        # Map tool names to row2 indices (only tools with a second row)
        self._tool_row2_index = {
            "remove_space": 1,
            "transform": 2,
        }

        # Wrap row 1 and row 2 in a vertical container
        self.tool_rows_container = QVBoxLayout()
        self.tool_rows_container.setContentsMargins(0, 0, 0, 0)
        self.tool_rows_container.setSpacing(0)
        self.tool_rows_container.addLayout(self.tool_bar_layout)
        self.tool_rows_container.addWidget(self.tool_stack_row2)

        root.addLayout(self.tool_rows_container)
        
        # Wrap viewer in scroll area for scrollbars
        from PyQt6.QtWidgets import QScrollArea
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidget(self.viewer)
        self.scroll_area.setWidgetResizable(False)  # Don't resize widget, just scroll
        self.scroll_area.setStyleSheet("background:#1e1e1e;")
        
        # Install event filter to catch wheel events over the black area
        self.scroll_area.viewport().installEventFilter(self)
        
        # Create horizontal layout for toolbar sidebar + canvas area + help panel
        self.canvas_area_layout = QHBoxLayout()
        self.canvas_area_layout.setContentsMargins(0, 0, 0, 0)
        self.canvas_area_layout.setSpacing(0)
        self._toolbar_wrapper = AutoScrollToolbarWrapper(self.toolbar_widget)
        self.canvas_area_layout.addWidget(self._toolbar_wrapper)
        self.canvas_area_layout.addWidget(self.scroll_area, 1)
        
        # Help panel (right sidebar)
        self.help_panel = QWidget()
        self.help_panel.setFixedWidth(260)
        help_panel_layout = QVBoxLayout(self.help_panel)
        help_panel_layout.setContentsMargins(8, 8, 8, 8)
        help_panel_layout.setSpacing(4)
        
        self.help_title = QLabel("Getting Started")
        self.help_title.setWordWrap(True)
        font = self.help_title.font()
        font.setPointSize(font.pointSize() + 1)
        self.help_title.setFont(font)
        help_panel_layout.addWidget(self.help_title)
        
        # Separator
        help_sep = QFrame()
        help_sep.setFrameShape(QFrame.Shape.HLine)
        help_sep.setFixedHeight(1)
        help_panel_layout.addWidget(help_sep)
        
        self.help_content = QLabel()
        self.help_content.setWordWrap(True)
        self.help_content.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.help_content.setTextFormat(Qt.TextFormat.RichText)
        help_panel_layout.addWidget(self.help_content, 1)
        
        # Load help visibility from config
        config = load_config()
        help_visible = config.get("help_panel_visible", False)
        self.help_panel.setVisible(help_visible)
        self._update_help_content(None)
        
        self.canvas_area_layout.addWidget(self.help_panel)
        
        root.addLayout(self.canvas_area_layout, 1)
        
        # Create status bar
        self._create_status_bar()
        root.addWidget(self.status_bar)
        
        # Create crosshair overlay
        self.crosshair_overlay = CrosshairOverlay(self, self.scroll_area, self.viewer)

        # Start with "Select tool" placeholder (index 0)
        self.tool_stack.setCurrentIndex(0)
        # Set default global colors (Primary/Secondary)
        self._refresh_color_selector_ui()

        # Add keyboard shortcuts
        from PyQt6.QtGui import QShortcut, QKeySequence
        
        # Ctrl+C, Ctrl+V, Ctrl+Z, Ctrl+Y, Delete handled by Edit menu actions
        
        # Escape to cancel/discard current uncommitted tool state
        escape_shortcut = QShortcut(QKeySequence("Escape"), self)
        escape_shortcut.activated.connect(self._escape_cancel)
        
        # Initialize tool buttons state (disabled until source is loaded)
        self.update_tool_buttons_state()
        
        # Apply saved tool defaults
        self.apply_tool_defaults()
        
        # Create blank canvas on startup
        self.create_startup_blank_canvas()

    def eventFilter(self, obj, event):
        """Filter events for scroll area viewport to handle Shift+wheel zoom anywhere"""
        # Check if this is a wheel event on the scroll area viewport
        if obj == self.scroll_area.viewport() and event.type() == QEvent.Type.Wheel:
            modifiers = event.modifiers()
            delta = event.angleDelta().y()
            
            # Alt + Wheel: Change crosshair circle size if magnifier enabled, else scroll horizontally
            if modifiers & Qt.KeyboardModifier.AltModifier:
                if hasattr(self, 'crosshair_enabled') and self.crosshair_enabled:
                    step = 10
                    if delta > 0:
                        self.crosshair_size = min(320, self.crosshair_size + step)
                    else:
                        self.crosshair_size = max(80, self.crosshair_size - step)
                    self._update_magnifier_size_checks()
                    self.viewer.update()
                else:
                    h_bar = self.scroll_area.horizontalScrollBar()
                    h_bar.setValue(h_bar.value() - delta)
                return True  # Event handled
            
            # Ctrl + Wheel: Zoom canvas
            if modifiers & Qt.KeyboardModifier.ControlModifier:
                if delta > 0:
                    self.zoom_in()
                else:
                    self.zoom_out()
                return True  # Event handled
        
        # Pass event to default handler
        return super().eventFilter(obj, event)
    
    def _create_status_bar(self):
        """Create the status bar at the bottom of the window"""
        from PyQt6.QtWidgets import QFrame
        
        config = load_config()
        
        self.status_bar = QWidget()
        self.status_bar.setObjectName("statusBar")
        self.status_bar.setFixedHeight(24)
        if self._is_dark_mode:
            self.status_bar.setStyleSheet("""
                #statusBar { background-color: #2d2d2d; border: 1px solid #555; }
                #statusBar QLabel { color: #c0c0c0; font-size: 11px; padding: 0px 4px; border: none; }
            """)
        else:
            self.status_bar.setStyleSheet("""
                #statusBar { background-color: #f0f0f0; border: 1px solid #c0c0c0; }
                #statusBar QLabel { color: #404040; font-size: 11px; padding: 0px 4px; border: none; }
            """)
        
        status_layout = QHBoxLayout(self.status_bar)
        status_layout.setContentsMargins(8, 2, 8, 2)
        status_layout.setSpacing(0)
        
        # Cursor position label
        self.status_cursor_label = QLabel("X: —  Y: —")
        self.status_cursor_label.setMinimumWidth(100)
        status_layout.addWidget(self.status_cursor_label)
        
        # Separator
        self.status_sep1 = QLabel("|")
        self.status_sep1.setStyleSheet("color: #a0a0a0; padding: 0px 8px;")
        status_layout.addWidget(self.status_sep1)
        
        # Color swatch (small colored square)
        self.status_color_swatch = QLabel()
        self.status_color_swatch.setFixedSize(14, 14)
        self.status_color_swatch.setStyleSheet("background-color: #808080; border: 1px solid #606060;")
        status_layout.addWidget(self.status_color_swatch)
        
        # Pixel color label (clickable to toggle format)
        self.status_color_format = config.get("status_bar_color_format", "rgb")
        self.status_color_label = QLabel("RGB: —, —, —")
        self.status_color_label.setMinimumWidth(110)
        self.status_color_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.status_color_label.setToolTip("Click to toggle RGB/Hex format")
        self.status_color_label.mousePressEvent = self._toggle_color_format
        status_layout.addWidget(self.status_color_label)
        
        # Separator
        self.status_sep2 = QLabel("|")
        self.status_sep2.setStyleSheet("color: #a0a0a0; padding: 0px 8px;")
        status_layout.addWidget(self.status_sep2)
        
        # Image size label
        self.status_size_label = QLabel("— × —")
        self.status_size_label.setMinimumWidth(80)
        status_layout.addWidget(self.status_size_label)
        
        # Separator
        self.status_sep3 = QLabel("|")
        self.status_sep3.setStyleSheet("color: #a0a0a0; padding: 0px 8px;")
        status_layout.addWidget(self.status_sep3)
        
        # Zoom level label
        self.status_zoom_label = QLabel("100%")
        self.status_zoom_label.setMinimumWidth(45)
        status_layout.addWidget(self.status_zoom_label)
        
        # Separator before filename
        self.status_sep4 = QLabel("|")
        self.status_sep4.setStyleSheet("color: #a0a0a0; padding: 0px 8px;")
        status_layout.addWidget(self.status_sep4)
        
        # Filename label
        self.status_filename_label = QLabel("")
        status_layout.addWidget(self.status_filename_label)
        
        # Spacer to push modified indicator to the right
        status_layout.addStretch()
        
        # Modified indicator
        self.status_modified_label = QLabel("")
        self.status_modified_label.setStyleSheet("color: #d04040; font-weight: bold;")
        status_layout.addWidget(self.status_modified_label)
        
        # Apply visibility settings from config
        self._apply_status_bar_config()
    
    def _apply_status_bar_config(self):
        """Apply status bar visibility settings from config"""
        config = load_config()
        
        # Overall visibility
        self.status_bar.setVisible(config.get("status_bar_visible", True))
        
        # Individual sections
        show_cursor = config.get("status_bar_cursor", True)
        self.status_cursor_label.setVisible(show_cursor)
        self.status_sep1.setVisible(show_cursor and config.get("status_bar_color", True))
        
        show_color = config.get("status_bar_color", True)
        self.status_color_swatch.setVisible(show_color)
        self.status_color_label.setVisible(show_color)
        self.status_sep2.setVisible(show_color and config.get("status_bar_size", True))
        
        show_size = config.get("status_bar_size", True)
        self.status_size_label.setVisible(show_size)
        self.status_sep3.setVisible(show_size and config.get("status_bar_zoom", True))
        
        show_zoom = config.get("status_bar_zoom", True)
        self.status_zoom_label.setVisible(show_zoom)
        
        show_modified = config.get("status_bar_modified", True)
        self.status_modified_label.setVisible(show_modified)
    
    def _toggle_color_format(self, event):
        """Toggle between RGB and Hex color format"""
        if self.status_color_format == "rgb":
            self.status_color_format = "hex"
        else:
            self.status_color_format = "rgb"
        
        # Save preference
        config = load_config()
        config["status_bar_color_format"] = self.status_color_format
        save_config(config)
        
        # Update display
        self._update_status_bar()
    
    def _update_status_bar(self):
        """Update all status bar information"""
        if not hasattr(self, 'status_bar'):
            return
        
        # Update image size
        if self.viewer.image:
            w, h = self.viewer.image.size
            self.status_size_label.setText(f"{w} × {h}")
        else:
            self.status_size_label.setText("— × —")
        
        # Update zoom level
        if hasattr(self.viewer, 'scale') and self.viewer.scale:
            zoom_pct = int(self.viewer.scale * 100)
            self.status_zoom_label.setText(f"{zoom_pct}%")
        else:
            self.status_zoom_label.setText("100%")
        
        # Update modified indicator
        if self.has_unsaved_changes:
            self.status_modified_label.setText("● Modified")
        else:
            self.status_modified_label.setText("")
        
        # Update filename
        if self.current_path:
            filename = os.path.basename(self.current_path)
            self.status_filename_label.setText(filename)
            self.status_sep4.setVisible(True)
        else:
            self.status_filename_label.setText("")
            self.status_sep4.setVisible(False)
    
    def _update_status_cursor(self, x, y, color=None):
        """Update cursor position and color in status bar"""
        if not hasattr(self, 'status_bar'):
            return
        
        # Update cursor position
        if x is not None and y is not None:
            self.status_cursor_label.setText(f"X: {x}  Y: {y}")
        else:
            self.status_cursor_label.setText("X: —  Y: —")
        
        # Update pixel color and swatch
        if color is not None:
            r, g, b = color[0], color[1], color[2]
            # Update color swatch
            self.status_color_swatch.setStyleSheet(f"background-color: rgb({r},{g},{b}); border: 1px solid #606060;")
            # Update color text
            if self.status_color_format == "hex":
                self.status_color_label.setText(f"#{r:02X}{g:02X}{b:02X}")
            else:
                self.status_color_label.setText(f"RGB: {r}, {g}, {b}")
        else:
            # Gray swatch when no color
            self.status_color_swatch.setStyleSheet("background-color: #808080; border: 1px solid #606060;")
            if self.status_color_format == "hex":
                self.status_color_label.setText("#——————")
            else:
                self.status_color_label.setText("RGB: —, —, —")
    
    def _toggle_status_bar_visible(self, visible):
        """Toggle overall status bar visibility"""
        self.status_bar.setVisible(visible)
        config = load_config()
        config["status_bar_visible"] = visible
        save_config(config)
    
    def _toggle_status_bar_section(self, section, visible):
        """Toggle visibility of a status bar section"""
        config = load_config()
        config[f"status_bar_{section}"] = visible
        save_config(config)
        self._apply_status_bar_config()

    def create_menu_bar(self):
        """Create the application menu bar"""
        menubar = self.menuBar()
        
        # ===== File Menu =====
        file_menu = menubar.addMenu("File")
        
        new_action = file_menu.addAction("New")
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_blank_image)
        
        open_action = file_menu.addAction("Open")
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        
        # Recent Files submenu
        self.recent_files_menu = file_menu.addMenu("Recent Files")
        self.update_recent_files_menu()
        
        file_menu.addSeparator()
        
        # Restore Previous action
        restore_previous_action = file_menu.addAction("Restore Previous Image")
        restore_previous_action.setShortcut("Ctrl+Shift+Z")
        restore_previous_action.triggered.connect(self.restore_previous_image)
        
        file_menu.addSeparator()
        
        save_action = file_menu.addAction("Save")
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save)
        
        save_as_action = file_menu.addAction("Save As")
        save_as_action.setShortcut("Ctrl+Shift+S")
        save_as_action.triggered.connect(self.save_as)
        
        # Upload to FTP submenu
        upload_menu = file_menu.addMenu("Upload to FTP")
        self.ftp_upload_menu = upload_menu  # Store reference for updating
        self.update_ftp_upload_menu()
        
        file_menu.addSeparator()
        
        exit_action = file_menu.addAction("Exit")
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        
        # ===== Edit Menu =====
        edit_menu = menubar.addMenu("Edit")
        
        undo_action = edit_menu.addAction("Undo")
        undo_action.setShortcut("Ctrl+Z")
        undo_action.triggered.connect(self.viewer.undo)
        
        redo_action = edit_menu.addAction("Redo")
        redo_action.setShortcut("Ctrl+Y")
        redo_action.triggered.connect(self.viewer.redo)
        
        edit_menu.addSeparator()
        
        copy_action = edit_menu.addAction("Copy")
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(self.copy)
        
        paste_action = edit_menu.addAction("Paste")
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.paste_from_clipboard_global)
        
        delete_action = edit_menu.addAction("Delete")
        delete_action.setShortcut("Delete")
        delete_action.triggered.connect(self._delete_selection)
        
        edit_menu.addSeparator()
        
        set_as_image_action = edit_menu.addAction("Set as Image")
        set_as_image_action.triggered.connect(self.crop_to_content)
        
        # ===== View Menu =====
        view_menu = menubar.addMenu("View")
        
        # Toolbar toggle
        self.toolbar_action = view_menu.addAction("Toolbar")
        self.toolbar_action.setCheckable(True)
        self.toolbar_action.setChecked(True)  # Checked by default
        self.toolbar_action.setToolTip("Show/hide the tool icon toolbar")
        self.toolbar_action.toggled.connect(self.toggle_toolbar)
        
        # Help Panel toggle
        self.help_panel_action = view_menu.addAction("Help Panel")
        self.help_panel_action.setCheckable(True)
        self.help_panel_action.setChecked(load_config().get("help_panel_visible", False))
        self.help_panel_action.setToolTip("Show/hide the tool help panel")
        self.help_panel_action.toggled.connect(self._toggle_help_panel)
        
        # Upload to FTP button toggle
        self.ftp_button_action = view_menu.addAction("Upload Button")
        self.ftp_button_action.setCheckable(True)
        ftp_config = load_config()
        ftp_visible = ftp_config.get("ftp_button_visible", False)
        self.ftp_button_action.setChecked(ftp_visible)
        self.ftp_button_action.setToolTip("Show/hide the Upload button")
        self.ftp_button_action.toggled.connect(self.toggle_ftp_button)
        
        # Status Bar submenu
        self.status_bar_menu = view_menu.addMenu("Status Bar")
        
        # Show/hide status bar
        config = load_config()
        self.status_bar_visible_action = self.status_bar_menu.addAction("Show Status Bar")
        self.status_bar_visible_action.setCheckable(True)
        self.status_bar_visible_action.setChecked(config.get("status_bar_visible", True))
        self.status_bar_visible_action.toggled.connect(self._toggle_status_bar_visible)
        
        self.status_bar_menu.addSeparator()
        
        # Individual section toggles
        self.status_bar_cursor_action = self.status_bar_menu.addAction("Cursor Position")
        self.status_bar_cursor_action.setCheckable(True)
        self.status_bar_cursor_action.setChecked(config.get("status_bar_cursor", True))
        self.status_bar_cursor_action.toggled.connect(lambda checked: self._toggle_status_bar_section("cursor", checked))
        
        self.status_bar_color_action = self.status_bar_menu.addAction("Pixel Color")
        self.status_bar_color_action.setCheckable(True)
        self.status_bar_color_action.setChecked(config.get("status_bar_color", True))
        self.status_bar_color_action.toggled.connect(lambda checked: self._toggle_status_bar_section("color", checked))
        
        self.status_bar_size_action = self.status_bar_menu.addAction("Image Size")
        self.status_bar_size_action.setCheckable(True)
        self.status_bar_size_action.setChecked(config.get("status_bar_size", True))
        self.status_bar_size_action.toggled.connect(lambda checked: self._toggle_status_bar_section("size", checked))
        
        self.status_bar_zoom_action = self.status_bar_menu.addAction("Zoom Level")
        self.status_bar_zoom_action.setCheckable(True)
        self.status_bar_zoom_action.setChecked(config.get("status_bar_zoom", True))
        self.status_bar_zoom_action.toggled.connect(lambda checked: self._toggle_status_bar_section("zoom", checked))
        
        self.status_bar_modified_action = self.status_bar_menu.addAction("Modified Indicator")
        self.status_bar_modified_action.setCheckable(True)
        self.status_bar_modified_action.setChecked(config.get("status_bar_modified", True))
        self.status_bar_modified_action.toggled.connect(lambda checked: self._toggle_status_bar_section("modified", checked))
        
        view_menu.addSeparator()

        # Magnifier submenu
        magnifier_menu = view_menu.addMenu("Magnifier")
        
        self.magnifier_action = magnifier_menu.addAction("Enable Magnifier")
        self.magnifier_action.setCheckable(True)
        self.magnifier_action.setToolTip(
            "Enable magnified cursor preview (Alt+Wheel also changes circle size)"
        )
        self.magnifier_action.toggled.connect(self.toggle_crosshair)
        
        magnifier_menu.addSeparator()
        
        # Size options
        self._magnifier_size_actions = {}
        magnifier_sizes = [80, 100, 120, 140, 160, 200, 240, 280, 320]
        for size in magnifier_sizes:
            action = magnifier_menu.addAction(f"{size}px")
            action.setCheckable(True)
            action.setChecked(size == self.crosshair_size)
            action.triggered.connect(lambda checked, s=size: self._set_magnifier_size(s))
            self._magnifier_size_actions[size] = action
        
        # Guide Lines (crosshair lines across canvas)
        self.guide_lines_action = view_menu.addAction("Guide Lines")
        self.guide_lines_action.setCheckable(True)
        self.guide_lines_action.setToolTip(
            "Show horizontal and vertical guide lines that follow the cursor"
        )
        self.guide_lines_action.toggled.connect(self.toggle_guide_lines)

        # Pixel Grid (shows gridlines between pixels at high zoom)
        self.pixel_grid_action = view_menu.addAction("Pixel Grid")
        self.pixel_grid_action.setCheckable(True)
        self.pixel_grid_action.setToolTip(
            "Show gridlines between pixels when zoomed in (300%+)"
        )
        self.pixel_grid_action.toggled.connect(self.toggle_pixel_grid)

        view_menu.addSeparator()
        
        # Zoom submenu
        zoom_menu = view_menu.addMenu("Zoom")
        
        zoom_in_action = zoom_menu.addAction("Zoom In")
        zoom_in_action.setShortcut("Ctrl++")
        zoom_in_action.triggered.connect(self.zoom_in)
        
        # Also add Ctrl+= as alternative (Ctrl++ requires Shift on most keyboards)
        from PyQt6.QtGui import QShortcut, QKeySequence
        zoom_in_alt = QShortcut(QKeySequence("Ctrl+="), self)
        zoom_in_alt.activated.connect(self.zoom_in)
        
        zoom_out_action = zoom_menu.addAction("Zoom Out")
        zoom_out_action.setShortcut("Ctrl+-")
        zoom_out_action.triggered.connect(self.zoom_out)
        
        zoom_reset_action = zoom_menu.addAction("Reset Zoom (100%)")
        zoom_reset_action.setShortcut("Ctrl+0")
        zoom_reset_action.triggered.connect(self.zoom_reset)
        
        zoom_menu.addSeparator()
        
        for zoom_level in ["25%", "50%", "75%", "100%", "150%", "200%", "300%", "400%"]:
            action = zoom_menu.addAction(zoom_level)
            action.triggered.connect(lambda checked, z=zoom_level: self.set_zoom_level(z))
        
        view_menu.addSeparator()
        
        # Theme submenu
        theme_menu = view_menu.addMenu("Theme")
        from PyQt6.QtGui import QActionGroup
        self._theme_action_group = QActionGroup(self)
        self._theme_action_group.setExclusive(True)
        
        config = load_config()
        saved_theme = config.get("theme_mode", "system")
        
        theme_system = theme_menu.addAction("System")
        theme_system.setCheckable(True)
        theme_system.setChecked(saved_theme == "system")
        theme_system.triggered.connect(lambda: self._set_theme("system"))
        self._theme_action_group.addAction(theme_system)
        
        theme_light = theme_menu.addAction("Light")
        theme_light.setCheckable(True)
        theme_light.setChecked(saved_theme == "light")
        theme_light.triggered.connect(lambda: self._set_theme("light"))
        self._theme_action_group.addAction(theme_light)
        
        theme_dark = theme_menu.addAction("Dark")
        theme_dark.setCheckable(True)
        theme_dark.setChecked(saved_theme == "dark")
        theme_dark.triggered.connect(lambda: self._set_theme("dark"))
        self._theme_action_group.addAction(theme_dark)
        
        # ===== Tools Menu =====
        tools_menu = menubar.addMenu("Tools")
        
        # Tools in alphabetical order
        tools = [
            ("Arrow", "arrow"),
            ("Blur", "blur"),
            ("Color && Light", "color_light"),
            ("Crop", "crop"),
            ("Cut Out", "cutout"),
            ("Cut/Paste", "cutpaste"),
            ("Freehand", "freehand"),
            ("Highlight", "highlight"),
            ("Line", "line"),
            ("Magnify Inset", "magnify_inset"),
            ("Step Marker", "step_marker"),
            ("Oval", "oval"),
            ("Outline", "outline"),
            ("Pixelate", "pixelate"),
            ("Rectangle", "rectangle"),
            ("Remove Space", "remove_space"),
            ("Text", "text"),
            ("Transform", "transform"),
        ]
        
        for name, tool_id in tools:
            action = tools_menu.addAction(name)
            action.triggered.connect(lambda checked, t=tool_id: self.select_tool(t))
        
        # ===== Settings Menu =====
        settings_menu = menubar.addMenu("Settings")
        
        edit_toolbar_action = settings_menu.addAction("Edit Toolbar")
        edit_toolbar_action.triggered.connect(self.open_toolbar_editor)
        
        tool_defaults_action = settings_menu.addAction("Tool Defaults")
        tool_defaults_action.triggered.connect(self.open_tool_defaults)
        
        edit_palette_action = settings_menu.addAction("Edit Color Palette")
        edit_palette_action.triggered.connect(self.open_palette_editor)
        
        image_settings_action = settings_menu.addAction("Image Settings")
        image_settings_action.triggered.connect(self.open_image_settings)
        
        ftp_settings_action = settings_menu.addAction("FTP Settings")
        ftp_settings_action.triggered.connect(self.open_ftp_settings)
        
        settings_menu.addSeparator()
        
        # Smooth drawing checkbox - controls anti-aliasing for previews
        self.smooth_drawing_action = settings_menu.addAction("Smooth Drawing (anti-aliased)")
        self.smooth_drawing_action.setCheckable(True)
        config = load_config()
        self.smooth_drawing_action.setChecked(config.get("smooth_drawing", False))
        self._cached_smooth_drawing = config.get("smooth_drawing", False)
        self.smooth_drawing_action.triggered.connect(self.toggle_smooth_drawing)
        
        settings_menu.addSeparator()
        
        export_settings_action = settings_menu.addAction("Export Settings...")
        export_settings_action.triggered.connect(self.export_settings)
        
        import_settings_action = settings_menu.addAction("Import Settings...")
        import_settings_action.triggered.connect(self.import_settings)
        
        # ===== Help Menu =====
        help_menu = menubar.addMenu("Help")
        
        getting_started_action = help_menu.addAction("Getting Started")
        getting_started_action.triggered.connect(self.show_getting_started)
        
        user_guide_action = help_menu.addAction("User Guide")
        user_guide_action.triggered.connect(self.show_user_guide)
        
        shortcuts_action = help_menu.addAction("Keyboard Shortcuts")
        shortcuts_action.triggered.connect(self.show_keyboard_shortcuts)
        
        help_menu.addSeparator()
        
        report_bug_action = help_menu.addAction("Report a Bug...")
        report_bug_action.triggered.connect(self.report_bug)
        
        send_feedback_action = help_menu.addAction("Send Feedback...")
        send_feedback_action.triggered.connect(self.send_feedback)
        
        known_issues_action = help_menu.addAction("Known Issues")
        known_issues_action.triggered.connect(lambda: __import__('webbrowser').open("https://github.com/dposto/magpie/issues"))
        
        help_menu.addSeparator()
        
        licenses_action = help_menu.addAction("Licenses")
        licenses_action.triggered.connect(self.show_licenses)
        
        system_info_action = help_menu.addAction("System Information")
        system_info_action.triggered.connect(self.show_system_info)
        
        help_menu.addSeparator()
        
        about_action = help_menu.addAction("About Magpie")
        about_action.triggered.connect(self.show_about_dialog)
    
    def update_ftp_upload_menu(self):
        """Update the FTP upload submenu with current destinations"""
        self.ftp_upload_menu.clear()
        
        config = load_config()
        destinations = config.get("destinations", [])
        
        if destinations:
            for dest in destinations:
                action = self.ftp_upload_menu.addAction(dest["name"])
                action.triggered.connect(lambda checked, d=dest["name"]: self.publish_to_destination(d))
            
            self.ftp_upload_menu.addSeparator()
        
        browse_action = self.ftp_upload_menu.addAction("Browse...")
        browse_action.triggered.connect(self.publish_browse)
        
        settings_action = self.ftp_upload_menu.addAction("Settings...")
        settings_action.triggered.connect(self.open_ftp_settings)
    
    def update_recent_files_menu(self):
        """Update the Recent Files submenu"""
        self.recent_files_menu.clear()
        
        config = load_config()
        recent_files = config.get("recent_files", [])
        
        if recent_files:
            for file_path in recent_files[:10]:  # Show max 10 recent files
                # Show just the filename in the menu
                filename = os.path.basename(file_path)
                action = self.recent_files_menu.addAction(filename)
                action.setToolTip(file_path)  # Full path as tooltip
                action.triggered.connect(lambda checked, path=file_path: self.open_recent_file(path))
            
            self.recent_files_menu.addSeparator()
            clear_action = self.recent_files_menu.addAction("Clear Recent Files")
            clear_action.triggered.connect(self.clear_recent_files)
        else:
            no_files_action = self.recent_files_menu.addAction("No recent files")
            no_files_action.setEnabled(False)
    
    def add_to_recent_files(self, file_path):
        """Add a file to the recent files list"""
        config = load_config()
        recent_files = config.get("recent_files", [])
        
        # Remove if already in list
        if file_path in recent_files:
            recent_files.remove(file_path)
        
        # Add to front
        recent_files.insert(0, file_path)
        
        # Keep only last 10
        recent_files = recent_files[:10]
        
        config["recent_files"] = recent_files
        save_config(config)
        
        # Update menu
        self.update_recent_files_menu()
    
    def open_recent_file(self, file_path):
        """Open a file from recent files list"""
        import os
        if os.path.exists(file_path):
            self._load_image_from_path(file_path)
        else:
            QMessageBox.warning(self, "File Not Found", f"The file no longer exists:\n{file_path}")
            # Remove from recent files
            config = load_config()
            recent_files = config.get("recent_files", [])
            if file_path in recent_files:
                recent_files.remove(file_path)
                config["recent_files"] = recent_files
                save_config(config)
                self.update_recent_files_menu()
    
    def clear_recent_files(self):
        """Clear the recent files list"""
        config = load_config()
        config["recent_files"] = []
        save_config(config)
        self.update_recent_files_menu()
    
    def set_zoom_level(self, level_str):
        """Set zoom to a specific level from menu"""
        self.zoom_combo.setCurrentText(level_str)
    
    def show_getting_started(self):
        """Show Getting Started guide"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QScrollArea, QWidget
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Getting Started")
        dialog.setMinimumSize(500, 400)
        
        layout = QVBoxLayout(dialog)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        
        # Getting started content
        guide_text = """<h2>Getting Started</h2>

<p>Magpie is a lightweight image editor built for preparing clean, annotated screenshots for documentation.</p>

<p>For detailed instructions on any tool, click the ? button in the toolbar to open the help panel. It updates automatically as you switch tools.</p>

<hr/>

<p style="font-size: 13px;">Open an Image</p>
<p>
File → Open (Ctrl+O)<br/>
Drag and drop an image file onto the window<br/>
Ctrl+V — paste from clipboard (works from any tool)<br/>
File → New — create a blank canvas
</p>

<p style="font-size: 13px;">Navigate the Canvas</p>
<p>
Ctrl+Scroll — zoom in/out<br/>
Ctrl+Drag — pan (when zoomed in)<br/>
Ctrl+0 — reset zoom to fit<br/>
+/- buttons — zoom in/out
</p>

<hr/>

<p style="font-size: 13px;">Clean Up the Screenshot</p>

<p style="font-size: 12px;">Crop</p>
<p>Drag to define the area to keep, adjust with handles, then click Apply Crop. Press Escape or Cancel to discard.</p>

<p style="font-size: 12px;">Cut Out</p>
<p>Removes a horizontal or vertical strip from the image and joins the two halves. Drag inside the strip to move it, drag the edge handles to resize. Choose a seam style (Sawtooth, Line, or No effect) to indicate removed content.</p>

<p style="font-size: 12px;">Remove Space</p>
<p>Automatically detects and removes empty rows or columns of uniform color. Choose a direction and detection mode, click Preview, then Apply. Adjust Keep, Min Gap, and Tolerance sliders to fine-tune.</p>

<hr/>

<p style="font-size: 13px;">Annotate</p>

<p style="font-size: 12px;">Step Marker</p>
<p>Click to place numbered badges that auto-increment. Drag the badge to reposition, drag the tail handle to point at a target. Click Apply All to commit.</p>

<p style="font-size: 12px;">Arrow and Line</p>
<p>Click and drag to draw. After releasing, four control point handles appear — drag the endpoints to reposition, or drag the inner handles to bend into a curve. Click outside the shape to apply, right-click to cancel.</p>

<p style="font-size: 12px;">Text</p>
<p>Click and drag to create a text box, then type. Adjust font, size, alignment, bold/italic/underline, shadow, and outline in the toolbar. Click outside the text box to apply.</p>

<p style="font-size: 12px;">Highlight</p>
<p>Three styles: Pen (freehand stroke), Rectangle (semi-transparent box), and Spotlight (dims everything outside the rectangle). Strokes apply immediately on release.</p>

<p style="font-size: 12px;">Rectangle and Oval</p>
<p>Click and drag to draw. Hold Shift for a perfect square or circle. Drag handles to resize after drawing. Enable Fill to use the Secondary color. Click outside to apply.</p>

<p style="font-size: 12px;">Magnify Inset</p>
<p>Click and drag to select a source area, then click elsewhere to place a zoomed callout. Adjust shape, zoom level, border, and connection lines. Click Apply to commit.</p>

<hr/>

<p style="font-size: 13px;">Redact and Adjust</p>

<p style="font-size: 12px;">Pixelate</p>
<p>Drag a rectangle over sensitive information. The mosaic effect previews in real time. Click outside to apply. Adjust Block Size for more or less obscuring.</p>

<p style="font-size: 12px;">Blur</p>
<p>Drag a rectangle to define the area. Choose Inside or Outside, and adjust Radius and Feather. Click outside to apply.</p>

<p style="font-size: 12px;">Color and Light</p>
<p>Adjust Brightness, Contrast, Hue, and Sharpness with sliders. All adjustments preview live and are computed from the original image. Click Apply to commit, Reset to revert.</p>

<p style="font-size: 12px;">Transform</p>
<p>Rotate (90° quick buttons or custom angle), flip horizontally/vertically, and resize by pixel dimensions or percentage. Changes preview live. Click Apply to commit.</p>

<p style="font-size: 12px;">Outline</p>
<p>Adds a border around the entire image. Set thickness and corner radius, click Preview to see it, then Apply to commit.</p>

<hr/>

<p style="font-size: 13px;">Draw Freely</p>

<p style="font-size: 12px;">Freehand</p>
<p>Six modes: Pen, Brush, Spray Can, Flood Fill, Color Eraser, and Eraser. Adjust size and tolerance as needed. Uses the Primary color.</p>

<p style="font-size: 12px;">Cut / Paste</p>
<p>Drag to select a rectangular area, then Cut, Copy, or Delete. Click inside a selection to drag-move it. After pasting, drag to reposition and use handles to resize. Click outside to apply.</p>

<hr/>

<p style="font-size: 13px;">Colors</p>
<p>Click the Primary or Secondary swatch to choose which one to edit, then pick a color from the palette. Use the eyedropper to pick a color directly from the canvas.</p>

<p style="font-size: 13px;">Undo and Save</p>
<p>
Ctrl+Z — undo<br/>
Ctrl+Y — redo<br/>
Ctrl+S — save<br/>
Ctrl+C — copy to clipboard<br/>
Use the Upload dropdown to publish via FTP, FTPS, or SFTP if configured.
</p>

<p style="font-size: 13px;">Typical Workflow</p>
<p>
1. Open or paste a screenshot<br/>
2. Crop or Cut Out unwanted areas<br/>
3. Add Step Markers and Arrows<br/>
4. Highlight key areas<br/>
5. Pixelate or blur sensitive data<br/>
6. Save or Upload
</p>
"""
        
        label = QLabel(guide_text)
        label.setWordWrap(True)
        label.setTextFormat(Qt.TextFormat.RichText)
        label.setStyleSheet("padding: 10px;")
        content_layout.addWidget(label)
        content_layout.addStretch()
        
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        layout.addWidget(ok_btn)
        
        dialog.exec()
    
    def show_user_guide(self):
        """Open User Guide in the default browser"""
        import webbrowser
        webbrowser.open("https://dposto.github.io/magpie/")
    
    def show_keyboard_shortcuts(self):
        """Show keyboard shortcuts reference"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QScrollArea, QWidget, QGridLayout, QFrame
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Keyboard Shortcuts")
        dialog.setMinimumSize(500, 450)
        
        layout = QVBoxLayout(dialog)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        
        # Detect dark mode for key label styling
        is_dark = self.palette().window().color().lightnessF() < 0.5
        if is_dark:
            key_style = "background-color: #444; color: #eee; padding: 3px 8px; border: 1px solid #666; border-radius: 3px;"
        else:
            key_style = "background-color: #e8e8e8; color: #222; padding: 3px 8px; border: 1px solid #ccc; border-radius: 3px;"
        
        # Shortcuts organized by category
        shortcuts = [
            ("File", [
                ("Ctrl+N", "New blank image"),
                ("Ctrl+O", "Open file"),
                ("Ctrl+S", "Save"),
                ("Ctrl+Shift+S", "Save As"),
                ("Ctrl+Shift+Z", "Restore previous image"),
                ("Alt+F4", "Exit"),
            ]),
            ("Edit", [
                ("Ctrl+Z", "Undo"),
                ("Ctrl+Y", "Redo"),
                ("Ctrl+C", "Copy selection or image"),
                ("Ctrl+V", "Paste from clipboard (works from any tool)"),
                ("Delete", "Delete selection or paste preview"),
            ]),
            ("View", [
                ("Ctrl++ / Ctrl+=", "Zoom in"),
                ("Ctrl+-", "Zoom out"),
                ("Ctrl+0", "Reset zoom to 100%"),
            ]),
            ("Canvas Navigation", [
                ("Ctrl+Scroll", "Zoom in/out"),
                ("Ctrl+Drag", "Pan/scroll the canvas"),
                ("Scroll Wheel", "Scroll vertically"),
                ("Alt+Scroll", "Adjust magnifier size (when enabled)"),
            ]),
            ("Drawing Tools", [
                ("Left Click", "Draw / place with primary color"),
                ("Right Click", "Cancel current shape"),
            ]),
            ("Text Tool", [
                ("Enter", "Apply current text"),
                ("Escape", "Cancel text editing"),
                ("Left / Right", "Move cursor"),
                ("Home / End", "Jump to start / end of text"),
                ("Backspace / Delete", "Delete characters"),
            ]),
        ]
        
        for category, items in shortcuts:
            # Category header
            header = QLabel(f"<b>{category}</b>")
            header.setStyleSheet("font-size: 13px; padding-top: 10px;")
            content_layout.addWidget(header)
            
            # Shortcuts grid
            grid = QGridLayout()
            grid.setColumnStretch(1, 1)
            for i, (key, desc) in enumerate(items):
                key_label = QLabel(f"<code>{key}</code>")
                key_label.setStyleSheet(key_style)
                key_label.setTextFormat(Qt.TextFormat.RichText)
                desc_label = QLabel(desc)
                desc_label.setStyleSheet("padding-left: 10px;")
                grid.addWidget(key_label, i, 0)
                grid.addWidget(desc_label, i, 1)
            
            grid_widget = QWidget()
            grid_widget.setLayout(grid)
            content_layout.addWidget(grid_widget)
        
        content_layout.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        layout.addWidget(ok_btn)
        
        dialog.exec()
    
    def report_bug(self):
        """Open bug report on GitHub"""
        import webbrowser
        import urllib.parse
        
        # Gather system info for the bug report
        system_info = self._get_system_info_text()
        
        # Create issue body template
        body = f"""## Bug Description
[Describe what happened]

## Steps to Reproduce
1. 
2. 
3. 

## Expected Behavior
[What should have happened]

## Actual Behavior
[What actually happened]

## System Information
```
{system_info}
```
"""
        
        # GitHub new issue URL with pre-filled template
        github_url = f"https://github.com/dposto/magpie/issues/new?labels=bug&title=Bug:+&body={urllib.parse.quote(body)}"
        
        try:
            webbrowser.open(github_url)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open browser:\n{e}\n\nPlease report bugs at:\nhttps://github.com/dposto/magpie/issues")
    
    def send_feedback(self):
        """Open feedback dialog with GitHub options"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout
        import webbrowser
        import urllib.parse
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Send Feedback")
        dialog.setMinimumWidth(350)
        
        layout = QVBoxLayout(dialog)
        
        layout.addWidget(QLabel("<b>What would you like to send?</b>"))
        layout.addSpacing(10)
        
        # Option buttons
        idea_btn = QPushButton("💡  Suggest a Feature")
        idea_btn.setStyleSheet("text-align: left; padding: 10px;")
        idea_btn.clicked.connect(lambda: self._open_github_issue("enhancement", "Feature Request: ", dialog))
        layout.addWidget(idea_btn)
        
        bug_btn = QPushButton("🐞  Report a Bug")
        bug_btn.setStyleSheet("text-align: left; padding: 10px;")
        bug_btn.clicked.connect(lambda: (dialog.accept(), self.report_bug()))
        layout.addWidget(bug_btn)
        
        question_btn = QPushButton("❓  Ask a Question")
        question_btn.setStyleSheet("text-align: left; padding: 10px;")
        question_btn.clicked.connect(lambda: self._open_github_issue("question", "Question: ", dialog))
        layout.addWidget(question_btn)
        
        layout.addSpacing(10)
        
        # Link to all discussions/issues
        github_link = QLabel('<a href="https://github.com/dposto/magpie/issues">View all issues on GitHub</a>')
        github_link.setOpenExternalLinks(True)
        github_link.setStyleSheet("color: #0066cc;")
        layout.addWidget(github_link)
        
        layout.addSpacing(10)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        cancel_btn.setDefault(True)
        layout.addWidget(cancel_btn)
        
        dialog.exec()
    
    def _open_github_issue(self, label, title_prefix, parent_dialog):
        """Helper to open GitHub issue with label"""
        import webbrowser
        import urllib.parse
        
        parent_dialog.accept()
        
        github_url = f"https://github.com/dposto/magpie/issues/new?labels={label}&title={urllib.parse.quote(title_prefix)}"
        
        try:
            webbrowser.open(github_url)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open browser:\n{e}")
    
    def show_licenses(self):
        """Show license information"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QScrollArea, QWidget, QTextEdit
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Licenses")
        dialog.setMinimumSize(550, 450)
        
        layout = QVBoxLayout(dialog)
        
        license_text = f"""<h2>Licenses</h2>

<p style="font-size: 13px;">Magpie</p>
<p>Copyright &copy; 2025-2026 David Posto<br/>
License: MIT License</p>

<p style="padding: 10px; margin: 10px 0; font-family: monospace; font-size: 11px;">
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the &ldquo;Software&rdquo;), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:<br/><br/>
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.<br/><br/>
THE SOFTWARE IS PROVIDED &ldquo;AS IS&rdquo;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
</p>

<hr/>

<p style="font-size: 13px;">Third-Party Libraries</p>

<p style="font-size: 12px;">PyQt6</p>
<p>Copyright &copy; Riverbank Computing Limited<br/>
License: GPL v3 / Commercial</p>

<p style="font-size: 12px;">Pillow (PIL Fork)</p>
<p>Copyright &copy; 2010 Jeffrey A. Clark and contributors<br/>
License: HPND License (Historical Permission Notice and Disclaimer)</p>

<p style="font-size: 12px;">NumPy</p>
<p>Copyright &copy; NumPy Developers<br/>
License: BSD 3-Clause License</p>

<p style="font-size: 12px;">keyring</p>
<p>Copyright &copy; Jason R. Coombs and contributors<br/>
License: MIT License</p>

<p style="font-size: 12px;">paramiko (optional, for SFTP)</p>
<p>Copyright &copy; Jeff Forcier and contributors<br/>
License: LGPL v2.1</p>

<p style="font-size: 12px;">Python</p>
<p>Copyright &copy; Python Software Foundation<br/>
License: PSF License</p>

<hr/>

<p style="font-size: 13px;">Icons</p>

<p>Tool and toolbar icons are sourced from <a href="https://www.svgrepo.com">SVG Repo</a> and may have been modified.</p>

<p style="font-size: 12px;">SVG Repo License</p>
<p>
No attribution required. Icons are provided under the SVG Repo License,<br/>
which permits free use in personal and commercial projects.<br/><br/>
Vectors and icons by <a href="https://www.svgrepo.com">SVG Repo</a>
</p>
"""
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QLabel(license_text)
        content.setWordWrap(True)
        content.setTextFormat(Qt.TextFormat.RichText)
        content.setOpenExternalLinks(True)
        content.setStyleSheet("padding: 10px;")
        content.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        layout.addWidget(ok_btn)
        
        dialog.exec()
    
    def show_system_info(self):
        """Show system information dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QTextEdit
        
        dialog = QDialog(self)
        dialog.setWindowTitle("System Information")
        dialog.setMinimumSize(450, 350)
        
        layout = QVBoxLayout(dialog)
        
        # Gather system info
        info_text = self._get_system_info_text()
        
        # Display in a text edit for easy copying
        text_edit = QTextEdit()
        text_edit.setPlainText(info_text)
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("font-family: monospace;")
        layout.addWidget(text_edit)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(lambda: self._copy_system_info(info_text))
        btn_layout.addWidget(copy_btn)
        
        btn_layout.addStretch()
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        ok_btn.setDefault(True)
        btn_layout.addWidget(ok_btn)
        
        layout.addLayout(btn_layout)
        
        dialog.exec()
    
    def _get_system_info_text(self):
        """Gather system information for display/copying"""
        import platform
        import sys
        
        try:
            from PyQt6.QtCore import QT_VERSION_STR, PYQT_VERSION_STR
            qt_version = QT_VERSION_STR
            pyqt_version = PYQT_VERSION_STR
        except:
            qt_version = "Unknown"
            pyqt_version = "Unknown"
        
        try:
            from PIL import __version__ as pil_version
        except:
            pil_version = "Unknown"
        
        info_lines = [
            "Magpie",
            "=" * 40,
            f"App Version:     {APP_VERSION}",
            "",
            "Python Environment",
            "-" * 40,
            f"Python:          {sys.version.split()[0]}",
            f"PyQt6:           {pyqt_version}",
            f"Qt:              {qt_version}",
            f"Pillow:          {pil_version}",
            "",
            "System",
            "-" * 40,
            f"OS:              {platform.system()} {platform.release()}",
            f"Platform:        {platform.platform()}",
            f"Architecture:    {platform.machine()}",
        ]
        
        # Try to get more system details
        try:
            if platform.system() == "Linux":
                try:
                    with open("/etc/os-release") as f:
                        for line in f:
                            if line.startswith("PRETTY_NAME="):
                                distro = line.split("=")[1].strip().strip('"')
                                info_lines.append(f"Distribution:    {distro}")
                                break
                except:
                    pass
        except:
            pass
        
        return "\n".join(info_lines)
    
    def _copy_system_info(self, text):
        """Copy system info to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "Copied", "System information copied to clipboard.")

    def show_about_dialog(self):
        """Show the About dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle("About Magpie")
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout(dialog)
        
        # App info text
        info_text = f"""<div style="text-align: center;">
<h2 style="margin-bottom: 5px;">Magpie</h2>
<p style="color: #666; margin-top: 0;">Permissive Annotation Extension</p>
<p style="color: #666; margin-top: 0;">Version {APP_VERSION}</p>
</div>

<p>A simple but powerful screenshot annotation tool for technical writers.</p>

<p>Features:</p>
<ul style="font-size: 12px;">
<li>Shape tools: Rectangle, Oval, Line, Arrow (with Bezier curve control points)</li>
<li>Annotation tools: Text, Step Marker, Highlight (Pen, Rectangle, Spotlight)</li>
<li>Freehand drawing: Pen, Brush, Spray Can, Flood Fill, Color Eraser, Eraser</li>
<li>Image tools: Crop, Cut Out, Pixelate, Blur, Remove Space, Magnify Inset</li>
<li>Adjustments: Color &amp; Light (Brightness, Contrast, Hue, Sharpness), Transform (Rotate, Flip, Resize), Outline</li>
<li>Color palette with Primary and Secondary colors and pick-from-canvas eyedropper</li>
<li>Full clipboard integration (copy, paste, paste from system clipboard)</li>
<li>FTP publishing with saved destinations</li>
<li>Dark mode support</li>
</ul>

<p style="color: #666; font-size: 11px; margin-top: 20px;">
A sudo sketchy project by David Posto.<br/><br/>
See Help → Keyboard Shortcuts for shortcut reference.<br/>
See Help → Licenses for third-party license information.
</p>
"""
        
        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        info_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        ok_btn.setDefault(True)
        button_layout.addWidget(ok_btn)
        
        layout.addLayout(button_layout)
        
        dialog.exec()
    
    def copy_about_info(self, html_text, dialog):
        """Copy about info to clipboard as plain text"""
        import re
        # Strip HTML tags for plain text
        plain_text = re.sub(r'<[^>]+>', '', html_text)
        plain_text = plain_text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        # Clean up extra whitespace
        plain_text = '\n'.join(line.strip() for line in plain_text.split('\n') if line.strip())
        
        QApplication.clipboard().setText(plain_text)
        
        # Brief feedback
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.information(dialog, "Copied", "About information copied to clipboard.")

    def update_tool_buttons_state(self):
        """Enable/disable tools based on source availability"""
        
        # Update Set as Image button - enabled if there's paste content OR a selection
        has_paste_content = (
            self.viewer.cutpaste_paste_pos is not None and 
            self.viewer.cutpaste_clipboard is not None
        )
        has_selection = (
            self.viewer.cutpaste_selection is not None or
            (self.viewer.sel_start is not None and self.viewer.sel_end is not None)
        )
        # Set as Image available for both paste content and selections (including Crop tool selection)
        self.btn_crop_canvas.setEnabled(has_paste_content or has_selection)
        
        # Update Cut/Paste tool buttons - enabled when there's a selection OR paste preview
        self.btn_copy.setEnabled(has_paste_content or has_selection)
        self.btn_cut.setEnabled(has_paste_content or has_selection)
        self.btn_cutpaste_crop.setEnabled(has_paste_content or has_selection)
        
        # Update Crop tool buttons - enabled when there's a selection
        self.btn_crop_apply.setEnabled(has_selection)
        self.btn_crop_cancel.setEnabled(has_selection)
        
        # Update undo/redo buttons based on history availability
        # Also enable undo when step markers are placed (can undo per-marker)
        has_undo = len(self.viewer.history) > 0
        if hasattr(self, 'active_tool') and self.active_tool == "step_marker":
            has_undo = has_undo or bool(self.viewer.step_markers) or bool(self.viewer.current_marker)
        self.btn_undo.setEnabled(has_undo)
        has_redo = len(self.viewer.redo_stack) > 0
        if hasattr(self, 'active_tool') and self.active_tool == "step_marker":
            has_redo = has_redo or bool(self.viewer.step_markers_redo)
        self.btn_redo.setEnabled(has_redo)

    def on_source_loaded(self):
        """Call this when user selects/loads a source image"""
        self.source_loaded = True
        self.update_tool_buttons_state()
        # Update status bar with new image info
        self._update_status_bar()

    def on_tool_combo_changed(self, index):
        """Handle tool selection from dropdown"""
        tool = self.tool_combo.itemData(index)
        if tool:
            self.select_tool(tool)
        else:
            # Index 0 is the "Select tool" placeholder. Any other None-data row is a separator; ignore it.
            if index == 0:
                # "Select tool" placeholder selected - show empty panel
                # Clear cutpaste state if active
                if self.active_tool == "cutpaste":
                    self.viewer.cutpaste_selection = None
                    self.viewer.cutpaste_paste_pos = None
                    self.viewer.cutpaste_clipboard = None
                    self.viewer.sel_start = None
                    self.viewer.sel_end = None
                self.active_tool = None
                self.tool_stack.setCurrentIndex(0)
                self.tool_stack_row2.setVisible(False)
                self._active_color_slot = 'primary'
                self._refresh_color_selector_ui()
                self._set_active_color_slot('primary')
                # Uncheck all toolbar buttons
                for btn in self.tool_buttons.values():
                    btn.setChecked(False)
            else:
                # Separator clicked: revert to the current active tool (or placeholder if none).
                prev_tool = getattr(self, 'active_tool', None)
                prev_idx = self.tool_combo.findData(prev_tool) if prev_tool else 0
                if prev_idx < 0:
                    prev_idx = 0
                self.tool_combo.blockSignals(True)
                self.tool_combo.setCurrentIndex(prev_idx)
                self.tool_combo.blockSignals(False)
                return
    
    def _apply_pending_annotations(self):
        """Auto-apply any uncommitted shapes/annotations to the image.
        
        Called before tool switches, paste operations, and other actions
        that change the image context, so in-progress work isn't lost.
        """
        if not self.viewer.image:
            return
        if self.active_tool == "rectangle" and self.viewer.current_rect:
            self.apply_pending_rectangles([self.viewer.current_rect])
        elif self.active_tool == "oval" and self.viewer.current_oval:
            self.apply_pending_ovals([self.viewer.current_oval])
        elif self.active_tool == "line" and self.viewer.current_line:
            self.apply_pending_lines([self.viewer.current_line])
        elif self.active_tool == "arrow" and self.viewer.current_arrow:
            self.apply_pending_arrows([self.viewer.current_arrow])
        elif self.active_tool == "highlight":
            self.apply_all_highlights()
        elif self.active_tool == "step_marker":
            if self.viewer.current_marker:
                self.viewer.step_markers.append(self.viewer.current_marker)
                self.viewer.marker_counter += 1
                self.viewer.current_marker = None
                self.viewer.placing_new_marker = False
            if self.viewer.step_markers:
                self.apply_markers_to_image()
        elif self.active_tool == "text":
            if self.viewer.current_text:
                self.apply_text_to_image()
        elif self.active_tool == "magnify_inset":
            if self.viewer.inset_source_rect and self.viewer.inset_dest_pos:
                self._apply_magnify_inset()
        elif self.active_tool == "blur":
            if self.viewer.current_blur_rect:
                self.apply_blur()
        elif self.active_tool == "pixelate":
            if self.viewer.current_pixelate_rect:
                self.apply_pixelate()
        
        # Always clear shape preview state — even if the apply above handled it,
        # this ensures the WYSIWYG preview canvas doesn't linger and paint over
        # subsequent operations like paste
        self.viewer.clear_shape_preview()
        self.viewer.current_rect = None
        self.viewer.current_oval = None
        self.viewer.current_line = None
        self.viewer.current_arrow = None
        self.viewer.current_pixelate_rect = None
        self.viewer.current_blur_rect = None

    def _escape_cancel(self):
        """Cancel/discard the current tool's uncommitted state (Escape key).
        
        Mirrors right-click cancel behavior for each tool.
        Also dismisses paste preview from any tool (Ctrl+V can paste from anywhere).
        """
        v = self.viewer
        tool = self.active_tool
        
        # Dismiss paste preview regardless of active tool —
        # Ctrl+V can create a paste preview from any tool
        if v.cutpaste_paste_pos and v.cutpaste_clipboard:
            v.cutpaste_paste_pos = None
            v.cutpaste_clipboard = None
            v.update()
            self.update_tool_buttons_state()
            return
        
        # Text tool: skip if actively editing (viewer keyPressEvent handles Escape there).
        # Handle the non-editing case where a text box exists but isn't being edited.
        if tool == "text":
            if v.text_editing:
                return  # Let viewer's keyPressEvent handle it
            if v.current_text:
                v.current_text = None
                v.text_editing = False
                v.stop_cursor_blink()
                v.update()
                return
        
        # Shape tools: discard current shape
        elif tool == "rectangle":
            if v.current_rect:
                v.current_rect = None
                v.sel_start = None
                v.sel_end = None
                v.clear_shape_preview()
                v.update()
                return
        elif tool == "oval":
            if v.current_oval:
                v.current_oval = None
                v.sel_start = None
                v.sel_end = None
                v.clear_shape_preview()
                v.update()
                return
        elif tool == "line":
            if v.current_line:
                v.current_line = None
                v.line_keep_straight = True
                v.sel_start = None
                v.sel_end = None
                v.clear_shape_preview()
                v.update()
                return
        elif tool == "arrow":
            if v.current_arrow:
                v.current_arrow = None
                v.arrow_keep_straight = True
                v.sel_start = None
                v.sel_end = None
                v.clear_shape_preview()
                v.update()
                return
        
        # Highlight tool: discard current rectangle or strokes
        elif tool == "highlight":
            if v.current_highlight_rect or getattr(v, 'highlight_strokes', []):
                v.current_highlight_rect = None
                v.highlight_strokes = []
                v.current_highlight_stroke = None
                v.sel_start = None
                v.sel_end = None
                v.update()
                return
        
        # Step marker: discard current marker being placed
        elif tool == "step_marker":
            if v.current_marker:
                v.current_marker = None
                v.placing_new_marker = False
                v.dragging_badge = False
                v.dragging_tail_handle = False
                v.active_marker_index = None
                v.update()
                self.update_tool_buttons_state()
                return
        
        # Cut/Paste tool: clear paste preview or selection
        elif tool == "cutpaste":
            if v.cutpaste_paste_pos or v.cutpaste_selection:
                v.cutpaste_paste_pos = None
                v.cutpaste_clipboard = None
                v.cutpaste_selection = None
                v.sel_start = None
                v.sel_end = None
                v.update()
                self.update_tool_buttons_state()
                return
        
        # Crop / Cut Out: clear selection
        elif tool in ("crop", "cutout"):
            if v.sel_start is not None or v.selection_finalized:
                v.sel_start = None
                v.sel_end = None
                v.selection_finalized = False
                v.dragging_handle = None
                v._crop_moving = False
                v._cutout_preview_key = None
                v._cutout_preview_pm = None
                v.update()
                self.update_tool_buttons_state()
                return
        
        # Blur / Pixelate: discard current rectangle
        elif tool == "blur":
            if v.current_blur_rect:
                v.current_blur_rect = None
                v.sel_start = None
                v.sel_end = None
                v.update()
                return
        elif tool == "pixelate":
            if v.current_pixelate_rect:
                v.current_pixelate_rect = None
                v.sel_start = None
                v.sel_end = None
                v.update()
                return
        
        # Magnify inset: discard current inset
        elif tool == "magnify_inset":
            if v.inset_source_rect or v.inset_dest_pos:
                v.inset_source_rect = None
                v.inset_dest_pos = None
                v.inset_dest_size = None
                v.sel_start = None
                v.sel_end = None
                v.clear_shape_preview()
                v.update()
                return
        
        elif tool == "transform":
            if getattr(self, '_transform_preview_image', None) is not None:
                self._transform_cancel_preview()
                return
            if getattr(self, '_resize_preview_image', None) is not None:
                self._transform_resize_cancel()
                return
        
        elif tool == "color_light":
            if getattr(self, '_cl_preview_image', None) is not None:
                self._color_light_cancel()
                return

    def _delete_selection(self):
        """Delete selected/pasted area without copying to clipboard (Delete key).
        
        For paste preview: removes the pasted content (discards it).
        For cutpaste selection: fills the selected area with white.
        """
        v = self.viewer
        
        # Skip if text tool is actively editing (Delete has meaning there)
        if self.active_tool == "text" and v.text_editing and v.current_text:
            return
        
        # If there's a paste preview, just discard it
        if v.cutpaste_paste_pos and v.cutpaste_clipboard:
            v.cutpaste_paste_pos = None
            v.cutpaste_clipboard = None
            v.update()
            self.update_tool_buttons_state()
            logging.debug("Deleted paste preview")
            return
        
        # If there's a cutpaste selection, fill with white (like cut but no clipboard)
        if self.active_tool == "cutpaste" and v.cutpaste_selection:
            x1, y1, x2, y2 = v.cutpaste_selection
            
            # Convert to image coordinates
            img_x1 = int((x1 - v.offset.x()) / v.scale)
            img_y1 = int((y1 - v.offset.y()) / v.scale)
            img_x2 = int((x2 - v.offset.x()) / v.scale)
            img_y2 = int((y2 - v.offset.y()) / v.scale)
            
            # Clamp to image boundaries
            img_x1 = max(0, min(v.image.width, img_x1))
            img_y1 = max(0, min(v.image.height, img_y1))
            img_x2 = max(0, min(v.image.width, img_x2))
            img_y2 = max(0, min(v.image.height, img_y2))
            
            # Fill with white
            qimg = PilToQImage(v.image, for_painting=True)
            painter = QPainter(qimg)
            painter.fillRect(img_x1, img_y1, img_x2 - img_x1, img_y2 - img_y1, QColor(255, 255, 255))
            painter.end()
            
            result = QImageToPil(qimg)
            v.set_image(result)
            
            # Clear selection
            v.cutpaste_selection = None
            v.sel_start = None
            v.sel_end = None
            v.update()
            self.update_tool_buttons_state()
            logging.debug("Deleted selection")
            return

    def select_tool(self, tool):
        if not tool:
            return
            
        # Auto-apply any pending annotations before switching tools
        self._apply_pending_annotations()
        
        # Reset non-apply tool states when switching away
        if self.active_tool == "outline":
            self.viewer.outline_preview_active = False
            self.outline_preview_btn.setText("Preview")
            self.outline_apply_btn.setEnabled(False)
        elif self.active_tool == "remove_space":
            self.viewer.rspace_preview_image = None
            self.rspace_apply_btn.setEnabled(False)
            self.rspace_cancel_btn.setEnabled(False)
        elif self.active_tool == "cutpaste":
            # Clear any selection or unset paste when switching away
            self.viewer.cutpaste_selection = None
            self.viewer.cutpaste_paste_pos = None
            self.viewer.cutpaste_clipboard = None
            self.viewer.cutpaste_resizing = None
            self.viewer.sel_start = None
            self.viewer.sel_end = None
            self.viewer.update()
        elif self.active_tool == "transform":
            # Auto-apply any active rotation preview when switching away
            if getattr(self, '_transform_preview_image', None) is not None:
                self._transform_rotate_custom()
            # Auto-apply any active resize preview when switching away
            if getattr(self, '_resize_preview_image', None) is not None:
                self._transform_resize()
        elif self.active_tool == "color_light":
            # Auto-apply any active color/light adjustments when switching away
            if getattr(self, '_cl_preview_image', None) is not None:
                self._color_light_apply()
        
        self.active_tool = tool
        self._update_active_color_slot_from_tool()
        self._update_help_content(tool)
        # Tool indices match alphabetical dropdown order (index 0 is "Select tool" placeholder)
        tool_index = {
            "arrow": 1, "blur": 2, "color_light": 3, "crop": 4, "cutout": 5, "cutpaste": 6, "freehand": 7,
            "highlight": 8, "line": 9, "magnify_inset": 10, "step_marker": 11, "oval": 12, "outline": 13, "pixelate": 14,
            "rectangle": 15, "remove_space": 16, "text": 17, "transform": 18
        }[tool]
        self.tool_stack.setCurrentIndex(tool_index)
        
        # Auto-show/hide second row for tools that have overflow settings
        if tool in self._tool_row2_index:
            self.tool_stack_row2.setCurrentIndex(self._tool_row2_index[tool])
            self.tool_stack_row2.setVisible(True)
        else:
            self.tool_stack_row2.setVisible(False)
        
        # Update transform size display when selecting transform tool
        if tool == "transform":
            self._transform_update_size_display()
        
        # Update toolbar button states
        for tool_id, btn in self.tool_buttons.items():
            btn.setChecked(tool_id == tool)
        
        # Clear ALL selections and tool states when switching tools
        self.viewer.sel_start = None
        self.viewer.sel_end = None
        self.viewer.drag_mode = None
        self.viewer.current_rect = None
        self.viewer.current_oval = None
        self.viewer.current_line = None
        self.viewer.current_arrow = None
        self.viewer.clear_shape_preview()
        self.viewer.rectangles = []
        self.viewer.ovals = []
        self.viewer.lines = []
        self.viewer.arrows = []
        self.viewer.dragging_handle = None
        self.viewer.current_highlight_rect = None
        self.viewer.highlight_strokes = []
        self.viewer.current_highlight_stroke = None
        self.viewer.current_pixelate_rect = None
        self.viewer.current_blur_rect = None
        self.viewer.outline_preview_active = False
        self.viewer.rspace_preview_image = None
        self.viewer.inset_source_rect = None
        self.viewer.inset_dest_pos = None
        self.viewer.inset_dragging_dest = False
        self.viewer.current_marker = None
        self.viewer.current_text = None
        self.viewer.update()
    
    def _create_toolbar_button(self, tool_id):
        """Create a toolbar QAction for the given tool"""
        from PyQt6.QtGui import QAction
        
        tooltip = self.toolbar_tool_definitions.get(tool_id, tool_id.title())
        
        action = QAction(self)
        action.setToolTip(tooltip)
        action.setCheckable(True)
        action.triggered.connect(lambda checked, t=tool_id: self.select_tool_from_toolbar(t))
        
        icon = self._create_tool_icon(tool_id)
        action.setIcon(icon)
        
        self._toolbar_action_group.addAction(action)
        
        return action
    
    def _refresh_bar_icons(self):
        """Reload top bar button icons with current theme colors."""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        small_icons = {"undo", "redo", "minus", "plus"}
        for icon_name, btn in self._bar_icon_map.items():
            svg_path = os.path.join(script_dir, "icons", f"{icon_name}.svg")
            if os.path.exists(svg_path):
                try:
                    icon = self._load_themed_svg_icon(svg_path)
                    if icon and not icon.isNull():
                        btn.setIcon(icon)
                        if icon_name in small_icons:
                            btn.setIconSize(QSize(18, 18))
                            btn.setText("")
                            btn.setFixedWidth(30)
                        else:
                            btn.setIconSize(QSize(24, 24))
                            btn.setText("")
                            btn.setFixedWidth(36)
                except Exception:
                    pass
            else:
                if icon_name == "undo":
                    btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowBack))
                elif icon_name == "redo":
                    btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowForward))
                elif icon_name == "minus":
                    btn.setText("-")
                elif icon_name == "plus":
                    btn.setText("+")
    
    def _toggle_help_panel(self, checked):
        """Show or hide the help panel."""
        self.help_panel.setVisible(checked)
        # Sync the View menu action
        if hasattr(self, 'help_panel_action'):
            self.help_panel_action.blockSignals(True)
            self.help_panel_action.setChecked(checked)
            self.help_panel_action.blockSignals(False)
        config = load_config()
        config["help_panel_visible"] = checked
        save_config(config)

    def _update_help_content(self, tool_id):
        """Update the help panel content for the given tool."""
        help_texts = {
            None: (
                "Getting Started",
                "Welcome to Magpie!<br><br>"
                "Open an image:<br>"
                "• File → Open<br>"
                "• Paste with Ctrl+V<br>"
                "• Drag and drop a file into the canvas<br><br>"
                "New blank canvas:<br>"
                "• Click New or File → New<br><br>"
                "Select a tool:<br>"
                "• Choose from the toolbar or Tools menu<br><br>"
                "Zoom:<br>"
                "• Ctrl+Scroll over the canvas<br>"
                "• +/- buttons<br><br>"
                "Undo / Redo:<br>"
                "• Ctrl+Z / Ctrl+Y<br><br>"
                "Save:<br>"
                "• Ctrl+S<br>"
                "• Copy to clipboard with Ctrl+C<br><br>"
                "Colors:<br>"
                "• Click the Primary or Secondary swatch to choose which to change, then pick from the palette"
            ),
            "arrow": (
                "Arrow",
                "Draw arrows on the image.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw an arrow from start to end point<br>"
                "• Release to place the arrow in edit mode<br><br>"
                "Control points:<br>"
                "• Four handles appear — two endpoints and two inner curve handles<br>"
                "• Drag the endpoints to reposition the arrow — the inner handles follow automatically to keep it straight<br>"
                "• Drag an inner handle to bend the arrow into a curve — once moved, the inner handles become independent and endpoints will no longer move them<br><br>"
                "Committing:<br>"
                "• Click anywhere outside the arrow to set it in place<br>"
                "• Right-click to cancel without applying<br><br>"
                "Options:<br>"
                "• Width — line thickness<br>"
                "• Rounded — smooth line joins<br><br>"
                "Uses the Primary color."
            ),
            "blur": (
                "Blur",
                "Blur or obscure areas of the image.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw a rectangle over the area to blur<br>"
                "• A live preview shows the blur effect as you draw<br><br>"
                "Editing:<br>"
                "• Drag the corner or edge handles to resize the rectangle<br>"
                "• The blur preview updates in real time as you adjust<br><br>"
                "Committing:<br>"
                "• Click anywhere outside the rectangle to apply<br>"
                "• Right-click to cancel without applying<br><br>"
                "Options:<br>"
                "• Area — Inside blurs within the rectangle, Outside blurs everything else<br>"
                "• Radius — blur strength (higher = more blurred)<br>"
                "• Feather — soft edge that blends the blur boundary (% of shortest side)"
            ),
            "color_light": (
                "Color & Light",
                "Adjust brightness, contrast, hue, and sharpness of the entire image.<br><br>"
                "Usage:<br>"
                "• Drag any slider to see a live preview<br>"
                "• All adjustments are computed from the original image, so sliders don't compound on each other<br><br>"
                "Committing:<br>"
                "• Click Apply to commit the adjustments to the image<br>"
                "• Click Reset to revert all sliders to their defaults<br><br>"
                "Sliders:<br>"
                "• Brightness — lighten or darken the image<br>"
                "• Contrast — increase or flatten tonal range<br>"
                "• Hue — shift all colors around the color wheel<br>"
                "• Sharpness — sharpen detail or soften the image"
            ),
            "crop": (
                "Crop",
                "Crop the image to a selected area.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw the crop region<br><br>"
                "Editing:<br>"
                "• Drag the corner or edge handles to resize the crop area<br>"
                "• Drag inside the crop area to reposition it<br><br>"
                "Committing:<br>"
                "• Click Apply Crop to apply<br>"
                "• Click Cancel or press Escape to cancel"
            ),
            "cutout": (
                "Cut Out",
                "Cut a strip out of the image to remove unwanted vertical or horizontal space.<br><br>"
                "Usage:<br>"
                "• A horizontal or vertical strip is shown on the image<br>"
                "• Drag inside the strip to move it<br>"
                "• Drag the edge handles to resize the strip width<br><br>"
                "Committing:<br>"
                "• Click Apply Cut to remove the strip and join the two halves<br><br>"
                "Options:<br>"
                "• Cut Style — Sawtooth (zigzag seam), Line (straight seam), or No effect (clean join)<br>"
                "• Size — strip width in pixels<br>"
                "• Gap — extra space removed at the seam (%)<br>"
                "• Preview — Outline shows the removal zone, Result shows the actual output"
            ),
            "cutpaste": (
                "Cut / Paste",
                "Select, cut, copy, and paste rectangular regions of the image.<br><br>"
                "Selecting:<br>"
                "• Click and drag to draw a selection rectangle<br><br>"
                "Actions:<br>"
                "• Cut — removes the selected area and places it on the clipboard<br>"
                "• Copy — copies the selected area to the clipboard<br>"
                "• Paste — places clipboard content onto the canvas<br>"
                "• Delete — fills the selection with white<br><br>"
                "Moving a selection:<br>"
                "• Click and drag inside the selection to cut and move it<br>"
                "• After pasting, drag the preview to reposition it<br>"
                "• Drag the handles on a paste preview to resize it<br><br>"
                "Committing:<br>"
                "• Click outside the paste preview to apply it<br>"
                "• Right-click to cancel the selection or paste preview<br><br>"
                "Shortcuts:<br>"
                "• Ctrl+V — paste from system clipboard (works from any tool)<br>"
                "• Escape — cancel paste preview or selection"
            ),
            "freehand": (
                "Freehand",
                "Draw freely on the image with various brush modes.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw a stroke<br>"
                "• Each stroke is applied immediately on release<br><br>"
                "Modes:<br>"
                "• Pen — solid line drawing<br>"
                "• Brush — softer, wider strokes<br>"
                "• Spray Can — spatter / airbrush effect<br>"
                "• Flood Fill — click to fill a contiguous area with color<br>"
                "• Color Eraser — replaces one color with another wherever you paint<br>"
                "• Eraser — erases to white<br><br>"
                "Options:<br>"
                "• Size — stroke width (applies to Pen, Brush, Spray Can, and Eraser)<br>"
                "• Tolerance — how closely a color must match to be replaced (Color Eraser and Flood Fill only)<br><br>"
                "Uses the Primary color. Secondary color is used as the replacement for Color Eraser."
            ),
            "highlight": (
                "Highlight",
                "Highlight areas of the image to draw attention.<br><br>"
                "Styles:<br>"
                "• Pen — click and drag to draw a freehand highlight stroke<br>"
                "• Rectangle — click and drag to draw a semi-transparent highlight box<br>"
                "• Spotlight — click and drag a rectangle; everything outside it is dimmed<br><br>"
                "Committing:<br>"
                "• Pen and Rectangle strokes apply immediately on release<br>"
                "• Spotlight applies immediately on release<br><br>"
                "Options:<br>"
                "• Size — stroke width (Pen mode only)<br>"
                "• Dim — how much the area outside the spotlight is darkened (Spotlight only)<br>"
                "• Feather — soft edge on the spotlight boundary (Spotlight only)<br><br>"
                "Uses the Primary color for Pen and Rectangle highlights."
            ),
            "line": (
                "Line",
                "Draw straight or curved lines on the image.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw a line from start to end point<br>"
                "• Release to place the line in edit mode<br><br>"
                "Control points:<br>"
                "• Four handles appear — two endpoints and two inner curve handles<br>"
                "• Drag the endpoints to reposition the line — the inner handles follow automatically to keep it straight<br>"
                "• Drag an inner handle to bend the line into a curve — once moved, the inner handles become independent and endpoints will no longer move them<br><br>"
                "Committing:<br>"
                "• Click anywhere outside the line to set it in place<br>"
                "• Right-click to cancel without applying<br><br>"
                "Options:<br>"
                "• Width — line thickness<br>"
                "• Rounded — round line caps<br><br>"
                "Uses the Primary color."
            ),
            "magnify_inset": (
                "Magnify Inset",
                "Create a zoomed callout from a source area of the image.<br><br>"
                "Drawing:<br>"
                "• Click and drag to select the source area you want to magnify<br>"
                "• Release to place the source selection<br>"
                "• Click elsewhere on the canvas to place the magnified inset<br><br>"
                "Editing:<br>"
                "• Drag the inset to reposition it<br>"
                "• Drag the source selection handles to resize the source area<br><br>"
                "Committing:<br>"
                "• Click Apply to commit the inset to the image<br>"
                "• Click outside both the source and inset to apply<br>"
                "• Right-click to cancel without applying<br><br>"
                "Options:<br>"
                "• Shape — Rectangle or Oval inset<br>"
                "• Zoom — magnification level (125% to 300%)<br>"
                "• Border — border thickness around the inset<br>"
                "• Connected — draw lines connecting the source area to the inset"
            ),
            "step_marker": (
                "Step Marker",
                "Place numbered markers for step-by-step instructions.<br><br>"
                "Placing:<br>"
                "• Click on the canvas to place a numbered marker<br>"
                "• Numbers auto-increment with each new marker<br><br>"
                "Editing:<br>"
                "• Drag the badge (numbered circle) to reposition it<br>"
                "• Drag the tail handle (small dot) to adjust the pointer direction and length<br>"
                "• Click on any previously placed marker to re-edit it<br><br>"
                "Committing:<br>"
                "• Click on empty space to finalize the current marker and place a new one<br>"
                "• Click Apply All to commit all markers to the image<br>"
                "• Undo removes one marker at a time<br><br>"
                "Options:<br>"
                "• Size — marker diameter<br>"
                "• Start # — starting number for the sequence<br><br>"
                "Uses the Primary color."
            ),
            "oval": (
                "Oval",
                "Draw ovals and circles on the image.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw an oval<br>"
                "• Hold Shift for a perfect circle<br><br>"
                "Editing:<br>"
                "• Drag the corner or edge handles to resize the oval<br><br>"
                "Committing:<br>"
                "• Click anywhere outside the oval to set it in place<br>"
                "• Right-click to cancel without applying<br><br>"
                "Options:<br>"
                "• Width — border thickness<br>"
                "• Fill — fill the oval with the Secondary color<br><br>"
                "Uses the Primary color for the border."
            ),
            "outline": (
                "Outline",
                "Add a border outline around the entire image.<br><br>"
                "Usage:<br>"
                "• Click Preview to see the outline on the canvas<br>"
                "• Adjust options while previewing to see changes in real time<br><br>"
                "Committing:<br>"
                "• Click Apply to commit the outline to the image<br><br>"
                "Options:<br>"
                "• Thickness — border width in pixels<br>"
                "• Corner Radius — rounds the corners of the outline<br><br>"
                "Uses the Primary color."
            ),
            "pixelate": (
                "Pixelate",
                "Pixelate (mosaic) an area of the image to hide information.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw a rectangle over the area to pixelate<br>"
                "• A live preview shows the mosaic effect as you draw<br><br>"
                "Editing:<br>"
                "• Drag the corner or edge handles to resize the rectangle<br>"
                "• The pixelation preview updates in real time as you adjust<br><br>"
                "Committing:<br>"
                "• Click anywhere outside the rectangle to apply<br>"
                "• Right-click to cancel without applying<br><br>"
                "Options:<br>"
                "• Block Size — size of the mosaic blocks (larger = more obscured)"
            ),
            "rectangle": (
                "Rectangle",
                "Draw rectangles and squares on the image.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw a rectangle<br>"
                "• Hold Shift for a perfect square<br><br>"
                "Editing:<br>"
                "• Drag the corner or edge handles to resize the rectangle<br><br>"
                "Committing:<br>"
                "• Click anywhere outside the rectangle to set it in place<br>"
                "• Right-click to cancel without applying<br><br>"
                "Options:<br>"
                "• Width — border thickness<br>"
                "• Rounded — rounded corners<br>"
                "• Fill — fill with the Secondary color<br><br>"
                "Uses the Primary color for the border."
            ),
            "remove_space": (
                "Remove Space",
                "Automatically detect and remove horizontal or vertical empty space from the image.<br><br>"
                "Usage:<br>"
                "• Choose a direction and detection mode, then click Preview<br>"
                "• Detected strips are highlighted on the canvas<br>"
                "• Click Apply to remove the detected strips, or Cancel to discard<br><br>"
                "Options:<br>"
                "• Direction — Both, Vertical, or Horizontal<br>"
                "• Detect — White/Near-white, Auto-detect background color, Pick Color, or Duplicate Lines<br>"
                "• Keep — pixels of gap to preserve where space was removed<br>"
                "• Min Gap — minimum strip size in pixels to detect<br>"
                "• Tolerance — how closely a color must match the target to count as empty (0 = exact match)"
            ),
            "text": (
                "Text",
                "Add text to the image.<br><br>"
                "Drawing:<br>"
                "• Click and drag to draw a text box, then start typing<br>"
                "• The text wraps within the box boundaries<br><br>"
                "Editing:<br>"
                "• Click inside the text box to reposition the cursor<br>"
                "• Click and drag inside to select text<br>"
                "• Drag the corner or edge handles to resize the text box<br><br>"
                "Committing:<br>"
                "• Click anywhere outside the text box to apply<br>"
                "• Right-click to cancel without applying<br>"
                "• An empty text box is discarded automatically<br><br>"
                "Options:<br>"
                "• Font, Size, Align — font family, point size, and text alignment<br>"
                "• B / I / U — Bold, Italic, Underline<br>"
                "• Shadow — adds a drop shadow behind the text<br>"
                "• Outline + Thickness — adds a colored outline around each character<br><br>"
                "Uses the Primary color for text, Secondary for outline."
            ),
            "transform": (
                "Transform",
                "Rotate, flip, and resize the entire image.<br><br>"
                "Rotate and Flip:<br>"
                "• ↺ 90° / ↻ 90° — quick rotation left or right<br>"
                "• Angle — custom rotation with live preview (0.5° steps)<br>"
                "• Flip H / Flip V — mirror the image horizontally or vertically<br><br>"
                "Resize:<br>"
                "• W / H — set new dimensions in pixels<br>"
                "• Scale — resize by percentage<br>"
                "• Lock Ratio — keeps the aspect ratio when changing one dimension<br><br>"
                "Committing:<br>"
                "• All changes preview live on the canvas<br>"
                "• Click Apply to commit, Reset to revert<br>"
                "• Changes auto-apply when switching to another tool"
            ),
        }
        
        title, content = help_texts.get(tool_id, help_texts[None])
        self.help_title.setText(title)
        self.help_content.setText(content)

    def _populate_toolbar(self):
        """Populate vertical toolbar sidebar with actions based on config"""
        from PyQt6.QtGui import QAction, QActionGroup
        
        config = load_config()
        most_used = config.get("toolbar_most_used", [])
        less_used = config.get("toolbar_less_used", [])
        hidden = config.get("toolbar_hidden", [])
        
        if not most_used and not less_used and not hidden:
            most_used = sorted(self.toolbar_tool_definitions.keys())
        else:
            all_configured = set(most_used) | set(less_used) | set(hidden)
            for tool_id in sorted(self.toolbar_tool_definitions.keys()):
                if tool_id not in all_configured:
                    less_used.append(tool_id)
        
        self.toolbar_widget.clear()
        
        for action in self._toolbar_action_group.actions():
            self._toolbar_action_group.removeAction(action)
        
        self.tool_buttons = {}
        
        for tool_id in most_used:
            if tool_id in self.toolbar_tool_definitions:
                action = self._create_toolbar_button(tool_id)
                self.tool_buttons[tool_id] = action
                self.toolbar_widget.addAction(action)
        
        if less_used:
            self.toolbar_widget.addSeparator()
            
            for tool_id in less_used:
                if tool_id in self.toolbar_tool_definitions:
                    action = self._create_toolbar_button(tool_id)
                    self.tool_buttons[tool_id] = action
                    self.toolbar_widget.addAction(action)
        
        if hasattr(self, 'active_tool') and self.active_tool:
            for tool_id, action in self.tool_buttons.items():
                action.setChecked(tool_id == self.active_tool)
    
    def _update_shape_preview(self):
        """Generate WYSIWYG preview for the current active shape tool."""
        v = self.viewer
        if not v.image:
            v.clear_shape_preview()
            return
        
        tool = getattr(self, 'active_tool', None)
        
        try:
            if tool == "rectangle" and v.current_rect:
                cache_key = ("rect", v.current_rect, tuple(self.primary_color), tuple(self.secondary_color),
                            self.fill_enabled.isChecked(),
                            self.rect_width.currentText(), self.rect_rounded.currentText())
            elif tool == "oval" and v.current_oval:
                cache_key = ("oval", v.current_oval, tuple(self.primary_color), tuple(self.secondary_color),
                            self.oval_fill_enabled.isChecked(), self.oval_width.currentText())
            elif tool == "line" and v.current_line:
                cache_key = ("line", v.current_line, tuple(self.primary_color),
                            self.line_width_combo.currentText(), self.line_rounded.isChecked(),
                            v.line_keep_straight)
            elif tool == "arrow" and v.current_arrow:
                cache_key = ("arrow", v.current_arrow, tuple(self.primary_color),
                            self.arrow_width_combo.currentText(), self.arrow_rounded.isChecked(),
                            v.arrow_keep_straight)
            elif tool == "text" and v.current_text:
                text_str, x1, y1, x2, y2 = v.current_text
                cache_key = ("text", text_str, x1, y1, x2, y2, tuple(self.primary_color),
                            tuple(self.secondary_color),
                            self.text_font.currentText(), self.text_size.value(),
                            self.text_bold.isChecked() if hasattr(self, 'text_bold') else False,
                            self.text_italic.isChecked() if hasattr(self, 'text_italic') else False,
                            self.text_underline.isChecked() if hasattr(self, 'text_underline') else False,
                            self.text_outline.isChecked(), self.text_outline_thickness.value(),
                            self.text_shadow.isChecked() if hasattr(self, 'text_shadow') else False,
                            getattr(self, 'text_alignment', 'center'))
            else:
                v.clear_shape_preview()
                return
        except (AttributeError, RuntimeError):
            v.clear_shape_preview()
            return
        
        if v._shape_preview_key == cache_key and v.shape_preview_image is not None:
            return
        
        try:
            result = None
            qimg_result = None
            if tool == "rectangle":
                result = self._render_rectangles([v.current_rect])
            elif tool == "oval":
                result = self._render_ovals([v.current_oval])
            elif tool == "line":
                qimg_result = self._render_lines([v.current_line], as_qimage=True)
            elif tool == "arrow":
                qimg_result = self._render_arrows([v.current_arrow], as_qimage=True)
            elif tool == "text":
                result = self._render_text_preview()
            
            if qimg_result is not None:
                # Fast path: skip PIL, build QPixmap directly from QImage
                # Convert to RGBA8888 to match update_view's pipeline exactly
                # (avoids subtle pixel differences from premultiplied alpha at non-100% zoom)
                display_qimg = qimg_result.convertToFormat(QImage.Format.Format_RGBA8888)
                w, h = display_qimg.width(), display_qimg.height()
                if not hasattr(v, '_checker_tile') or v._checker_tile is None:
                    cs = 8
                    v._checker_tile = QPixmap(cs * 2, cs * 2)
                    v._checker_tile.fill(QColor(255, 255, 255))
                    tp = QPainter(v._checker_tile)
                    tp.fillRect(cs, 0, cs, cs, QColor(204, 204, 204))
                    tp.fillRect(0, cs, cs, cs, QColor(204, 204, 204))
                    tp.end()
                composited = QPixmap(w, h)
                cp = QPainter(composited)
                cp.drawTiledPixmap(0, 0, w, h, v._checker_tile)
                cp.drawImage(0, 0, display_qimg)
                cp.end()
                # Store a lightweight sentinel as shape_preview_image (for size info)
                # and the ready-to-draw pixmap
                v.shape_preview_image = v.image  # Reference only, not a copy
                v.shape_preview_pixmap = composited
                v._shape_preview_key = cache_key
            elif result:
                v.shape_preview_image = result
                v.shape_preview_pixmap = None
                v._shape_preview_key = cache_key
            else:
                v.clear_shape_preview()
        except Exception:
            v.clear_shape_preview()

    def rebuild_toolbar(self):
        """Rebuild toolbar after config change"""
        self._populate_toolbar()
        
        # Update button states
        if hasattr(self, 'update_tool_buttons_state'):
            self.update_tool_buttons_state()
    
    def select_tool_from_toolbar(self, tool):
        """Handle tool selection from toolbar icon buttons"""
        # Update the dropdown to match
        tool_idx = self.tool_combo.findData(tool)
        if tool_idx >= 0:
            self.tool_combo.blockSignals(True)
            self.tool_combo.setCurrentIndex(tool_idx)
            self.tool_combo.blockSignals(False)
        
        # Select the tool
        self.select_tool(tool)
    
    def toggle_toolbar(self, visible):
        """Toggle toolbar sidebar visibility"""
        self.toolbar_visible = visible
        if hasattr(self, '_toolbar_wrapper'):
            self._toolbar_wrapper.setVisible(visible)
        else:
            self.toolbar_widget.setVisible(visible)
    
    def toggle_ftp_button(self, visible):
        """Toggle Upload button visibility"""
        self.btn_publish.setVisible(visible)
        config = load_config()
        config["ftp_button_visible"] = visible
        save_config(config)
    
    def _load_themed_svg_icon(self, svg_path):
        """Load an SVG icon and recolor it to match the current theme.
        
        Handles both true vector SVGs (color replacement on stroke/fill) and
        SVGs containing embedded PNG bitmaps (pixel-level inversion).
        In light mode, loads the SVG as-is.
        """
        from PyQt6.QtGui import QIcon, QPixmap, QImage
        
        if not self._is_dark_mode:
            # Light mode — use the SVG directly, no modification needed
            icon = QIcon(svg_path)
            return icon if not icon.isNull() else None
        
        # Dark mode — load and recolor
        with open(svg_path, 'r', encoding='utf-8') as f:
            svg_data = f.read()
        
        # Detect if this is an embedded-bitmap SVG (contains base64 PNG/image data)
        if 'data:image/' in svg_data or 'xlink:href' in svg_data:
            # Embedded bitmap — render to QImage then invert pixel colors
            # First render the SVG to get the raster content
            icon = QIcon(svg_path)
            if icon.isNull():
                return None
            pixmap = icon.pixmap(28, 28)
            img = pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)
            
            # Invert RGB channels while preserving alpha
            for y in range(img.height()):
                for x in range(img.width()):
                    px = img.pixelColor(x, y)
                    if px.alpha() > 0:
                        # Invert toward light gray (#c8c8c8 = 200,200,200)
                        # Map dark pixels to light, light pixels to dark
                        img.setPixelColor(x, y, QColor(
                            255 - px.red(),
                            255 - px.green(),
                            255 - px.blue(),
                            px.alpha()
                        ))
            
            return QIcon(QPixmap.fromImage(img))
        else:
            # True vector SVG — do text-based color replacement
            from PyQt6.QtCore import QByteArray
            import re
            
            target = "#c8c8c8"  # rgb(200,200,200) — matches programmatic fallback
            
            # Replace common dark stroke/fill hex colors
            dark_colors = [
                "#000000", "#000", "#111111", "#111", "#1a1a1a",
                "#222222", "#222", "#282828", "#333333", "#333",
                "#404040", "#2b2b2b", "#191919", "#0d0d0d",
                "#373737", "#3a3a3a", "#444444", "#444",
            ]
            for dark in dark_colors:
                svg_data = svg_data.replace(dark, target)
            
            # Replace named dark colors in fill/stroke attributes and CSS
            dark_named = ["black", "Black"]
            for name in dark_named:
                # Attribute form: fill="black" or stroke="black"
                svg_data = svg_data.replace(f'fill="{name}"', f'fill="{target}"')
                svg_data = svg_data.replace(f'stroke="{name}"', f'stroke="{target}"')
                svg_data = svg_data.replace(f"fill='{name}'", f"fill='{target}'")
                svg_data = svg_data.replace(f"stroke='{name}'", f"stroke='{target}'")
                # CSS form: fill:black or stroke:black
                svg_data = svg_data.replace(f'fill:{name}', f'fill:{target}')
                svg_data = svg_data.replace(f'stroke:{name}', f'stroke:{target}')
            
            # Handle rgb() notation for dark values
            def _replace_dark_rgb(m):
                r, g, b = int(m.group(1)), int(m.group(2)), int(m.group(3))
                if r <= 80 and g <= 80 and b <= 80:
                    return target
                return m.group(0)
            svg_data = re.sub(
                r'rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)',
                _replace_dark_rgb, svg_data
            )
            
            # Set default fill on root <svg> element so paths without
            # explicit fill inherit the light color instead of black
            svg_tag_match = re.search(r'<svg\b[^>]*>', svg_data)
            if svg_tag_match and 'fill=' not in svg_tag_match.group(0):
                svg_data = svg_data.replace(
                    svg_tag_match.group(0),
                    svg_tag_match.group(0).replace('<svg', f'<svg fill="{target}"', 1),
                    1
                )
            
            # Render modified SVG to pixmap
            try:
                from PyQt6.QtSvg import QSvgRenderer
                renderer = QSvgRenderer(QByteArray(svg_data.encode('utf-8')))
                if not renderer.isValid():
                    return None
                pixmap = QPixmap(28, 28)
                pixmap.fill(Qt.GlobalColor.transparent)
                painter = QPainter(pixmap)
                renderer.render(painter)
                painter.end()
                return QIcon(pixmap)
            except ImportError:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.svg', delete=False, mode='w', encoding='utf-8') as tmp:
                    tmp.write(svg_data)
                    tmp_path = tmp.name
                icon = QIcon(tmp_path)
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                return icon

    def _create_tool_icon(self, tool_id):
        """Create icon for a tool - loads from icons/ folder SVG, falls back to programmatic drawing"""
        from PyQt6.QtGui import QIcon, QPixmap
        
        # Try loading custom SVG icon first
        icon_name_map = {
            "rectangle": "rectangle",
            "oval": "oval",
            "line": "line",
            "arrow": "arrow",
            "freehand": "freehand",
            "remove_space": "removespace",
            "text": "text",
            "transform": "transform",
            "blur": "blur",
            "color_light": "color",
            "crop": "crop",
            "cutout": "cutout",
            "cutpaste": "cutpaste",
            "highlight": "highlight",
            "outline": "outline",
            "pixelate": "pixelate",
            "magnify_inset": "magnifyinset",
            "step_marker": "stepmarker",
        }
        
        svg_name = icon_name_map.get(tool_id)
        if svg_name:
            # Look for icons folder next to the script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            svg_path = os.path.join(script_dir, "icons", f"{svg_name}.svg")
            if os.path.exists(svg_path):
                try:
                    icon = self._load_themed_svg_icon(svg_path)
                    if icon and not icon.isNull():
                        return icon
                except Exception:
                    pass
        
        # Fall back to programmatic icon drawing
        
        size = 28
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Set drawing color - adapts to theme for visibility
        icon_color = QColor(200, 200, 200) if self._is_dark_mode else QColor(40, 40, 40)
        pen = QPen(icon_color, 2.5, Qt.PenStyle.SolidLine, 
                   Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        
        margin = 4
        
        if tool_id == "rectangle":
            # Draw rectangle
            painter.drawRect(margin, margin, size - 2*margin, size - 2*margin)
            
        elif tool_id == "oval":
            # Draw circle/ellipse
            painter.drawEllipse(margin, margin, size - 2*margin, size - 2*margin)
            
        elif tool_id == "line":
            # Draw diagonal line
            painter.drawLine(margin, size - margin, size - margin, margin)
            
        elif tool_id == "arrow":
            # Draw arrow pointing right
            mid_y = size // 2
            painter.drawLine(margin + 2, mid_y, size - margin - 4, mid_y)
            # Arrowhead
            painter.drawLine(size - margin - 4, mid_y, size - margin - 8, mid_y - 4)
            painter.drawLine(size - margin - 4, mid_y, size - margin - 8, mid_y + 4)
            
        elif tool_id == "freehand":
            # Draw curved freehand line
            path = QPainterPath()
            path.moveTo(margin + 2, size - margin - 4)
            path.cubicTo(margin + 6, margin + 6, 
                        size - margin - 6, size - margin - 2,
                        size - margin - 2, margin + 4)
            painter.drawPath(path)
            
        elif tool_id == "remove_space":
            # Draw arrows pointing inward (compress/squeeze)
            painter.setPen(QPen(icon_color, 1.5))
            mid = size // 2
            # Top arrow pointing down
            painter.drawLine(mid, margin + 2, mid, mid - 3)
            painter.drawLine(mid - 3, mid - 6, mid, mid - 3)
            painter.drawLine(mid + 3, mid - 6, mid, mid - 3)
            # Bottom arrow pointing up
            painter.drawLine(mid, size - margin - 2, mid, mid + 3)
            painter.drawLine(mid - 3, mid + 6, mid, mid + 3)
            painter.drawLine(mid + 3, mid + 6, mid, mid + 3)
            # Dashed line in middle
            painter.setPen(QPen(icon_color, 1, Qt.PenStyle.DashLine))
            painter.drawLine(margin + 2, mid, size - margin - 2, mid)
            
        elif tool_id == "text":
            # Draw letter "A"
            painter.setFont(painter.font())
            font = painter.font()
            font.setPixelSize(20)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "A")
            
        elif tool_id == "transform":
            # Draw rotate arrow with resize arrows
            cx, cy = size // 2, size // 2
            # Curved rotate arrow (arc)
            path = QPainterPath()
            path.moveTo(cx + 7, cy - 7)
            path.arcTo(cx - 8, cy - 8, 16, 16, 45, 270)
            painter.drawPath(path)
            # Arrowhead on arc
            painter.drawLine(int(cx + 7), int(cy - 7), int(cx + 4), int(cy - 10))
            painter.drawLine(int(cx + 7), int(cy - 7), int(cx + 10), int(cy - 4))
            # Small resize arrows in corner
            painter.drawLine(size - margin - 2, size - margin - 8, size - margin - 2, size - margin - 2)
            painter.drawLine(size - margin - 8, size - margin - 2, size - margin - 2, size - margin - 2)
            
        elif tool_id == "blur":
            # Draw concentric blurred circles to suggest gaussian blur
            painter.setPen(Qt.PenStyle.NoPen)
            cx, cy = size // 2, size // 2
            for i in range(4, 0, -1):
                alpha = 30 + i * 25
                r = 3 + i * 3
                painter.setBrush(QBrush(QColor(icon_color.red(), icon_color.green(), icon_color.blue(), alpha)))
                painter.drawEllipse(cx - r, cy - r, r * 2, r * 2)
            
        elif tool_id == "color_light":
            # Draw sun/brightness icon with colored rays
            cx, cy = size // 2, size // 2
            # Central circle (half bright, half dark to suggest brightness/contrast)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(255, 200, 50)))
            painter.drawEllipse(cx - 5, cy - 5, 10, 10)
            # Rays around the circle
            import math
            painter.setPen(QPen(QColor(255, 200, 50), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            for i in range(8):
                angle = math.radians(i * 45)
                x1 = cx + int(7 * math.cos(angle))
                y1 = cy + int(7 * math.sin(angle))
                x2 = cx + int(10 * math.cos(angle))
                y2 = cy + int(10 * math.sin(angle))
                painter.drawLine(x1, y1, x2, y2)
            
        elif tool_id == "crop":
            # Draw crop corners
            corner_len = 8
            painter.drawLine(margin, margin, margin + corner_len, margin)
            painter.drawLine(margin, margin, margin, margin + corner_len)
            
            painter.drawLine(size - margin, margin, size - margin - corner_len, margin)
            painter.drawLine(size - margin, margin, size - margin, margin + corner_len)
            
            painter.drawLine(margin, size - margin, margin + corner_len, size - margin)
            painter.drawLine(margin, size - margin, margin, size - margin - corner_len)
            
            painter.drawLine(size - margin, size - margin, size - margin - corner_len, size - margin)
            painter.drawLine(size - margin, size - margin, size - margin, size - margin - corner_len)
            
        elif tool_id == "cutout":
            # Draw scissors-like shape
            # Blade 1
            painter.drawLine(margin + 4, margin + 4, size // 2, size // 2)
            painter.drawEllipse(margin + 2, margin + 2, 4, 4)
            # Blade 2
            painter.drawLine(margin + 4, size - margin - 4, size // 2, size // 2)
            painter.drawEllipse(margin + 2, size - margin - 6, 4, 4)
            # Cutting line
            pen_dashed = QPen(icon_color, 1.5, Qt.PenStyle.DashLine)
            painter.setPen(pen_dashed)
            painter.drawLine(size // 2 + 2, size // 2, size - margin, size // 2)
            
        elif tool_id == "cutpaste":
            # Draw clipboard icon
            painter.setPen(pen)
            painter.drawRect(margin + 3, margin + 5, size - 2*margin - 6, size - 2*margin - 5)
            # Clip at top
            painter.drawRect(margin + 7, margin + 2, size - 2*margin - 14, 4)
            
        elif tool_id == "highlight":
            # Draw highlighter marker
            painter.setBrush(QBrush(QColor(255, 255, 0, 120)))
            path = QPainterPath()
            path.moveTo(margin + 4, margin + 2)
            path.lineTo(size - margin - 8, margin + 2)
            path.lineTo(size - margin - 4, size - margin - 2)
            path.lineTo(margin, size - margin - 2)
            path.closeSubpath()
            painter.drawPath(path)
            
        elif tool_id == "outline":
            # Draw a rectangle outline (border around canvas)
            painter.setPen(QPen(icon_color, 2.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRect(margin + 2, margin + 2, size - 2*margin - 4, size - 2*margin - 4)
            # Inner lighter rect to suggest image
            painter.setPen(QPen(QColor(160, 160, 160), 0.5, Qt.PenStyle.DashLine))
            painter.drawRect(margin + 5, margin + 5, size - 2*margin - 10, size - 2*margin - 10)
            
        elif tool_id == "pixelate":
            # Draw pixelated squares
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(icon_color))
            block_size = 5
            for i in range(0, size - margin, block_size + 2):
                for j in range(0, size - margin, block_size + 2):
                    if (i + j) % 2 == 0:
                        painter.drawRect(margin + i, margin + j, block_size, block_size)
            
        elif tool_id == "magnify_inset":
            # Draw small box connected to larger box (zoom callout)
            # Small source box (left)
            painter.drawRect(margin, margin + 6, 8, 8)
            # Large inset box (right)
            painter.drawRect(margin + 12, margin + 2, 12, 16)
            # Connection lines (trapezoid)
            painter.setPen(QPen(icon_color, 1.5, Qt.PenStyle.SolidLine))
            painter.drawLine(margin + 8, margin + 6, margin + 12, margin + 2)
            painter.drawLine(margin + 8, margin + 14, margin + 12, margin + 18)
            
        elif tool_id == "step_marker":
            # Draw circled "1" with pointer tail
            import math
            painter.drawEllipse(margin + 4, margin, size - 2*margin - 8, size - 2*margin)
            # Small tail
            cx = margin + size // 2 - 4
            cy = margin + size // 2
            angle = math.radians(45)
            length = 8
            tx = cx + length * math.cos(angle)
            ty = cy + length * math.sin(angle)
            painter.drawLine(int(cx), int(cy), int(tx), int(ty))
            font = painter.font()
            font.setPixelSize(14)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(margin + 4, margin, size - 2*margin - 8, size - 2*margin, 
                           Qt.AlignmentFlag.AlignCenter, "1")
            
        painter.end()
        
        icon = QIcon(pixmap)
        return icon

    @staticmethod
    def _pil_draw_with_transparency(base_image, draw_func):
        """Draw on an image supporting transparent colors (including alpha=0).
        
        Strategy: Run draw_func twice — once on the real layer with actual colors,
        and once on a detection layer to find WHERE drawing occurred.
        Then paste the real layer onto the base using the detected mask.
        
        Args:
            base_image: PIL RGBA image to draw on
            draw_func: callable(draw, layer) that does the actual drawing
        Returns:
            Modified PIL RGBA image
        """
        from PIL import Image as PILImage, ImageDraw, ImageChops
        
        # Draw the actual shape with real colors on the layer
        layer = PILImage.new('RGBA', base_image.size, (0, 0, 0, 0))
        layer_draw = ImageDraw.Draw(layer)
        draw_func(layer_draw, layer)
        
        # Detect where drawing occurred by drawing the same shapes on a
        # known background and comparing. Any changed pixel = drawn area.
        detect_bg = (127, 127, 127, 255)
        detect = PILImage.new('RGBA', base_image.size, detect_bg)
        detect_draw = ImageDraw.Draw(detect)
        draw_func(detect_draw, detect)
        
        blank = PILImage.new('RGBA', base_image.size, detect_bg)
        
        # Find pixels that changed: difference > 0 on any channel
        diff = ImageChops.difference(detect, blank)
        r, g, b, a = diff.split()
        mask = ImageChops.lighter(ImageChops.lighter(r, g), ImageChops.lighter(b, a))
        mask = mask.point(lambda x: 255 if x > 0 else 0)
        
        result = base_image.copy()
        result.paste(layer, (0, 0), mask)
        return result

    def _render_rectangles(self, rects_to_draw):
        """Render rectangles onto image copy and return result PIL image"""
        v = self.viewer
        if not v.image or not rects_to_draw:
            return None
        
        try:
            line_width = int(self.rect_width.currentText())
        except ValueError:
            line_width = 2
        
        try:
            rounded = int(self.rect_rounded.currentText())
        except ValueError:
            rounded = 0
        
        outline_color = self.primary_color
        fill_color = self.secondary_color
        fill_enabled = self.fill_enabled.isChecked()
        
        # Use cached smooth drawing setting
        smooth = getattr(self, '_cached_smooth_drawing', False)
        
        if smooth:
            # Use Qt for anti-aliased drawing — use cached base QImage
            if getattr(v, '_cached_base_qimg', None) is None:
                v._cached_base_qimg = PilToQImage(v.image, for_painting=True)
            qimg = v._cached_base_qimg.copy()
            painter = QPainter(qimg)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            
            q_outline = QColor(*outline_color[:4]) if len(outline_color) >= 4 else QColor(*outline_color[:3])
            q_fill = QColor(*fill_color[:4]) if len(fill_color) >= 4 else QColor(*fill_color[:3])
            
            # Use Source mode if any color has transparency
            if (len(outline_color) >= 4 and outline_color[3] < 255) or \
               (fill_enabled and len(fill_color) >= 4 and fill_color[3] < 255):
                painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
            
            for rect in rects_to_draw:
                x1 = int((rect[0] - v.offset.x()) / v.scale)
                y1 = int((rect[1] - v.offset.y()) / v.scale)
                x2 = int((rect[2] - v.offset.x()) / v.scale)
                y2 = int((rect[3] - v.offset.y()) / v.scale)
                
                # Scale line width for zoom
                scaled_width = line_width
                
                if x2 > x1 and y2 > y1:
                    if fill_enabled:
                        painter.setBrush(QBrush(q_fill))
                    else:
                        painter.setBrush(Qt.BrushStyle.NoBrush)
                    
                    painter.setPen(QPen(q_outline, scaled_width, Qt.PenStyle.SolidLine,
                                       Qt.PenCapStyle.SquareCap, Qt.PenJoinStyle.MiterJoin))
                    
                    if rounded > 0:
                        scaled_rounded = rounded
                        painter.drawRoundedRect(x1, y1, x2 - x1, y2 - y1, scaled_rounded, scaled_rounded)
                    else:
                        painter.drawRect(x1, y1, x2 - x1, y2 - y1)
            
            painter.end()
            result = QImageToPil(qimg)
        else:
            # Use PIL for pixel-perfect drawing
            from PIL import Image as PILImage, ImageDraw
            
            if len(outline_color) >= 3:
                outline = tuple(outline_color[:3]) + (255,) if len(outline_color) == 3 else tuple(outline_color)
            else:
                outline = (0, 0, 0, 255)
            
            if len(fill_color) >= 3:
                fill = tuple(fill_color[:3]) + (255,) if len(fill_color) == 3 else tuple(fill_color)
            else:
                fill = (255, 255, 255, 255)
            
            result = v.image.copy().convert('RGBA')
            
            # Check if any color has transparency
            has_transparency = (outline[3] < 255) or (fill_enabled and fill[3] < 255)
            
            def _draw_rects(draw, layer):
                for rect in rects_to_draw:
                    x1 = int((rect[0] - v.offset.x()) / v.scale)
                    y1 = int((rect[1] - v.offset.y()) / v.scale)
                    x2 = int((rect[2] - v.offset.x()) / v.scale)
                    y2 = int((rect[3] - v.offset.y()) / v.scale)
                    
                    scaled_width = line_width
                    scaled_rounded = rounded if rounded > 0 else 0
                    
                    half = scaled_width / 2
                    rx1 = int(x1 - half)
                    ry1 = int(y1 - half)
                    rx2 = int(x2 + half)
                    ry2 = int(y2 + half)
                    
                    if rx2 > rx1 and ry2 > ry1:
                        f = fill if fill_enabled else None
                        if scaled_rounded > 0:
                            try:
                                draw.rounded_rectangle([rx1, ry1, rx2, ry2], radius=scaled_rounded,
                                                       fill=f, outline=outline, width=scaled_width)
                            except AttributeError:
                                draw.rectangle([rx1, ry1, rx2, ry2], fill=f, outline=outline, width=scaled_width)
                        else:
                            draw.rectangle([rx1, ry1, rx2, ry2], fill=f, outline=outline, width=scaled_width)
            
            if has_transparency:
                result = self._pil_draw_with_transparency(result, _draw_rects)
            else:
                draw = ImageDraw.Draw(result)
                _draw_rects(draw, result)
        
        return result

    def apply_pending_rectangles(self, rects_to_draw):
        """Apply rectangles to the image"""
        result = self._render_rectangles(rects_to_draw)
        if result:
            self.viewer.clear_shape_preview()
            self.viewer.set_image(result)

    def _render_ovals(self, ovals_to_draw):
        """Render ovals onto image copy and return result PIL image"""
        v = self.viewer
        if not v.image or not ovals_to_draw:
            return None
        
        try:
            line_width = int(self.oval_width.currentText())
        except ValueError:
            line_width = 2
        
        outline_color = self.primary_color
        fill_color = self.secondary_color
        fill_enabled = self.oval_fill_enabled.isChecked()
        
        # Use cached smooth drawing setting
        smooth = getattr(self, '_cached_smooth_drawing', False)
        
        if smooth:
            # Use Qt for anti-aliased drawing — use cached base QImage
            if getattr(v, '_cached_base_qimg', None) is None:
                v._cached_base_qimg = PilToQImage(v.image, for_painting=True)
            qimg = v._cached_base_qimg.copy()
            painter = QPainter(qimg)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            
            q_outline = QColor(*outline_color[:4]) if len(outline_color) >= 4 else QColor(*outline_color[:3])
            q_fill = QColor(*fill_color[:4]) if len(fill_color) >= 4 else QColor(*fill_color[:3])
            
            if (len(outline_color) >= 4 and outline_color[3] < 255) or \
               (fill_enabled and len(fill_color) >= 4 and fill_color[3] < 255):
                painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
            
            for oval in ovals_to_draw:
                x1 = int((oval[0] - v.offset.x()) / v.scale)
                y1 = int((oval[1] - v.offset.y()) / v.scale)
                x2 = int((oval[2] - v.offset.x()) / v.scale)
                y2 = int((oval[3] - v.offset.y()) / v.scale)
                
                scaled_width = line_width
                if x2 > x1 and y2 > y1:
                    if fill_enabled:
                        painter.setBrush(QBrush(q_fill))
                    else:
                        painter.setBrush(Qt.BrushStyle.NoBrush)
                    
                    painter.setPen(QPen(q_outline, scaled_width, Qt.PenStyle.SolidLine))
                    painter.drawEllipse(x1, y1, x2 - x1, y2 - y1)
            
            painter.end()
            result = QImageToPil(qimg)
        else:
            # Use PIL for pixel-perfect drawing
            from PIL import Image as PILImage, ImageDraw
            
            if len(outline_color) >= 3:
                outline = tuple(outline_color[:3]) + (255,) if len(outline_color) == 3 else tuple(outline_color)
            else:
                outline = (0, 0, 0, 255)
            
            if len(fill_color) >= 3:
                fill = tuple(fill_color[:3]) + (255,) if len(fill_color) == 3 else tuple(fill_color)
            else:
                fill = (255, 255, 255, 255)
            
            result = v.image.copy().convert('RGBA')
            has_transparency = (outline[3] < 255) or (fill_enabled and fill[3] < 255)
            
            def _draw_ovals(draw, layer):
                for oval in ovals_to_draw:
                    x1 = int((oval[0] - v.offset.x()) / v.scale)
                    y1 = int((oval[1] - v.offset.y()) / v.scale)
                    x2 = int((oval[2] - v.offset.x()) / v.scale)
                    y2 = int((oval[3] - v.offset.y()) / v.scale)
                    
                    scaled_width = line_width
                    half = scaled_width / 2
                    ox1 = int(x1 - half)
                    oy1 = int(y1 - half)
                    ox2 = int(x2 + half)
                    oy2 = int(y2 + half)
                    
                    if ox2 > ox1 and oy2 > oy1:
                        f = fill if fill_enabled else None
                        draw.ellipse([ox1, oy1, ox2, oy2], fill=f, outline=outline, width=scaled_width)
            
            if has_transparency:
                result = self._pil_draw_with_transparency(result, _draw_ovals)
            else:
                draw = ImageDraw.Draw(result)
                _draw_ovals(draw, result)
        
        return result

    def apply_pending_ovals(self, ovals_to_draw):
        """Apply ovals to the image"""
        result = self._render_ovals(ovals_to_draw)
        if result:
            self.viewer.clear_shape_preview()
            self.viewer.set_image(result)

    def _render_lines(self, lines_to_draw, as_qimage=False):
        """Render lines onto image copy and return result PIL image (or QImage if as_qimage=True)"""
        v = self.viewer
        if not v.image or not lines_to_draw:
            return None
        
        try:
            line_width = int(self.line_width_combo.currentText())
        except ValueError:
            line_width = 2
        
        line_color = self.primary_color
        rounded = self.line_rounded.isChecked()
        is_straight = v.line_keep_straight
        
        smooth = getattr(self, '_cached_smooth_drawing', False)
        
        if smooth or as_qimage:
            # Use Qt for drawing — use cached base QImage
            if getattr(v, '_cached_base_qimg', None) is None:
                v._cached_base_qimg = PilToQImage(v.image, for_painting=True)
            qimg = v._cached_base_qimg.copy()
            painter = QPainter(qimg)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, smooth)
            
            q_color = QColor(*line_color[:4]) if len(line_color) >= 4 else QColor(*line_color[:3])
            
            if len(line_color) >= 4 and line_color[3] < 255:
                painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
            
            cap_style = Qt.PenCapStyle.RoundCap if rounded else Qt.PenCapStyle.FlatCap
            scaled_line_width = line_width
            painter.setPen(QPen(q_color, scaled_line_width, Qt.PenStyle.SolidLine, cap_style))
            
            for line in lines_to_draw:
                x1 = int((line[0] - v.offset.x()) / v.scale)
                y1 = int((line[1] - v.offset.y()) / v.scale)
                x2 = int((line[6] - v.offset.x()) / v.scale)
                y2 = int((line[7] - v.offset.y()) / v.scale)
                
                if is_straight:
                    painter.drawLine(x1, y1, x2, y2)
                else:
                    cp1_x = int((line[2] - v.offset.x()) / v.scale)
                    cp1_y = int((line[3] - v.offset.y()) / v.scale)
                    cp2_x = int((line[4] - v.offset.x()) / v.scale)
                    cp2_y = int((line[5] - v.offset.y()) / v.scale)
                    path = QPainterPath()
                    path.moveTo(x1, y1)
                    path.cubicTo(cp1_x, cp1_y, cp2_x, cp2_y, x2, y2)
                    painter.drawPath(path)
            
            painter.end()
            if as_qimage:
                return qimg
            result = QImageToPil(qimg)
        else:
            # Use PIL for pixel-perfect drawing - approximate bezier with line segments
            from PIL import Image as PILImage, ImageDraw
            
            if len(line_color) >= 3:
                color = tuple(line_color[:3]) + (255,) if len(line_color) == 3 else tuple(line_color)
            else:
                color = (0, 0, 0, 255)
            
            result = v.image.copy().convert('RGBA')
            has_transparency = (color[3] < 255)
            
            def _draw_lines(draw, layer):
                for line in lines_to_draw:
                    x1 = int((line[0] - v.offset.x()) / v.scale)
                    y1 = int((line[1] - v.offset.y()) / v.scale)
                    x2 = int((line[6] - v.offset.x()) / v.scale)
                    y2 = int((line[7] - v.offset.y()) / v.scale)
                    
                    scaled_lw = line_width
                    
                    if is_straight:
                        draw.line([(x1, y1), (x2, y2)], fill=color, width=scaled_lw)
                    else:
                        cp1_x = int((line[2] - v.offset.x()) / v.scale)
                        cp1_y = int((line[3] - v.offset.y()) / v.scale)
                        cp2_x = int((line[4] - v.offset.x()) / v.scale)
                        cp2_y = int((line[5] - v.offset.y()) / v.scale)
                        points = []
                        steps = 20
                        for i in range(steps + 1):
                            t = i / steps
                            bx = (1-t)**3 * x1 + 3*(1-t)**2*t * cp1_x + 3*(1-t)*t**2 * cp2_x + t**3 * x2
                            by = (1-t)**3 * y1 + 3*(1-t)**2*t * cp1_y + 3*(1-t)*t**2 * cp2_y + t**3 * y2
                            points.append((round(bx), round(by)))
                        for i in range(len(points) - 1):
                            draw.line([points[i], points[i+1]], fill=color, width=scaled_lw)
                    
                    if rounded and scaled_lw > 2:
                        r = scaled_lw // 2
                        if r >= 1:
                            draw.ellipse([x1 - r, y1 - r, x1 + r, y1 + r], fill=color)
                            draw.ellipse([x2 - r, y2 - r, x2 + r, y2 + r], fill=color)
            
            if has_transparency:
                result = self._pil_draw_with_transparency(result, _draw_lines)
            else:
                draw = ImageDraw.Draw(result)
                _draw_lines(draw, result)
        
        return result

    def apply_pending_lines(self, lines_to_draw):
        """Apply lines to the image"""
        result = self._render_lines(lines_to_draw)
        if result:
            self.viewer.clear_shape_preview()
            self.viewer.set_image(result)

    def _render_arrows(self, arrows_to_draw, as_qimage=False):
        """Render arrows onto image copy and return result PIL image (or QImage if as_qimage=True)"""
        v = self.viewer
        if not v.image or not arrows_to_draw:
            return None
        
        # Use cached base QImage to avoid PIL→QImage conversion every frame
        if getattr(v, '_cached_base_qimg', None) is None:
            v._cached_base_qimg = PilToQImage(v.image, for_painting=True)
        qimg = v._cached_base_qimg.copy()
        
        painter = QPainter(qimg)
        smooth = getattr(self, '_cached_smooth_drawing', False)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, smooth)
        
        # Get drawing parameters
        try:
            line_width = int(self.arrow_width_combo.currentText())
        except ValueError:
            line_width = 2
        
        # Scale line width based on zoom
        scaled_line_width = line_width
            
        arrow_color = QColor(*self.primary_color)
        rounded = self.arrow_rounded.isChecked()
        
        if len(self.primary_color) >= 4 and self.primary_color[3] < 255:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        
        for arrow in arrows_to_draw:
            # Convert screen coordinates to image coordinates (now includes control points)
            x1 = int((arrow[0] - v.offset.x()) / v.scale)
            y1 = int((arrow[1] - v.offset.y()) / v.scale)
            cp1_x = int((arrow[2] - v.offset.x()) / v.scale)
            cp1_y = int((arrow[3] - v.offset.y()) / v.scale)
            cp2_x = int((arrow[4] - v.offset.x()) / v.scale)
            cp2_y = int((arrow[5] - v.offset.y()) / v.scale)
            x2 = int((arrow[6] - v.offset.x()) / v.scale)
            y2 = int((arrow[7] - v.offset.y()) / v.scale)
            
            # Clamp to image boundaries
            x1 = max(0, min(v.image.width, x1))
            y1 = max(0, min(v.image.height, y1))
            cp1_x = max(0, min(v.image.width, cp1_x))
            cp1_y = max(0, min(v.image.height, cp1_y))
            cp2_x = max(0, min(v.image.width, cp2_x))
            cp2_y = max(0, min(v.image.height, cp2_y))
            x2 = max(0, min(v.image.width, x2))
            y2 = max(0, min(v.image.height, y2))
            
            cap_style = Qt.PenCapStyle.RoundCap if rounded else Qt.PenCapStyle.FlatCap
            painter.setPen(QPen(arrow_color, scaled_line_width, Qt.PenStyle.SolidLine, cap_style))
            
            # Draw curved arrow with arrowhead (using scaled line width)
            v.draw_arrowhead(painter, x1, y1, cp1_x, cp1_y, cp2_x, cp2_y, x2, y2, arrow_color, scaled_line_width, v.arrow_keep_straight)
        
        painter.end()
        
        if as_qimage:
            return qimg
        return QImageToPil(qimg)

    def apply_pending_arrows(self, arrows_to_draw):
        """Apply arrows to the image"""
        result = self._render_arrows(arrows_to_draw)
        if result:
            self.viewer.clear_shape_preview()
            self.viewer.set_image(result)

    def _render_text_preview(self):
        """Render text preview onto image copy and return result PIL image.
        
        Uses the same rendering path as apply_text_to_image so preview matches final.
        """
        v = self.viewer
        if not v.image or not v.current_text:
            return None
        
        text_str, x1, y1, x2, y2 = v.current_text
        if not text_str:
            return None
        
        qimg = PilToQImage(v.image, for_painting=True)
        painter = QPainter(qimg)
        
        config = load_config()
        smooth = config.get("smooth_drawing", True)  # Text usually looks better with AA
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, smooth)
        
        font_name = self.text_font.currentText()
        font_size = self.text_size.value()
        color = self.primary_color
        outline_enabled = self.text_outline.isChecked()
        outline_color = self.secondary_color
        outline_thickness = self.text_outline_thickness.value()
        shadow_enabled = self.text_shadow.isChecked() if hasattr(self, 'text_shadow') else False
        
        x1_img = int((x1 - v.offset.x()) / v.scale)
        y1_img = int((y1 - v.offset.y()) / v.scale)
        x2_img = int((x2 - v.offset.x()) / v.scale)
        y2_img = int((y2 - v.offset.y()) / v.scale)
        box_width_img = x2_img - x1_img
        box_height_img = y2_img - y1_img
        size_img = font_size
        
        def _as_qcolor(val, default=QColor(0, 0, 0)):
            if isinstance(val, (tuple, list)) and len(val) >= 3:
                r, g, b = int(val[0]), int(val[1]), int(val[2])
                a = int(val[3]) if len(val) >= 4 else 255
                return QColor(r, g, b, a)
            if isinstance(val, QColor):
                return val
            return default
        
        text_color = _as_qcolor(color)
        
        if text_color.alpha() < 255:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        
        from PyQt6.QtGui import QFont, QPainterPath
        font = QFont(font_name)
        font.setPixelSize(size_img)
        font.setBold(self.text_bold.isChecked() if hasattr(self, 'text_bold') else True)
        font.setItalic(self.text_italic.isChecked() if hasattr(self, 'text_italic') else False)
        font.setUnderline(self.text_underline.isChecked() if hasattr(self, 'text_underline') else False)
        painter.setFont(font)
        metrics = painter.fontMetrics()
        
        # Word wrap
        padding = 10
        available_width = box_width_img - padding * 2
        lines = []
        current_line = ""
        current_start = 0
        last_break = -1
        last_break_line = ""
        
        for i, ch in enumerate(text_str):
            current_line += ch
            if ch == ' ':
                last_break = i
                last_break_line = current_line
            if metrics.horizontalAdvance(current_line) > available_width and len(current_line) > 1:
                if last_break > current_start:
                    lines.append(last_break_line.rstrip(' '))
                    current_start = last_break + 1
                    current_line = text_str[current_start:i + 1]
                    last_break = -1
                    last_break_line = ""
                else:
                    lines.append(current_line[:-1])
                    current_start = i
                    current_line = ch
                    last_break = -1
                    last_break_line = ""
        if current_line:
            lines.append(current_line)
        if not lines:
            lines = [text_str]
        
        line_height = metrics.height()
        total_height = line_height * len(lines)
        start_y = y1_img + (box_height_img - total_height) / 2 + line_height * 0.8
        
        shadow_offset = 2
        outline_width = outline_thickness
        alignment = self.text_alignment if hasattr(self, 'text_alignment') else "center"
        padding_img = 10
        
        for i, line in enumerate(lines):
            line_width = metrics.horizontalAdvance(line)
            
            if alignment == "left":
                x_img = x1_img + padding_img
            elif alignment == "right":
                x_img = x1_img + box_width_img - line_width - padding_img
            else:
                x_img = x1_img + (box_width_img - line_width) / 2
            
            y_img = start_y + i * line_height
            
            if shadow_enabled:
                shadow_path = QPainterPath()
                shadow_path.addText(x_img, y_img, font, line)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(0, 0, 0, 150))
                painter.save()
                painter.translate(shadow_offset, shadow_offset)
                painter.drawPath(shadow_path)
                painter.restore()
            
            text_path = QPainterPath()
            text_path.addText(x_img, y_img, font, line)
            
            if outline_enabled:
                outline_col = _as_qcolor(outline_color)
                painter.setPen(QPen(outline_col, outline_width, Qt.PenStyle.SolidLine,
                                   Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(text_path)
            
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(text_color)
            painter.drawPath(text_path)
        
        painter.end()
        return QImageToPil(qimg)

    def _freehand_draw_segment_realtime(self, p1, p2):
        """Draw a single freehand segment into QImage, then update() for instant display.
        
        paintEvent draws the live QImage directly — no pixmap scaling needed.
        Two QPainter calls total: one into QImage (data), one from QImage to screen (paintEvent).
        """
        v = self.viewer
        if v._freehand_live_qimg is None:
            return
        
        try:
            pen_size = int(self.freehand_size.currentText())
        except ValueError:
            pen_size = 3
        
        freehand_color = self.primary_color
        mode = getattr(self, 'freehand_mode', 'pen')
        
        draw_pen_size = pen_size
        is_eraser = (mode == 'eraser')
        if is_eraser:
            draw_pen_size = max(pen_size * 2, 8)
        elif mode == 'brush':
            draw_pen_size = max(pen_size * 2, 5)
        
        # Image coordinates
        ix1 = int((p1.x() - v.offset.x()) / v.scale)
        iy1 = int((p1.y() - v.offset.y()) / v.scale)
        ix2 = int((p2.x() - v.offset.x()) / v.scale)
        iy2 = int((p2.y() - v.offset.y()) / v.scale)
        
        smooth = getattr(v, '_freehand_smooth', False)
        
        if len(freehand_color) >= 3:
            color = QColor(*freehand_color[:4]) if len(freehand_color) >= 4 else QColor(*freehand_color[:3])
        else:
            color = QColor(0, 0, 0)
        
        painter = QPainter(v._freehand_live_qimg)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, smooth)
        if is_eraser:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
        elif color.alpha() < 255:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        
        if mode == 'spraycan':
            import random
            spray_radius = draw_pen_size * 5
            painter.setPen(QPen(color, 1, Qt.PenStyle.SolidLine))
            for _ in range(10):
                angle = random.uniform(0, 2 * 3.14159)
                distance = random.uniform(0, spray_radius)
                dx = int(distance * math.cos(angle))
                dy = int(distance * math.sin(angle))
                painter.drawPoint(ix2 + dx, iy2 + dy)
        else:
            painter.setPen(QPen(color, draw_pen_size, Qt.PenStyle.SolidLine,
                               Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawLine(ix1, iy1, ix2, iy2)
        painter.end()
        
        v.update()

    def _freehand_draw_dot_realtime(self, point):
        """Draw a single dot into QImage, then update()."""
        v = self.viewer
        if v._freehand_live_qimg is None:
            return
        
        try:
            pen_size = int(self.freehand_size.currentText())
        except ValueError:
            pen_size = 3
        
        freehand_color = self.primary_color
        mode = getattr(self, 'freehand_mode', 'pen')
        
        draw_pen_size = pen_size
        is_eraser = (mode == 'eraser')
        if is_eraser:
            draw_pen_size = max(pen_size * 2, 8)
        elif mode == 'brush':
            draw_pen_size = max(pen_size * 2, 5)
        
        ix = int((point.x() - v.offset.x()) / v.scale)
        iy = int((point.y() - v.offset.y()) / v.scale)
        
        smooth = getattr(v, '_freehand_smooth', False)
        
        if len(freehand_color) >= 3:
            color = QColor(*freehand_color[:4]) if len(freehand_color) >= 4 else QColor(*freehand_color[:3])
        else:
            color = QColor(0, 0, 0)
        
        painter = QPainter(v._freehand_live_qimg)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, smooth)
        if is_eraser:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
        elif color.alpha() < 255:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        painter.setPen(QPen(color, draw_pen_size, Qt.PenStyle.SolidLine,
                           Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawPoint(ix, iy)
        painter.end()
        
        v.update()

    def _freehand_begin_stroke(self):
        """Save image for undo, create live QImage for fast drawing."""
        v = self.viewer
        if v.image:
            v._freehand_undo_image = v.image.copy()
            v._freehand_live_qimg = PilToQImage(v.image).convertToFormat(QImage.Format.Format_ARGB32)
            # Cache smooth setting
            config = load_config()
            v._freehand_smooth = config.get("smooth_drawing", False)

    def _freehand_end_stroke(self):
        """Finalize stroke - convert QImage back to PIL, push undo state."""
        v = self.viewer
        if v._freehand_live_qimg is not None:
            # Convert the live QImage back to PIL for storage
            v.image = QImageToPil(v._freehand_live_qimg)
            v._freehand_live_qimg = None
        
        if v._freehand_undo_image is not None:
            v.history.append((v._freehand_undo_image, v.marker_counter))
            v.redo_stack = []
            if len(v.history) > 20:
                v.history.pop(0)
            v._freehand_undo_image = None
            if hasattr(self, 'has_unsaved_changes'):
                self.has_unsaved_changes = True
            if hasattr(self, 'update_tool_buttons_state'):
                self.update_tool_buttons_state()
            if hasattr(self, '_update_status_bar'):
                self._update_status_bar()
        
        # Do a full update_view to sync everything
        v.update_view()

    def apply_freehand_drawing(self, points):
        """Apply freehand drawing to the image"""
        v = self.viewer
        if not v.image or not points:
            return
        
        # Get drawing parameters
        try:
            pen_size = int(self.freehand_size.currentText())
        except ValueError:
            pen_size = 3
        
        freehand_color = self.primary_color  # tuple (r, g, b, a)
        mode = getattr(self, 'freehand_mode', 'pen')
        
        # Handle flood fill separately (single click)
        if mode == 'flood':
            self.apply_flood_fill(points[0])
            return
        
        # Handle color eraser separately (uses PIL directly)
        if mode == 'color_eraser':
            self.apply_color_eraser(points, pen_size, QColor(*freehand_color))
            return
        
        # Check if smooth drawing is enabled
        config = load_config()
        smooth = config.get("smooth_drawing", False)
        
        if smooth:
            # Use Qt-based drawing with anti-aliasing (Krita-style)
            self._apply_freehand_drawing_qt(points, pen_size, freehand_color, mode, v)
        else:
            # Use PIL for pixel-perfect sharp drawing
            self._apply_freehand_drawing_pil(points, pen_size, freehand_color, mode, v)
    
    def _apply_freehand_drawing_qt(self, points, pen_size, freehand_color, mode, v):
        """Anti-aliased freehand drawing using Qt QPainter on QImage (Krita-style)
        
        This draws directly to a QImage with anti-aliasing enabled, then converts
        back to PIL. This gives smooth, anti-aliased strokes like Krita.
        """
        from PIL import Image as PILImage
        
        # Convert PIL image to QImage using the fast method
        qimg = PilToQImage(v.image).convertToFormat(QImage.Format.Format_ARGB32)
        
        # Create painter on QImage with anti-aliasing
        painter = QPainter(qimg)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        
        # Set up pen/brush based on mode
        draw_pen_size = pen_size
        if len(freehand_color) >= 3:
            color = QColor(*freehand_color[:4]) if len(freehand_color) >= 4 else QColor(*freehand_color[:3])
        else:
            color = QColor(0, 0, 0)
        
        if mode == 'eraser':
            # Eraser paints with full transparency
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Clear)
            color = QColor(0, 0, 0, 0)
            draw_pen_size = max(pen_size * 2, 8)
        elif len(freehand_color) >= 4 and freehand_color[3] < 255:
            # Transparent color - use Source mode to replace pixels
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        
        if mode == 'brush':
            draw_pen_size = max(pen_size * 2, 5)
        
        if mode == 'spraycan':
            import random
            spray_radius = draw_pen_size * 5
            dots_per_point = 20
            painter.setPen(QPen(color, 1, Qt.PenStyle.SolidLine))
            
            for point in points:
                cx = int((point.x() - v.offset.x()) / v.scale)
                cy = int((point.y() - v.offset.y()) / v.scale)
                
                for _ in range(dots_per_point):
                    angle = random.uniform(0, 2 * 3.14159)
                    distance = random.uniform(0, spray_radius)
                    dx = int(distance * math.cos(angle))
                    dy = int(distance * math.sin(angle))
                    painter.drawPoint(cx + dx, cy + dy)
        else:
            # Pen, brush, or eraser - use round cap for smooth strokes
            painter.setPen(QPen(color, draw_pen_size, Qt.PenStyle.SolidLine, 
                               Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            
            if len(points) == 1:
                x = int((points[0].x() - v.offset.x()) / v.scale)
                y = int((points[0].y() - v.offset.y()) / v.scale)
                painter.drawPoint(x, y)
            else:
                for i in range(len(points) - 1):
                    x1 = int((points[i].x() - v.offset.x()) / v.scale)
                    y1 = int((points[i].y() - v.offset.y()) / v.scale)
                    x2 = int((points[i + 1].x() - v.offset.x()) / v.scale)
                    y2 = int((points[i + 1].y() - v.offset.y()) / v.scale)
                    painter.drawLine(x1, y1, x2, y2)
        
        painter.end()
        
        # Convert QImage back to PIL using fast method
        result = QImageToPil(qimg)
        
        v.set_image(result)
    
    def _apply_freehand_drawing_pil(self, points, pen_size, freehand_color, mode, v):
        """Sharp/pixel-perfect freehand drawing using PIL"""
        from PIL import Image as PILImage, ImageDraw
        
        # Work directly on a copy of the image
        result = v.image.copy().convert('RGBA')
        
        # Pen size represents image pixels directly
        draw_pen_size = pen_size
        
        # Get color
        if len(freehand_color) >= 3:
            color = tuple(freehand_color[:3]) + (255,) if len(freehand_color) == 3 else tuple(freehand_color)
        else:
            color = (0, 0, 0, 255)
        
        is_eraser = (mode == 'eraser')
        is_transparent = (len(color) >= 4 and color[3] < 255)
        
        if is_eraser:
            color = (0, 0, 0, 0)
            draw_pen_size = max(pen_size * 2, 8)
        elif mode == 'brush':
            draw_pen_size = max(pen_size * 2, 5)
        
        if is_eraser or is_transparent:
            # For eraser/transparent: draw mask on separate layer, then composite
            mask = PILImage.new('L', result.size, 0)
            mask_draw = ImageDraw.Draw(mask)
            overlay = PILImage.new('RGBA', result.size, color)
            
            if mode == 'spraycan':
                import random
                spray_radius = draw_pen_size * 5
                dots_per_point = 20
                for point in points:
                    cx = int((point.x() - v.offset.x()) / v.scale)
                    cy = int((point.y() - v.offset.y()) / v.scale)
                    for _ in range(dots_per_point):
                        angle = random.uniform(0, 2 * 3.14159)
                        distance = random.uniform(0, spray_radius)
                        dx = int(distance * math.cos(angle))
                        dy = int(distance * math.sin(angle))
                        mask_draw.point((cx + dx, cy + dy), fill=255)
            elif len(points) == 1:
                x = int((points[0].x() - v.offset.x()) / v.scale)
                y = int((points[0].y() - v.offset.y()) / v.scale)
                r = draw_pen_size // 2
                if r < 1:
                    mask_draw.point((x, y), fill=255)
                else:
                    mask_draw.ellipse([x - r, y - r, x + r, y + r], fill=255)
            else:
                for i in range(len(points) - 1):
                    x1 = int((points[i].x() - v.offset.x()) / v.scale)
                    y1 = int((points[i].y() - v.offset.y()) / v.scale)
                    x2 = int((points[i + 1].x() - v.offset.x()) / v.scale)
                    y2 = int((points[i + 1].y() - v.offset.y()) / v.scale)
                    mask_draw.line([(x1, y1), (x2, y2)], fill=255, width=draw_pen_size)
                    r = draw_pen_size // 2
                    if r >= 1:
                        mask_draw.ellipse([x1 - r, y1 - r, x1 + r, y1 + r], fill=255)
                        mask_draw.ellipse([x2 - r, y2 - r, x2 + r, y2 + r], fill=255)
            
            # Paste overlay (transparent or colored) using mask
            result.paste(overlay, (0, 0), mask)
        else:
            # Normal opaque drawing
            draw = ImageDraw.Draw(result)
            
            if mode == 'spraycan':
                import random
                spray_radius = draw_pen_size * 5
                dots_per_point = 20
                
                for point in points:
                    cx = int((point.x() - v.offset.x()) / v.scale)
                    cy = int((point.y() - v.offset.y()) / v.scale)
                    
                    for _ in range(dots_per_point):
                        angle = random.uniform(0, 2 * 3.14159)
                        distance = random.uniform(0, spray_radius)
                        dx = int(distance * math.cos(angle))
                        dy = int(distance * math.sin(angle))
                        draw.point((cx + dx, cy + dy), fill=color)
            else:
                # Pen, brush
                if len(points) == 1:
                    x = int((points[0].x() - v.offset.x()) / v.scale)
                    y = int((points[0].y() - v.offset.y()) / v.scale)
                    r = draw_pen_size // 2
                    if r < 1:
                        draw.point((x, y), fill=color)
                    else:
                        draw.ellipse([x - r, y - r, x + r, y + r], fill=color)
                else:
                    for i in range(len(points) - 1):
                        x1 = int((points[i].x() - v.offset.x()) / v.scale)
                        y1 = int((points[i].y() - v.offset.y()) / v.scale)
                        x2 = int((points[i + 1].x() - v.offset.x()) / v.scale)
                        y2 = int((points[i + 1].y() - v.offset.y()) / v.scale)
                        
                        draw.line([(x1, y1), (x2, y2)], fill=color, width=draw_pen_size)
                        
                        # Round caps
                        r = draw_pen_size // 2
                        if r >= 1:
                            draw.ellipse([x1 - r, y1 - r, x1 + r, y1 + r], fill=color)
                            draw.ellipse([x2 - r, y2 - r, x2 + r, y2 + r], fill=color)
        
        v.set_image(result)
    
    def apply_freehand_segment(self, points, first_segment=False):
        """Apply a single freehand segment in real-time (for instant feedback)
        
        Args:
            points: List of 2 points defining the segment
            first_segment: If True, push to undo history (for first segment of stroke)
        """
        v = self.viewer
        if not v.image or len(points) < 2:
            return
        
        # Get drawing parameters
        try:
            pen_size = int(self.freehand_size.currentText())
        except ValueError:
            pen_size = 3
        
        freehand_color = self.primary_color
        mode = getattr(self, 'freehand_mode', 'pen')
        
        from PIL import Image as PILImage, ImageDraw
        
        # Get color
        if len(freehand_color) >= 3:
            color = tuple(freehand_color[:3]) + (255,) if len(freehand_color) == 3 else tuple(freehand_color)
        else:
            color = (0, 0, 0, 255)
        
        draw_pen_size = pen_size
        is_eraser = (mode == 'eraser')
        is_transparent = (len(color) >= 4 and color[3] < 255)
        
        if is_eraser:
            color = (0, 0, 0, 0)
            draw_pen_size = max(pen_size * 2, 8)
        elif mode == 'brush':
            draw_pen_size = max(pen_size * 2, 5)
        
        if mode == 'spraycan':
            # Spraycan - draw dots
            import random
            result = v.image.copy().convert('RGBA')
            spray_radius = draw_pen_size * 5
            
            if is_eraser or is_transparent:
                mask = PILImage.new('L', result.size, 0)
                mask_draw = ImageDraw.Draw(mask)
                overlay = PILImage.new('RGBA', result.size, color)
                for point in points:
                    cx = int((point.x() - v.offset.x()) / v.scale)
                    cy = int((point.y() - v.offset.y()) / v.scale)
                    for _ in range(10):
                        angle = random.uniform(0, 2 * 3.14159)
                        distance = random.uniform(0, spray_radius)
                        dx = int(distance * math.cos(angle))
                        dy = int(distance * math.sin(angle))
                        mask_draw.point((cx + dx, cy + dy), fill=255)
                result.paste(overlay, (0, 0), mask)
            else:
                draw = ImageDraw.Draw(result)
                for point in points:
                    cx = int((point.x() - v.offset.x()) / v.scale)
                    cy = int((point.y() - v.offset.y()) / v.scale)
                    for _ in range(10):
                        angle = random.uniform(0, 2 * 3.14159)
                        distance = random.uniform(0, spray_radius)
                        dx = int(distance * math.cos(angle))
                        dy = int(distance * math.sin(angle))
                        draw.point((cx + dx, cy + dy), fill=color)
            
            v.set_image(result, push=first_segment)
        else:
            # Pen, brush, eraser - draw line segment
            result = v.image.copy().convert('RGBA')
            
            x1 = int((points[0].x() - v.offset.x()) / v.scale)
            y1 = int((points[0].y() - v.offset.y()) / v.scale)
            x2 = int((points[1].x() - v.offset.x()) / v.scale)
            y2 = int((points[1].y() - v.offset.y()) / v.scale)
            
            if is_eraser or is_transparent:
                mask = PILImage.new('L', result.size, 0)
                mask_draw = ImageDraw.Draw(mask)
                mask_draw.line([(x1, y1), (x2, y2)], fill=255, width=draw_pen_size)
                r = draw_pen_size // 2
                if r >= 1:
                    mask_draw.ellipse([x1 - r, y1 - r, x1 + r, y1 + r], fill=255)
                    mask_draw.ellipse([x2 - r, y2 - r, x2 + r, y2 + r], fill=255)
                overlay = PILImage.new('RGBA', result.size, color)
                result.paste(overlay, (0, 0), mask)
            else:
                draw = ImageDraw.Draw(result)
                draw.line([(x1, y1), (x2, y2)], fill=color, width=draw_pen_size)
                r = draw_pen_size // 2
                if r >= 1:
                    draw.ellipse([x1 - r, y1 - r, x1 + r, y1 + r], fill=color)
                    draw.ellipse([x2 - r, y2 - r, x2 + r, y2 + r], fill=color)
            
            v.set_image(result, push=first_segment)
    
    def draw_dot(self, painter, point, viewer, size):
        """Draw a single dot (for single clicks)"""
        # Convert screen coordinates to image coordinates
        x = int((point.x() - viewer.offset.x()) / viewer.scale)
        y = int((point.y() - viewer.offset.y()) / viewer.scale)
        
        # Clamp to image boundaries
        x = max(0, min(viewer.image.width, x))
        y = max(0, min(viewer.image.height, y))
        
        # Draw a filled circle for the dot
        painter.setBrush(painter.pen().color())
        size = int(size)
        radius = size // 2
        painter.drawEllipse(x - radius, y - radius, size, size)
    
    def draw_connected_lines(self, painter, points, viewer):
        """Draw connected lines through points (for pen, brush, eraser)"""
        for i in range(len(points) - 1):
            # Convert screen coordinates to image coordinates
            x1 = int((points[i].x() - viewer.offset.x()) / viewer.scale)
            y1 = int((points[i].y() - viewer.offset.y()) / viewer.scale)
            x2 = int((points[i + 1].x() - viewer.offset.x()) / viewer.scale)
            y2 = int((points[i + 1].y() - viewer.offset.y()) / viewer.scale)
            
            # Clamp to image boundaries
            x1 = max(0, min(viewer.image.width, x1))
            y1 = max(0, min(viewer.image.height, y1))
            x2 = max(0, min(viewer.image.width, x2))
            y2 = max(0, min(viewer.image.height, y2))
            
            painter.drawLine(x1, y1, x2, y2)
    
    def draw_spray_paint(self, painter, points, viewer, color, size):
        """Draw spray paint effect (many random dots)"""
        import random
        spray_radius = size * 5  # Spray area is larger than pen size
        dots_per_point = 20  # Number of dots per mouse position
        
        for point in points:
            # Convert screen coordinates to image coordinates
            cx = int((point.x() - viewer.offset.x()) / viewer.scale)
            cy = int((point.y() - viewer.offset.y()) / viewer.scale)
            
            # Draw random dots around this center point
            for _ in range(dots_per_point):
                # Random position within spray radius
                angle = random.uniform(0, 2 * 3.14159)
                distance = random.uniform(0, spray_radius)
                dx = int(distance * math.cos(angle))
                dy = int(distance * math.sin(angle))
                
                x = cx + dx
                y = cy + dy
                
                # Clamp to image boundaries
                if 0 <= x < viewer.image.width and 0 <= y < viewer.image.height:
                    painter.setPen(QPen(color, 1, Qt.PenStyle.SolidLine))
                    painter.drawPoint(x, y)
    
    def apply_color_eraser(self, points, size, target_color):
        """Erase only pixels of a specific color (NumPy-accelerated)"""
        v = self.viewer
        import numpy as np
        
        target_rgb = np.array([target_color.red(), target_color.green(), target_color.blue()], dtype=np.int16)
        tolerance = self.color_eraser_tolerance.value() if hasattr(self, 'color_eraser_tolerance') else 30
        
        img_copy = v.image.copy()
        arr = np.array(img_copy)
        is_rgba = arr.shape[2] == 4 if len(arr.shape) == 3 else False
        h, w = arr.shape[:2]
        
        # Pre-build circular mask for this brush size
        diam = size * 2 + 1
        yy, xx = np.ogrid[-size:size+1, -size:size+1]
        circle_mask = (xx*xx + yy*yy) <= size*size
        
        for point in points:
            cx = int((point.x() - v.offset.x()) / v.scale)
            cy = int((point.y() - v.offset.y()) / v.scale)
            
            # Compute bounding box clipped to image
            x1 = max(0, cx - size)
            y1 = max(0, cy - size)
            x2 = min(w, cx + size + 1)
            y2 = min(h, cy + size + 1)
            if x1 >= x2 or y1 >= y2:
                continue
            
            # Clip the circle mask to match the clipped region
            mx1 = x1 - (cx - size)
            my1 = y1 - (cy - size)
            mx2 = mx1 + (x2 - x1)
            my2 = my1 + (y2 - y1)
            mask_clip = circle_mask[my1:my2, mx1:mx2]
            
            # Extract region and compute color distance
            region = arr[y1:y2, x1:x2]
            diff = np.abs(region[:, :, :3].astype(np.int16) - target_rgb).sum(axis=2)
            
            # Combined mask: inside circle AND color matches
            erase = mask_clip & (diff <= tolerance)
            
            # Replace matching pixels with white
            if is_rgba:
                region[erase] = [255, 255, 255, 255]
            else:
                region[erase] = [255, 255, 255]
        
        from PIL import Image
        v.set_image(Image.fromarray(arr, img_copy.mode))
    
    def apply_color_eraser_realtime(self, points):
        """Apply color eraser in real-time as you drag (NumPy-accelerated)"""
        v = self.viewer
        import numpy as np
        
        if not v.image:
            return
        
        # Get drawing parameters
        try:
            pen_size = int(self.freehand_size.currentText())
        except ValueError:
            pen_size = 3
        
        eraser_size = max(pen_size * 2, 8)
        
        # Color Eraser target color comes from the global Primary color.
        pr = getattr(self, 'primary_color', (0, 0, 0, 255))
        if len(pr) >= 4 and pr[3] == 0:
            return
        target_rgb = np.array([int(pr[0]), int(pr[1]), int(pr[2])], dtype=np.int16)
        
        tolerance = self.color_eraser_tolerance.value() if hasattr(self, 'color_eraser_tolerance') else 30
        
        # Work directly with PIL image
        if v.image.mode not in ('RGB', 'RGBA'):
            v.image = v.image.convert('RGB')
        
        # Ensure image is writable
        try:
            test = np.array(v.image)
            test.flags.writeable
        except Exception:
            v.image = v.image.copy()
        
        arr = np.array(v.image)
        is_rgba = arr.shape[2] == 4 if len(arr.shape) == 3 else False
        h, w = arr.shape[:2]
        
        # Pre-build circular mask
        yy, xx = np.ogrid[-eraser_size:eraser_size+1, -eraser_size:eraser_size+1]
        circle_mask = (xx*xx + yy*yy) <= eraser_size*eraser_size
        
        modified = False
        for point in points:
            cx = int((point.x() - v.offset.x()) / v.scale)
            cy = int((point.y() - v.offset.y()) / v.scale)
            
            x1 = max(0, cx - eraser_size)
            y1 = max(0, cy - eraser_size)
            x2 = min(w, cx + eraser_size + 1)
            y2 = min(h, cy + eraser_size + 1)
            if x1 >= x2 or y1 >= y2:
                continue
            
            mx1 = x1 - (cx - eraser_size)
            my1 = y1 - (cy - eraser_size)
            mx2 = mx1 + (x2 - x1)
            my2 = my1 + (y2 - y1)
            mask_clip = circle_mask[my1:my2, mx1:mx2]
            
            region = arr[y1:y2, x1:x2]
            diff = np.abs(region[:, :, :3].astype(np.int16) - target_rgb).sum(axis=2)
            erase = mask_clip & (diff <= tolerance)
            
            if erase.any():
                if is_rgba:
                    region[erase] = [255, 255, 255, 255]
                else:
                    region[erase] = [255, 255, 255]
                modified = True
        
        if modified:
            from PIL import Image
            v.image = Image.fromarray(arr, v.image.mode)
            v.set_image(v.image)
    
    def _copy_image_to_clipboard(self, pil_image):
        """Copy a PIL image to the system clipboard with transparency support.
        
        Sets multiple MIME types to maximize compatibility:
        - image/png: Best for transparency (GIMP, Inkscape, Chrome, etc.)
        - application/x-qt-image: Qt apps
        - Standard QImage: Fallback for apps reading raw pixmap
        
        On Linux, also tries xclip for broader X11 clipboard support.
        """
        from PyQt6.QtCore import QMimeData, QBuffer, QIODevice
        import io
        
        clipboard = QApplication.clipboard()
        mime = QMimeData()
        
        # Generate PNG bytes from PIL directly (most reliable)
        png_buf = io.BytesIO()
        pil_image.convert('RGBA').save(png_buf, format='PNG')
        png_bytes = png_buf.getvalue()
        
        from PyQt6.QtCore import QByteArray
        png_qba = QByteArray(png_bytes)
        
        # Set PNG mime type (primary - preserves transparency)
        mime.setData("image/png", png_qba)
        
        # Also set as Qt image for Qt-based apps
        qimg = PilToQImage(pil_image).convertToFormat(QImage.Format.Format_ARGB32)
        mime.setImageData(qimg.copy())
        
        clipboard.setMimeData(mime)
        
        # On Linux, also try xclip which some apps prefer for reading clipboard
        if platform.system() == 'Linux':
            try:
                import subprocess
                proc = subprocess.Popen(
                    ['xclip', '-selection', 'clipboard', '-t', 'image/png', '-i'],
                    stdin=subprocess.PIPE, stderr=subprocess.DEVNULL
                )
                proc.communicate(input=png_bytes, timeout=2)
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
                pass  # xclip not available or failed, Qt clipboard is still set

    def copy_selection(self):
        """Copy the selected area or pasted content to clipboard"""
        v = self.viewer
        
        # If there's a paste preview, copy that
        if v.cutpaste_paste_pos and v.cutpaste_clipboard:
            # Copy to system clipboard with transparency
            self._copy_image_to_clipboard(v.cutpaste_clipboard)
            logging.debug(f"Copied pasted image: {v.cutpaste_clipboard.width}x{v.cutpaste_clipboard.height}")
            return
        
        # Otherwise, copy from selection
        if not v.image or not v.cutpaste_selection:
            logging.info("No selection to copy")
            return
        
        # Get selection in screen coordinates
        x1, y1, x2, y2 = v.cutpaste_selection
        
        # Convert to image coordinates
        img_x1 = int((x1 - v.offset.x()) / v.scale)
        img_y1 = int((y1 - v.offset.y()) / v.scale)
        img_x2 = int((x2 - v.offset.x()) / v.scale)
        img_y2 = int((y2 - v.offset.y()) / v.scale)
        
        # Clamp to image boundaries
        img_x1 = max(0, min(v.image.width, img_x1))
        img_y1 = max(0, min(v.image.height, img_y1))
        img_x2 = max(0, min(v.image.width, img_x2))
        img_y2 = max(0, min(v.image.height, img_y2))
        
        # Ensure coordinates are in the right order (user may drag any direction)
        img_x1, img_x2 = sorted((img_x1, img_x2))
        img_y1, img_y2 = sorted((img_y1, img_y2))
        
        # Copy the region to internal clipboard
        v.cutpaste_clipboard = v.image.crop((img_x1, img_y1, img_x2, img_y2))
        
        # Also copy to system clipboard with transparency
        self._copy_image_to_clipboard(v.cutpaste_clipboard)
        
        logging.debug(f"Copied region: {img_x2 - img_x1}x{img_y2 - img_y1}")
    
    def cut_selection(self):
        """Cut the selected area or pasted content (copy and remove/replace with white)"""
        v = self.viewer
        
        # If there's a paste preview, copy it then remove the preview
        if v.cutpaste_paste_pos and v.cutpaste_clipboard:
            # Copy to clipboard with transparency
            self._copy_image_to_clipboard(v.cutpaste_clipboard)
            logging.debug(f"Cut pasted image: {v.cutpaste_clipboard.width}x{v.cutpaste_clipboard.height}")
            
            # Clear the paste preview completely (so buttons will be disabled)
            v.cutpaste_paste_pos = None
            # Also clear clipboard from internal storage since it's been cut
            # (it's now in system clipboard if user wants to paste again)
            v.cutpaste_clipboard = None
            v.update()
            self.update_tool_buttons_state()
            return
        
        # Otherwise, cut from selection
        if not v.image or not v.cutpaste_selection:
            logging.info("No selection to cut")
            return
        
        # Copy first
        self.copy_selection()
        
        # Get selection in screen coordinates
        x1, y1, x2, y2 = v.cutpaste_selection
        
        # Convert to image coordinates
        img_x1 = int((x1 - v.offset.x()) / v.scale)
        img_y1 = int((y1 - v.offset.y()) / v.scale)
        img_x2 = int((x2 - v.offset.x()) / v.scale)
        img_y2 = int((y2 - v.offset.y()) / v.scale)
        
        # Clamp to image boundaries
        img_x1 = max(0, min(v.image.width, img_x1))
        img_y1 = max(0, min(v.image.height, img_y1))
        img_x2 = max(0, min(v.image.width, img_x2))
        img_y2 = max(0, min(v.image.height, img_y2))
        
        # Ensure coordinates are in the right order (user may drag any direction)
        img_x1, img_x2 = sorted((img_x1, img_x2))
        img_y1, img_y2 = sorted((img_y1, img_y2))
        
        # Fill with white
        qimg = PilToQImage(v.image, for_painting=True)
        painter = QPainter(qimg)
        painter.fillRect(img_x1, img_y1, img_x2 - img_x1, img_y2 - img_y1, QColor(255, 255, 255))
        painter.end()
        
        result = QImageToPil(qimg)
        v.set_image(result)
        
        # Clear selection completely
        v.cutpaste_selection = None
        v.sel_start = None
        v.sel_end = None
        v.update()
        
        # Update button states since selection is gone
        self.update_tool_buttons_state()
        
        logging.debug("Cut selection")
    
    def cut_selection_for_move(self):
        """Cut selection and prepare it for moving (MS Paint style)"""
        v = self.viewer
        if not v.image or not v.cutpaste_selection:
            return
        
        # Copy the selection to clipboard
        self.copy_selection()
        
        # Fill the original area with white
        x1, y1, x2, y2 = v.cutpaste_selection
        
        # Convert to image coordinates
        img_x1 = int((x1 - v.offset.x()) / v.scale)
        img_y1 = int((y1 - v.offset.y()) / v.scale)
        img_x2 = int((x2 - v.offset.x()) / v.scale)
        img_y2 = int((y2 - v.offset.y()) / v.scale)
        
        # Clamp to image boundaries
        img_x1 = max(0, min(v.image.width, img_x1))
        img_y1 = max(0, min(v.image.height, img_y1))
        img_x2 = max(0, min(v.image.width, img_x2))
        img_y2 = max(0, min(v.image.height, img_y2))
        
        # Ensure coordinates are in the right order (user may drag any direction)
        img_x1, img_x2 = sorted((img_x1, img_x2))
        img_y1, img_y2 = sorted((img_y1, img_y2))
        
        # Fill with white
        qimg = PilToQImage(v.image, for_painting=True)
        painter = QPainter(qimg)
        painter.fillRect(img_x1, img_y1, img_x2 - img_x1, img_y2 - img_y1, QColor(255, 255, 255))
        painter.end()
        
        result = QImageToPil(qimg)
        v.set_image(result, push=True)  # Push to history for undo
        
        # Set up paste preview at the same location
        v.cutpaste_paste_pos = (x1, y1, x2, y2)
        v.cutpaste_selection = None
        v.update()
    
    def paste_selection(self):
        """Paste the clipboard content (from internal clipboard or system clipboard)"""
        v = self.viewer
        
        # First try to get image from system clipboard
        clipboard = QApplication.clipboard()
        mime_data = clipboard.mimeData()
        
        # Debug: show what's in clipboard
        logging.debug(f"Clipboard formats: {mime_data.formats()}")
        
        pasted_from_system = False
        
        # Try direct image data first (screenshots)
        if mime_data.hasImage():
            qimg = clipboard.image()
            if not qimg.isNull():
                pil_img = QImageToPil(qimg)
                # Check and resize if image is too large
                pil_img = self.check_and_resize_large_image(pil_img)
                if pil_img is None:
                    return
                v.cutpaste_clipboard = pil_img
                pasted_from_system = True
                logging.debug(f"Pasted image from system clipboard: {pil_img.width}x{pil_img.height}")
        
        # Try GNOME copied files format
        if not pasted_from_system and 'x-special/gnome-copied-files' in mime_data.formats():
            data = mime_data.data('x-special/gnome-copied-files')
            if data:
                # Decode the data - format is "copy\nfile:///path/to/file\n"
                text = bytes(data).decode('utf-8').strip()
                logging.debug(f"GNOME copied files data: {text}")
                lines = text.split('\n')
                for line in lines:
                    if line.startswith('file://'):
                        file_path = line[7:]  # Remove file:// prefix
                        logging.debug(f"Trying to load: {file_path}")
                        
                        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                            try:
                                with Image.open(file_path) as _img:
                                    pil_img = _img.copy()
                                # Check and resize if image is too large
                                pil_img = self.check_and_resize_large_image(pil_img)
                                if pil_img is None:
                                    return
                                v.cutpaste_clipboard = pil_img
                                pasted_from_system = True
                                logging.debug(f"Loaded image from GNOME copied file: {file_path}")
                                break
                            except Exception as e:
                                logging.warning(f"Could not load image: {e}")
        
        # Try URLs (other file managers)
        if not pasted_from_system and mime_data.hasUrls():
            urls = mime_data.urls()
            logging.debug(f"Clipboard URLs: {[url.toString() for url in urls]}")
            for url in urls:
                file_path = url.toLocalFile()
                if not file_path:
                    file_path = url.toString()
                    # Remove file:// prefix if present
                    if file_path.startswith('file://'):
                        file_path = file_path[7:]
                
                logging.debug(f"Trying to load: {file_path}")
                
                # Check if it's an image file
                if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                    try:
                        with Image.open(file_path) as _img:
                            pil_img = _img.copy()
                        # Check and resize if image is too large
                        pil_img = self.check_and_resize_large_image(pil_img)
                        if pil_img is None:
                            return
                        v.cutpaste_clipboard = pil_img
                        pasted_from_system = True
                        logging.debug(f"Loaded image from file: {file_path}")
                        break
                    except Exception as e:
                        logging.warning(f"Could not load image from file: {e}")
        
        # Try text that might be a file path
        if not pasted_from_system and mime_data.hasText():
            text = clipboard.text().strip()
            logging.debug(f"Clipboard text: {text[:100]}")
            # Remove file:// prefix if present
            if text.startswith('file://'):
                text = text[7:]
            
            if text and text.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                try:
                    with Image.open(text) as _img:
                        pil_img = _img.copy()
                    # Check and resize if image is too large
                    pil_img = self.check_and_resize_large_image(pil_img)
                    if pil_img is None:
                        return
                    v.cutpaste_clipboard = pil_img
                    pasted_from_system = True
                    logging.debug(f"Loaded image from path: {text}")
                except Exception as e:
                    logging.warning(f"Could not load image from path: {e}")
        
        # If no image in clipboard, use internal clipboard
        if not v.cutpaste_clipboard:
            logging.info("Nothing to paste - no image in clipboard")
            return
        
        # Get paste image dimensions
        paste_width = v.cutpaste_clipboard.width
        paste_height = v.cutpaste_clipboard.height
        
        # Expand canvas if needed to fit the pasted image
        if v.image:
            current_width, current_height = v.image.size
            new_width = max(current_width, paste_width)
            new_height = max(current_height, paste_height)
            
            if new_width > current_width or new_height > current_height:
                # Create expanded canvas and paste current image at top-left
                expanded = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 255))
                expanded.paste(v.image.convert('RGBA'), (0, 0))
                v.set_image(expanded)
                logging.debug(f"Expanded canvas from {current_width}x{current_height} to {new_width}x{new_height}")
        
        # Position paste preview at visible top-left corner
        parent = self.window() if hasattr(self, 'window') else self
        if hasattr(parent, 'scroll_area'):
            scroll_x = parent.scroll_area.horizontalScrollBar().value()
            scroll_y = parent.scroll_area.verticalScrollBar().value()
        elif hasattr(self, 'scroll_area'):
            scroll_x = self.scroll_area.horizontalScrollBar().value()
            scroll_y = self.scroll_area.verticalScrollBar().value()
        else:
            scroll_x, scroll_y = 0, 0
        screen_x1 = scroll_x
        screen_y1 = scroll_y
        screen_x2 = screen_x1 + paste_width * v.scale
        screen_y2 = screen_y1 + paste_height * v.scale
        
        v.cutpaste_paste_pos = (screen_x1, screen_y1, screen_x2, screen_y2)
        
        v.update()
        # Update button states since we now have paste content
        self.update_tool_buttons_state()
        
        if pasted_from_system:
            logging.debug(f"Pasted {paste_width}x{paste_height} at top-left - drag to position, click outside to apply")
        else:
            logging.debug("Pasted at top-left - drag to position, click outside to apply")
    
    def apply_paste(self):
        """Apply the paste preview permanently to the image"""
        v = self.viewer
        if not v.cutpaste_paste_pos or not v.cutpaste_clipboard:
            return
        
        # Get paste position in screen coordinates
        px1, py1, px2, py2 = v.cutpaste_paste_pos
        
        # Convert to image coordinates
        img_x = int((px1 - v.offset.x()) / v.scale)
        img_y = int((py1 - v.offset.y()) / v.scale)
        img_w = max(1, int((px2 - px1) / v.scale))
        img_h = max(1, int((py2 - py1) / v.scale))
        
        # Scale clipboard to match the (possibly resized) preview dimensions
        clip = v.cutpaste_clipboard
        if clip.width != img_w or clip.height != img_h:
            clip = clip.resize((img_w, img_h), Image.Resampling.LANCZOS)
        
        # Paste onto the image (preserve alpha when present)
        base = v.image.copy()
        orig_mode = base.mode
        
        has_alpha = ("A" in getattr(clip, 'getbands', lambda: ())())
        if has_alpha:
            if base.mode != 'RGBA':
                base = base.convert('RGBA')
            if clip.mode != 'RGBA':
                clip = clip.convert('RGBA')
            base.paste(clip, (img_x, img_y), clip)
            result = base
            if orig_mode == 'RGB':
                rgb = Image.new('RGB', result.size, (255, 255, 255))
                rgb.paste(result, mask=result.split()[3])
                result = rgb
        else:
            base.paste(clip, (img_x, img_y))
            result = base
        
        # Clear paste preview BEFORE set_image so the repaint triggered by
        # update_view doesn't re-draw the paste overlay on top of the result
        v.cutpaste_paste_pos = None
        v.cutpaste_clipboard = None
        v.cutpaste_resizing = None
        
        v.set_image(result)
        v.update()
        
        # Update button states since paste content is gone
        self.update_tool_buttons_state()
        logging.debug('Paste applied')

    def apply_flood_fill(self, click_point):
        """Fill connected area with selected color (supports transparent colors)"""
        from PIL import ImageDraw, Image as PILImage, ImageChops
        v = self.viewer
        
        if not v.image:
            return
        
        # Convert screen coordinates to image coordinates
        x = int((click_point.x() - v.offset.x()) / v.scale)
        y = int((click_point.y() - v.offset.y()) / v.scale)
        
        # Clamp to image boundaries
        x = max(0, min(v.image.width - 1, x))
        y = max(0, min(v.image.height - 1, y))
        
        # Get the fill color (full RGBA)
        fill_color = tuple(self.primary_color[:4]) if len(self.primary_color) >= 4 else tuple(self.primary_color[:3]) + (255,)
        
        try:
            img_copy = v.image.copy().convert('RGBA')
            
            # Use an RGB copy to determine the flood region (PIL floodfill only works on RGB)
            rgb_copy = img_copy.convert('RGB')
            target_rgb = rgb_copy.getpixel((x, y))
            
            # Pick a marker color that differs from the target
            marker_color = (254, 1, 254)
            if target_rgb == marker_color:
                marker_color = (1, 254, 1)
            
            # Flood fill the RGB copy with the marker to identify the region
            filled = rgb_copy.copy()
            ImageDraw.floodfill(filled, (x, y), marker_color, thresh=0)
            
            # Build mask using PIL (no numpy): diff the before/after images
            diff = ImageChops.difference(rgb_copy, filled)
            # Any channel > 0 means pixel changed - convert to binary mask
            mask = diff.convert('L').point(lambda p: 255 if p > 0 else 0)
            
            # Check mask has any pixels
            if mask.getextrema()[1] == 0:
                return
            
            # Create overlay with fill color and paste using mask to replace pixels
            overlay = PILImage.new('RGBA', img_copy.size, fill_color)
            img_copy.paste(overlay, (0, 0), mask)
            
            v.set_image(img_copy)
        except Exception as e:
            logging.warning(f"Flood fill error: {e}")
            import traceback
            traceback.print_exc()

    # ---------------- Global Color Selector ----------------

    def _rgba_css(self, rgba):
        r, g, b, a = rgba
        return f"rgba({r}, {g}, {b}, {a/255.0:.3f})"

    def _build_global_color_selector(self):
        """Build the always-visible Paint-style color selector."""
        w = QWidget()
        w.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        # Primary/Secondary swatches
        self._primary_btn = ColorSwatchButton()
        self._primary_btn.setFixedSize(50, 34)
        self._primary_btn.setToolTip("Primary color")
        self._primary_btn.clicked.connect(lambda: self._set_active_color_slot('primary'))

        self._secondary_btn = ColorSwatchButton()
        self._secondary_btn.setFixedSize(50, 34)
        self._secondary_btn.setToolTip("Secondary color")
        self._secondary_btn.clicked.connect(lambda: self._set_active_color_slot('secondary'))

        lay.addWidget(self._primary_btn)
        lay.addWidget(self._secondary_btn)

        # Palette display
        palette_box = QWidget()
        grid = QGridLayout(palette_box)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(2)
        grid.setVerticalSpacing(2)
        palette_box.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        self._palette_buttons = []
        
        # Handle both positioned dict and list formats
        if isinstance(self._global_palette, dict):
            # Positioned format - display exactly as positioned
            if not self._global_palette:
                # Empty palette
                cols, rows = 6, 2
            else:
                max_row = max((pos[0] for pos in self._global_palette.keys()), default=1)
                max_col = max((pos[1] for pos in self._global_palette.keys()), default=5)
                rows = max_row + 1
                cols = max_col + 1
            
            # Add buttons at their exact positions
            for (row, col), rgba in self._global_palette.items():
                btn = PaletteButton(rgba)
                btn.setFixedSize(18, 18)
                btn.setToolTip("Transparent" if rgba[3] == 0 else f"{rgba[0]},{rgba[1]},{rgba[2]}")
                btn.clicked.connect(lambda checked=False, c=rgba: self._apply_palette_color(c))
                grid.addWidget(btn, row, col)
                self._palette_buttons.append((btn, rgba))
        else:
            # List format - use automatic layout (backwards compatibility)
            n = len(self._global_palette)
            cols, rows, _ = ColorPaletteEditorDialog.calculate_palette_grid_layout(n, for_dialog=False)
            
            for i, rgba in enumerate(self._global_palette):
                btn = PaletteButton(rgba)
                btn.setFixedSize(18, 18)
                btn.setToolTip("Transparent" if rgba[3] == 0 else f"{rgba[0]},{rgba[1]},{rgba[2]}")
                btn.clicked.connect(lambda checked=False, c=rgba: self._apply_palette_color(c))
                r = i // cols
                c = i % cols
                grid.addWidget(btn, r, c)
                self._palette_buttons.append((btn, rgba))
        
        # Calculate and set fixed size
        palette_width = cols * 18 + (cols - 1) * 2
        palette_height = rows * 18 + (rows - 1) * 2
        palette_box.setFixedSize(palette_width, palette_height)

        lay.addWidget(palette_box)

        # Paintbrush indicator (clickable for quick eyedropper from canvas)
        self._eyedropper_indicator = QPushButton("🖌")
        self._eyedropper_indicator.setFixedSize(36, 34)
        self._eyedropper_indicator.setStyleSheet("font-size: 20px; background-color: #3a3a3a; border: 1px solid #666;" if self._is_dark_mode else "font-size: 20px; background-color: white; border: 1px solid #ccc;")
        self._eyedropper_indicator.setToolTip("Click to pick a color from the canvas")
        self._eyedropper_indicator.clicked.connect(self._start_quick_eyedropper)
        lay.addWidget(self._eyedropper_indicator)

        # Custom color button with fixed width
        self._custom_color_btn = QPushButton("Custom")
        self._custom_color_btn.setFixedSize(70, 34)
        self._custom_color_btn.clicked.connect(self._pick_custom_color_for_active_slot)
        lay.addWidget(self._custom_color_btn)

        self._refresh_color_selector_ui()
        return w

    def _get_colors_in_use(self):
        """
        Determine which color slots are in use for the current tool.
        Returns: tuple (primary_in_use: bool, secondary_in_use: bool)
        """
        tool = getattr(self, 'active_tool', None)
        
        if tool is None:
            return (False, False)
        
        # Tools that never use colors
        if tool in ('crop', 'cutpaste', 'pixelate', 'blur', 'remove_space', 'transform'):
            return (False, False)
        
        # Step Marker: Primary for badge color, Secondary for text color
        if tool == 'step_marker':
            return (True, True)
        
        # Magnify Inset: Primary for border/connection color
        if tool == 'magnify_inset':
            return (True, False)
        
        # Outline: Primary for border color
        if tool == 'outline':
            return (True, False)
        
        # Arrow: Always Primary, Never Secondary
        if tool == 'arrow':
            return (True, False)
        
        # Cut Out: Primary only if Sawtooth is selected, Never Secondary
        if tool == 'cutout':
            if hasattr(self, 'cut_style'):
                uses_primary = (self.cut_style.currentText() in ("Sawtooth", "Line"))
                return (uses_primary, False)
            return (False, False)
        
        # Freehand: Primary if certain modes are selected, Never Secondary
        if tool == 'freehand':
            if hasattr(self, 'freehand_mode'):
                # Primary for: pen, brush, spraycan, flood, color_eraser
                # Neither for: eraser
                uses_primary = self.freehand_mode in ('pen', 'brush', 'spraycan', 'flood', 'color_eraser')
                return (uses_primary, False)
            return (False, False)
        
        # Highlight: Always Primary, Never Secondary
        if tool == 'highlight':
            return (True, False)
        
        # Line: Always Primary, Never Secondary
        if tool == 'line':
            return (True, False)
        
        # Oval: Always Primary, Secondary if Fill is selected
        if tool == 'oval':
            secondary_in_use = hasattr(self, 'oval_fill_enabled') and self.oval_fill_enabled.isChecked()
            return (True, secondary_in_use)
        
        # Rectangle: Always Primary, Secondary if Fill is selected
        if tool == 'rectangle':
            secondary_in_use = hasattr(self, 'fill_enabled') and self.fill_enabled.isChecked()
            return (True, secondary_in_use)
        
        # Text: Always Primary, Secondary if Outline is selected
        if tool == 'text':
            secondary_in_use = hasattr(self, 'text_outline') and self.text_outline.isChecked()
            return (True, secondary_in_use)
        
        # Default: no colors in use
        return (False, False)

    def _set_active_color_slot(self, slot: str):
        if slot not in ('primary', 'secondary'):
            return
        self._active_color_slot = slot
        self._refresh_color_selector_ui()

    def _apply_palette_color(self, rgba):
        if self._active_color_slot == 'primary':
            self.primary_color = tuple(rgba)
            # Keep legacy target color (used by Color Eraser) aligned with Primary.
            self.selected_freehand_color = (self.primary_color[0], self.primary_color[1], self.primary_color[2])
        else:
            self.secondary_color = tuple(rgba)
        self._refresh_color_selector_ui()
        # Invalidate shape preview so color change is reflected immediately
        self.viewer.shape_preview_pixmap = None
        self.viewer._shape_preview_key = None
        self._update_shape_preview()
        self.viewer.update()

    def _pick_custom_color_for_active_slot(self):
        # Guard: don't open multiple dialogs
        if getattr(self, '_custom_dialog_open', False):
            return
        self._custom_dialog_open = True
        try:
            initial = self.primary_color if self._active_color_slot == 'primary' else self.secondary_color
            rgba = self._pick_color_modal_rgba(initial, 'Select Color', self._custom_color_btn)
            if rgba is None:
                return
            # Guard: avoid accidental fully-transparent custom colors
            # (some platforms/dialog states can yield alpha=0 even when a visible color was chosen).
            if len(rgba) == 4 and rgba[3] == 0:
                rgba = (rgba[0], rgba[1], rgba[2], 255)

            self._apply_palette_color(rgba)
        finally:
            self._custom_dialog_open = False

    def _start_quick_eyedropper(self):
        """Start a quick eyedropper pick directly from canvas without opening a dialog."""
        if getattr(self, '_eyedropper_active', False):
            return
        if self.viewer.image is None:
            return
        
        self._eyedropper_active = True
        self._eyedropper_dialog = None  # No dialog for quick mode
        self._eyedropper_button = None
        self._eyedropper_spinner_angle = 0
        self._quick_eyedropper = True  # Flag for quick mode
        
        # Start spinner animation
        self._eyedropper_timer.start()
        
        # Set crosshair cursor
        self.viewer.setCursor(Qt.CursorShape.CrossCursor)

    def _finish_quick_eyedropper(self, rgb):
        """Finish quick eyedropper - apply sampled color directly to active slot."""
        if not getattr(self, '_quick_eyedropper', False):
            return
        
        self._eyedropper_active = False
        self._quick_eyedropper = False
        
        # Stop spinner animation
        self._eyedropper_timer.stop()
        
        # Reset indicator appearance
        if hasattr(self, '_eyedropper_indicator'):
            if self._is_dark_mode:
                self._eyedropper_indicator.setStyleSheet(
                    "font-size: 20px; background-color: #3a3a3a; border: 1px solid #666;"
                )
            else:
                self._eyedropper_indicator.setStyleSheet(
                    "font-size: 20px; background-color: white; border: 1px solid #ccc;"
                )
        
        # Restore cursor
        try:
            self.viewer.unsetCursor()
        except Exception:
            pass
        
        if rgb is not None:
            rgba = (rgb[0], rgb[1], rgb[2], 255)
            self._apply_palette_color(rgba)

    def _refresh_color_selector_ui(self):
        """Refresh the UI (swatch fills + which slot is active + which colors are in use)."""
        if not hasattr(self, '_primary_btn'):
            return

        # Get which colors are in use for the current tool
        primary_in_use, secondary_in_use = self._get_colors_in_use()
        
        # Set color values (for checkerboard pattern on transparent colors)
        self._primary_btn.set_color(self.primary_color)
        self._secondary_btn.set_color(self.secondary_color)
        
        # Set checkmark visibility
        self._primary_btn.set_in_use(primary_in_use)
        self._secondary_btn.set_in_use(secondary_in_use)
        
        # Set editability (affects border - drawn in paintEvent)
        self._primary_btn.set_editable(self._active_color_slot == 'primary')
        self._secondary_btn.set_editable(self._active_color_slot == 'secondary')
        
        # Set opacity for dimming effect (colors not in use)
        if primary_in_use:
            self._primary_btn.setStyleSheet("opacity: 1.0;")
        else:
            self._primary_btn.setStyleSheet("opacity: 0.5;")
        
        if secondary_in_use:
            self._secondary_btn.setStyleSheet("opacity: 1.0;")
        else:
            self._secondary_btn.setStyleSheet("opacity: 0.5;")

        # Update tooltips to indicate usage
        primary_tooltip = "Primary color"
        if primary_in_use:
            primary_tooltip += " (in use)"
        else:
            primary_tooltip += " (not used by current tool)"
        self._primary_btn.setToolTip(primary_tooltip)
        
        secondary_tooltip = "Secondary color"
        if secondary_in_use:
            secondary_tooltip += " (in use)"
        else:
            secondary_tooltip += " (not used by current tool)"
        self._secondary_btn.setToolTip(secondary_tooltip)

        # Palette swatches draw themselves, no need to set stylesheet
        # Just trigger an update if needed
        for btn, rgba in getattr(self, '_palette_buttons', []):
            btn.update()

    def _update_active_color_slot_from_tool(self):
        """Refresh the color selector UI to reflect which colors are in use.
        Does NOT change which color is editable - user must click to change that."""
        # Just refresh the UI to show checkmarks and dimming
        # Don't automatically switch the active color slot
        self._refresh_color_selector_ui()

    def select_outline_color(self, color):
        self.selected_outline = color
        # Update all outline buttons to show selection with thicker, more obvious border
        for c, btn in self.outline_colors.items():
            if c == color:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;")  # Gold border
            else:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        # Reset custom button
        self.outline_custom_btn.setStyleSheet("")
        self.update_rect_preview()

    def select_fill_color(self, color):
        self.selected_fill = color
        self.update_fill_color_display()
        self.update_rect_preview()

    # ---------------- Eyedropper helpers ----------------

    def _force_restore_cursor(self):
        """Best-effort: fully clear any QApplication override cursor stack.

        Qt keeps override cursors in a stack; if we ever fail to pop one,
        the cursor can get stuck as a crosshair.
        """
        try:
            # overrideCursor() returns the current override cursor or None
            while QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()
        except Exception:
            pass


    def _update_eyedropper_spinner(self):
        """Update the spinner animation - rainbow for paintbrush indicator or black/white for button"""
        if not self._eyedropper_active:
            return
        
        # Increment spinner angle
        self._eyedropper_spinner_angle = (self._eyedropper_spinner_angle + 30) % 360
        
        # Check if toolbar is visible
        toolbar_visible = hasattr(self, '_color_selector_widget') and self._color_selector_widget.isVisible()
        
        if toolbar_visible and hasattr(self, '_eyedropper_indicator'):
            # Use rainbow effect on paintbrush indicator
            # Convert angle to hue (0-360) for rainbow colors
            hue = self._eyedropper_spinner_angle
            color = QColor.fromHsv(hue, 255, 255)  # Full saturation and value
            
            self._eyedropper_indicator.setStyleSheet(
                f"font-size: 20px; "
                f"background-color: rgb({color.red()}, {color.green()}, {color.blue()}); "
                f"border: 2px solid #000;"
            )
        elif self._eyedropper_button:
            # Fall back to black/white animation on custom button
            ratio = self._eyedropper_spinner_angle / 360.0
            gray_value = int(255 * ratio)
            
            self._eyedropper_button.setStyleSheet(
                f"background-color: rgb({gray_value}, {gray_value}, {gray_value}); "
                f"border: 2px solid #000000;"
            )

    
    def _start_eyedropper(self, dlg: QColorDialog, button=None):
        """Temporarily hide the color dialog and let the user click the canvas to sample a color.

        Left-click samples. Right-click or click outside canvas cancels.
        
        Args:
            dlg: The color dialog to hide/restore
            button: The custom color button to animate (optional)
        """
        if getattr(self, '_eyedropper_active', False):
            return

        if self.viewer.image is None:
            # Nothing to sample
            return

        self._eyedropper_active = True
        self._eyedropper_dialog = dlg
        self._eyedropper_button = button
        self._eyedropper_spinner_angle = 0
        
        # Start spinner animation
        self._eyedropper_timer.start()

        # Remember and temporarily disable modality so the canvas can receive clicks
        self._eyedropper_restore_modality = dlg.windowModality()
        try:
            self._eyedropper_restore_modal = dlg.isModal()
        except Exception:
            self._eyedropper_restore_modal = True

        dlg.setWindowModality(Qt.WindowModality.NonModal)
        try:
            dlg.setModal(False)
        except Exception:
            pass
        dlg.hide()

        # Safety: ensure the main window is re-enabled (exec()-style modality can disable it)
        try:
            self.setEnabled(True)
        except Exception:
            pass

        # Eyedropper input capture:
        # Use widget-level cursor + mouse grab instead of QApplication override cursor.
        # This prevents the cursor from getting stuck and prevents accidental clicks on other UI.
        try:
            self.viewer.setCursor(Qt.CursorShape.CrossCursor)
            self.viewer.grabMouse()
        except Exception:
            pass

        # Give focus back to the main window/viewer
        self.activateWindow()
        self.raise_()
        self.viewer.setFocus()

    def _finish_eyedropper(self, rgb):
        if not self._eyedropper_active:
            return

        dlg = self._eyedropper_dialog
        button = self._eyedropper_button
        self._eyedropper_active = False
        self._eyedropper_dialog = None
        self._eyedropper_button = None
        
        # Stop spinner animation
        self._eyedropper_timer.stop()
        
        # Reset paintbrush indicator to normal appearance
        if hasattr(self, '_eyedropper_indicator'):
            if self._is_dark_mode:
                self._eyedropper_indicator.setStyleSheet(
                    "font-size: 20px; background-color: #3a3a3a; border: 1px solid #666;"
                )
            else:
                self._eyedropper_indicator.setStyleSheet(
                    "font-size: 20px; background-color: white; border: 1px solid #ccc;"
                )
        
        # Restore button appearance if we have one
        if button and rgb is not None:
            button.setStyleSheet(
                f"background-color: rgb{rgb}; border: 1px solid #666;"
            )

        # Release mouse + restore normal cursor
        try:
            self.viewer.releaseMouse()
        except Exception:
            pass
        try:
            self.viewer.unsetCursor()
        except Exception:
            pass

        if dlg is None:
            return

        # Restore modality and show dialog again
        if self._eyedropper_restore_modality is not None:
            dlg.setWindowModality(self._eyedropper_restore_modality)
        try:
            dlg.setModal(bool(self._eyedropper_restore_modal))
        except Exception:
            pass

        if rgb is not None:
            q = QColor(*rgb)
            # Update the dialog's current/selected color
            if hasattr(dlg, 'setCurrentColor'):
                dlg.setCurrentColor(q)
            if hasattr(dlg, 'setSelectedColor'):
                try:
                    dlg.setSelectedColor(q)
                except Exception:
                    pass

        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _cancel_eyedropper(self):
        # Same as finish, but without changing color
        self._finish_eyedropper(None)
    
    def _abort_eyedropper(self):
        """Abort picking (e.g., user clicked outside the canvas).
        
        This cancels the color-pick flow and closes the color dialog instead of reopening it.
        """
        if not getattr(self, '_eyedropper_active', False):
            return
        
        dlg = getattr(self, '_eyedropper_dialog', None)
        button = self._eyedropper_button
        
        # Reset state + input capture
        self._eyedropper_active = False
        self._eyedropper_dialog = None
        self._eyedropper_button = None
        
        # Stop spinner animation
        self._eyedropper_timer.stop()
        
        # Restore button appearance if we have one
        if button:
            # Restore to original color (get from selected color variable)
            # We don't have the original color here, so just reset to normal border
            pass
        
        try:
            self.viewer.releaseMouse()
        except Exception:
            pass
        try:
            self.viewer.unsetCursor()
        except Exception:
            pass
        
        # Close the dialog (reject) instead of showing it again
        if dlg is not None:
            try:
                dlg.reject()  # Close without accepting
            except Exception:
                pass

    def _install_eyedropper_button(self, dlg: QColorDialog, custom_button=None):
        """Install a 'Pick Color from Canvas' button into the QColorDialog.
        
        Args:
            dlg: The color dialog
            custom_button: The custom color button to animate during picking
        """
        # Create button as child of color dialog
        btn = QPushButton('Pick Color from Canvas', dlg)
        btn.setToolTip('Click to pick a color from the canvas')
        btn.clicked.connect(lambda: self._start_eyedropper(dlg, custom_button))
        btn.setMinimumHeight(32)
        
        def _insert_btn_into_qcolordialog():
            """Insert the button into QColorDialog's internal layout"""
            from PyQt6.QtWidgets import QLayout, QGridLayout
            
            # Strategy 1: Find "Custom colors" label (try multiple variations)
            custom_color_labels = ["custom colors", "custom", "custom colour", "custom colours"]
            for lay in dlg.findChildren(QLayout):
                if not hasattr(lay, "insertWidget"):
                    continue
                for i in range(lay.count()):
                    item = lay.itemAt(i)
                    w = item.widget() if item else None
                    if isinstance(w, QLabel):
                        label_text = w.text().strip().lower()
                        if any(text in label_text for text in custom_color_labels):
                            lay.insertWidget(i, btn)
                            btn.show()
                            return
            
            # Strategy 2: Find the grid with custom color buttons (usually 2 rows)
            for grid in dlg.findChildren(QGridLayout):
                # Custom colors grid is typically smaller (2 rows, 8 columns)
                if grid.rowCount() == 2 and grid.columnCount() >= 4:
                    # Get parent layout and insert before grid
                    parent_layout = grid.parent().layout() if grid.parent() else None
                    if parent_layout and hasattr(parent_layout, "insertWidget"):
                        # Find grid's position in parent
                        for i in range(parent_layout.count()):
                            if parent_layout.itemAt(i).layout() == grid:
                                parent_layout.insertWidget(i, btn)
                                btn.show()
                                return
            
            # Strategy 3: Find "Add to Custom Colors" button and insert above it
            for child_btn in dlg.findChildren(QPushButton):
                btn_text = child_btn.text().lower()
                if "add" in btn_text and "custom" in btn_text:
                    parent_layout = child_btn.parent().layout() if child_btn.parent() else None
                    if parent_layout and hasattr(parent_layout, "insertWidget"):
                        for i in range(parent_layout.count()):
                            item = parent_layout.itemAt(i)
                            if item.widget() == child_btn:
                                parent_layout.insertWidget(max(0, i - 1), btn)
                                btn.show()
                                return
            
            # Fallback: append to main layout
            if dlg.layout() is not None:
                dlg.layout().addWidget(btn)
                btn.show()
        
        # Let Qt finish building QColorDialog internals first
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(0, _insert_btn_into_qcolordialog)
        
        # Disable if there's nothing to sample
        btn.setEnabled(self.viewer.image is not None)

        return btn


    
    def _pick_color_modal_rgba(self, initial_rgba, title: str, custom_button=None):
        # Open a non-native QColorDialog with alpha + 'Pick from Canvas' support.
        # Returns (r,g,b,a) or None.
        try:
            rgba = tuple(initial_rgba)
        except Exception:
            rgba = (0, 0, 0, 255)
        if len(rgba) == 3:
            rgba = (rgba[0], rgba[1], rgba[2], 255)

        dlg = QColorDialog(QColor(rgba[0], rgba[1], rgba[2], rgba[3]), self)
        dlg.setWindowTitle(title)
        dlg.setOption(QColorDialog.ColorDialogOption.DontUseNativeDialog, True)
        dlg.setOption(QColorDialog.ColorDialogOption.ShowAlphaChannel, True)
        dlg.setWindowFlag(Qt.WindowType.Tool, True)
        dlg.setWindowModality(Qt.WindowModality.NonModal)
        try:
            dlg.setModal(False)
        except Exception:
            pass

        # Inject an eyedropper button
        self._install_eyedropper_button(dlg, custom_button)

        loop = QEventLoop()
        dlg.finished.connect(self._force_restore_cursor)
        def _on_dlg_finished(_):
            if getattr(self, '_eyedropper_active', False) and getattr(self, '_eyedropper_dialog', None) is dlg:
                self._eyedropper_active = False
                self._eyedropper_dialog = None
        dlg.finished.connect(_on_dlg_finished)
        dlg.finished.connect(loop.quit)

        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

        loop.exec()

        if dlg.result() == QDialog.DialogCode.Accepted:
            c = dlg.selectedColor()
            if c.isValid():
                return (c.red(), c.green(), c.blue(), c.alpha())
        return None

    def _pick_color_modal(self, initial_rgb, title: str, custom_button=None):
        """Open a modal, parented QColorDialog that behaves well on both X11 and Wayland.

        Returns an (r, g, b) tuple, or None if the user cancels.
        
        Args:
            initial_rgb: Initial color as (r, g, b) tuple
            title: Dialog window title
            custom_button: The custom color button that triggered this dialog (for spinner animation)
        """
        try:
            rgb = tuple(initial_rgb)
        except Exception:
            rgb = (0, 0, 0)

        dlg = QColorDialog(QColor(*rgb), self)
        dlg.setWindowTitle(title)

        # Wayland-safe default: avoid native/portal dialogs that can stack behind the app
        dlg.setOption(QColorDialog.ColorDialogOption.DontUseNativeDialog, True)

        # Keep above *this* app without forcing global always-on-top
        dlg.setWindowFlag(Qt.WindowType.Tool, True)

        # IMPORTANT: do not make this dialog Qt-modal, because that disables the main window
        # and prevents the canvas from receiving clicks for the eyedropper. We keep it
        # non-modal and use a local QEventLoop to *wait* for accept/reject.
        dlg.setWindowModality(Qt.WindowModality.NonModal)
        try:
            dlg.setModal(False)
        except Exception:
            pass

        # Inject an eyedropper button (best-effort placement), passing the custom button for animation
        self._install_eyedropper_button(dlg, custom_button)

        # IMPORTANT: do NOT use dlg.exec() here.
        # QDialog.exec() disables other top-level windows until it returns.
        # That makes the canvas-eyedropper unusable (the app stays unclickable
        # even if we hide the dialog). Instead, we show the dialog and wait
        # on a local event loop that can temporarily drop modality safely.
        loop = QEventLoop()
        # If the dialog is closed while eyedropper is active, make sure we clean up
        dlg.finished.connect(self._force_restore_cursor)
        def _on_dlg_finished(_):
            if getattr(self, '_eyedropper_active', False) and getattr(self, '_eyedropper_dialog', None) is dlg:
                self._eyedropper_active = False
                self._eyedropper_dialog = None
        dlg.finished.connect(_on_dlg_finished)
        dlg.finished.connect(loop.quit)

        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

        loop.exec()

        if dlg.result() == QDialog.DialogCode.Accepted:
            c = dlg.selectedColor()
            if c.isValid():
                return (c.red(), c.green(), c.blue())
        return None

    def pick_fill_color_popup(self):
        """Open color picker for fill color"""
        rgb = self._pick_color_modal(self.selected_fill, "Select Fill Color", self.fill_color_btn)
        if rgb is None:
            return
        self.selected_fill = rgb
        self.update_fill_color_display()
        self.update_rect_preview()

    def update_fill_color_display(self):
        """Update fill color button display based on checkbox state"""
        fill_enabled = self.fill_enabled.isChecked()
        
        if fill_enabled:
            # Show active color
            self.fill_color_btn.setStyleSheet(
                f"background-color: rgb{self.selected_fill}; border: 2px solid #666;"
            )
            self.fill_color_btn.setEnabled(True)
        else:
            # Disabled appearance - grayed out
            self.fill_color_btn.setStyleSheet(
                f"background-color: rgb{self.selected_fill}; border: 1px solid #666; opacity: 0.3;"
            )
            self.fill_color_btn.setEnabled(False)

    def pick_outline_custom(self):
        rgb = self._pick_color_modal(self.selected_outline, "Select Outline Color", self.outline_custom_btn)
        if rgb is None:
            return
        self.selected_outline = rgb
        self.outline_custom_btn.setStyleSheet(
            f"background-color: rgb{rgb}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;"
        )
        # Reset palette buttons
        for c, btn in self.outline_colors.items():
            btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        self.update_rect_preview()

    def update_rect_preview(self):
        """Update the viewer when rectangle settings change"""
        self.viewer.shape_preview_pixmap = None  # Force pixmap rebuild
        self.viewer._shape_preview_key = None  # Invalidate cache
        self._update_shape_preview()
        self.viewer.update()

    # ---------------- Oval color methods ----------------

    def select_oval_outline_color(self, color):
        self.selected_oval_outline = color
        # Update all oval outline buttons to show selection with thicker, more obvious border
        for c, btn in self.oval_outline_colors.items():
            if c == color:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;")  # Gold border
            else:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        # Reset custom button
        self.oval_outline_custom_btn.setStyleSheet("")
        self.update_oval_preview()

    def pick_oval_outline_custom(self):
        rgb = self._pick_color_modal(self.selected_oval_outline, "Select Oval Outline Color", self.oval_outline_custom_btn)
        if rgb is None:
            return
        self.selected_oval_outline = rgb
        self.oval_outline_custom_btn.setStyleSheet(
            f"background-color: rgb{rgb}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;"
        )
        # Reset palette buttons
        for c, btn in self.oval_outline_colors.items():
            btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        self.update_oval_preview()

    def pick_oval_fill_color_popup(self):
        """Open color picker for oval fill color"""
        rgb = self._pick_color_modal(self.selected_oval_fill, "Select Oval Fill Color", self.oval_fill_color_btn)
        if rgb is None:
            return
        self.selected_oval_fill = rgb
        self.update_oval_fill_color_display()
        self.update_oval_preview()

    def update_oval_fill_color_display(self):
        """Update oval fill color button display based on checkbox state"""
        fill_enabled = self.oval_fill_enabled.isChecked()
        
        if fill_enabled:
            # Show active color
            self.oval_fill_color_btn.setStyleSheet(
                f"background-color: rgb{self.selected_oval_fill}; border: 2px solid #666;"
            )
            self.oval_fill_color_btn.setEnabled(True)
        else:
            # Disabled appearance - grayed out
            self.oval_fill_color_btn.setStyleSheet(
                f"background-color: rgb{self.selected_oval_fill}; border: 1px solid #666; opacity: 0.3;"
            )
            self.oval_fill_color_btn.setEnabled(False)

    def update_oval_preview(self):
        """Update the viewer when oval settings change"""
        self.viewer.shape_preview_pixmap = None
        self.viewer._shape_preview_key = None
        self._update_shape_preview()
        self.viewer.update()

    # ---------------- Line color methods ----------------

    def select_line_color(self, color):
        self.selected_line_color = color
        # Update all line color buttons to show selection
        for c, btn in self.line_colors.items():
            if c == color:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;")
            else:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        # Reset custom button
        self.line_custom_btn.setStyleSheet("")
        self.update_line_preview()

    def pick_line_custom(self):
        rgb = self._pick_color_modal(self.selected_line_color, "Select Line Color", self.line_custom_btn)
        if rgb is None:
            return
        self.selected_line_color = rgb
        self.line_custom_btn.setStyleSheet(
            f"background-color: rgb{rgb}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;"
        )
        # Reset palette buttons
        for c, btn in self.line_colors.items():
            btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        self.update_line_preview()

    def update_line_preview(self):
        """Update the viewer when line settings change"""
        self.viewer.shape_preview_pixmap = None
        self.viewer._shape_preview_key = None
        self._update_shape_preview()
        self.viewer.update()

    # ---------------- Arrow color methods ----------------

    def select_arrow_color(self, color):
        self.selected_arrow_color = color
        # Update all arrow color buttons to show selection
        for c, btn in self.arrow_colors.items():
            if c == color:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;")
            else:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        # Reset custom button
        self.arrow_custom_btn.setStyleSheet("")
        self.update_arrow_preview()

    def pick_arrow_custom(self):
        rgb = self._pick_color_modal(self.selected_arrow_color, "Select Arrow Color", self.arrow_custom_btn)
        if rgb is None:
            return
        self.selected_arrow_color = rgb
        self.arrow_custom_btn.setStyleSheet(
            f"background-color: rgb{rgb}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;"
        )
        # Reset palette buttons
        for c, btn in self.arrow_colors.items():
            btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        self.update_arrow_preview()

    def update_arrow_preview(self):
        """Update the viewer when arrow settings change"""
        self.viewer.shape_preview_pixmap = None
        self.viewer._shape_preview_key = None
        self._update_shape_preview()
        self.viewer.update()

    # ---------------- Freehand methods ----------------

    def select_freehand_mode(self, mode):
        """Select freehand mode — sets the dropdown and internal state"""
        mode_to_display = {
            'pen': 'Pen', 'brush': 'Brush', 'spraycan': 'Spray Can',
            'flood': 'Flood Fill', 'color_eraser': 'Color Eraser', 'eraser': 'Eraser'
        }
        display = mode_to_display.get(mode, 'Pen')
        
        # Update dropdown without re-triggering the change handler
        self.freehand_mode_dropdown.blockSignals(True)
        idx = self.freehand_mode_dropdown.findText(display)
        if idx >= 0:
            self.freehand_mode_dropdown.setCurrentIndex(idx)
        self.freehand_mode_dropdown.blockSignals(False)
        
        self.freehand_mode = mode
        
        # Enable/disable tolerance based on mode
        tol_enabled = (mode == 'color_eraser')
        self._tolerance_label.setEnabled(tol_enabled)
        self.color_eraser_tolerance.setEnabled(tol_enabled)
        
        # Update color selector to reflect which colors are in use
        self._refresh_color_selector_ui()
        
        # Ensure freehand tool is active when selecting a freehand mode
        # (but not during init when active_tool is None - let user choose their tool)
        if hasattr(self, 'active_tool') and self.active_tool is not None and self.active_tool != 'freehand':
            # Set active tool to freehand without re-triggering select_tool's auto-apply logic
            self.active_tool = 'freehand'
            self.tool_stack.setCurrentIndex(7)  # Freehand is index 7
            # Update toolbar button states
            for tool_id, btn in self.tool_buttons.items():
                btn.setChecked(tool_id == 'freehand')
            # Update dropdown
            idx = self.tool_combo.findData('freehand')
            if idx >= 0:
                self.tool_combo.blockSignals(True)
                self.tool_combo.setCurrentIndex(idx)
                self.tool_combo.blockSignals(False)

    def _on_freehand_mode_changed(self, text):
        """Handle freehand mode dropdown change"""
        display_to_mode = {
            'Pen': 'pen', 'Brush': 'brush', 'Spray Can': 'spraycan',
            'Flood Fill': 'flood', 'Color Eraser': 'color_eraser', 'Eraser': 'eraser'
        }
        mode = display_to_mode.get(text, 'pen')
        self.select_freehand_mode(mode)

    def select_freehand_color(self, color):
        self.selected_freehand_color = color
        # Update all freehand color buttons to show selection with external border
        for c, btn in self.freehand_colors.items():
            if c == color:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;")
            else:
                btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")
        # Reset custom button border only (keep its color)
        if hasattr(self, 'freehand_custom_color'):
            self.freehand_custom_btn.setStyleSheet(
                f"background-color: rgb{self.freehand_custom_color}; border: 1px solid #666;"
            )
        else:
            self.freehand_custom_btn.setStyleSheet(
                f"background-color: rgb(0, 0, 0); border: 1px solid #666;"
            )

    def pick_freehand_custom(self):
        rgb = self._pick_color_modal(self.selected_freehand_color, "Select Freehand Color", self.freehand_custom_btn)
        if rgb is None:
            return
        self.selected_freehand_color = rgb
        self.freehand_custom_color = rgb  # Store custom color separately
        self.freehand_custom_btn.setStyleSheet(
            f"background-color: rgb{rgb}; border: 2px solid #FFD700; outline: 2px solid #FFD700; outline-offset: 2px;"
        )
        # Reset palette buttons
        for c, btn in self.freehand_colors.items():
            btn.setStyleSheet(f"background-color: rgb{c}; border: 1px solid #666;")

    def check_unsaved_changes(self):
        """Check if there are unsaved changes and prompt user. Returns True if OK to proceed, False to cancel."""
        if not self.has_unsaved_changes:
            return True
        
        from PyQt6.QtWidgets import QMessageBox
        
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Unsaved Changes")
        msg.setText("You have unsaved changes.")
        msg.setInformativeText("Do you want to save your changes before continuing?")
        
        # Use custom buttons for better text
        save_btn = msg.addButton("Save", QMessageBox.ButtonRole.AcceptRole)
        continue_btn = msg.addButton("Continue without Saving", QMessageBox.ButtonRole.DestructiveRole)
        cancel_btn = msg.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        msg.setDefaultButton(save_btn)
        
        msg.exec()
        clicked = msg.clickedButton()
        
        if clicked == save_btn:
            # Try to save
            self.save()
            # If save was successful, has_unsaved_changes will be False
            # If user cancelled save dialog, we should also cancel the operation
            return not self.has_unsaved_changes
        elif clicked == continue_btn:
            return True
        else:  # Cancel
            return False
    
    def reset_for_new_session(self):
        """Reset editor state for a new image session."""
        v = self.viewer
        # Clear history
        v.history = []
        v.redo_stack = []
        # Reset zoom
        v.scale = 1.0
        if hasattr(self, 'zoom_combo'):
            self.zoom_combo.setCurrentText("100%")
        # Clear all tool states
        v.sel_start = None
        v.sel_end = None
        v.selection_finalized = False
        v.drag_mode = None
        v.current_rect = None
        v.rectangles = []
        v.current_oval = None
        v.ovals = []
        v.current_line = None
        v.lines = []
        v.current_arrow = None
        v.arrows = []
        v.freehand_points = []
        v.freehand_last_pos = None
        v.highlight_strokes = []
        v.current_highlight_stroke = None
        v.current_highlight_rect = None
        v.current_pixelate_rect = None
        v.step_markers = []
        v.step_markers_redo = []
        v.current_marker = None
        v.marker_counter = 1
        v.active_marker_index = None
        v.dragging_badge = False
        v.dragging_tail_handle = False
        v.placing_new_marker = False
        v.current_text = None
        v.text_editing = False
        v.cutpaste_selection = None
        v.cutpaste_clipboard = None
        v.cutpaste_paste_pos = None
        # Clear preview states for tools with live preview
        v._transform_preview_active = False
        v.rspace_preview_image = None
        self._transform_preview_image = None
        self._resize_preview_image = None
        self._cl_preview_image = None
        # Reset outline preview
        v.outline_preview_active = False
        # Reset unsaved changes flag
        self.has_unsaved_changes = False

    def open_file(self):
        # Check for unsaved changes first
        if not self.check_unsaved_changes():
            return
        
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Image", self._session_save_dir,
            "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tiff *.tif *.svg);;All Files (*)"
        )
        if path:
            self._session_save_dir = os.path.dirname(path)
            self._load_image_from_path(path)
    
    def dragEnterEvent(self, event):
        """Accept drag-and-drop of image files"""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                path = url.toLocalFile()
                if path and path.lower().endswith(
                    ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.svg')
                ):
                    event.acceptProposedAction()
                    return
        event.ignore()
    
    def dropEvent(self, event):
        """Open the first dropped image file"""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                path = url.toLocalFile()
                if path and path.lower().endswith(
                    ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif', '.svg')
                ):
                    if not self.check_unsaved_changes():
                        return
                    self._session_save_dir = os.path.dirname(path)
                    self._load_image_from_path(path)
                    return
    
    def check_and_resize_large_image(self, image):
        """Check if image is too large and prompt/resize based on settings
        
        Returns: PIL Image (either original or resized), or None if rejected.
        """
        width, height = image.size
        
        # Hard safety ceiling — non-configurable, prevents memory exhaustion
        if width > _MAX_IMAGE_HARD_LIMIT or height > _MAX_IMAGE_HARD_LIMIT:
            QMessageBox.warning(
                self, "Image Too Large",
                f"This image is {width}x{height} pixels, which exceeds the\n"
                f"maximum supported size of {_MAX_IMAGE_HARD_LIMIT}x{_MAX_IMAGE_HARD_LIMIT}.\n\n"
                "The image cannot be loaded."
            )
            return None
        
        config = load_config()
        
        # Check if feature is enabled
        if not config.get("check_image_size", True):
            return image
        
        max_dim = config.get("max_image_dimension", 1920)
        action = config.get("large_image_action", "prompt")
        
        width, height = image.size
        
        # Check if image exceeds limit (either dimension)
        if width <= max_dim and height <= max_dim:
            return image  # Within limits
        
        # Check session preference
        if self.session_large_image_preference == "keep":
            return image
        elif self.session_large_image_preference == "resize":
            return self._resize_image_proportionally(image, max_dim)
        
        # Handle based on action setting
        if action == "ignore":
            return image
        elif action == "always_resize":
            return self._resize_image_proportionally(image, max_dim)
        elif action == "prompt":
            # Show smart prompt dialog
            return self._prompt_large_image_resize(image, width, height, max_dim)
        
        return image
    
    def _resize_image_proportionally(self, image, max_dim):
        """Resize image so largest dimension equals max_dim"""
        width, height = image.size
        
        if width > height:
            new_width = max_dim
            new_height = int(height * (max_dim / width))
        else:
            new_height = max_dim
            new_width = int(width * (max_dim / height))
        
        resized = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        logging.debug(f"Resized image from {width}x{height} to {new_width}x{new_height}")
        return resized
    
    def _prompt_large_image_resize(self, image, width, height, max_dim):
        """Show dialog prompting user about large image"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QRadioButton, QCheckBox, QDialogButtonBox, QLabel
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Large Image Detected")
        dialog.setMinimumWidth(500)
        
        layout = QVBoxLayout(dialog)
        
        # Calculate new dimensions (proportional)
        if width > height:
            new_width = max_dim
            new_height = int(height * (max_dim / width))
        else:
            new_height = max_dim
            new_width = int(width * (max_dim / height))
        
        # Calculate scale percentage
        scale_percent = int((new_width / width) * 100)
        
        # Info label
        info_label = QLabel(f"This image is {width}×{height} pixels.\n"
                           f"The image can be resized proportionally to {new_width}×{new_height} ({scale_percent}% of original size).\n")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        layout.addSpacing(10)
        
        # Radio buttons
        resize_radio = QRadioButton(f"Resize proportionally to {new_width}×{new_height} (recommended)")
        resize_radio.setChecked(True)
        layout.addWidget(resize_radio)
        
        layout.addSpacing(5)
        
        keep_radio = QRadioButton(f"Keep original size ({width}×{height})")
        layout.addWidget(keep_radio)
        
        layout.addSpacing(15)
        
        # Remember checkbox
        remember_checkbox = QCheckBox("Remember my choice for this session")
        layout.addWidget(remember_checkbox)
        
        layout.addSpacing(10)
        
        # Settings note
        settings_note = QLabel("This prompt can be enabled, disabled, or modified in Settings > Image Settings.")
        settings_note.setStyleSheet("color: gray; font-size: 10pt;")
        layout.addWidget(settings_note)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        for btn in button_box.buttons():
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(button_box)
        
        # Show dialog
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if resize_radio.isChecked():
                # Remember preference if checkbox is checked
                if remember_checkbox.isChecked():
                    self.session_large_image_preference = "resize"
                return self._resize_image_proportionally(image, max_dim)
            else:
                # Remember preference if checkbox is checked
                if remember_checkbox.isChecked():
                    self.session_large_image_preference = "keep"
                return image
        else:
            # Cancelled - keep original
            return image
    
    def _save_image_snapshot(self):
        """Save a snapshot of the current image before loading a new one"""
        if self.viewer.image:
            # Copy the current image
            image_copy = self.viewer.image.copy()
            # Copy the history
            history_copy = [(img.copy(), counter) for img, counter in self.viewer.history]
            # Store snapshot
            self.previous_image_snapshot = (image_copy, self.current_path, history_copy, self.viewer.marker_counter)
            logging.debug(f"Saved snapshot: {self.current_path or 'unsaved image'}")
    
    def restore_previous_image(self):
        """Restore the previously saved image snapshot"""
        if not self.previous_image_snapshot:
            QMessageBox.information(self, "No Previous Image", "No previous image to restore.")
            return
        
        # Check for unsaved changes
        if not self.check_unsaved_changes():
            return
        
        image_copy, old_path, history_copy, marker_counter = self.previous_image_snapshot
        
        # Restore the image
        self.viewer.set_image(image_copy, push=False)
        self.current_path = old_path
        self.viewer.history = history_copy
        self.viewer.marker_counter = marker_counter
        self.viewer.update_view()
        self.on_source_loaded()
        self.has_unsaved_changes = True  # Mark as unsaved since it's a restore
        
        # Clear the snapshot (can only go back once)
        self.previous_image_snapshot = None
        
        logging.debug(f"Restored previous image: {old_path or 'unsaved image'}")
        self.update_tool_buttons_state()
    
    def _load_image_from_path(self, path):
        """Load an image from a file path (used by open_file and recent files)"""
        # Auto-apply any pending annotations/previews before loading new image
        self._apply_pending_annotations()
        if getattr(self, '_transform_preview_image', None) is not None:
            self._transform_rotate_custom()
        if getattr(self, '_resize_preview_image', None) is not None:
            self._transform_resize()
        if getattr(self, '_cl_preview_image', None) is not None:
            self._color_light_apply()
        # Apply remove space preview if active
        if hasattr(self, 'viewer') and getattr(self.viewer, 'rspace_preview_image', None) is not None:
            self._rspace_apply() if hasattr(self, '_rspace_apply') else None
        
        # Save snapshot of current image before loading new one
        self._save_image_snapshot()
        
        self.reset_for_new_session()
        self.current_path = path
        
        # Load and check size
        if path.lower().endswith('.svg'):
            # SVG files can't be opened by PIL — render via Qt first
            try:
                from PyQt6.QtSvg import QSvgRenderer
                from PyQt6.QtCore import QByteArray
                renderer = QSvgRenderer(path)
                if renderer.isValid():
                    size = renderer.defaultSize()
                    w, h = size.width(), size.height()
                    # Clamp SVG dimensions before allocating QImage
                    if w <= 0 or h <= 0:
                        logging.warning(f"Invalid SVG dimensions: {w}x{h}")
                        return
                    if w > _MAX_IMAGE_HARD_LIMIT or h > _MAX_IMAGE_HARD_LIMIT:
                        QMessageBox.warning(
                            self, "SVG Too Large",
                            f"This SVG's dimensions ({w}×{h}) exceed the\n"
                            f"maximum supported size of {_MAX_IMAGE_HARD_LIMIT}×{_MAX_IMAGE_HARD_LIMIT}."
                        )
                        return
                    from PyQt6.QtCore import QSize as _QSize
                    qimg = QImage(_QSize(w, h), QImage.Format.Format_RGBA8888)
                    qimg.fill(Qt.GlobalColor.transparent)
                    painter = QPainter(qimg)
                    renderer.render(painter)
                    painter.end()
                    loaded_image = QImageToPil(qimg)
                else:
                    logging.warning(f"Invalid SVG file: {path}")
                    return
            except ImportError:
                # Try loading SVG as QIcon fallback
                from PyQt6.QtGui import QIcon, QPixmap
                icon = QIcon(path)
                if icon.isNull():
                    logging.warning(f"Cannot load SVG (QtSvg not available): {path}")
                    return
                pixmap = icon.pixmap(256, 256)
                qimg = pixmap.toImage().convertToFormat(QImage.Format.Format_RGBA8888)
                loaded_image = QImageToPil(qimg)
        else:
            try:
                with Image.open(path) as _img:
                    loaded_image = _img.convert("RGBA")
            except Image.DecompressionBombWarning:
                QMessageBox.warning(
                    self, "Image Too Large",
                    f"This image exceeds the safe pixel limit and cannot be opened.\n\n"
                    f"File: {os.path.basename(path)}"
                )
                return
            except Exception as e:
                QMessageBox.warning(
                    self, "Cannot Open Image",
                    f"Failed to open image:\n{e}"
                )
                return
        checked_image = self.check_and_resize_large_image(loaded_image)
        if checked_image is None:
            return
        
        self.viewer.set_image(checked_image, push=False)
        self.viewer.scale = 1.0  # Reset zoom for new source
        self.viewer.update_view()
        self.on_source_loaded()
        self.has_unsaved_changes = False  # Fresh load has no unsaved changes
        
        # Add to recent files
        self.add_to_recent_files(path)

    def paste(self):
        """Paste from system clipboard - ask user whether to paste on top or start new session"""
        # Auto-apply any pending annotations so they aren't lost
        self._apply_pending_annotations()
        
        clipboard = QApplication.clipboard()
        mime_data = clipboard.mimeData()
        
        pil_img = None
        
        # Try to get image from clipboard
        if mime_data.hasImage():
            img = clipboard.image()
            if not img.isNull():
                pil_img = QImageToPil(img)
                logging.debug("Pasted image from clipboard")
        
        # Try GNOME copied files format
        if not pil_img and 'x-special/gnome-copied-files' in mime_data.formats():
            data = mime_data.data('x-special/gnome-copied-files')
            if data:
                # Decode the data - format is "copy\nfile:///path/to/file\n"
                text = bytes(data).decode('utf-8').strip()
                lines = text.split('\n')
                for line in lines:
                    if line.startswith('file://'):
                        file_path = line[7:]  # Remove file:// prefix
                        
                        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                            try:
                                with Image.open(file_path) as _img:
                                    pil_img = _img.copy()
                                logging.debug(f"Loaded image from GNOME copied file: {file_path}")
                                break
                            except Exception as e:
                                logging.warning(f"Could not load image: {e}")
        
        # If no image, check if clipboard has URLs (copied files from other file managers)
        if not pil_img and mime_data.hasUrls():
            urls = mime_data.urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if not file_path:
                    file_path = urls[0].toString()
                    if file_path.startswith('file://'):
                        file_path = file_path[7:]
                try:
                    with Image.open(file_path) as _img:
                        pil_img = _img.copy()
                    logging.debug(f"Loaded image from copied file: {file_path}")
                except Exception as e:
                    logging.warning(f"Could not load image from file: {e}")
        
        # If no image, check if clipboard has text that might be a file path
        if not pil_img and mime_data.hasText():
            text = clipboard.text().strip()
            # Check if it looks like an image file path
            if text.startswith('file://'):
                text = text[7:]
            if text and (text.endswith('.png') or text.endswith('.jpg') or text.endswith('.jpeg') or 
                        text.endswith('.gif') or text.endswith('.bmp') or text.endswith('.webp')):
                try:
                    with Image.open(text) as _img:
                        pil_img = _img.copy()
                    logging.debug(f"Loaded image from path: {text}")
                except Exception as e:
                    logging.warning(f"Could not load image from path: {e}")
        
        if not pil_img:
            logging.info("No image in clipboard")
            return
        
        # Check and resize if image is too large
        pil_img = self.check_and_resize_large_image(pil_img)
        if pil_img is None:
            return
        
        # If there's already an image open, ask user what to do
        if self.viewer.image:
            from PyQt6.QtWidgets import QMessageBox
            
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Icon.Question)
            msg.setWindowTitle("Paste Image")
            msg.setText("An image is already open.")
            msg.setInformativeText("Would you like to paste on top of the current image, or start a new session with the clipboard image?")
            
            paste_on_top_btn = msg.addButton("Paste On Top", QMessageBox.ButtonRole.ActionRole)
            new_session_btn = msg.addButton("New Session", QMessageBox.ButtonRole.ActionRole)
            cancel_btn = msg.addButton(QMessageBox.StandardButton.Cancel)
            
            msg.exec()
            
            clicked = msg.clickedButton()
            
            if clicked == paste_on_top_btn:
                # Paste on top of current image
                # First, expand canvas if needed to fit the pasted image
                v = self.viewer
                current_width, current_height = v.image.size
                paste_width, paste_height = pil_img.width, pil_img.height
                
                # Calculate new canvas size (expand if pasted image is larger)
                new_width = max(current_width, paste_width)
                new_height = max(current_height, paste_height)
                
                if new_width > current_width or new_height > current_height:
                    # Create expanded canvas and paste current image at top-left
                    expanded = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 255))
                    expanded.paste(v.image.convert('RGBA'), (0, 0))
                    v.set_image(expanded)
                    logging.debug(f"Expanded canvas from {current_width}x{current_height} to {new_width}x{new_height}")
                
                self.select_tool("cutpaste")
                v.cutpaste_clipboard = pil_img
                
                # Position paste preview at visible top-left corner
                scroll_x = self.scroll_area.horizontalScrollBar().value()
                scroll_y = self.scroll_area.verticalScrollBar().value()
                screen_x1 = scroll_x
                screen_y1 = scroll_y
                screen_x2 = screen_x1 + paste_width * v.scale
                screen_y2 = screen_y1 + paste_height * v.scale
                
                v.cutpaste_paste_pos = (screen_x1, screen_y1, screen_x2, screen_y2)
                v.update()
                logging.debug(f"Pasted {paste_width}x{paste_height} at top-left - drag to position, click outside to apply")
            elif clicked == new_session_btn:
                # Check for unsaved changes before starting new session
                if not self.check_unsaved_changes():
                    return
                # Start new session with clipboard image
                self.reset_for_new_session()
                self.current_path = None
                self.viewer.set_image(pil_img, push=False)
                self.viewer.scale = 1.0  # Reset zoom for new source
                self.viewer.update_view()
                self.on_source_loaded()
                self.has_unsaved_changes = False
                logging.debug("Loaded clipboard image as new session")
            # else: Cancel - do nothing
        else:
            # No image open, just load the pasted image as the main image
            self.current_path = None
            self.viewer.set_image(pil_img, push=False)
            self.viewer.scale = 1.0  # Reset zoom for new source
            self.zoom_combo.setCurrentText("100%")
            self.viewer.update_view()
            self.on_source_loaded()
            self.has_unsaved_changes = False
            logging.debug("Loaded pasted image")

    def new_blank_image(self):
        """Create a new blank white image with custom dimensions"""
        # Check for unsaved changes first
        if not self.check_unsaved_changes():
            return
        
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton
        
        # Create dialog for size input
        dialog = QDialog(self)
        dialog.setWindowTitle("New Blank Image")
        layout = QVBoxLayout(dialog)
        
        # Width input
        width_layout = QHBoxLayout()
        width_layout.addWidget(QLabel("Width (pixels):"))
        width_input = QLineEdit(str(self.last_blank_width))
        width_input.setFixedWidth(100)
        width_layout.addWidget(width_input)
        layout.addLayout(width_layout)
        
        # Height input
        height_layout = QHBoxLayout()
        height_layout.addWidget(QLabel("Height (pixels):"))
        height_input = QLineEdit(str(self.last_blank_height))
        height_input.setFixedWidth(100)
        height_layout.addWidget(height_input)
        layout.addLayout(height_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        # Show dialog
        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                width = int(width_input.text())
                height = int(height_input.text())
                
                # Validate dimensions
                if width < 1 or height < 1 or width > 10000 or height > 10000:
                    logging.warning("Invalid dimensions. Must be between 1 and 10000 pixels.")
                    return
                
                # Remember the dimensions
                self.last_blank_width = width
                self.last_blank_height = height
                
                # Auto-apply pending changes before creating new image
                self._apply_pending_annotations()
                if getattr(self, '_transform_preview_image', None) is not None:
                    self._transform_rotate_custom()
                if getattr(self, '_resize_preview_image', None) is not None:
                    self._transform_resize()
                if getattr(self, '_cl_preview_image', None) is not None:
                    self._color_light_apply()
                
                # Save snapshot of current image before creating new one
                self._save_image_snapshot()
                
                # Reset for new session
                self.reset_for_new_session()
                
                # Create blank white image
                blank_img = Image.new('RGB', (width, height), color='white')
                self.viewer.set_image(blank_img, push=False)
                self.viewer.scale = 1.0  # Reset zoom for new source
                self.zoom_combo.setCurrentText("100%")
                self.viewer.update_view()
                self.current_path = None
                self.on_source_loaded()
                self.has_unsaved_changes = False
                logging.debug(f"Created blank {width}x{height} image")
                
            except ValueError:
                logging.warning("Invalid input. Please enter valid numbers.")
    
    def create_startup_blank_canvas(self):
        """Create a blank canvas when the app starts"""
        # Create blank white image with remembered dimensions
        blank_img = Image.new('RGB', (self.last_blank_width, self.last_blank_height), color='white')
        self.viewer.set_image(blank_img, push=False)
        self.viewer.scale = 1.0
        if hasattr(self, 'zoom_combo'):
            self.zoom_combo.setCurrentText("100%")
        self.viewer.update_view()
        self.current_path = None
        self.on_source_loaded()
        self.has_unsaved_changes = False
    
    def paste_from_clipboard_global(self):
        """Paste from system clipboard - works globally with Ctrl+V"""
        # Auto-apply any pending annotations so they aren't lost
        self._apply_pending_annotations()
        
        clipboard = QApplication.clipboard()
        mime = clipboard.mimeData()
        
        pil_img = None
        
        # Try image data first
        if mime.hasImage():
            qimg = clipboard.image()
            if not qimg.isNull():
                buffer = BytesIO()
                qba = QByteArray()
                qbuf = QBuffer(qba)
                qbuf.open(QBuffer.OpenModeFlag.WriteOnly)
                qimg.save(qbuf, "PNG")
                qbuf.close()
                buffer.write(qba.data())
                buffer.seek(0)
                pil_img = Image.open(buffer).convert("RGBA")
        
        # Try GNOME copied files format (right-click copy in Nautilus)
        if not pil_img and 'x-special/gnome-copied-files' in mime.formats():
            data = mime.data('x-special/gnome-copied-files')
            if data:
                text = bytes(data).decode('utf-8').strip()
                lines = text.split('\n')
                for line in lines:
                    if line.startswith('file://'):
                        file_path = line[7:]
                        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif')):
                            try:
                                with Image.open(file_path) as _img:
                                    pil_img = _img.convert("RGBA")
                                break
                            except Exception as e:
                                logging.warning(f"Could not load image: {e}")
        
        # Try URLs (other file managers)
        if not pil_img and mime.hasUrls():
            urls = mime.urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if not file_path:
                    file_path = urls[0].toString()
                    if file_path.startswith('file://'):
                        file_path = file_path[7:]
                if file_path and file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif')):
                    try:
                        with Image.open(file_path) as _img:
                            pil_img = _img.convert("RGBA")
                    except Exception as e:
                        logging.warning(f"Could not load image from URL: {e}")
        
        # Try text that looks like a file path
        if not pil_img and mime.hasText():
            text = clipboard.text().strip()
            if text.startswith('file://'):
                text = text[7:]
            if text and text.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff', '.tif')):
                try:
                    with Image.open(text) as _img:
                        pil_img = _img.convert("RGBA")
                except Exception:
                    pass
        
        if not pil_img:
            return
        
        # Hard safety ceiling check
        w, h = pil_img.size
        if w > _MAX_IMAGE_HARD_LIMIT or h > _MAX_IMAGE_HARD_LIMIT:
            QMessageBox.warning(
                self, "Image Too Large",
                f"This image is {w}x{h} pixels, which exceeds the\n"
                f"maximum supported size of {_MAX_IMAGE_HARD_LIMIT}x{_MAX_IMAGE_HARD_LIMIT}.\n\n"
                "The image cannot be loaded."
            )
            return
        
        v = self.viewer
        paste_width, paste_height = pil_img.width, pil_img.height
        
        if v.image:
            # Expand canvas if needed
            current_width, current_height = v.image.size
            
            new_width = max(current_width, paste_width)
            new_height = max(current_height, paste_height)
            
            if new_width > current_width or new_height > current_height:
                new_canvas = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 255))
                if v.image.mode != 'RGBA':
                    v.image = v.image.convert('RGBA')
                new_canvas.paste(v.image, (0, 0))
                # Use set_image so the canvas expansion is on the undo stack
                v.set_image(new_canvas)
                logging.debug(f"Expanded canvas from {current_width}x{current_height} to {new_width}x{new_height}")
            
            # Position paste preview at visible top-left corner
            v.cutpaste_clipboard = pil_img
            v.cutpaste_selection = None
            scroll_x = self.scroll_area.horizontalScrollBar().value()
            scroll_y = self.scroll_area.verticalScrollBar().value()
            x1 = scroll_x
            y1 = scroll_y
            x2 = x1 + int(paste_width * v.scale)
            y2 = y1 + int(paste_height * v.scale)
            v.cutpaste_paste_pos = (x1, y1, x2, y2)
            
            v.update()
            
            self.has_unsaved_changes = True
            self.update_tool_buttons_state()
            logging.debug(f"Pasted {paste_width}x{paste_height} image from clipboard")
    
    def crop_to_content(self):
        """Crop canvas to pasted content or current selection"""
        v = self.viewer
        
        if not v.image:
            return
        
        # Check if there's a paste preview to crop to
        if v.cutpaste_paste_pos and v.cutpaste_clipboard:
            px1, py1, px2, py2 = v.cutpaste_paste_pos
            
            # Convert screen coords to image coords
            img_x1 = int((px1 - v.offset.x()) / v.scale)
            img_y1 = int((py1 - v.offset.y()) / v.scale)
            paste_width = v.cutpaste_clipboard.width
            paste_height = v.cutpaste_clipboard.height
            
            # Apply the paste first
            if v.image.mode != 'RGBA':
                v.image = v.image.convert('RGBA')
            
            # Create new image sized to the pasted content
            new_img = Image.new('RGBA', (paste_width, paste_height), (255, 255, 255, 255))
            new_img.paste(v.cutpaste_clipboard, (0, 0), v.cutpaste_clipboard if v.cutpaste_clipboard.mode == 'RGBA' else None)
            
            # Convert to RGB
            if new_img.mode == 'RGBA':
                rgb_img = Image.new('RGB', new_img.size, (255, 255, 255))
                rgb_img.paste(new_img, mask=new_img.split()[3])
                new_img = rgb_img
            
            # Set as new image
            v.set_image(new_img)
            
            # Clear paste state
            v.cutpaste_clipboard = None
            v.cutpaste_paste_pos = None
            v.cutpaste_selection = None
            v.sel_start = None
            v.sel_end = None
            
            # Update and repaint to clear blue outline
            v.update_view()
            v.update()  # Force repaint
            self.has_unsaved_changes = True
            
            # Update last blank size to match
            self.last_blank_width = paste_width
            self.last_blank_height = paste_height
            
            self.update_tool_buttons_state()  # Update crop button state
            logging.debug(f"Cropped canvas to {paste_width}x{paste_height}")
        
        # Otherwise check if there's a selection to crop to
        elif v.cutpaste_selection:
            # Use the crop_to_selection logic
            self.crop_to_selection()
        
        else:
            logging.info("No pasted content or selection to crop to. Paste an image or select an area first.")
    
    def crop_to_selection(self):
        """Crop canvas to the current selection or paste preview in Cut/Paste tool"""
        v = self.viewer
        
        # If there's a paste preview, just apply Set as Image instead
        if v.cutpaste_paste_pos and v.cutpaste_clipboard:
            self.crop_to_content()
            return
        
        # Otherwise crop to selection
        if not v.image or not v.cutpaste_selection:
            logging.info("No selection to crop to. Select an area first.")
            return
        
        # Get selection coordinates (screen coords)
        sx1, sy1, sx2, sy2 = v.cutpaste_selection
        
        # Convert to image coordinates
        img_x1 = int((sx1 - v.offset.x()) / v.scale)
        img_y1 = int((sy1 - v.offset.y()) / v.scale)
        img_x2 = int((sx2 - v.offset.x()) / v.scale)
        img_y2 = int((sy2 - v.offset.y()) / v.scale)
        
        # Clamp to image bounds
        img_x1 = max(0, min(img_x1, v.image.width))
        img_y1 = max(0, min(img_y1, v.image.height))
        img_x2 = max(0, min(img_x2, v.image.width))
        img_y2 = max(0, min(img_y2, v.image.height))
        
        # Ensure coordinates are in the right order (user may drag any direction)
        img_x1, img_x2 = sorted((img_x1, img_x2))
        img_y1, img_y2 = sorted((img_y1, img_y2))
        
        # Ensure we have a valid selection
        if img_x2 <= img_x1 or img_y2 <= img_y1:
            logging.warning("Invalid selection area")
            return
        
        # Crop the image
        cropped = v.image.crop((img_x1, img_y1, img_x2, img_y2))
        
        # Convert to RGB if needed
        if cropped.mode == 'RGBA':
            rgb_img = Image.new('RGB', cropped.size, (255, 255, 255))
            rgb_img.paste(cropped, mask=cropped.split()[3])
            cropped = rgb_img
        
        # Set as new image
        v.set_image(cropped)
        
        # Clear selection
        v.cutpaste_selection = None
        v.sel_start = None
        v.sel_end = None
        
        # Update
        v.update_view()
        self.has_unsaved_changes = True
        
        # Update button states
        self.update_tool_buttons_state()
        
        crop_width = img_x2 - img_x1
        crop_height = img_y2 - img_y1
        logging.debug(f"Cropped canvas to selection: {crop_width}x{crop_height}")
    
    def import_image(self):
        """Import an image file to paste on top of current image"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Image", "",
            "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp);;All Files (*)"
        )
        
        if file_path:
            try:
                with Image.open(file_path) as _img:
                    pil_img = _img.copy()
                
                # Check and resize if image is too large
                pil_img = self.check_and_resize_large_image(pil_img)
                if pil_img is None:
                    return
                
                v = self.viewer
                
                # Expand canvas if needed to fit the imported image
                if v.image:
                    current_width, current_height = v.image.size
                    paste_width, paste_height = pil_img.width, pil_img.height
                    
                    # Calculate new canvas size (expand if imported image is larger)
                    new_width = max(current_width, paste_width)
                    new_height = max(current_height, paste_height)
                    
                    if new_width > current_width or new_height > current_height:
                        # Create expanded canvas and paste current image at top-left
                        expanded = Image.new('RGBA', (new_width, new_height), (255, 255, 255, 255))
                        expanded.paste(v.image.convert('RGBA'), (0, 0))
                        v.set_image(expanded)
                        logging.debug(f"Expanded canvas from {current_width}x{current_height} to {new_width}x{new_height}")
                else:
                    paste_width, paste_height = pil_img.width, pil_img.height
                
                # Set as clipboard content
                v.cutpaste_clipboard = pil_img
                
                # Position paste preview at top-left (0,0) in image coordinates
                # Convert to screen coordinates using offset and scale
                screen_x1 = v.offset.x()
                screen_y1 = v.offset.y()
                screen_x2 = screen_x1 + paste_width * v.scale
                screen_y2 = screen_y1 + paste_height * v.scale
                
                v.cutpaste_paste_pos = (screen_x1, screen_y1, screen_x2, screen_y2)
                v.update()
                # Update button states since we now have paste content
                self.update_tool_buttons_state()
                logging.debug(f"Imported {paste_width}x{paste_height} at top-left - drag to position, click outside to apply")
                
            except Exception as e:
                logging.warning(f"Could not load image: {e}")

    def _rescale_paste_preview(self, old_scale, new_scale):
        """Recalculate paste preview position when zoom changes."""
        v = self.viewer
        if not v.cutpaste_paste_pos or not v.cutpaste_clipboard:
            return
        # Convert current screen coords to image coords using old scale
        px1, py1, px2, py2 = v.cutpaste_paste_pos
        ix = (px1 - v.offset.x()) / old_scale
        iy = (py1 - v.offset.y()) / old_scale
        # Recalculate screen coords at new scale
        pw = v.cutpaste_clipboard.width * new_scale
        ph = v.cutpaste_clipboard.height * new_scale
        nx1 = ix * new_scale + v.offset.x()
        ny1 = iy * new_scale + v.offset.y()
        v.cutpaste_paste_pos = (nx1, ny1, nx1 + pw, ny1 + ph)

    def _rescale_cutpaste_selection(self, old_scale, new_scale):
        """Recalculate cutpaste selection when zoom changes."""
        v = self.viewer
        if not v.cutpaste_selection:
            return
        x1, y1, x2, y2 = v.cutpaste_selection
        ix1 = (x1 - v.offset.x()) / old_scale
        iy1 = (y1 - v.offset.y()) / old_scale
        ix2 = (x2 - v.offset.x()) / old_scale
        iy2 = (y2 - v.offset.y()) / old_scale
        v.cutpaste_selection = (
            ix1 * new_scale + v.offset.x(),
            iy1 * new_scale + v.offset.y(),
            ix2 * new_scale + v.offset.x(),
            iy2 * new_scale + v.offset.y()
        )

    def zoom_in(self):
        """Zoom in by 25% increments"""
        old_scale = self.viewer.scale
        current_percent = int(self.viewer.scale * 100)
        new_percent = ((current_percent + 24) // 25 * 25) + 25
        new_percent = min(1000, new_percent)
        self.viewer.scale = new_percent / 100.0
        self._rescale_paste_preview(old_scale, self.viewer.scale)
        self._rescale_cutpaste_selection(old_scale, self.viewer.scale)
        self.viewer.update_view()
        self.zoom_combo.setCurrentText(f"{new_percent}%")
        self._update_status_bar()

    def zoom_out(self):
        """Zoom out by 25% increments"""
        old_scale = self.viewer.scale
        current_percent = int(self.viewer.scale * 100)
        new_percent = ((current_percent + 24) // 25 * 25) - 25
        new_percent = max(25, new_percent)
        self.viewer.scale = new_percent / 100.0
        self._rescale_paste_preview(old_scale, self.viewer.scale)
        self._rescale_cutpaste_selection(old_scale, self.viewer.scale)
        self.viewer.update_view()
        self.zoom_combo.setCurrentText(f"{new_percent}%")
        self._update_status_bar()

    def zoom_reset(self):
        """Reset zoom to 100%"""
        old_scale = self.viewer.scale
        self.viewer.scale = 1.0
        self._rescale_paste_preview(old_scale, self.viewer.scale)
        self._rescale_cutpaste_selection(old_scale, self.viewer.scale)
        self.viewer.update_view()
        self.zoom_combo.setCurrentText("100%")
        self._update_status_bar()

    def zoom_combo_changed(self, text):
        """Handle zoom percentage dropdown changes"""
        try:
            zoom_text = text.strip().rstrip('%')
            zoom_value = int(zoom_text)
            zoom_value = max(10, min(1000, zoom_value))
            old_scale = self.viewer.scale
            self.viewer.scale = zoom_value / 100.0
            self._rescale_paste_preview(old_scale, self.viewer.scale)
            self._rescale_cutpaste_selection(old_scale, self.viewer.scale)
            self.viewer.update_view()
            self._update_status_bar()
        except ValueError:
            zoom_percent = int(self.viewer.scale * 100)
            self.zoom_combo.setCurrentText(f"{zoom_percent}%")
    
    def toggle_crosshair(self, state):
        """Toggle magnifier (crosshair) cursor mode.

        Supports both QCheckBox.stateChanged (int) and QAction.toggled (bool).
        """
        if isinstance(state, bool):
            self.crosshair_enabled = state
        else:
            try:
                self.crosshair_enabled = (state == Qt.CheckState.Checked.value)
            except Exception:
                self.crosshair_enabled = bool(state)

        # Keep the menu action in sync if it exists
        if hasattr(self, "magnifier_action") and self.magnifier_action.isChecked() != self.crosshair_enabled:
            self.magnifier_action.blockSignals(True)
            self.magnifier_action.setChecked(self.crosshair_enabled)
            self.magnifier_action.blockSignals(False)
        if self.crosshair_enabled:
            self.viewer.setMouseTracking(True)
            if hasattr(self, 'crosshair_overlay'):
                self.crosshair_overlay.show()
                self.crosshair_overlay.update()
        else:
            if hasattr(self, 'crosshair_overlay'):
                self.crosshair_overlay.hide()
    
    def _set_magnifier_size(self, size):
        """Set magnifier circle size from menu"""
        self.crosshair_size = size
        self._update_magnifier_size_checks()
        if self.crosshair_enabled and hasattr(self, 'crosshair_overlay'):
            self.crosshair_overlay.update()
    
    def _update_magnifier_size_checks(self):
        """Update checkmarks on magnifier size menu items"""
        if hasattr(self, '_magnifier_size_actions'):
            for s, action in self._magnifier_size_actions.items():
                action.setChecked(s == self.crosshair_size)
    
    def toggle_guide_lines(self, state):
        """Toggle guide lines (ruler-style crosshair lines across canvas)."""
        if isinstance(state, bool):
            self.guide_lines_enabled = state
        else:
            try:
                self.guide_lines_enabled = (state == Qt.CheckState.Checked.value)
            except Exception:
                self.guide_lines_enabled = bool(state)
        
        # Keep the menu action in sync if it exists
        if hasattr(self, "guide_lines_action") and self.guide_lines_action.isChecked() != self.guide_lines_enabled:
            self.guide_lines_action.blockSignals(True)
            self.guide_lines_action.setChecked(self.guide_lines_enabled)
            self.guide_lines_action.blockSignals(False)
        
        # Enable mouse tracking if guide lines are on
        if self.guide_lines_enabled:
            self.viewer.setMouseTracking(True)
        
        # Trigger redraw
        self.viewer.update()

    def toggle_pixel_grid(self, state):
        """Toggle pixel grid overlay (gridlines between pixels at high zoom)."""
        if isinstance(state, bool):
            self.pixel_grid_enabled = state
        else:
            try:
                self.pixel_grid_enabled = (state == Qt.CheckState.Checked.value)
            except Exception:
                self.pixel_grid_enabled = bool(state)
        
        if hasattr(self, "pixel_grid_action") and self.pixel_grid_action.isChecked() != self.pixel_grid_enabled:
            self.pixel_grid_action.blockSignals(True)
            self.pixel_grid_action.setChecked(self.pixel_grid_enabled)
            self.pixel_grid_action.blockSignals(False)
        
        self.viewer.update()

    def copy(self):
        if not self.viewer.image:
            return
        # If Cut/Paste tool is active with a selection or paste preview, copy that
        if self.active_tool == "cutpaste":
            if (self.viewer.cutpaste_paste_pos and self.viewer.cutpaste_clipboard):
                self.copy_selection()
                return
            if self.viewer.cutpaste_selection:
                self.copy_selection()
                return
        # Otherwise copy the entire image (from Copy button / File menu)
        self._copy_image_to_clipboard(self.viewer.image)


    def save(self):
        if not self.viewer.image:
            return
        if not self.current_path:
            self.save_as()
            return
        
        img = self.viewer.image
        ext = os.path.splitext(self.current_path)[1].lower()
        
        try:
            if ext in ('.jpg', '.jpeg'):
                if img.mode == 'RGBA':
                    bg = Image.new('RGB', img.size, (255, 255, 255))
                    bg.paste(img, mask=img.split()[-1])
                    bg.save(self.current_path, 'BMP')
                else:
                    img.convert('RGB').save(self.current_path, 'BMP')
            else:
                img.save(self.current_path)
        except Exception as e:
            QMessageBox.warning(self, "Save Error", f"Could not save file:\n{e}")
            return
        
        self.has_unsaved_changes = False
        self._update_status_bar()

    def save_as(self):
        if not self.viewer.image:
            return

        filters = (
            "PNG Image (*.png);;"
            "JPEG Image (*.jpg *.jpeg);;"
            "BMP Image (*.bmp);;"
            "GIF Image (*.gif);;"
            "WebP Image (*.webp);;"
            "TIFF Image (*.tiff *.tif);;"
            "ICO Image (*.ico);;"
            "All Files (*)"
        )

        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Save Image", self._session_save_dir, filters
        )

        if not path:
            return

        # Remember the directory for this session
        self._session_save_dir = os.path.dirname(path)

        # If no extension, add one based on the selected filter
        if "." not in os.path.basename(path):
            ext_map = {
                "PNG": ".png", "JPEG": ".jpg", "BMP": ".bmp",
                "GIF": ".gif", "WebP": ".webp", "TIFF": ".tiff",
                "ICO": ".ico",
            }
            ext = ".png"  # default
            for key, val in ext_map.items():
                if key in selected_filter:
                    ext = val
                    break
            path += ext

        self.current_path = path

        # Handle format-specific saving
        img = self.viewer.image
        ext = os.path.splitext(path)[1].lower()

        try:
            if ext in ('.jpg', '.jpeg'):
                # JPEG doesn't support alpha - convert to RGB
                if img.mode in ('RGBA', 'LA', 'PA'):
                    bg = Image.new('RGB', img.size, (255, 255, 255))
                    bg.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    bg.save(path, 'JPEG', quality=95)
                else:
                    img.convert('RGB').save(path, 'JPEG', quality=95)
            elif ext == '.ico':
                # ICO needs specific sizes
                img.save(path, 'ICO')
            elif ext == '.bmp':
                if img.mode == 'RGBA':
                    bg = Image.new('RGB', img.size, (255, 255, 255))
                    bg.paste(img, mask=img.split()[-1])
                    bg.save(path, 'BMP')
                else:
                    img.convert('RGB').save(path, 'BMP')
            else:
                img.save(path)
        except Exception as e:
            QMessageBox.warning(self, "Save Error", f"Could not save file:\n{e}")
            return

        self.has_unsaved_changes = False
        self._update_status_bar()

    def update_publish_combo(self):
        """No-op — kept for compatibility. Upload is now a simple button."""
        pass
    
    def on_publish_selected(self, index):
        """No-op — kept for compatibility. Upload is now a simple button."""
        pass
    
    def publish_to_destination(self, destination_name):
        """Open publish dialog with a specific destination pre-selected"""
        if not self.viewer.image:
            QMessageBox.warning(self, "No Image", "No image to publish.")
            return
        
        config = load_config()
        dialog = FTPUploadDialog(self, config, destination_name)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if dialog.uploaded_url:
                logging.debug(f"Uploaded to: {dialog.uploaded_url}")
                self.has_unsaved_changes = False
            # Refresh combo in case destinations changed
            self.update_publish_combo()
    
    def publish(self):
        """Open publish dialog to upload image to FTP (Browse mode)"""
        if not self.viewer.image:
            QMessageBox.warning(self, "No Image", "No image to publish.")
            return
        
        config = load_config()
        dialog = FTPUploadDialog(self, config)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if dialog.uploaded_url:
                logging.debug(f"Uploaded to: {dialog.uploaded_url}")
                self.has_unsaved_changes = False
            # Refresh combo in case destinations changed
            self.update_publish_combo()
    
    def open_ftp_settings(self):
        """Open FTP settings dialog"""
        config = load_config()
        dialog = FTPSettingsDialog(self, config)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Refresh publish combo with new destinations
            self.update_publish_combo()
            # Also refresh FTP upload menu
            if hasattr(self, 'ftp_upload_menu'):
                self.update_ftp_upload_menu()
    
    def open_image_settings(self):
        """Open image settings dialog"""
        config = load_config()
        dialog = ImageSettingsDialog(self, config)
        dialog.exec()
    
    def toggle_smooth_drawing(self, checked):
        """Toggle smooth (anti-aliased) drawing mode"""
        config = load_config()
        config["smooth_drawing"] = checked
        save_config(config)
        self._cached_smooth_drawing = checked
        # Update the viewer to refresh
        if self.viewer:
            self.viewer.update()
    
    def _set_theme(self, mode):
        """Set theme mode: 'system', 'light', or 'dark'. Saves to config and applies."""
        config = load_config()
        config["theme_mode"] = mode
        save_config(config)
        self._apply_theme(mode)
    
    def _apply_theme(self, mode):
        """Apply theme mode live to the running app."""
        if mode == "dark":
            is_dark = True
        elif mode == "light":
            is_dark = False
        else:
            palette = QApplication.instance().palette()
            is_dark = palette.color(palette.ColorRole.Window).lightness() < 128
        
        old_dark = self._is_dark_mode
        self._is_dark_mode = is_dark
        
        app = QApplication.instance()
        
        # 1. Force palette
        if is_dark:
            from PyQt6.QtGui import QPalette, QColor as QC
            dp = QPalette()
            dp.setColor(QPalette.ColorRole.Window, QC(45, 45, 45))
            dp.setColor(QPalette.ColorRole.WindowText, QC(224, 224, 224))
            dp.setColor(QPalette.ColorRole.Base, QC(35, 35, 35))
            dp.setColor(QPalette.ColorRole.AlternateBase, QC(53, 53, 53))
            dp.setColor(QPalette.ColorRole.ToolTipBase, QC(58, 58, 58))
            dp.setColor(QPalette.ColorRole.ToolTipText, QC(224, 224, 224))
            dp.setColor(QPalette.ColorRole.Text, QC(224, 224, 224))
            dp.setColor(QPalette.ColorRole.Button, QC(53, 53, 53))
            dp.setColor(QPalette.ColorRole.ButtonText, QC(224, 224, 224))
            dp.setColor(QPalette.ColorRole.BrightText, QC(255, 0, 0))
            dp.setColor(QPalette.ColorRole.Link, QC(42, 130, 218))
            dp.setColor(QPalette.ColorRole.Highlight, QC(42, 130, 218))
            dp.setColor(QPalette.ColorRole.HighlightedText, QC(0, 0, 0))
            dp.setColor(QPalette.ColorRole.PlaceholderText, QC(160, 160, 160))
            dp.setColor(QPalette.ColorRole.Light, QC(70, 70, 70))
            dp.setColor(QPalette.ColorRole.Midlight, QC(60, 60, 60))
            dp.setColor(QPalette.ColorRole.Mid, QC(45, 45, 45))
            dp.setColor(QPalette.ColorRole.Dark, QC(30, 30, 30))
            dp.setColor(QPalette.ColorRole.Shadow, QC(0, 0, 0))
            app.setPalette(dp)
        else:
            app.setPalette(app.style().standardPalette())
        
        # 2. App-level stylesheet (menus, tooltips, menubar)
        if is_dark:
            app.setStyleSheet("""
                QToolTip { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #666; padding: 3px; }
                QMenu { background-color: #2d2d2d; border: 1px solid #555; padding: 2px; color: #e0e0e0; }
                QMenu::item { padding: 4px 20px 4px 20px; color: #e0e0e0; }
                QMenu::item:selected { background-color: #4a4a4a; color: #ffffff; }
                QMenu::item:disabled { color: #777777; }
                QMenu::indicator { width: 14px; height: 14px; margin-left: 6px; border: 1px solid #666; border-radius: 2px; background-color: #3a3a3a; }
                QMenu::indicator:checked { background-color: #4080d0; border: 1px solid #5090e0; image: none; }
                QMenu::separator { height: 1px; background-color: #555; margin: 3px 6px; }
                QMenuBar { background-color: #2d2d2d; color: #e0e0e0; }
                QMenuBar::item { background-color: transparent; color: #e0e0e0; padding: 4px 8px; }
                QMenuBar::item:selected { background-color: #4a4a4a; }
                QComboBox { color: #e0e0e0; background-color: #3a3a3a; border: 1px solid #555; }
                QComboBox QAbstractItemView { color: #e0e0e0; background-color: #2d2d2d; selection-background-color: #4a4a4a; selection-color: #ffffff; border: 1px solid #555; }
                QComboBox:editable { background-color: #3a3a3a; color: #e0e0e0; }
                QDialog { background-color: #2d2d2d; color: #e0e0e0; }
                QGroupBox { color: #e0e0e0; border: 1px solid #555; margin-top: 8px; padding-top: 8px; }
                QGroupBox::title { color: #e0e0e0; }
                QLineEdit { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #555; padding: 2px 4px; }
                QListWidget { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #555; }
                QTextEdit { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #555; }
            """)
        else:
            app.setStyleSheet("""
                QToolTip { background-color: #ffffee; color: #000000; border: 1px solid #a0a0a0; padding: 3px; }
                QMainWindow { background-color: #f0f0f0; }
                QWidget { background-color: #f0f0f0; color: #000000; }
                QLabel { background-color: transparent; color: #000000; }
                QPushButton { color: #000000; }
                QComboBox { color: #000000; }
                QSpinBox { color: #000000; }
                QDoubleSpinBox { color: #000000; }
                QCheckBox { color: #000000; }
                QSlider { background-color: transparent; }
                QMenu { background-color: #ffffff; border: 1px solid #a0a0a0; padding: 2px; color: #000000; }
                QMenu::item { padding: 4px 20px 4px 20px; color: #000000; }
                QMenu::item:selected { background-color: #e8e8e8; color: #000000; }
                QMenu::indicator { width: 14px; height: 14px; margin-left: 6px; border: 1px solid #808080; border-radius: 2px; background-color: #ffffff; }
                QMenu::indicator:checked { background-color: #4080d0; border: 1px solid #2060a0; image: none; }
                QMenu::separator { height: 1px; background-color: #d0d0d0; margin: 3px 6px; }
                QMenuBar { background-color: #f0f0f0; color: #000000; }
                QMenuBar::item { color: #000000; padding: 4px 8px; }
                QMenuBar::item:selected { background-color: #e8e8e8; }
                QScrollArea { background-color: #c8c8c8; }
            """)
        
        # 3. Toolbar sidebar
        if hasattr(self, 'toolbar_widget'):
            if is_dark:
                self.toolbar_widget.setStyleSheet("""
                    QToolBar { background-color: #2d2d2d; border-right: 1px solid #555; spacing: 0px; padding: 4px 2px 0px 2px; margin: 0px; }
                    QToolButton { min-width: 36px; max-width: 36px; min-height: 36px; max-height: 36px; border: 1px solid transparent; border-radius: 4px; padding: 0px; margin: 1px 0px; background-color: transparent; }
                    QToolButton:hover { background-color: #444; border: 1px solid #666; }
                    QToolButton:checked { background-color: #3a4570; border: 2px solid #6a6adc; }
                    QToolBar::separator { height: 2px; margin: 3px 4px; background-color: #555; }
                """)
            else:
                self.toolbar_widget.setStyleSheet("""
                    QToolBar { background-color: #f0f0f0; border-right: 1px solid #808080; spacing: 0px; padding: 4px 2px 0px 2px; margin: 0px; }
                    QToolButton { min-width: 36px; max-width: 36px; min-height: 36px; max-height: 36px; border: 1px solid transparent; border-radius: 4px; padding: 0px; margin: 1px 0px; background-color: transparent; }
                    QToolButton:hover { background-color: #e0e0e0; border: 1px solid #aaa; }
                    QToolButton:checked { background-color: #d0d8ff; border: 2px solid #5050d0; }
                    QToolBar::separator { height: 2px; margin: 3px 4px; background-color: #606060; }
                """)
        
        # 4. Toolbar separator
        if hasattr(self, 'toolbar_separator1'):
            self.toolbar_separator1.setStyleSheet("background-color: #555;" if is_dark else "background-color: #808080;")
        
        # 5. Status bar
        if hasattr(self, 'status_bar'):
            if is_dark:
                self.status_bar.setStyleSheet("""
                    #statusBar { background-color: #2d2d2d; border: 1px solid #555; }
                    #statusBar QLabel { color: #c0c0c0; font-size: 11px; padding: 0px 4px; border: none; }
                """)
            else:
                self.status_bar.setStyleSheet("""
                    #statusBar { background-color: #f0f0f0; border: 1px solid #c0c0c0; }
                    #statusBar QLabel { color: #404040; font-size: 11px; padding: 0px 4px; border: none; }
                """)
        
        # 6. Rebuild toolbar icons and bar icons for correct theme colors
        self._populate_toolbar()
        self._refresh_bar_icons()
        
        # 7. Eyedropper / color picker indicator
        if hasattr(self, '_eyedropper_indicator'):
            if is_dark:
                self._eyedropper_indicator.setStyleSheet("font-size: 20px; background-color: #3a3a3a; border: 1px solid #666;")
            else:
                self._eyedropper_indicator.setStyleSheet("font-size: 20px; background-color: white; border: 1px solid #ccc;")
        
        # 8. Help panel
        if hasattr(self, 'help_panel'):
            if is_dark:
                self.help_panel.setStyleSheet("QWidget { background-color: #2d2d2d; } QLabel { color: #e0e0e0; background-color: transparent; }")
            else:
                self.help_panel.setStyleSheet("QWidget { background-color: #f5f5f5; } QLabel { color: #202020; background-color: transparent; }")
        
        # 9. Force repaint everything
        self.update()
        self.repaint()
        for child in self.findChildren(QWidget):
            child.update()
    
    def export_settings(self):
        """Export all settings to a JSON file"""
        from datetime import datetime
        
        # Default filename with date
        default_name = f"Magpie_settings_{datetime.now().strftime('%Y%m%d')}.json"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Settings",
            default_name,
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            # Load current config
            config = load_config()
            
            # Remove items that shouldn't be exported (paths specific to this machine)
            export_config = config.copy()
            
            # Remove recent files (machine-specific paths)
            export_config.pop("recent_files", None)
            
            # Remove last destination paths (machine-specific)
            export_config.pop("destination_last_paths", None)
            
            # Never export credentials
            export_config.pop("ftp_pass_encoded", None)
            
            # Add export metadata with schema version for future compatibility
            # Schema version history:
            #   1 - Initial version (v132)
            # When making breaking changes to settings structure, increment schema_version
            # and add migration logic in import_settings() -> _migrate_settings()
            export_config["_export_info"] = {
                "app": "Magpie",
                "schema_version": 1,
                "app_version": "132",
                "export_date": datetime.now().isoformat(),
            }
            
            # Write to file
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_config, f, indent=2)
            
            QMessageBox.information(
                self,
                "Export Successful",
                f"Settings exported successfully to:\n{file_path}"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export settings:\n{str(e)}"
            )
    
    # --- Settings import validation schema ---
    # Maps config keys to (type, default, optional_validator).
    # Validator returns True if value is acceptable.
    _IMPORT_SCHEMA = {
        # Toolbox / Toolbar: lists of strings (tool names)
        "toolbox_most_used":    (list, [],    lambda v: all(isinstance(s, str) for s in v)),
        "toolbox_less_used":    (list, [],    lambda v: all(isinstance(s, str) for s in v)),
        "toolbox_hidden":       (list, [],    lambda v: all(isinstance(s, str) for s in v)),
        "toolbar_most_used":    (list, [],    lambda v: all(isinstance(s, str) for s in v)),
        "toolbar_less_used":    (list, [],    lambda v: all(isinstance(s, str) for s in v)),
        "toolbar_hidden":       (list, [],    lambda v: all(isinstance(s, str) for s in v)),
        # Tool defaults: dict of dicts
        "tool_defaults":        (dict, {},    None),
        "tool_last_values":     (dict, {},    None),
        # Palette: dict or None
        "custom_palette":       ((dict, type(None)), None, None),
        # Image settings
        "check_image_size":     (bool, True,  None),
        "max_image_dimension":  (int,  1920,  lambda v: 64 <= v <= 16384),
        "large_image_action":   (str,  "prompt", lambda v: v in ("prompt", "always_resize", "ignore")),
        # FTP / upload settings
        "ftp_host":             (str,  "",    lambda v: len(v) <= 512),
        "ftp_url":              (str,  "",    lambda v: len(v) <= 1024),
        "ftp_user":             (str,  "",    lambda v: len(v) <= 256),
        "ftp_pass_encoded":     (str,  "",    lambda v: len(v) <= 1024),
        "upload_protocol":      (str,  "FTP", lambda v: v in ("FTP", "FTPS", "SFTP")),
        "web_url_base":         (str,  "",    lambda v: len(v) <= 1024),
        "url_template":         (str,  "",    lambda v: len(v) <= 1024),
        "destinations":         (list, [],    lambda v: all(isinstance(d, dict) for d in v)),
        "remember_last_folder": (bool, True,  None),
        "copy_url_after_upload":(bool, True,  None),
    }

    @staticmethod
    def _validate_setting(key, value):
        """Validate a single imported setting against the schema.
        Returns (is_valid, sanitized_value)."""
        schema = CutoutTool._IMPORT_SCHEMA.get(key)
        if schema is None:
            return False, None
        expected_type, default, validator = schema
        if not isinstance(value, expected_type):
            return False, default
        if validator is not None and not validator(value):
            return False, default
        return True, value

    def _get_validated(self, import_config, key):
        """Get a validated value from imported config, falling back to schema default."""
        schema = self._IMPORT_SCHEMA.get(key)
        if schema is None:
            return None
        _, default, _ = schema
        if key not in import_config:
            return default
        valid, value = self._validate_setting(key, import_config[key])
        return value if valid else default

    def import_settings(self):
        """Import settings from a JSON file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Settings",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            # Read the import file
            with open(file_path, "r", encoding="utf-8") as f:
                import_config = json.load(f)
            
            # Verify it's a valid settings file
            export_info = import_config.get("_export_info", {})
            if export_info.get("app") not in ("Magpie", "Pannex"):
                # Still allow import but warn user
                reply = QMessageBox.question(
                    self,
                    "Unrecognized File",
                    "This file doesn't appear to be a Magpie settings export.\n\n"
                    "Do you want to import it anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
            
            # Ask user what to import
            dialog = ImportSettingsDialog(self, import_config)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            
            # Get selected categories
            selected = dialog.get_selected_categories()
            
            if not selected:
                return
            
            # Load current config to merge with
            current_config = load_config()
            
            # Merge selected settings (all values validated against schema)
            if "toolbox" in selected:
                current_config["toolbox_most_used"] = self._get_validated(import_config, "toolbox_most_used")
                current_config["toolbox_less_used"] = self._get_validated(import_config, "toolbox_less_used")
                current_config["toolbox_hidden"] = self._get_validated(import_config, "toolbox_hidden")
            
            if "toolbar" in selected:
                current_config["toolbar_most_used"] = self._get_validated(import_config, "toolbar_most_used")
                current_config["toolbar_less_used"] = self._get_validated(import_config, "toolbar_less_used")
                current_config["toolbar_hidden"] = self._get_validated(import_config, "toolbar_hidden")
            
            if "tool_defaults" in selected:
                current_config["tool_defaults"] = self._get_validated(import_config, "tool_defaults")
                current_config["tool_last_values"] = self._get_validated(import_config, "tool_last_values")
            
            if "palette" in selected:
                current_config["custom_palette"] = self._get_validated(import_config, "custom_palette")
            
            if "image_settings" in selected:
                current_config["check_image_size"] = self._get_validated(import_config, "check_image_size")
                current_config["max_image_dimension"] = self._get_validated(import_config, "max_image_dimension")
                current_config["large_image_action"] = self._get_validated(import_config, "large_image_action")
            
            if "ftp_settings" in selected:
                current_config["ftp_host"] = self._get_validated(import_config, "ftp_host")
                current_config["ftp_url"] = self._get_validated(import_config, "ftp_url")
                current_config["ftp_user"] = self._get_validated(import_config, "ftp_user")
                # Credentials are never imported — use keyring or re-enter per session
                current_config["ftp_pass_encoded"] = ""
                current_config["upload_protocol"] = self._get_validated(import_config, "upload_protocol")
                current_config["web_url_base"] = self._get_validated(import_config, "web_url_base")
                current_config["url_template"] = self._get_validated(import_config, "url_template")
                current_config["destinations"] = self._get_validated(import_config, "destinations")
                current_config["remember_last_folder"] = self._get_validated(import_config, "remember_last_folder")
                current_config["copy_url_after_upload"] = self._get_validated(import_config, "copy_url_after_upload")
            
            # Save merged config
            save_config(current_config)
            
            # Apply changes
            if "toolbox" in selected:
                self.update_toolbox_dropdown()
            
            if "toolbar" in selected:
                self.rebuild_toolbar()
            
            if "tool_defaults" in selected:
                self.apply_tool_defaults()
            
            if "palette" in selected:
                self._global_palette = self.load_palette_from_config()
                self.rebuild_palette()
            
            if "ftp_settings" in selected:
                self.update_publish_combo()
                if hasattr(self, 'ftp_upload_menu'):
                    self.update_ftp_upload_menu()
            
            QMessageBox.information(
                self,
                "Import Successful",
                "Settings imported successfully!\n\n"
                "Some changes may require restarting the application to take full effect."
            )
            
        except json.JSONDecodeError as e:
            QMessageBox.critical(
                self,
                "Import Failed",
                f"Invalid JSON file:\n{str(e)}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Import Failed",
                f"Failed to import settings:\n{str(e)}"
            )
    
    def open_toolbox_editor(self):
        """Open toolbox editor dialog"""
        config = load_config()
        dialog = ToolboxEditorDialog(self, config)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Refresh toolbox dropdown with new organization
            self.update_toolbox_dropdown()
    
    def open_toolbar_editor(self):
        """Open toolbar editor dialog"""
        config = load_config()
        dialog = ToolbarEditorDialog(self, config)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Rebuild toolbar with new organization
            self.rebuild_toolbar()
    
    def open_tool_defaults(self):
        """Open tool defaults dialog"""
        config = load_config()
        dialog = ToolDefaultsDialog(self, config)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Apply defaults immediately
            self.apply_tool_defaults()
    
    def apply_tool_defaults(self):
        """Apply tool defaults from config to the UI widgets"""
        config = load_config()
        defaults = config.get("tool_defaults", {})
        last_values = config.get("tool_last_values", {})
        
        # Helper function to get the value to apply
        def get_value(key, default_value):
            setting = defaults.get(key, {})
            mode = setting.get("mode", "default")
            
            if mode == "default":
                return default_value
            elif mode == "remember":
                return last_values.get(key, default_value)
            elif mode == "specific":
                return setting.get("value", default_value)
            return default_value
        
        # Rectangle
        self.rect_width.setCurrentText(str(get_value("rect_width", "2")))
        self.rect_rounded.setCurrentText(str(get_value("rect_rounded", "0")))
        fill_val = get_value("rect_fill", False)
        self.fill_enabled.setChecked(fill_val if isinstance(fill_val, bool) else False)
        
        # Oval
        self.oval_width.setCurrentText(str(get_value("oval_width", "2")))
        oval_fill_val = get_value("oval_fill", False)
        self.oval_fill_enabled.setChecked(oval_fill_val if isinstance(oval_fill_val, bool) else False)
        
        # Line
        self.line_width_combo.setCurrentText(str(get_value("line_width", "2")))
        line_round_val = get_value("line_rounded", True)
        self.line_rounded.setChecked(line_round_val if isinstance(line_round_val, bool) else True)
        
        # Arrow
        self.arrow_width_combo.setCurrentText(str(get_value("arrow_width", "2")))
        arrow_round_val = get_value("arrow_rounded", True)
        self.arrow_rounded.setChecked(arrow_round_val if isinstance(arrow_round_val, bool) else True)
        
        # Freehand
        freehand_mode_val = get_value("freehand_mode", "Pen")
        mode_map = {"Pen": "pen", "Brush": "brush", "Spray Can": "spraycan", 
                    "Flood Fill": "flood", "Color Eraser": "color_eraser", "Eraser": "eraser"}
        mode_key = mode_map.get(freehand_mode_val, "pen")
        self.select_freehand_mode(mode_key)
        self.freehand_size.setCurrentText(str(get_value("freehand_size", "3")))
        
        # Highlight
        highlight_style_val = get_value("highlight_style", "Rectangle")
        idx = self.highlight_style.findText(highlight_style_val)
        if idx >= 0:
            self.highlight_style.setCurrentIndex(idx)
        highlight_size_val = get_value("highlight_size", 15)
        try:
            self.highlight_size.setValue(int(highlight_size_val))
        except (ValueError, TypeError):
            pass
        
        # Pixelate
        pixelate_size_val = get_value("pixelate_size", 10)
        try:
            self.pixelate_size.setValue(int(pixelate_size_val))
        except (ValueError, TypeError):
            pass
        
        # Blur
        blur_area_val = get_value("blur_area", "Inside")
        if blur_area_val:
            idx = self.blur_inside.findText(str(blur_area_val))
            if idx >= 0:
                self.blur_inside.setCurrentIndex(idx)
        blur_radius_val = get_value("blur_radius", 5)
        try:
            self.blur_radius.setValue(int(blur_radius_val))
        except (ValueError, TypeError):
            pass
        
        # Magnify Inset
        inset_shape_val = get_value("inset_shape", "Rectangle")
        if inset_shape_val:
            idx = self.inset_shape.findText(str(inset_shape_val))
            if idx >= 0:
                self.inset_shape.setCurrentIndex(idx)
        inset_zoom_val = get_value("inset_zoom", "200%")
        if inset_zoom_val:
            idx = self.inset_zoom.findText(str(inset_zoom_val))
            if idx >= 0:
                self.inset_zoom.setCurrentIndex(idx)
        inset_border_val = get_value("inset_border", 3)
        try:
            self.inset_border.setValue(int(inset_border_val))
        except (ValueError, TypeError):
            pass
        inset_connection_val = get_value("inset_connection", "Yes")
        if inset_connection_val:
            idx = self.inset_connection.findText(str(inset_connection_val))
            if idx >= 0:
                self.inset_connection.setCurrentIndex(idx)
        
        # Outline
        outline_thickness_val = get_value("outline_thickness", 2)
        try:
            self.outline_thickness.setValue(int(outline_thickness_val))
        except (ValueError, TypeError):
            pass
        outline_corner_radius_val = get_value("outline_corner_radius", 0)
        try:
            self.outline_corner_radius.setValue(int(outline_corner_radius_val))
        except (ValueError, TypeError):
            pass
        
        # Numbers
        step_marker_size_val = get_value("step_marker_size", 40)
        try:
            self.step_marker_size.setValue(int(step_marker_size_val))
        except (ValueError, TypeError):
            pass
        
        # Text
        text_font_val = get_value("text_font", "DejaVu Sans")
        idx = self.text_font.findText(text_font_val)
        if idx >= 0:
            self.text_font.setCurrentIndex(idx)
        
        text_size_val = get_value("text_size", 24)
        try:
            self.text_size.setValue(int(text_size_val))
        except (ValueError, TypeError):
            pass
        
        text_outline_val = get_value("text_outline", False)
        self.text_outline.setChecked(text_outline_val if isinstance(text_outline_val, bool) else False)
        
        text_outline_thick_val = get_value("text_outline_thickness", 3)
        try:
            self.text_outline_thickness.setValue(int(text_outline_thick_val))
        except (ValueError, TypeError):
            pass
        
        text_shadow_val = get_value("text_shadow", False)
        self.text_shadow.setChecked(text_shadow_val if isinstance(text_shadow_val, bool) else False)
        
        text_align_val = get_value("text_alignment", "Center")
        align_map = {"Left": "left", "Center": "center", "Right": "right"}
        self.set_text_alignment(align_map.get(text_align_val, "center"))
        
        # Colors - now with palette support
        primary_setting = defaults.get("primary_color", {})
        primary_mode = primary_setting.get("mode", "default")
        if primary_mode == "default":
            self.primary_color = (0, 0, 0, 255)
        elif primary_mode == "remember":
            saved_primary = last_values.get("primary_color", (0, 0, 0, 255))
            self.primary_color = tuple(saved_primary) if isinstance(saved_primary, list) else saved_primary
        elif primary_mode == "palette":
            # Get color from current palette at the saved position
            palette_pos = primary_setting.get("palette_pos")
            if palette_pos and hasattr(self, '_global_palette'):
                pos_tuple = tuple(palette_pos)
                rgba = self._global_palette.get(pos_tuple)
                if rgba:
                    self.primary_color = tuple(rgba)
                else:
                    # Fallback to saved value if palette position no longer exists
                    val = primary_setting.get("value", (0, 0, 0, 255))
                    self.primary_color = tuple(val) if isinstance(val, list) else val if val else (0, 0, 0, 255)
            else:
                val = primary_setting.get("value", (0, 0, 0, 255))
                self.primary_color = tuple(val) if isinstance(val, list) else val if val else (0, 0, 0, 255)
        elif primary_mode == "specific":
            val = primary_setting.get("value", (0, 0, 0, 255))
            self.primary_color = tuple(val) if isinstance(val, list) else val if val else (0, 0, 0, 255)
        
        secondary_setting = defaults.get("secondary_color", {})
        secondary_mode = secondary_setting.get("mode", "default")
        if secondary_mode == "default":
            self.secondary_color = (255, 255, 255, 255)
        elif secondary_mode == "remember":
            saved_secondary = last_values.get("secondary_color", (255, 255, 255, 255))
            self.secondary_color = tuple(saved_secondary) if isinstance(saved_secondary, list) else saved_secondary
        elif secondary_mode == "palette":
            # Get color from current palette at the saved position
            palette_pos = secondary_setting.get("palette_pos")
            if palette_pos and hasattr(self, '_global_palette'):
                pos_tuple = tuple(palette_pos)
                rgba = self._global_palette.get(pos_tuple)
                if rgba:
                    self.secondary_color = tuple(rgba)
                else:
                    # Fallback to saved value if palette position no longer exists
                    val = secondary_setting.get("value", (255, 255, 255, 255))
                    self.secondary_color = tuple(val) if isinstance(val, list) else val if val else (255, 255, 255, 255)
            else:
                val = secondary_setting.get("value", (255, 255, 255, 255))
                self.secondary_color = tuple(val) if isinstance(val, list) else val if val else (255, 255, 255, 255)
        elif secondary_mode == "specific":
            val = secondary_setting.get("value", (255, 255, 255, 255))
            self.secondary_color = tuple(val) if isinstance(val, list) else val if val else (255, 255, 255, 255)
        
        # Update color display
        if hasattr(self, '_update_color_display'):
            self._update_color_display()
    
    def save_last_tool_values(self):
        """Save current tool values for 'Remember Last' feature"""
        config = load_config()
        
        last_values = {
            "rect_width": self.rect_width.currentText(),
            "rect_rounded": self.rect_rounded.currentText(),
            "rect_fill": self.fill_enabled.isChecked(),
            "oval_width": self.oval_width.currentText(),
            "oval_fill": self.oval_fill_enabled.isChecked(),
            "line_width": self.line_width_combo.currentText(),
            "line_rounded": self.line_rounded.isChecked(),
            "arrow_width": self.arrow_width_combo.currentText(),
            "arrow_rounded": self.arrow_rounded.isChecked(),
            "freehand_mode": self.freehand_mode,
            "freehand_size": self.freehand_size.currentText(),
            "highlight_style": self.highlight_style.currentText(),
            "highlight_size": self.highlight_size.value(),
            "pixelate_size": self.pixelate_size.value(),
            "blur_area": self.blur_inside.currentText(),
            "blur_radius": self.blur_radius.value(),
            "inset_shape": self.inset_shape.currentText(),
            "inset_zoom": self.inset_zoom.currentText(),
            "inset_border": self.inset_border.value(),
            "inset_connection": self.inset_connection.currentText(),
            "outline_thickness": self.outline_thickness.value(),
            "step_marker_size": self.step_marker_size.value(),
            "text_font": self.text_font.currentText(),
            "text_size": self.text_size.value(),
            "text_outline": self.text_outline.isChecked(),
            "text_outline_thickness": self.text_outline_thickness.value(),
            "text_shadow": self.text_shadow.isChecked(),
            "text_alignment": self.text_alignment,
            "primary_color": list(self.primary_color),
            "secondary_color": list(self.secondary_color),
        }
        
        config["tool_last_values"] = last_values
        save_config(config)
    
    def open_palette_editor(self):
        """Open color palette editor dialog"""
        dialog = ColorPaletteEditorDialog(self, self._global_palette)
        # Use run() instead of exec() to avoid hide/show corruption bug
        result = dialog.run()
        logging.debug(f"Dialog result: {result}, Accepted={QDialog.DialogCode.Accepted}")
        
        if result == QDialog.DialogCode.Accepted:
            # Get the new palette
            new_palette = dialog.get_palette()
            logging.debug(f"Got palette with {len(new_palette)} colors")
            
            # Save to config
            config = load_config()
            config['custom_palette'] = new_palette
            save_config(config)
            
            # Update the palette
            self._global_palette = new_palette
            self.rebuild_palette()
            logging.debug("Palette rebuilt")
        else:
            logging.debug("Dialog was rejected")
    
    def load_palette_from_config(self):
        """Load custom palette from config or return default"""
        config = load_config()
        custom_palette = config.get('custom_palette', None)
        
        if custom_palette:
            # Check if it's positioned dict format
            if isinstance(custom_palette, dict):
                # Convert string keys back to tuples if needed
                positioned = {}
                for key, value in custom_palette.items():
                    try:
                        if isinstance(key, str):
                            parsed = ast.literal_eval(key)
                            if not (isinstance(parsed, tuple) and len(parsed) == 2):
                                continue
                            row, col = int(parsed[0]), int(parsed[1])
                        else:
                            row, col = key
                        rgba = tuple(int(v) for v in value)
                        if len(rgba) < 3:
                            continue
                        positioned[(row, col)] = rgba
                    except (ValueError, TypeError, SyntaxError):
                        continue
                return positioned
            else:
                # Legacy list format - convert to positioned
                positioned = {}
                for i, c in enumerate(custom_palette):
                    # Ensure RGBA values are integers
                    rgba = tuple(int(v) for v in c)
                    if len(rgba) == 3:
                        rgba = rgba + (255,)
                    row = i // 10
                    col = i % 10
                    positioned[(row, col)] = rgba
                return positioned
        
        # Return default palette as positioned dict (6 per row)
        default_list = [
            (0, 0, 0, 0),            # Transparent
            (255, 255, 255, 255),    # White
            (0, 0, 0, 255),          # Black
            (192, 192, 192, 255),    # Lt Gray
            (128, 128, 128, 255),    # Dk Gray
            (255, 0, 0, 255),        # Red
            (255, 165, 0, 255),      # Orange
            (255, 255, 0, 255),      # Yellow
            (0, 255, 0, 255),        # Green
            (0, 255, 255, 255),      # Lt Blue (Cyan)
            (0, 0, 255, 255),        # Dk Blue
            (157, 0, 255, 255),      # Purple
        ]
        # Convert to positioned dict - 6 colors per row
        positioned = {}
        for i, rgba in enumerate(default_list):
            row = i // 6  # 6 per row instead of 10
            col = i % 6
            positioned[(row, col)] = rgba
        return positioned
    
    def rebuild_palette(self):
        """Rebuild the color palette display after changes"""
        # Remove old color selector
        if hasattr(self, '_color_selector_widget'):
            self._color_selector_widget.setParent(None)
            self._color_selector_widget.deleteLater()
        
        # Rebuild color selector with new palette
        self._color_selector_widget = self._build_global_color_selector()
        self._bar_icon_map["custom"] = self._custom_color_btn
        self._bar_icon_map["picker"] = self._eyedropper_indicator
        self._refresh_bar_icons()
        
        # Insert back into top bar, just before the trailing stretch
        count = self._global_bar.count()
        self._global_bar.insertWidget(count - 1, self._color_selector_widget)
        
        # Refresh UI
        self._refresh_color_selector_ui()
    
    def update_toolbox_dropdown(self):
        """Update the toolbox dropdown based on saved configuration"""
        config = load_config()
        
        # All available tools with their display names
        all_tools = {
            "arrow": "Arrow",
            "blur": "Blur",
            "crop": "Crop",
            "cutout": "Cut Out",
            "cutpaste": "Cut/Paste",
            "freehand": "Freehand",
            "highlight": "Highlight",
            "line": "Line",
            "magnify_inset": "Magnify Inset",
            "step_marker": "Step Marker",
            "oval": "Oval",
            "outline": "Outline",
            "pixelate": "Pixelate",
            "rectangle": "Rectangle",
            "remove_space": "Remove Space",
            "text": "Text",
            "transform": "Transform"
        }
        
        most_used = config.get("toolbox_most_used", [])
        less_used = config.get("toolbox_less_used", [])
        hidden = config.get("toolbox_hidden", [])
        
        # Ensure any new tools not in any list get added to less_used
        if most_used or less_used or hidden:
            all_configured = set(most_used) | set(less_used) | set(hidden)
            for tool_id in sorted(all_tools.keys()):
                if tool_id not in all_configured:
                    less_used.append(tool_id)
        
        # Block signals while rebuilding
        self.tool_combo.blockSignals(True)
        self.tool_combo.clear()
        
        # Add "Select tool" placeholder
        self.tool_combo.addItem("Select tool", None)
        
        # If no customization, show all tools in alphabetical order
        if not most_used and not less_used and not hidden:
            for tool_id in sorted(all_tools.keys()):
                self.tool_combo.addItem(all_tools[tool_id], tool_id)
        else:
            # Add most used tools (in saved order)
            for tool_id in most_used:
                if tool_id in all_tools:
                    self.tool_combo.addItem(all_tools[tool_id], tool_id)
            
            # Add separator if we have both sections
            if most_used and less_used:
                self.tool_combo.insertSeparator(self.tool_combo.count())
            
            # Add less used tools (in saved order)
            for tool_id in less_used:
                if tool_id in all_tools:
                    self.tool_combo.addItem(all_tools[tool_id], tool_id)
        
        # Preserve current selection after rebuilding (if possible)
        current_tool = getattr(self, 'active_tool', None)
        idx = 0
        if current_tool:
            found = self.tool_combo.findData(current_tool)
            if found != -1:
                idx = found
        self.tool_combo.setCurrentIndex(idx)

        # Restore signals
        self.tool_combo.blockSignals(False)
    
    def publish_browse(self):
        """Open publish dialog in browse mode (from menu)"""
        self.publish()

    # ---------------- Cut Out ----------------

    def _invalidate_cutout_preview(self):
        """Clear cached cutout preview and repaint viewer."""
        self.viewer._cutout_preview_key = None
        self.viewer._cutout_preview_pm = None
        self.viewer.update()

    def _update_cutout_controls(self):
        """Enable/disable cutout controls based on current cut style."""
        style = self.cut_style.currentText()
        gap_enabled = (style == "Sawtooth")
        self.gap.setEnabled(gap_enabled)
        self._gap_label.setEnabled(gap_enabled)
        self._gap_pct_label.setEnabled(gap_enabled)

    def apply_cut(self):
        v = self.viewer
        if not v.image or v.sel_start is None or v.sel_end is None:
            return

        r, g, b, a = self.primary_color

        outline = None if int(a) == 0 else (int(r), int(g), int(b), int(a))

        style = self.cut_style.currentText()
        gap_percent = self.gap.value()

        if v.drag_mode == "horizontal":
            # Horizontal cut (remove horizontal strip)
            y1 = int((min(v.sel_start.y(), v.sel_end.y()) - v.offset.y()) / v.scale)
            y2 = int((max(v.sel_start.y(), v.sel_end.y()) - v.offset.y()) / v.scale)
            
            # Clamp to image bounds
            y1 = max(0, min(v.image.height, y1))
            y2 = max(0, min(v.image.height, y2))
            
            result = horizontal_cut(
                v.image, y1, y2, self.saw.value(), gap_percent, outline, style
            )
        else:
            # Vertical cut (remove vertical strip)
            x1 = int((min(v.sel_start.x(), v.sel_end.x()) - v.offset.x()) / v.scale)
            x2 = int((max(v.sel_start.x(), v.sel_end.x()) - v.offset.x()) / v.scale)
            
            # Clamp to image bounds
            x1 = max(0, min(v.image.width, x1))
            x2 = max(0, min(v.image.width, x2))
            
            result = vertical_cut(
                v.image, x1, x2, self.saw.value(), gap_percent, outline, style
            )

        v.set_image(result)
        v.sel_start = v.sel_end = None
        v.selection_finalized = False
        v._cutout_preview_key = None
        v._cutout_preview_pm = None
        v.update()

    # ---------------- Crop ----------------

    def apply_crop(self):
        v = self.viewer
        if not v.image or v.sel_start is None or v.sel_end is None:
            return

        # Convert screen coordinates to image coordinates
        x1 = int((min(v.sel_start.x(), v.sel_end.x()) - v.offset.x()) / v.scale)
        y1 = int((min(v.sel_start.y(), v.sel_end.y()) - v.offset.y()) / v.scale)
        x2 = int((max(v.sel_start.x(), v.sel_end.x()) - v.offset.x()) / v.scale)
        y2 = int((max(v.sel_start.y(), v.sel_end.y()) - v.offset.y()) / v.scale)

        # Clamp to image boundaries
        x1 = max(0, x1)
        y1 = max(0, y1)
        x2 = min(v.image.width, x2)
        y2 = min(v.image.height, y2)

        # Crop the image
        if x2 > x1 and y2 > y1:
            cropped = v.image.crop((x1, y1, x2, y2))
            v.set_image(cropped)
        
        v.sel_start = v.sel_end = None
        v.selection_finalized = False
        v.update()
        
        # Update button states since selection is cleared
        self.update_tool_buttons_state()

    def cancel_selection(self):
        v = self.viewer
        v.sel_start = v.sel_end = None
        v.selection_finalized = False
        v.current_rect = None
        v.rectangles = []
        v._cutout_preview_key = None
        v._cutout_preview_pm = None
        v.update()
        
        # Update button states since selection is cleared
        self.update_tool_buttons_state()

    # ---------------- Rectangle ----------------
    # Rectangles are now applied immediately when handles disappear


# =========================================================
# Entry
    # ---------------- Highlight Tool ----------------
    
    def apply_all_highlights(self):
        """Apply all highlight strokes and rectangles using R2_MASKPEN-style bitwise AND,
        or spotlight dimming effect."""
        v = self.viewer
        if not v.image:
            return
        
        style = self.highlight_style.currentText() if hasattr(self, 'highlight_style') else "Rectangle"
        
        # Spotlight mode: dim everything outside the rectangle
        if style == "Spotlight":
            if not v.current_highlight_rect:
                return
            
            from PIL import Image as PILImage, ImageDraw
            import numpy as np
            
            opacity = self.spotlight_opacity.value() if hasattr(self, 'spotlight_opacity') else 60
            feather_pct = self.spotlight_feather.value() if hasattr(self, 'spotlight_feather') else 0
            dim_alpha = int(255 * opacity / 100)
            
            x1, y1, x2, y2 = v.current_highlight_rect
            # Convert to image coordinates
            ix1 = int((x1 - v.offset.x()) / v.scale)
            iy1 = int((y1 - v.offset.y()) / v.scale)
            ix2 = int((x2 - v.offset.x()) / v.scale)
            iy2 = int((y2 - v.offset.y()) / v.scale)
            
            # Clamp
            ix1 = max(0, min(v.image.width, ix1))
            iy1 = max(0, min(v.image.height, iy1))
            ix2 = max(0, min(v.image.width, ix2))
            iy2 = max(0, min(v.image.height, iy2))
            
            # Convert feather percentage to image pixels
            rect_w = ix2 - ix1
            rect_h = iy2 - iy1
            half_short = min(rect_w, rect_h) / 2.0
            feather = half_short * feather_pct / 100.0
            
            result = v.image.copy().convert('RGBA')
            w, h = result.size
            
            if feather > 0:
                # Feathered spotlight: gradient alpha mask
                ys = np.arange(h).reshape(-1, 1)
                xs = np.arange(w).reshape(1, -1)
                # Distance inward from rect edges
                dx = np.minimum(xs - ix1, ix2 - 1 - xs)
                dy = np.minimum(ys - iy1, iy2 - 1 - ys)
                d = np.minimum(dx, dy).astype(np.float32)
                # Inside rect: d >= 0, outside: d < 0
                # Feather zone: 0 <= d < feather → gradient
                # d >= feather → fully clear (inside spotlight)
                # d < 0 → fully dimmed (outside spotlight)
                alpha = np.full((h, w), dim_alpha, dtype=np.float32)
                inside = d >= feather
                alpha[inside] = 0
                feather_zone = (d >= 0) & (d < feather)
                alpha[feather_zone] = dim_alpha * (1.0 - d[feather_zone] / feather)
                
                overlay = PILImage.fromarray(
                    np.stack([np.zeros((h, w), dtype=np.uint8)] * 3 + [alpha.astype(np.uint8)], axis=-1),
                    mode='RGBA'
                )
            else:
                # Hard edge spotlight
                overlay = PILImage.new('RGBA', result.size, (0, 0, 0, dim_alpha))
                overlay_draw = ImageDraw.Draw(overlay)
                overlay_draw.rectangle([ix1, iy1, ix2, iy2], fill=(0, 0, 0, 0))
            
            result = PILImage.alpha_composite(result, overlay)
            
            v.set_image(result)
            v.current_highlight_rect = None
            return
        
        # Standard highlight modes (Pen, Rectangle)
        # Check if there's anything to apply
        has_strokes = hasattr(v, 'highlight_strokes') and v.highlight_strokes
        has_rect = hasattr(v, 'current_highlight_rect') and v.current_highlight_rect
        
        if not has_strokes and not has_rect:
            return
        
        # Get settings
        # Highlight now uses the global Primary color (Paint-style selector)
        # instead of a per-tool color dropdown.
        size = self.highlight_size.value()
        r, g, b, a = getattr(self, 'primary_color', (255, 255, 0, 255))
        # Transparent highlight is a no-op.
        if a == 0:
            return
        
        # Create a mask where we want to apply highlight
        from PIL import Image as PILImage, ImageDraw
        mask = PILImage.new('L', (v.image.width, v.image.height), 0)
        mask_draw = ImageDraw.Draw(mask)
        
        # Draw all strokes on the mask
        if has_strokes:
            for stroke in v.highlight_strokes:
                if len(stroke) > 1:
                    points = []
                    for pt in stroke:
                        x = int((pt.x() - v.offset.x()) / v.scale)
                        y = int((pt.y() - v.offset.y()) / v.scale)
                        points.append((x, y))
                    # Draw thick line by drawing multiple lines with offsets
                    for offset_x in range(-size//2, size//2 + 1):
                        for offset_y in range(-size//2, size//2 + 1):
                            if offset_x*offset_x + offset_y*offset_y <= (size//2)*(size//2):
                                offset_points = [(x+offset_x, y+offset_y) for x, y in points]
                                if len(offset_points) > 1:
                                    mask_draw.line(offset_points, fill=255, width=1)
        
        # Draw rectangle on the mask
        if has_rect:
            x1, y1, x2, y2 = v.current_highlight_rect
            # Convert to image coordinates
            x1 = int((x1 - v.offset.x()) / v.scale)
            y1 = int((y1 - v.offset.y()) / v.scale)
            x2 = int((x2 - v.offset.x()) / v.scale)
            y2 = int((y2 - v.offset.y()) / v.scale)
            
            # Clamp to image bounds
            x1 = max(0, min(v.image.width, x1))
            y1 = max(0, min(v.image.height, y1))
            x2 = max(0, min(v.image.width, x2))
            y2 = max(0, min(v.image.height, y2))
            
            mask_draw.rectangle([x1, y1, x2, y2], fill=255)
        
        # Apply R2_MASKPEN: bitwise AND between image and highlight color
        # Preserve alpha channel — only modify RGB
        img_rgba = v.image.convert('RGBA')
        pixels = img_rgba.load()
        mask_pixels = mask.load()
        
        # Create new image for result
        result = img_rgba.copy()
        result_pixels = result.load()
        
        # Apply bitwise AND where mask is active
        # Get dim opacity for transparent pixel tinting
        dim_pct = self.highlight_dim.value() if hasattr(self, 'highlight_dim') else 60
        tint_alpha = int(255 * dim_pct / 100)
        
        for y in range(v.image.height):
            for x in range(v.image.width):
                if mask_pixels[x, y] > 0:
                    img_r, img_g, img_b, img_a = pixels[x, y]
                    if img_a == 0:
                        # Fully transparent: apply highlight as semi-transparent tint
                        result_pixels[x, y] = (r, g, b, tint_alpha)
                    elif img_a < 255:
                        # Semi-transparent: composite against white, apply AND,
                        # keep original alpha
                        fa = img_a / 255.0
                        cr = int(img_r * fa + 255 * (1.0 - fa))
                        cg = int(img_g * fa + 255 * (1.0 - fa))
                        cb = int(img_b * fa + 255 * (1.0 - fa))
                        result_pixels[x, y] = (cr & r, cg & g, cb & b, img_a)
                    else:
                        # Fully opaque: normal bitwise AND
                        result_pixels[x, y] = (img_r & r, img_g & g, img_b & b, img_a)
        
        # Update viewer image and clear highlights
        v.set_image(result)
        v.highlight_strokes = []
        v.current_highlight_rect = None
        v.current_highlight_stroke = None

    # ---------------- Pixelate Tool ----------------
    
    def apply_pixelate(self):
        """Apply pixelation effect to selected rectangle"""
        v = self.viewer
        if not v.image or not v.current_pixelate_rect:
            return
        
        # Get settings
        block_size = self.pixelate_size.value()
        
        # Convert to image coordinates
        x1, y1, x2, y2 = v.current_pixelate_rect
        x1 = int((x1 - v.offset.x()) / v.scale)
        y1 = int((y1 - v.offset.y()) / v.scale)
        x2 = int((x2 - v.offset.x()) / v.scale)
        y2 = int((y2 - v.offset.y()) / v.scale)
        
        # Clamp to image bounds
        x1 = max(0, min(v.image.width, x1))
        y1 = max(0, min(v.image.height, y1))
        x2 = max(0, min(v.image.width, x2))
        y2 = max(0, min(v.image.height, y2))
        
        if x2 <= x1 or y2 <= y1:
            return
        
        # Get the selected region
        from PIL import Image as PILImage
        img = v.image.copy()
        
        # Pixelate using BOX averaging + NEAREST upscale (ShareX-style)
        region = img.crop((x1, y1, x2, y2))
        rw, rh = region.size
        
        # BOX filter averages all pixels in each cell (no subpixel color bleed)
        small_width = max(1, rw // block_size)
        small_height = max(1, rh // block_size)
        small = region.resize((small_width, small_height), PILImage.Resampling.BOX)
        pixelated = small.resize((rw, rh), PILImage.Resampling.NEAREST)
        
        # Paste back into image
        img.paste(pixelated, (x1, y1))
        
        # Update viewer image and clear pixelate state
        v.set_image(img)
        v.current_pixelate_rect = None

    def apply_blur(self):
        """Apply gaussian blur effect to selected rectangle (inside or outside) with optional feathered edge"""
        v = self.viewer
        if not v.image or not v.current_blur_rect:
            return
        
        from PIL import Image as PILImage, ImageFilter, ImageDraw
        blur_radius = self.blur_radius.value()
        blur_inside = self.blur_inside.currentText() == "Inside"
        feather_pct = self.blur_feather.value()
        
        # Convert to image coordinates
        x1, y1, x2, y2 = v.current_blur_rect
        x1 = int((x1 - v.offset.x()) / v.scale)
        y1 = int((y1 - v.offset.y()) / v.scale)
        x2 = int((x2 - v.offset.x()) / v.scale)
        y2 = int((y2 - v.offset.y()) / v.scale)
        
        # Clamp to image bounds
        x1 = max(0, min(v.image.width, x1))
        y1 = max(0, min(v.image.height, y1))
        x2 = max(0, min(v.image.width, x2))
        y2 = max(0, min(v.image.height, y2))
        
        if x2 <= x1 or y2 <= y1:
            return
        
        # Convert feather percentage to pixels (% of half the shortest side)
        half_short = min(x2 - x1, y2 - y1) / 2.0
        feather = int(half_short * feather_pct / 100.0)
        
        img = v.image.copy().convert('RGBA')
        
        if feather <= 0:
            # No feather — hard edge (original behavior)
            if blur_inside:
                region = img.crop((x1, y1, x2, y2))
                blurred = region.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                img.paste(blurred, (x1, y1))
            else:
                blurred_full = img.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                unblurred_region = img.crop((x1, y1, x2, y2))
                img = blurred_full
                img.paste(unblurred_region, (x1, y1))
        else:
            # Feathered edge — use gradient mask to blend blur smoothly
            import numpy as np
            w, h = img.size
            
            if blur_inside:
                # Blur the selected region, blend with gradient mask at edges
                # Expand crop area by feather to avoid edge artifacts
                ex1 = max(0, x1 - feather)
                ey1 = max(0, y1 - feather)
                ex2 = min(w, x2 + feather)
                ey2 = min(h, y2 + feather)
                
                expanded_region = img.crop((ex1, ey1, ex2, ey2))
                blurred_expanded = expanded_region.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                
                # Build gradient mask using numpy
                ew, eh = ex2 - ex1, ey2 - ey1
                ys = np.arange(eh).reshape(-1, 1)
                xs = np.arange(ew).reshape(1, -1)
                # Distance from each edge of the original rect within the expanded space
                dx = np.minimum(xs - (x1 - ex1), (x2 - ex1) - 1 - xs)
                dy = np.minimum(ys - (y1 - ey1), (y2 - ey1) - 1 - ys)
                d = np.minimum(dx, dy).astype(np.float32)
                alpha = np.clip(d / feather, 0.0, 1.0) * 255
                mask = PILImage.fromarray(alpha.astype(np.uint8), mode='L')
                
                composited = PILImage.composite(blurred_expanded, expanded_region, mask)
                img.paste(composited, (ex1, ey1))
            else:
                # Blur outside — blur full image, feathered transition at rect edges
                blurred_full = img.filter(ImageFilter.GaussianBlur(radius=blur_radius))
                
                ys = np.arange(h).reshape(-1, 1)
                xs = np.arange(w).reshape(1, -1)
                # Distance inward from rect edges (negative outside rect)
                dx = np.minimum(xs - x1, x2 - 1 - xs)
                dy = np.minimum(ys - y1, y2 - 1 - ys)
                d = np.minimum(dx, dy).astype(np.float32)
                # Outside rect or in feather zone: blend toward blur
                # d < 0 → fully blurred (255), d >= feather → fully sharp (0)
                alpha = np.clip((feather - d) / feather, 0.0, 1.0) * 255
                # Ensure fully outside rect is always blurred
                outside = (dx < 0) | (dy < 0)
                alpha[outside] = 255
                mask = PILImage.fromarray(alpha.astype(np.uint8), mode='L')
                
                img = PILImage.composite(blurred_full, img, mask)
        
        # Convert back if original wasn't RGBA
        if v.image.mode == 'RGB':
            img = img.convert('RGB')
        
        v.set_image(img)
        v.current_blur_rect = None

    def _toggle_outline_preview(self):
        """Toggle outline preview on/off"""
        self.viewer.outline_preview_active = not self.viewer.outline_preview_active
        if self.viewer.outline_preview_active:
            self.outline_preview_btn.setText("Remove Preview")
            self.outline_apply_btn.setEnabled(True)
        else:
            self.outline_preview_btn.setText("Preview")
            self.outline_apply_btn.setEnabled(False)
        self.viewer.update()

    def apply_outline(self):
        """Apply outline border to the image - directly replaces border pixels, with optional rounded corners"""
        from PIL import Image as PILImage, ImageDraw
        v = self.viewer
        if not v.image:
            return
        
        thickness = self.outline_thickness.value()
        corner_radius = self.outline_corner_radius.value()
        color = self.primary_color  # RGBA tuple
        
        img = v.image.copy().convert('RGBA')
        w, h = img.size
        
        if corner_radius > 0:
            # Use Qt for high-quality antialiased rounded corner clipping + border
            src = PilToQImage(img)
            out = QImage(w, h, QImage.Format.Format_RGBA8888)
            out.fill(Qt.GlobalColor.transparent)
            
            painter = QPainter(out)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            # Clip image to rounded rect
            rounded_path = QPainterPath()
            rounded_path.addRoundedRect(QRectF(0, 0, w, h), corner_radius, corner_radius)
            painter.setClipPath(rounded_path)
            painter.drawImage(0, 0, src)
            
            # Draw the border on top if thickness > 0
            if thickness > 0:
                painter.setClipping(False)
                border_color = QColor(*color)
                half_t = thickness / 2.0
                # Use Source mode so transparent colors actually clear pixels
                painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
                border_pen = QPen(border_color, thickness, Qt.PenStyle.SolidLine, Qt.PenCapStyle.SquareCap, Qt.PenJoinStyle.RoundJoin)
                painter.setPen(border_pen)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawRoundedRect(QRectF(half_t, half_t, w - thickness, h - thickness), max(0, corner_radius - half_t), max(0, corner_radius - half_t))
            
            painter.end()
            img = QImageToPil(out)
        else:
            # Original square corner outline
            # Create a mask for the border area (white = border, black = keep)
            mask = PILImage.new('L', img.size, 0)
            mask_draw = ImageDraw.Draw(mask)
            mask_draw.rectangle([0, 0, w - 1, thickness - 1], fill=255)
            mask_draw.rectangle([0, h - thickness, w - 1, h - 1], fill=255)
            mask_draw.rectangle([0, 0, thickness - 1, h - 1], fill=255)
            mask_draw.rectangle([w - thickness, 0, w - 1, h - 1], fill=255)
            
            # Create solid color image with the chosen color (including its alpha)
            color_img = PILImage.new('RGBA', img.size, color)
            
            # Paste the color image over the original using the mask
            img.paste(color_img, (0, 0), mask)
        
        v.set_image(img)
        v.outline_preview_active = False
        self.outline_preview_btn.setText("Preview")
        self.outline_apply_btn.setEnabled(False)
        v.update()

    def _get_rspace_target_color(self, img):
        """Get the target color for empty space detection based on user selection."""
        mode = self.rspace_detect.currentText()
        if mode == "White/Near-white":
            return (255, 255, 255)
        elif mode == "Auto-detect":
            # Sample corners and edges to detect background color
            w, h = img.size
            pixels = img.convert('RGB')
            samples = []
            for x, y in [(0, 0), (w-1, 0), (0, h-1), (w-1, h-1),
                          (w//2, 0), (w//2, h-1), (0, h//2), (w-1, h//2)]:
                samples.append(pixels.getpixel((x, y)))
            from collections import Counter
            rounded = [((r//10)*10, (g//10)*10, (b//10)*10) for r, g, b in samples]
            most_common = Counter(rounded).most_common(1)[0][0]
            return most_common
        else:  # Pick Color
            return self.primary_color[:3]

    def _compute_remove_space(self, img):
        """Compute the image with empty space removed using numpy for speed."""
        import numpy as np
        from PIL import Image as PILImage
        
        direction = self.rspace_direction.currentText()
        tolerance = self.rspace_tolerance_slider.value()
        keep = self.rspace_keep_slider.value()
        min_gap = self.rspace_min_gap_slider.value()
        detect_mode = self.rspace_detect.currentText()
        
        # Convert to numpy array (H, W, 3)
        rgb = img.convert('RGB')
        arr = np.array(rgb, dtype=np.int16)
        h, w = arr.shape[:2]
        
        if detect_mode == "Duplicate Lines":
            # Duplicate Lines mode: find runs of identical adjacent rows/columns
            rows_to_keep = list(range(h))
            if direction in ("Both", "Vertical"):
                # Compare each row to the one above it
                # row_dup[i] = True means row i is a duplicate of row i-1
                row_diff = np.abs(arr[1:] - arr[:-1])  # (H-1, W, 3)
                row_dup = np.all(row_diff <= tolerance, axis=(1, 2))  # (H-1,) bool
                # Pad: first row is never a duplicate
                row_dup = np.concatenate(([False], row_dup))
                rows_to_keep = self._collapse_bands(row_dup, h, keep, min_gap)
            
            cols_to_keep = list(range(w))
            if direction in ("Both", "Horizontal"):
                # Compare each column to the one left of it
                col_diff = np.abs(arr[:, 1:] - arr[:, :-1])  # (H, W-1, 3)
                col_dup = np.all(col_diff <= tolerance, axis=(0, 2))  # (W-1,) bool
                # Pad: first column is never a duplicate
                col_dup = np.concatenate(([False], col_dup))
                cols_to_keep = self._collapse_bands(col_dup, w, keep, min_gap)
        else:
            # Color-match modes: find rows/columns that match a target color
            target = self._get_rspace_target_color(img)
            target_arr = np.array(target, dtype=np.int16)
            diff = np.abs(arr - target_arr)
            empty_mask = np.all(diff <= tolerance, axis=2)  # (H, W) bool
            
            rows_to_keep = list(range(h))
            if direction in ("Both", "Vertical"):
                row_empty = np.all(empty_mask, axis=1)  # (H,) bool
                rows_to_keep = self._collapse_bands(row_empty, h, keep, min_gap)
            
            cols_to_keep = list(range(w))
            if direction in ("Both", "Horizontal"):
                col_empty = np.all(empty_mask, axis=0)  # (W,) bool
                cols_to_keep = self._collapse_bands(col_empty, w, keep, min_gap)
        
        # Build result using numpy indexing
        if len(rows_to_keep) == 0 or len(cols_to_keep) == 0:
            return img
        
        src_arr = np.array(img)
        result_arr = src_arr[np.ix_(rows_to_keep, cols_to_keep)]
        
        return PILImage.fromarray(result_arr, img.mode)

    def _collapse_bands(self, empty_flags, total, keep, min_gap):
        """Given a boolean array of empty rows/cols, return indices to keep.
        
        Collapses runs of empty lines that are >= min_gap wide down to 'keep' lines.
        """
        to_keep = []
        i = 0
        while i < total:
            if empty_flags[i]:
                band_start = i
                while i < total and empty_flags[i]:
                    i += 1
                band_size = i - band_start
                if band_size >= min_gap:
                    # Collapse: keep only 'keep' lines from center
                    if keep > 0:
                        mid = band_start + band_size // 2
                        half = keep // 2
                        start = max(band_start, mid - half)
                        to_keep.extend(range(start, min(i, start + keep)))
                else:
                    # Band too small to collapse, keep all
                    to_keep.extend(range(band_start, i))
            else:
                to_keep.append(i)
                i += 1
        return to_keep

    def _preview_remove_space(self):
        """Generate and show preview of empty space removal."""
        v = self.viewer
        if not v.image:
            return
        
        result = self._compute_remove_space(v.image)
        v.rspace_preview_image = result
        self.rspace_apply_btn.setEnabled(True)
        self.rspace_cancel_btn.setEnabled(True)
        v.update()

    def _rspace_live_update(self):
        """Re-run preview if preview is already active (debounced)."""
        if self.viewer.rspace_preview_image is not None:
            # Use a timer to debounce rapid changes
            if not hasattr(self, '_rspace_debounce_timer'):
                from PyQt6.QtCore import QTimer
                self._rspace_debounce_timer = QTimer()
                self._rspace_debounce_timer.setSingleShot(True)
                self._rspace_debounce_timer.timeout.connect(self._preview_remove_space)
            self._rspace_debounce_timer.start(150)  # 150ms debounce

    def _rspace_keep_slider_changed(self, val):
        self.rspace_keep_label.setText(str(val))
        self._rspace_live_update()

    def _rspace_min_gap_slider_changed(self, val):
        self.rspace_min_gap_label.setText(str(val))
        self._rspace_live_update()

    def _rspace_tolerance_slider_changed(self, val):
        self.rspace_tolerance_label.setText(str(val))
        self._rspace_live_update()

    def _apply_remove_space(self):
        """Apply the previewed empty space removal."""
        v = self.viewer
        if v.rspace_preview_image is None:
            return
        
        v.set_image(v.rspace_preview_image)
        v.rspace_preview_image = None
        self.rspace_apply_btn.setEnabled(False)
        self.rspace_cancel_btn.setEnabled(False)
        v.update()

    def _cancel_remove_space(self):
        """Cancel the remove space preview."""
        v = self.viewer
        v.rspace_preview_image = None
        self.rspace_apply_btn.setEnabled(False)
        self.rspace_cancel_btn.setEnabled(False)
        v.update()

    # ===================== Transform Tool Methods =====================

    def _transform_rotate(self, angle):
        """Rotate image by 90° increments."""
        from PIL import Image as PILImage
        v = self.viewer
        if not v.image:
            return
        v.history.append((v.image.copy(), v.marker_counter))
        v.redo_stack = []
        if angle == 90:
            v.image = v.image.transpose(PILImage.Transpose.ROTATE_270)
        elif angle == -90:
            v.image = v.image.transpose(PILImage.Transpose.ROTATE_90)
        v.set_image(v.image)
        self._transform_update_size_display()

    def _transform_rotate_custom(self):
        """Apply rotation by custom angle permanently."""
        from PIL import Image as PILImage
        v = self.viewer
        if not v.image:
            return
        
        if getattr(self, '_transform_preview_image', None) is not None:
            # Preview is active — commit from the original
            original = self._transform_preview_image
            self._transform_preview_image = None
            v._transform_preview_active = False
            angle = self.transform_angle.value()
            if angle == 0:
                # Angle was reset to 0, just restore original
                v.set_image(original)
            else:
                # Push original to history, set rotated as current
                v.history.append((original.copy(), v.marker_counter))
                v.redo_stack = []
                rotated = original.rotate(-angle, expand=True, resample=PILImage.Resampling.BICUBIC)
                v.set_image(rotated)
            # Reset angle to 0 after applying
            self.transform_angle.blockSignals(True)
            self.transform_angle.setValue(0)
            self.transform_angle.blockSignals(False)
        else:
            # No preview — direct apply
            angle = self.transform_angle.value()
            if angle == 0:
                return
            v.history.append((v.image.copy(), v.marker_counter))
            v.redo_stack = []
            v.image = v.image.rotate(-angle, expand=True, resample=PILImage.Resampling.BICUBIC)
            v.set_image(v.image)
            self.transform_angle.blockSignals(True)
            self.transform_angle.setValue(0)
            self.transform_angle.blockSignals(False)
        self._transform_update_size_display()

    def _transform_live_preview(self, angle):
        """Update live preview as angle spinbox changes."""
        from PIL import Image as PILImage
        v = self.viewer
        if not v.image:
            return
        
        if angle == 0:
            # Revert to original if we have a preview
            if getattr(self, '_transform_preview_image', None) is not None:
                v.image = self._transform_preview_image
                self._transform_preview_image = None
                v._transform_preview_active = False
                v._cached_base_qimg = None
                v.update_view()
                self._transform_update_size_display()
            return
        
        # Store original on first preview
        if getattr(self, '_transform_preview_image', None) is None:
            self._transform_preview_image = v.image.copy()
        
        # Rotate from original (not from previous preview)
        rotated = self._transform_preview_image.rotate(-angle, expand=True, resample=PILImage.Resampling.BICUBIC)
        v.image = rotated
        v._transform_preview_active = True
        v._cached_base_qimg = None
        v.update_view()
        self._transform_update_size_display()

    def _transform_cancel_preview(self):
        """Cancel rotation preview, restore original image."""
        v = self.viewer
        if getattr(self, '_transform_preview_image', None) is not None:
            v.image = self._transform_preview_image
            self._transform_preview_image = None
            v._transform_preview_active = False
            v._cached_base_qimg = None
            v.update_view()
            self.transform_angle.blockSignals(True)
            self.transform_angle.setValue(0)
            self.transform_angle.blockSignals(False)
            self._transform_update_size_display()

    def _transform_flip_h(self):
        """Flip image horizontally."""
        from PIL import Image as PILImage
        v = self.viewer
        if not v.image:
            return
        v.history.append((v.image.copy(), v.marker_counter))
        v.redo_stack = []
        v.image = v.image.transpose(PILImage.Transpose.FLIP_LEFT_RIGHT)
        v.set_image(v.image)

    def _transform_flip_v(self):
        """Flip image vertically."""
        from PIL import Image as PILImage
        v = self.viewer
        if not v.image:
            return
        v.history.append((v.image.copy(), v.marker_counter))
        v.redo_stack = []
        v.image = v.image.transpose(PILImage.Transpose.FLIP_TOP_BOTTOM)
        v.set_image(v.image)

    # ---------------- Color & Light ----------------

    def _color_light_preview(self):
        """Debounced live preview — starts a short timer so rapid slider moves don't pile up."""
        if not hasattr(self, '_cl_timer'):
            from PyQt6.QtCore import QTimer
            self._cl_timer = QTimer()
            self._cl_timer.setSingleShot(True)
            self._cl_timer.timeout.connect(self._color_light_preview_execute)
        self._cl_timer.start(50)  # 50ms debounce

    def _color_light_preview_execute(self):
        """Actually compute and show the color/light preview."""
        from PIL import ImageEnhance, Image as PILImage
        v = self.viewer
        if not v.image:
            return
        
        brightness = self.cl_brightness.value()
        contrast = self.cl_contrast.value()
        hue = self.cl_hue.value()
        sharpness = self.cl_sharpness.value()
        
        # All at zero = no change
        if brightness == 0 and contrast == 0 and hue == 0 and sharpness == 0:
            if getattr(self, '_cl_preview_image', None) is not None:
                v.image = self._cl_preview_image
                self._cl_preview_image = None
                v._cached_base_qimg = None
                v.update_view()
                self.btn_cl_reset.setEnabled(False)
                self.btn_cl_apply.setEnabled(False)
            return
        
        # Store original on first change
        if getattr(self, '_cl_preview_image', None) is None:
            self._cl_preview_image = v.image.copy()
        
        result = self._cl_preview_image.copy()
        
        # Apply brightness: factor 1.0 = no change, 0 = black, 2 = double
        if brightness != 0:
            factor = 1.0 + brightness / 100.0
            result = ImageEnhance.Brightness(result).enhance(factor)
        
        # Apply contrast: factor 1.0 = no change
        if contrast != 0:
            factor = 1.0 + contrast / 100.0
            result = ImageEnhance.Contrast(result).enhance(factor)
        
        # Apply hue rotation using numpy vectorized operations
        if hue != 0:
            import numpy as np
            if result.mode != 'RGB':
                result = result.convert('RGB')
            arr = np.array(result, dtype=np.float32) / 255.0
            r, g, b = arr[:,:,0], arr[:,:,1], arr[:,:,2]
            maxc = np.maximum(np.maximum(r, g), b)
            minc = np.minimum(np.minimum(r, g), b)
            diff = maxc - minc
            
            # Hue calculation
            h = np.zeros_like(maxc)
            mask = diff > 0
            rm = mask & (maxc == r)
            gm = mask & (maxc == g) & ~rm
            bm = mask & ~rm & ~gm
            h[rm] = (60 * ((g[rm] - b[rm]) / diff[rm])) % 360
            h[gm] = (60 * ((b[gm] - r[gm]) / diff[gm]) + 120) % 360
            h[bm] = (60 * ((r[bm] - g[bm]) / diff[bm]) + 240) % 360
            
            s = np.where(maxc > 0, diff / maxc, 0)
            val = maxc
            
            # Rotate
            h = (h + hue) % 360
            
            # HSV to RGB — fully vectorized (no Python loop)
            hi = (h / 60.0).astype(np.int32) % 6
            f = h / 60.0 - np.floor(h / 60.0)
            p = val * (1 - s)
            q = val * (1 - f * s)
            t = val * (1 - (1 - f) * s)
            
            # Build output using np.select for each channel
            conditions = [hi == 0, hi == 1, hi == 2, hi == 3, hi == 4, hi == 5]
            ro = np.select(conditions, [val, q, p, p, t, val])
            go = np.select(conditions, [t, val, val, q, p, p])
            bo = np.select(conditions, [p, p, t, val, val, q])
            
            out = np.stack([ro, go, bo], axis=-1)
            out = (out * 255).clip(0, 255).astype(np.uint8)
            result = PILImage.fromarray(out, 'RGB')
        
        # Apply sharpness: factor 1.0 = no change, 0 = blurred, 2 = sharpened
        if sharpness != 0:
            factor = 1.0 + sharpness / 100.0
            result = ImageEnhance.Sharpness(result).enhance(factor)
        
        v.image = result
        v._cached_base_qimg = None
        v.update_view()
        self.btn_cl_reset.setEnabled(True)
        self.btn_cl_apply.setEnabled(True)

    def _color_light_apply(self):
        """Apply color/light adjustments permanently."""
        v = self.viewer
        if not v.image:
            return
        
        if getattr(self, '_cl_preview_image', None) is not None:
            original = self._cl_preview_image
            self._cl_preview_image = None
            # Push original to history
            v.history.append((original.copy(), v.marker_counter))
            v.redo_stack = []
            # Current v.image is already the adjusted version
            v.set_image(v.image)
        
        # Reset sliders to zero
        self.cl_brightness.blockSignals(True)
        self.cl_contrast.blockSignals(True)
        self.cl_hue.blockSignals(True)
        self.cl_sharpness.blockSignals(True)
        self.cl_brightness.setValue(0)
        self.cl_contrast.setValue(0)
        self.cl_hue.setValue(0)
        self.cl_sharpness.setValue(0)
        self.cl_brightness.blockSignals(False)
        self.cl_contrast.blockSignals(False)
        self.cl_hue.blockSignals(False)
        self.cl_sharpness.blockSignals(False)
        self.btn_cl_reset.setEnabled(False)
        self.btn_cl_apply.setEnabled(False)

    def _color_light_cancel(self):
        """Cancel color/light adjustments, restore original."""
        v = self.viewer
        if getattr(self, '_cl_preview_image', None) is not None:
            v.image = self._cl_preview_image
            self._cl_preview_image = None
            v._cached_base_qimg = None
            v.update_view()
        
        # Reset sliders to zero
        self.cl_brightness.blockSignals(True)
        self.cl_contrast.blockSignals(True)
        self.cl_hue.blockSignals(True)
        self.cl_sharpness.blockSignals(True)
        self.cl_brightness.setValue(0)
        self.cl_contrast.setValue(0)
        self.cl_hue.setValue(0)
        self.cl_sharpness.setValue(0)
        self.cl_brightness.blockSignals(False)
        self.cl_contrast.blockSignals(False)
        self.cl_hue.blockSignals(False)
        self.cl_sharpness.blockSignals(False)
        self.btn_cl_reset.setEnabled(False)
        self.btn_cl_apply.setEnabled(False)

    def _transform_w_changed(self, val):
        """Handle width spinbox change - update height if locked, trigger preview."""
        if self._transform_updating:
            return
        if self.transform_lock_ratio.isChecked() and hasattr(self, '_transform_aspect'):
            self._transform_updating = True
            new_h = max(1, round(val / self._transform_aspect))
            self.transform_h.setValue(new_h)
            # Update percentage to match
            orig = getattr(self, '_resize_preview_image', None)
            ref_w = orig.width if orig else (self.viewer.image.width if self.viewer.image else 1)
            pct = round(val / ref_w * 100)
            self.transform_pct.setValue(max(1, pct))
            self._transform_updating = False
        self._transform_resize_preview()

    def _transform_h_changed(self, val):
        """Handle height spinbox change - update width if locked, trigger preview."""
        if self._transform_updating:
            return
        if self.transform_lock_ratio.isChecked() and hasattr(self, '_transform_aspect'):
            self._transform_updating = True
            new_w = max(1, round(val * self._transform_aspect))
            self.transform_w.setValue(new_w)
            # Update percentage to match
            orig = getattr(self, '_resize_preview_image', None)
            ref_h = orig.height if orig else (self.viewer.image.height if self.viewer.image else 1)
            pct = round(val / ref_h * 100)
            self.transform_pct.setValue(max(1, pct))
            self._transform_updating = False
        self._transform_resize_preview()

    def _transform_pct_changed(self, pct):
        """Handle scale percentage change - update W/H and trigger preview."""
        if self._transform_updating:
            return
        orig = getattr(self, '_resize_preview_image', None)
        ref_w = orig.width if orig else (self.viewer.image.width if self.viewer.image else 1)
        ref_h = orig.height if orig else (self.viewer.image.height if self.viewer.image else 1)
        self._transform_updating = True
        self.transform_w.setValue(max(1, round(ref_w * pct / 100)))
        self.transform_h.setValue(max(1, round(ref_h * pct / 100)))
        self._transform_updating = False
        self._transform_resize_preview()

    def _transform_resize_preview(self):
        """Show live resize preview."""
        from PIL import Image as PILImage
        v = self.viewer
        if not v.image or self._transform_updating:
            return
        
        new_w = self.transform_w.value()
        new_h = self.transform_h.value()
        
        # Store original on first change
        if getattr(self, '_resize_preview_image', None) is None:
            # Check if dimensions actually differ from current
            if new_w == v.image.width and new_h == v.image.height:
                return
            self._resize_preview_image = v.image.copy()
        
        # If back to original size, revert
        orig = self._resize_preview_image
        if new_w == orig.width and new_h == orig.height:
            v.image = orig
            self._resize_preview_image = None
            v._transform_preview_active = False
            v._cached_base_qimg = None
            v.update_view()
            self._transform_update_button_states()
            return
        
        resized = orig.resize((new_w, new_h), PILImage.Resampling.LANCZOS)
        v.image = resized
        v._transform_preview_active = True
        v._cached_base_qimg = None
        v.update_view()
        self._transform_update_button_states()

    def _transform_resize(self):
        """Apply resize permanently."""
        from PIL import Image as PILImage
        v = self.viewer
        if not v.image:
            return
        
        new_w = self.transform_w.value()
        new_h = self.transform_h.value()
        
        if getattr(self, '_resize_preview_image', None) is not None:
            # Preview active — commit from original
            original = self._resize_preview_image
            self._resize_preview_image = None
            v._transform_preview_active = False
            
            if new_w == original.width and new_h == original.height:
                # No actual change
                v.set_image(original)
            else:
                v.history.append((original.copy(), v.marker_counter))
                v.redo_stack = []
                resized = original.resize((new_w, new_h), PILImage.Resampling.LANCZOS)
                v.set_image(resized)
        else:
            # No preview — direct apply
            if new_w == v.image.width and new_h == v.image.height:
                return
            v.history.append((v.image.copy(), v.marker_counter))
            v.redo_stack = []
            v.image = v.image.resize((new_w, new_h), PILImage.Resampling.LANCZOS)
            v.set_image(v.image)
        
        self._transform_update_size_display()

    def _transform_resize_cancel(self):
        """Cancel resize preview, restore original dimensions."""
        v = self.viewer
        if getattr(self, '_resize_preview_image', None) is not None:
            v.image = self._resize_preview_image
            self._resize_preview_image = None
            v._transform_preview_active = False
            v._cached_base_qimg = None
            v.update_view()
        self._transform_update_size_display()

    def _transform_reset_size(self):
        """Reset size spinboxes to current image dimensions."""
        self._transform_update_size_display()

    def _transform_update_size_display(self):
        """Update the W/H spinboxes and percentage to match current image."""
        v = self.viewer
        if not v.image:
            return
        self._transform_updating = True
        self.transform_w.setValue(v.image.width)
        self.transform_h.setValue(v.image.height)
        self.transform_pct.setValue(100)
        self._transform_aspect = v.image.width / v.image.height if v.image.height > 0 else 1.0
        self._transform_updating = False
        self._transform_update_button_states()

    def _transform_update_button_states(self):
        """Enable/disable transform buttons based on active preview state."""
        has_angle_preview = getattr(self, '_transform_preview_image', None) is not None
        has_resize_preview = getattr(self, '_resize_preview_image', None) is not None
        
        # Angle Reset/Apply: enabled only when angle preview is active
        self.btn_rotate_reset.setEnabled(has_angle_preview)
        self.btn_rotate_apply.setEnabled(has_angle_preview)
        
        # Resize Reset/Apply: enabled only when resize preview is active
        self.btn_resize_reset.setEnabled(has_resize_preview)
        self.btn_resize.setEnabled(has_resize_preview)
        
        # 90° rotations and flips: disabled when angle preview is active
        self.btn_rotate_ccw.setEnabled(not has_angle_preview)
        self.btn_rotate_cw.setEnabled(not has_angle_preview)
        self.btn_flip_h.setEnabled(not has_angle_preview)
        self.btn_flip_v.setEnabled(not has_angle_preview)

    def _apply_magnify_inset(self):
        """Apply magnified inset to the image"""
        from PIL import Image as PILImage, ImageDraw
        v = self.viewer
        if not v.image or not v.inset_source_rect or not v.inset_dest_pos:
            return
        
        zoom = int(self.inset_zoom.currentText().replace('%', '')) / 100.0
        border_w = self.inset_border.value()
        is_oval = self.inset_shape.currentText() == "Oval"
        border_color = tuple(self.primary_color[:4]) if len(self.primary_color) >= 4 else tuple(self.primary_color[:3]) + (255,)
        
        # Convert source screen coords to image coords
        sx1, sy1, sx2, sy2 = v.inset_source_rect
        ix1 = int((sx1 - v.offset.x()) / v.scale)
        iy1 = int((sy1 - v.offset.y()) / v.scale)
        ix2 = int((sx2 - v.offset.x()) / v.scale)
        iy2 = int((sy2 - v.offset.y()) / v.scale)
        
        # Clamp
        ix1 = max(0, min(v.image.width, ix1))
        iy1 = max(0, min(v.image.height, iy1))
        ix2 = max(0, min(v.image.width, ix2))
        iy2 = max(0, min(v.image.height, iy2))
        
        if ix2 <= ix1 or iy2 <= iy1:
            return
        
        # Convert dest screen coords to image coords
        dx, dy = v.inset_dest_pos
        dest_ix = int((dx - v.offset.x()) / v.scale)
        dest_iy = int((dy - v.offset.y()) / v.scale)
        
        # Crop and scale
        region = v.image.crop((ix1, iy1, ix2, iy2))
        new_w = int(region.width * zoom)
        new_h = int(region.height * zoom)
        if new_w <= 0 or new_h <= 0:
            return
        scaled = region.resize((new_w, new_h), PILImage.Resampling.LANCZOS)
        
        img = v.image.copy().convert('RGBA')
        
        # -- 1. Connection --
        conn_mode = self.inset_connection.currentText() if hasattr(self, 'inset_connection') else "Yes"
        
        if conn_mode == "Yes":
            import math as _math
            overlay = PILImage.new('RGBA', img.size, (0, 0, 0, 0))
            ov_draw = ImageDraw.Draw(overlay)
            
            src_cx = (ix1 + ix2) / 2
            src_cy = (iy1 + iy2) / 2
            dst_cx = dest_ix + new_w / 2
            dst_cy = dest_iy + new_h / 2
            
            trap_fill = border_color[:3] + (40,)
            trap_outline = border_color[:3] + (120,)
            line_w = max(1, border_w // 2)
            
            if is_oval:
                src_rx = (ix2 - ix1) / 2
                src_ry = (iy2 - iy1) / 2
                dst_rx = new_w / 2
                dst_ry = new_h / 2
                src_r = (src_rx + src_ry) / 2
                dst_r = (dst_rx + dst_ry) / 2
                
                angle = _math.atan2(dst_cy - src_cy, dst_cx - src_cx)
                d = _math.sqrt((dst_cx - src_cx)**2 + (dst_cy - src_cy)**2)
                
                if d > 1:
                    ratio = max(-1.0, min(1.0, (dst_r - src_r) / d))
                    off = _math.asin(ratio)
                    tp1 = angle + _math.pi/2 + off
                    tp2 = angle - _math.pi/2 - off
                    
                    n_seg = 32
                    pts = []
                    
                    # Source arc: tp1 to tp2, short way (near side facing dest)
                    src_sweep = tp2 - tp1
                    if src_sweep > _math.pi:
                        src_sweep -= 2 * _math.pi
                    elif src_sweep < -_math.pi:
                        src_sweep += 2 * _math.pi
                    for i in range(n_seg + 1):
                        a = tp1 + (i / n_seg) * src_sweep
                        pts.append((int(src_cx + src_rx * _math.cos(a)),
                                    int(src_cy + src_ry * _math.sin(a))))
                    
                    # Dest arc: tp2 to tp1, long way (far side, away from source)
                    dst_sweep = tp1 - tp2
                    if dst_sweep > 0:
                        dst_sweep -= 2 * _math.pi
                    elif dst_sweep < -2 * _math.pi:
                        dst_sweep += 2 * _math.pi
                    for i in range(n_seg + 1):
                        a = tp2 + (i / n_seg) * dst_sweep
                        pts.append((int(dst_cx + dst_rx * _math.cos(a)),
                                    int(dst_cy + dst_ry * _math.sin(a))))
                    
                    ov_draw.polygon(pts, fill=trap_fill, outline=trap_outline, width=line_w)
            else:
                # Rectangle: cube/box connection - 4 faces
                faces = [
                    [(ix1, iy1), (ix2, iy1), (dest_ix + new_w, dest_iy), (dest_ix, dest_iy)],  # top
                    [(ix2, iy1), (ix2, iy2), (dest_ix + new_w, dest_iy + new_h), (dest_ix + new_w, dest_iy)],  # right
                    [(ix2, iy2), (ix1, iy2), (dest_ix, dest_iy + new_h), (dest_ix + new_w, dest_iy + new_h)],  # bottom
                    [(ix1, iy2), (ix1, iy1), (dest_ix, dest_iy), (dest_ix, dest_iy + new_h)],  # left
                ]
                for face in faces:
                    ov_draw.polygon(face, fill=trap_fill, outline=trap_outline, width=line_w)
            
            img = PILImage.alpha_composite(img, overlay)
        
        # -- 2. Paste the magnified inset --
        if is_oval:
            mask = PILImage.new('L', (new_w, new_h), 0)
            mask_draw = ImageDraw.Draw(mask)
            mask_draw.ellipse([0, 0, new_w - 1, new_h - 1], fill=255)
            scaled_rgba = scaled.convert('RGBA')
            img.paste(scaled_rgba, (dest_ix, dest_iy), mask)
        else:
            scaled_rgba = scaled.convert('RGBA')
            img.paste(scaled_rgba, (dest_ix, dest_iy))
        
        # -- 4. Inset border --
        if border_w > 0:
            draw = ImageDraw.Draw(img)
            if is_oval:
                draw.ellipse([dest_ix, dest_iy, dest_ix + new_w - 1, dest_iy + new_h - 1],
                           outline=border_color, width=border_w)
            else:
                draw.rectangle([dest_ix, dest_iy, dest_ix + new_w - 1, dest_iy + new_h - 1],
                              outline=border_color, width=border_w)
        
        # -- 5. Source outline (back face, hidden behind inset) --
        if border_w > 0:
            src_brd = PILImage.new('RGBA', img.size, (0, 0, 0, 0))
            src_brd_draw = ImageDraw.Draw(src_brd)
            src_brd_color = border_color[:3] + (255,)
            src_bw = max(1, border_w // 2)
            if is_oval:
                src_brd_draw.ellipse([ix1, iy1, ix2 - 1, iy2 - 1], outline=src_brd_color, width=src_bw)
            else:
                src_brd_draw.rectangle([ix1, iy1, ix2 - 1, iy2 - 1], outline=src_brd_color, width=src_bw)
            # Erase where inset covers
            erase_mask = PILImage.new('L', img.size, 255)
            erase_draw = ImageDraw.Draw(erase_mask)
            if is_oval:
                erase_draw.ellipse([dest_ix, dest_iy, dest_ix + new_w - 1, dest_iy + new_h - 1], fill=0)
            else:
                erase_draw.rectangle([dest_ix, dest_iy, dest_ix + new_w - 1, dest_iy + new_h - 1], fill=0)
            src_brd.putalpha(PILImage.composite(src_brd.split()[3], PILImage.new('L', img.size, 0), erase_mask))
            img = PILImage.alpha_composite(img, src_brd)
        
        v.set_image(img)
        v.inset_source_rect = None
        v.inset_dest_pos = None
        v.update()

    # ---------------- Numbers Tool ----------------
    
    def apply_single_marker_to_image(self, marker_data):
        """Apply a single step marker to the image immediately"""
        v = self.viewer
        if not v.image or not marker_data:
            return
        
        num, badge_x, badge_y, tail_x, tail_y, has_tail = marker_data
        
        # Create QImage from PIL
        qimg = PilToQImage(v.image, for_painting=True)
        painter = QPainter(qimg)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Get size - use actual pixel size, not scaled
        size = self.step_marker_size.value()
        
        # Convert from screen to image coordinates
        bx_img = int((badge_x - v.offset.x()) / v.scale)
        by_img = int((badge_y - v.offset.y()) / v.scale)
        tx_img = int((tail_x - v.offset.x()) / v.scale)
        ty_img = int((tail_y - v.offset.y()) / v.scale)
        size_img = size  # Use actual size, not scaled
        
        # Draw step marker
        import math
        from PyQt6.QtGui import QPainterPath, QFont
        from PyQt6.QtCore import QPointF, Qt
        
        # Get colors - primary = badge, secondary = text
        badge_color = QColor(*self.primary_color) if hasattr(self, 'primary_color') else QColor(220, 50, 50, 255)
        text_color = QColor(*self.secondary_color) if hasattr(self, 'secondary_color') else QColor(255, 255, 255)
        
        radius = size_img // 2
        
        # Calculate if tail should be drawn
        dx = tx_img - bx_img
        dy = ty_img - by_img
        distance = math.sqrt(dx * dx + dy * dy)
        draw_tail = has_tail and distance > radius * 0.4
        
        if draw_tail:
            # Draw complete teardrop as ONE unified path
            angle = math.atan2(dy, dx)
            
            # Dynamic spread based on distance - when point is close, narrow the tail
            max_spread = 85.0
            min_spread = 20.0
            norm_dist = distance / radius if radius > 0 else 1.0
            t = max(0.0, min(1.0, (norm_dist - 1.0) / 2.0))
            spread = math.radians(min_spread + (max_spread - min_spread) * t)
            
            left_angle = angle - spread
            right_angle = angle + spread
            
            left_x = bx_img + math.cos(left_angle) * radius
            left_y = by_img + math.sin(left_angle) * radius
            
            right_x = bx_img + math.cos(right_angle) * radius
            right_y = by_img + math.sin(right_angle) * radius
            
            # Create complete teardrop path
            path = QPainterPath()
            
            # Start with full circle
            path.addEllipse(
                bx_img - radius,
                by_img - radius,
                radius * 2,
                radius * 2
            )
            
            # Add tail triangle
            tail_path = QPainterPath()
            tail_path.moveTo(left_x, left_y)
            tail_path.lineTo(tx_img, ty_img)
            tail_path.lineTo(right_x, right_y)
            tail_path.closeSubpath()
            
            # Unite them
            path = path.united(tail_path)
            
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(badge_color))
            painter.drawPath(path)
        else:
            # No tail - just circle
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(badge_color))
            painter.drawEllipse(
                int(bx_img - radius),
                int(by_img - radius),
                int(radius * 2),
                int(radius * 2)
            )
        
        # Draw number - better centered
        painter.setPen(text_color)
        from PyQt6.QtGui import QFont
        font = QFont()
        font.setPixelSize(int(size_img * 0.6))
        font.setBold(True)
        painter.setFont(font)
        text = str(num)
        
        text_rect = painter.fontMetrics().boundingRect(text)
        text_x = int(bx_img - text_rect.width() / 2)
        text_y = int(by_img + text_rect.height() / 2 - text_rect.height() / 6)
        painter.drawText(text_x, text_y, text)
        
        painter.end()
        
        # Update viewer image
        v.set_image(QImageToPil(qimg))
    
    def apply_markers_to_image(self):
        """Apply all placed step markers to the image"""
        v = self.viewer
        if not v.image or not v.step_markers:
            return
        
        # Apply each marker individually
        for marker_data in v.step_markers:
            self.apply_single_marker_to_image(marker_data)
        
        # Clear markers state
        v.step_markers = []
        v.step_markers_redo = []
        v.current_marker = None
        v.marker_placement_phase = 0
        # Reset counter to 1 for next batch of markers
        v.marker_counter = 1

    # ---------------- Text Tool ----------------
    
    def set_text_alignment(self, alignment):
        """Set text alignment"""
        self.text_alignment = alignment
        
        # Sync dropdown if called programmatically
        if hasattr(self, 'text_align_combo'):
            self.text_align_combo.blockSignals(True)
            self.text_align_combo.setCurrentText(alignment.capitalize())
            self.text_align_combo.blockSignals(False)
        
        # Update preview
        self.update_text_preview()
    
    def update_text_preview(self):
        """Update text preview when settings change"""
        if hasattr(self.viewer, 'current_text') and self.viewer.current_text:
            self.viewer.clear_shape_preview()
            self._update_shape_preview()
            self.viewer.update()
    
    def _render_text_preview(self):
        """Render current text into image copy for WYSIWYG preview."""
        v = self.viewer
        if not v.image or not v.current_text:
            return None
        
        text_str, x1, y1, x2, y2 = v.current_text
        if not text_str:
            return None
        
        qimg = PilToQImage(v.image, for_painting=True)
        painter = QPainter(qimg)
        
        config = load_config()
        smooth = config.get("smooth_drawing", False)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, smooth)
        
        font_name = self.text_font.currentText()
        font_size = self.text_size.value()
        color = self.primary_color
        outline_enabled = self.text_outline.isChecked()
        outline_color = self.secondary_color
        outline_thickness = self.text_outline_thickness.value()
        shadow_enabled = self.text_shadow.isChecked() if hasattr(self, 'text_shadow') else False
        
        x1_img = int((x1 - v.offset.x()) / v.scale)
        y1_img = int((y1 - v.offset.y()) / v.scale)
        x2_img = int((x2 - v.offset.x()) / v.scale)
        y2_img = int((y2 - v.offset.y()) / v.scale)
        box_width_img = x2_img - x1_img
        box_height_img = y2_img - y1_img
        
        if box_width_img <= 0 or box_height_img <= 0:
            painter.end()
            return None
        
        def _as_qcolor(val, default=QColor(0, 0, 0)):
            if isinstance(val, (tuple, list)) and len(val) >= 3:
                r, g, b = int(val[0]), int(val[1]), int(val[2])
                a = int(val[3]) if len(val) >= 4 else 255
                return QColor(r, g, b, a)
            if isinstance(val, QColor):
                return val
            return default
        
        text_color = _as_qcolor(color)
        
        if text_color.alpha() < 255:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        
        from PyQt6.QtGui import QFont, QPainterPath
        font = QFont(font_name)
        font.setPixelSize(font_size)
        font.setBold(self.text_bold.isChecked() if hasattr(self, 'text_bold') else True)
        font.setItalic(self.text_italic.isChecked() if hasattr(self, 'text_italic') else False)
        font.setUnderline(self.text_underline.isChecked() if hasattr(self, 'text_underline') else False)
        painter.setFont(font)
        metrics = painter.fontMetrics()
        
        padding = 10
        available_width = box_width_img - padding * 2
        lines = []
        current_line = ""
        current_start = 0
        last_break = -1
        last_break_line = ""
        
        for i, ch in enumerate(text_str):
            current_line += ch
            if ch == ' ':
                last_break = i
                last_break_line = current_line
            if metrics.horizontalAdvance(current_line) > available_width and len(current_line) > 1:
                if last_break > current_start:
                    lines.append(last_break_line.rstrip(' '))
                    current_start = last_break + 1
                    current_line = text_str[current_start:i + 1]
                    last_break = -1
                    last_break_line = ""
                else:
                    lines.append(current_line[:-1])
                    current_start = i
                    current_line = ch
                    last_break = -1
                    last_break_line = ""
        if current_line:
            lines.append(current_line)
        if not lines:
            lines = [text_str]
        
        line_height = metrics.height()
        total_height = line_height * len(lines)
        start_y = y1_img + (box_height_img - total_height) / 2 + line_height * 0.8
        
        shadow_offset = 2
        outline_width = outline_thickness
        alignment = self.text_alignment if hasattr(self, 'text_alignment') else "center"
        padding_img = 10
        
        for i, line in enumerate(lines):
            line_width = metrics.horizontalAdvance(line)
            if alignment == "left":
                x_img = x1_img + padding_img
            elif alignment == "right":
                x_img = x1_img + box_width_img - line_width - padding_img
            else:
                x_img = x1_img + (box_width_img - line_width) / 2
            y_img = start_y + i * line_height
            
            if shadow_enabled:
                shadow_path = QPainterPath()
                shadow_path.addText(x_img, y_img, font, line)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(0, 0, 0, 150))
                painter.save()
                painter.translate(shadow_offset, shadow_offset)
                painter.drawPath(shadow_path)
                painter.restore()
            
            text_path = QPainterPath()
            text_path.addText(x_img, y_img, font, line)
            
            if outline_enabled:
                outline_col = _as_qcolor(outline_color)
                painter.setPen(QPen(outline_col, outline_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(text_path)
            
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(text_color)
            painter.drawPath(text_path)
        
        painter.end()
        return QImageToPil(qimg)

    def apply_text_to_image(self):
        """Apply text to the image"""
        v = self.viewer
        if not v.image or not v.current_text:
            return
        
        text_str, x1, y1, x2, y2 = v.current_text
        
        # Create QImage from PIL
        qimg = PilToQImage(v.image, for_painting=True)
        painter = QPainter(qimg)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Get settings
        font_name = self.text_font.currentText()
        font_size = self.text_size.value()
        color = self.primary_color
        outline_enabled = self.text_outline.isChecked()
        outline_color = self.secondary_color
        outline_thickness = self.text_outline_thickness.value()
        shadow_enabled = self.text_shadow.isChecked()
        
        # Convert box from screen to image coordinates
        x1_img = int((x1 - v.offset.x()) / v.scale)
        y1_img = int((y1 - v.offset.y()) / v.scale)
        x2_img = int((x2 - v.offset.x()) / v.scale)
        y2_img = int((y2 - v.offset.y()) / v.scale)
        box_width_img = x2_img - x1_img
        box_height_img = y2_img - y1_img
        size_img = font_size
        # Get colors
        colors = {
            "Black": QColor(0, 0, 0),
            "White": QColor(255, 255, 255),
            "Red": QColor(255, 0, 0),
            "Green": QColor(0, 200, 0),
            "Blue": QColor(0, 100, 255),
            "Yellow": QColor(255, 255, 0),
            "Orange": QColor(255, 140, 0),
            "Pink": QColor(255, 0, 255),
            "Purple": QColor(160, 32, 240),
            "Gray": QColor(128, 128, 128)
        }

        def _as_qcolor(val, default=QColor(0, 0, 0)):
            if isinstance(val, (tuple, list)) and len(val) >= 3:
                r, g, b = int(val[0]), int(val[1]), int(val[2])
                a = int(val[3]) if len(val) >= 4 else 255
                return QColor(r, g, b, a)
            if isinstance(val, QColor):
                return val
            if isinstance(val, str):
                return colors.get(val, default)
            return default

        text_color = _as_qcolor(color, QColor(0, 0, 0))
        
        # If text color is transparent, use Source mode to replace pixels
        if text_color.alpha() < 255:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        
        # Setup font
        from PyQt6.QtGui import QFont, QPainterPath
        font = QFont(font_name)
        font.setPixelSize(size_img)
        font.setBold(self.text_bold.isChecked() if hasattr(self, 'text_bold') else True)
        font.setItalic(self.text_italic.isChecked() if hasattr(self, 'text_italic') else False)
        font.setUnderline(self.text_underline.isChecked() if hasattr(self, 'text_underline') else False)
        painter.setFont(font)
        metrics = painter.fontMetrics()
        
        # Wrap text to fit box width (preserves exact spacing)
        padding = 10
        available_width = box_width_img - padding * 2
        lines = []
        current_line = ""
        current_start = 0
        last_break = -1
        last_break_line = ""
        
        for i, ch in enumerate(text_str):
            current_line += ch
            if ch == ' ':
                last_break = i
                last_break_line = current_line
            
            if metrics.horizontalAdvance(current_line) > available_width and len(current_line) > 1:
                if last_break > current_start:
                    lines.append(last_break_line.rstrip(' '))
                    current_start = last_break + 1
                    current_line = text_str[current_start:i + 1]
                    last_break = -1
                    last_break_line = ""
                else:
                    lines.append(current_line[:-1])
                    current_start = i
                    current_line = ch
                    last_break = -1
                    last_break_line = ""
        
        if current_line:
            lines.append(current_line)
        
        if not lines:
            lines = [text_str]
        
        # Calculate total height and starting position to center vertically
        line_height = metrics.height()
        total_height = line_height * len(lines)
        start_y = y1_img + (box_height_img - total_height) / 2 + line_height * 0.8
        
        # Draw each line
        shadow_offset = 2
        outline_width = outline_thickness
        alignment = self.text_alignment if hasattr(self, 'text_alignment') else "center"
        padding_img = 10
        
        for i, line in enumerate(lines):
            line_width = metrics.horizontalAdvance(line)
            
            # Calculate x position based on alignment
            if alignment == "left":
                x_img = x1_img + padding_img
            elif alignment == "right":
                x_img = x1_img + box_width_img - line_width - padding_img
            else:  # center
                x_img = x1_img + (box_width_img - line_width) / 2
            
            y_img = start_y + i * line_height
            
            # Draw shadow first (if enabled)
            if shadow_enabled:
                shadow_path = QPainterPath()
                shadow_path.addText(x_img, y_img, font, line)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(0, 0, 0, 150))
                painter.save()
                painter.translate(shadow_offset, shadow_offset)
                painter.drawPath(shadow_path)
                painter.restore()
            
            # Use QPainterPath for both outline and fill to ensure alignment
            text_path = QPainterPath()
            text_path.addText(x_img, y_img, font, line)
            
            # Draw outline (if enabled)
            if outline_enabled:
                outline_col = _as_qcolor(outline_color, QColor(0, 0, 0))
                painter.setPen(QPen(outline_col, outline_width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(text_path)
            
            # Draw main text fill
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(text_color)
            painter.drawPath(text_path)
        
        painter.end()
        
        # Update viewer image and clear text
        v.clear_shape_preview()
        v.set_image(QImageToPil(qimg))
        v.current_text = None

    def closeEvent(self, event):
        """Handle window close - prompt if there are unsaved changes."""
        # Save tool values for "Remember Last" feature
        try:
            self.save_last_tool_values()
        except Exception as e:
            logging.error(f"Failed to save last tool values: {e}")
        
        if self.has_unsaved_changes:
            from PyQt6.QtWidgets import QMessageBox
            
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setWindowTitle("Unsaved Changes")
            msg.setText("You have unsaved changes.")
            msg.setInformativeText("Do you want to save your changes before closing?")
            
            # Use custom buttons for better text
            save_btn = msg.addButton("Save", QMessageBox.ButtonRole.AcceptRole)
            continue_btn = msg.addButton("Continue without Saving", QMessageBox.ButtonRole.DestructiveRole)
            cancel_btn = msg.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
            msg.setDefaultButton(save_btn)
            
            msg.exec()
            clicked = msg.clickedButton()
            
            if clicked == save_btn:
                self.save()
                # If save was successful (user didn't cancel), allow close
                if not self.has_unsaved_changes:
                    event.accept()
                else:
                    event.ignore()
            elif clicked == continue_btn:
                event.accept()
            else:  # Cancel
                event.ignore()
        else:
            event.accept()

# =========================================================
# Main application entry point
# =========================================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application icon (for Windows taskbar, etc.)
    app_dir = os.path.dirname(os.path.abspath(__file__))
    for icon_name in ("magpie.ico", "magpie.png"):
        icon_path = os.path.join(app_dir, icon_name)
        if os.path.exists(icon_path):
            app.setWindowIcon(QIcon(icon_path))
            break
    
    app.setDesktopFileName("com.magpie.Magpie")
    app.setStyle("Fusion")
    
    # Match system font with light weight for crisp rendering
    from PyQt6.QtGui import QFont
    _app_font = app.font()
    _app_font.setWeight(QFont.Weight.Light)
    _app_font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    app.setFont(_app_font)
    
    # Disable focus highlight rectangle on buttons (Fusion style paints a blue
    # highlight on focused buttons which looks wrong for click-only interactions)
    from PyQt6.QtWidgets import QProxyStyle, QStyle
    class NoFocusFrameStyle(QProxyStyle):
        def drawPrimitive(self, element, option, painter, widget=None):
            if element == QStyle.PrimitiveElement.PE_FrameFocusRect:
                return  # Don't draw focus rectangle
            super().drawPrimitive(element, option, painter, widget)
    _style = NoFocusFrameStyle(app.style())
    _style.setParent(app)  # prevent garbage collection
    app.setStyle(_style)
    
    _palette = app.palette()
    _win_color = _palette.color(_palette.ColorRole.Window)
    _system_is_dark = _win_color.lightness() < 128
    
    # Check saved theme preference
    _startup_config = load_config()
    _theme_mode = _startup_config.get("theme_mode", "system")
    
    if _theme_mode == "dark":
        _is_dark = True
    elif _theme_mode == "light":
        _is_dark = False
    else:
        _is_dark = _system_is_dark
    
    if _is_dark:
        # Force dark palette when overriding
        if _theme_mode == "dark" and not _system_is_dark:
            from PyQt6.QtGui import QPalette, QColor as QC
            dark_palette = QPalette()
            dark_palette.setColor(QPalette.ColorRole.Window, QC(45, 45, 45))
            dark_palette.setColor(QPalette.ColorRole.WindowText, QC(224, 224, 224))
            dark_palette.setColor(QPalette.ColorRole.Base, QC(35, 35, 35))
            dark_palette.setColor(QPalette.ColorRole.AlternateBase, QC(53, 53, 53))
            dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QC(58, 58, 58))
            dark_palette.setColor(QPalette.ColorRole.ToolTipText, QC(224, 224, 224))
            dark_palette.setColor(QPalette.ColorRole.Text, QC(224, 224, 224))
            dark_palette.setColor(QPalette.ColorRole.Button, QC(53, 53, 53))
            dark_palette.setColor(QPalette.ColorRole.ButtonText, QC(224, 224, 224))
            dark_palette.setColor(QPalette.ColorRole.BrightText, QC(255, 0, 0))
            dark_palette.setColor(QPalette.ColorRole.Link, QC(42, 130, 218))
            dark_palette.setColor(QPalette.ColorRole.Highlight, QC(42, 130, 218))
            dark_palette.setColor(QPalette.ColorRole.HighlightedText, QC(0, 0, 0))
            app.setPalette(dark_palette)
        
        app.setStyleSheet("""
            QToolTip { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #666; padding: 3px; }
            QMenu { background-color: #2d2d2d; border: 1px solid #555; padding: 2px; color: #e0e0e0; }
            QMenu::item { padding: 4px 20px 4px 20px; color: #e0e0e0; }
            QMenu::item:selected { background-color: #4a4a4a; color: #ffffff; }
            QMenu::item:disabled { color: #777777; }
            QMenu::indicator { width: 14px; height: 14px; margin-left: 6px; border: 1px solid #666; border-radius: 2px; background-color: #3a3a3a; }
            QMenu::indicator:checked { background-color: #4080d0; border: 1px solid #5090e0; image: none; }
            QMenu::separator { height: 1px; background-color: #555; margin: 3px 6px; }
            QMenuBar { background-color: #2d2d2d; color: #e0e0e0; }
            QMenuBar::item { background-color: transparent; color: #e0e0e0; padding: 4px 8px; }
            QMenuBar::item:selected { background-color: #4a4a4a; }
            QComboBox { color: #e0e0e0; background-color: #3a3a3a; border: 1px solid #555; }
            QComboBox QAbstractItemView { color: #e0e0e0; background-color: #2d2d2d; selection-background-color: #4a4a4a; selection-color: #ffffff; border: 1px solid #555; }
            QComboBox:editable { background-color: #3a3a3a; color: #e0e0e0; }
            QDialog { background-color: #2d2d2d; color: #e0e0e0; }
            QGroupBox { color: #e0e0e0; border: 1px solid #555; margin-top: 8px; padding-top: 8px; }
            QGroupBox::title { color: #e0e0e0; }
            QLineEdit { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #555; padding: 2px 4px; }
            QListWidget { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #555; }
            QTextEdit { background-color: #3a3a3a; color: #e0e0e0; border: 1px solid #555; }
        """)
    else:
        # Reset palette when forcing light on a dark system
        if _theme_mode == "light" and _system_is_dark:
            app.setPalette(app.style().standardPalette())
        
        if _theme_mode == "light":
            # Explicit light theme — override everything for dark DE compatibility
            app.setStyleSheet("""
                QToolTip { background-color: #ffffee; color: #000000; border: 1px solid #a0a0a0; padding: 3px; }
                QMainWindow { background-color: #f0f0f0; }
                QWidget { background-color: #f0f0f0; color: #000000; }
                QLabel { background-color: transparent; color: #000000; }
                QPushButton { color: #000000; }
                QComboBox { color: #000000; }
                QSpinBox { color: #000000; }
                QDoubleSpinBox { color: #000000; }
                QCheckBox { color: #000000; }
                QSlider { background-color: transparent; }
                QMenu { background-color: #ffffff; border: 1px solid #a0a0a0; padding: 2px; color: #000000; }
                QMenu::item { padding: 4px 20px 4px 20px; color: #000000; }
                QMenu::item:selected { background-color: #e8e8e8; color: #000000; }
                QMenu::indicator { width: 14px; height: 14px; margin-left: 6px; border: 1px solid #808080; border-radius: 2px; background-color: #ffffff; }
                QMenu::indicator:checked { background-color: #4080d0; border: 1px solid #2060a0; image: none; }
                QMenu::separator { height: 1px; background-color: #d0d0d0; margin: 3px 6px; }
                QMenuBar { background-color: #f0f0f0; color: #000000; }
                QMenuBar::item { color: #000000; padding: 4px 8px; }
                QMenuBar::item:selected { background-color: #e8e8e8; }
                QScrollArea { background-color: #c8c8c8; }
            """)
        else:
            # System light — minimal overrides
            app.setStyleSheet("""
                QMenu { background-color: #ffffff; border: 1px solid #a0a0a0; padding: 2px; }
                QMenu::item { padding: 4px 20px 4px 20px; }
                QMenu::item:selected { background-color: #e8e8e8; color: #000000; }
                QMenu::indicator { width: 14px; height: 14px; margin-left: 6px; border: 1px solid #808080; border-radius: 2px; background-color: #ffffff; }
                QMenu::indicator:checked { background-color: #4080d0; border: 1px solid #2060a0; image: none; }
                QMenu::separator { height: 1px; background-color: #d0d0d0; margin: 3px 6px; }
                QMenuBar::item:selected { background-color: #e8e8e8; }
            """)
    
    # Warn if NumPy is missing
    if not _numpy_available:
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.warning(
            None,
            "Missing Dependency",
            "NumPy is not installed.\n\n"
            "Several features (Blur, Pixelate, Color & Light, Text rendering) "
            "will not work correctly.\n\n"
            "Install it with:  pip install numpy"
        )

    win = CutoutTool()
    win.show()
    
    # Handle file passed as command-line argument (from file manager "Open With")
    for arg in sys.argv[1:]:
        if os.path.isfile(arg) and arg.lower().endswith(
                ('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp', '.tiff', '.tif', '.svg', '.ico')):
            win._load_image_from_path(arg)
            break
    
    sys.exit(app.exec())
