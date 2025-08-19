# stego_gui_qt.py
import sys, os, traceback
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QMessageBox, QProgressBar, QSpacerItem, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# ---- import your real engine (zip + AES-GCM + LSB PNG) ----
try:
    from stego import embed as stego_embed, extract as stego_extract
except Exception as e:
    stego_embed = stego_extract = None
    _import_error = e
else:
    _import_error = None


# ---- Worker threads so the UI doesn't freeze ----
class EmbedWorker(QThread):
    done = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, cover, folder, output, password):
        super().__init__()
        self.cover, self.folder, self.output, self.password = cover, folder, output, password
    def run(self):
        try:
            stego_embed(self.cover, self.folder, self.output, self.password)
            self.done.emit(self.output)
        except Exception as e:
            self.error.emit(f"{e}\n\n{traceback.format_exc()}")

class ExtractWorker(QThread):
    done = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, stego_png, outdir, password):
        super().__init__()
        self.stego_png, self.outdir, self.password = stego_png, outdir, password
    def run(self):
        try:
            stego_extract(self.stego_png, self.outdir, self.password)
            self.done.emit(self.outdir)
        except Exception as e:
            self.error.emit(f"{e}\n\n{traceback.format_exc()}")


class StegoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Don't Thai to me : © 2025 Pisethz. All rights reserved.")
        self.setFixedSize(560, 380)

        # macOS-like stylesheet (rounded, soft grays, blue buttons)
        self.setStyleSheet("""
            QWidget {
                background-color: #f5f5f7;
                font-family: 'SF Pro Text', 'Helvetica Neue', Arial;
                font-size: 14px;
                color: #1d1d1f;
            }
            QLineEdit {
                border: 1px solid #d1d1d6;
                border-radius: 8px;
                padding: 8px 10px;
                background: #ffffff;
            }
            QPushButton {
                background-color: #007aff;
                color: #ffffff;
                border: none;
                border-radius: 10px;
                padding: 9px 16px;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #0a66d8; }
            QPushButton:disabled {
                background-color: #b9d3ff;
                color: #f0f6ff;
            }
            QLabel[hint="true"] {
                color: #6e6e73;
                font-size: 12px;
            }
            QProgressBar {
                border: 1px solid #d1d1d6;
                border-radius: 8px;
                background: #ffffff;
                text-align: center;
                height: 16px;
            }
            QProgressBar::chunk {
                border-radius: 8px;
                background-color: #007aff;
            }
        """)

        if _import_error:
            QMessageBox.critical(self, "Import error",
                "Could not import stego engine from stego.py.\n\n"
                f"{_import_error}\n\nMake sure stego.py is in the same folder.")
        
        # --- Layout
        root = QVBoxLayout(self)
        title = QLabel("🗂️ STEGOFOLDER")
        title.setStyleSheet("font-size:22px; font-weight:800;")
        title.setAlignment(Qt.AlignCenter)
        root.addWidget(title)

        hint = QLabel("Hide or extract a whole folder inside a PNG (AES-GCM + LSB).")
        hint.setProperty("hint", True)
        hint.setAlignment(Qt.AlignCenter)
        root.addWidget(hint)

        root.addSpacerItem(QSpacerItem(0, 6, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Row: secret folder + browse
        self.folder_edit = QLineEdit()
        self.folder_edit.setPlaceholderText("Folder to hide (recursively)")
        btn_folder = QPushButton("Browse Folder")
        btn_folder.clicked.connect(self.pick_folder)
        root.addLayout(self._row("Secret Folder:", self.folder_edit, btn_folder))

        # Row: cover image
        self.cover_edit = QLineEdit()
        self.cover_edit.setPlaceholderText("Cover PNG (lossless)")
        btn_cover = QPushButton("Browse Cover")
        btn_cover.clicked.connect(self.pick_cover)
        root.addLayout(self._row("Cover Image:", self.cover_edit, btn_cover))

        # Row: output stego image
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Save stego PNG as…")
        btn_output = QPushButton("Save As")
        btn_output.clicked.connect(self.pick_output)
        root.addLayout(self._row("Output File:", self.output_edit, btn_output))

        # Row: password
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pass_edit.setPlaceholderText("Password (AES-256-GCM)")
        root.addLayout(self._row("Password:", self.pass_edit))

        # Row: buttons (Embed / Extract)
        buttons = QHBoxLayout()
        self.btn_embed = QPushButton("🔒 Embed Folder")
        self.btn_embed.clicked.connect(self.do_embed)
        self.btn_extract = QPushButton("🔓 Extract Folder")
        self.btn_extract.clicked.connect(self.do_extract)
        buttons.addWidget(self.btn_embed)
        buttons.addWidget(self.btn_extract)
        root.addLayout(buttons)

        # Progress bar (indeterminate while working)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setVisible(False)
        root.addWidget(self.progress)

        # Sub-hint
        cap = QLabel("Tip: keep the image as PNG after embedding; converting to JPEG will corrupt hidden bits.")
        cap.setProperty("hint", True)
        cap.setAlignment(Qt.AlignCenter)
        root.addWidget(cap)

        self.embed_thread = None
        self.extract_thread = None

    # --- helpers
    def _row(self, label, *widgets):
        h = QHBoxLayout()
        lbl = QLabel(label)
        lbl.setMinimumWidth(110)
        h.addWidget(lbl)
        for w in widgets:
            h.addWidget(w)
        return h

    def pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder to Hide: © 2025 Pisethz. All rights reserved.")
        if d: self.folder_edit.setText(d)

    def pick_cover(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Cover PNG: © 2025 Pisethz. All rights reserved.", "", "PNG Images (*.png)")
        if f: self.cover_edit.setText(f)

    def pick_output(self):
        f, _ = QFileDialog.getSaveFileName(self, "Save Stego PNG: © 2025 Pisethz. All rights reserved.", "", "PNG Image (*.png)")
        if f and not f.lower().endswith(".png"):
            f += ".png"
        if f: self.output_edit.setText(f)

    # --- actions
    def set_working(self, working: bool):
        self.btn_embed.setDisabled(working)
        self.btn_extract.setDisabled(working)
        self.progress.setVisible(working)

    def do_embed(self):
        if _import_error:
            QMessageBox.critical(self, "Engine missing", "stego.py not loaded.")
            return
        folder  = self.folder_edit.text().strip()
        cover   = self.cover_edit.text().strip()
        output  = self.output_edit.text().strip()
        pwd     = self.pass_edit.text()

        if not folder or not os.path.isdir(folder):
            QMessageBox.warning(self, "Missing", "Please choose a valid folder to hide.")
            return
        if not cover.lower().endswith(".png") or not os.path.isfile(cover):
            QMessageBox.warning(self, "Missing", "Please choose a valid PNG cover image.")
            return
        if not output.lower().endswith(".png"):
            QMessageBox.warning(self, "Missing", "Please choose a PNG output filename.")
            return
        if not pwd:
            QMessageBox.warning(self, "Missing", "Please enter a password.")
            return

        self.set_working(True)
        self.embed_thread = EmbedWorker(cover, folder, output, pwd)
        self.embed_thread.done.connect(self._embed_done)
        self.embed_thread.error.connect(self._worker_error)
        self.embed_thread.start()

    def _embed_done(self, outpng):
        self.set_working(False)
        QMessageBox.information(self, "Success", f"Folder embedded into:\n{outpng}")

    def do_extract(self):
        if _import_error:
            QMessageBox.critical(self, "Engine missing", "stego.py not loaded.")
            return
        stego, _ = QFileDialog.getOpenFileName(self, "Select Stego PNG: © 2025 Pisethz. All rights reserved.", "", "PNG Images (*.png)")
        if not stego:
            return
        outdir = QFileDialog.getExistingDirectory(self, "Select Restore Location: © 2025 Pisethz. All rights reserved.")
        if not outdir:
            return
        pwd = self.pass_edit.text()
        if not pwd:
            QMessageBox.warning(self, "Missing", "Please enter the password (same as used for embed).")
            return

        self.set_working(True)
        self.extract_thread = ExtractWorker(stego, outdir, pwd)
        self.extract_thread.done.connect(self._extract_done)
        self.extract_thread.error.connect(self._worker_error)
        self.extract_thread.start()

    def _extract_done(self, outdir):
        self.set_working(False)
        QMessageBox.information(self, "Success", f"Extracted into:\n{outdir}\n\n"
                                 "Inside it you’ll see the original folder name restored.")

    def _worker_error(self, msg):
        self.set_working(False)
        QMessageBox.critical(self, "Error", msg)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = StegoApp()
    win.show()
    sys.exit(app.exec_())
