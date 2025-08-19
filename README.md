<div align="center">

# 🗂️🔒 StegoFolder GUI
### Hide & Extract Folders inside Images — with a beautiful macOS-style GUI ✨

<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python" />
<img src="https://img.shields.io/badge/PyQt5-GUI-orange?style=for-the-badge&logo=qt" />
<img src="https://img.shields.io/github/license/openai/openai-cookbook?style=for-the-badge" />

</div>

---

## ✨ Features

✅ Hide **entire folders** (with subfolders + files) inside an image  
✅ Extract back the folder securely with **password protection**  
✅ **macOS-style GUI** built with PyQt5 🎨  
✅ Cross-platform (Windows, macOS, Linux) 🖥️  
✅ Simple, clean & modern interface 💎  

---

## 🚀 Installation

Clone the repo & install dependencies:

```bash
git clone https://github.com/Pisethz/StegoFolder
cd Stego
pip install -r requirements.txt

```

🖥️ Usage

Run the GUI:

python stegogui.py

---
💻 GUI Instructions

1. Embed Folder (🔒)

    ▶️Select the folder you want to hide

    ▶️Select the cover PNG image

    ▶️Choose an output PNG file name

    ▶️Enter a password

    ▶️Click Embed Folder

2. Extract Folder (🔓)

    ▶️Select the stego PNG file

    ▶️Choose the output directory

    ▶️Enter the password used for embedding

    ▶️Click Extract Folder
---
⚙️ CLI Usage

You can also use StegoFolder from the command line.

🔒  Embed Folder (Hide)

python stego.py embed -c cover.png -i C:\data\myFolder -o stego.png -p "1234"

🔓  Extract Folder (Recover)

python stego.py extract -s stego.png -o C:\restore -p "1234"

Options:

    👉 --embed → Embed a folder

    👉 --extract → Extract a folder

    👉 --f → Folder to hide (only for embed)

    👉 --c → Cover PNG image (only for embed)

    👉 --o → Output PNG (embed) or restore folder (extract)

    👉 --s → Stego PNG file (extract)

    👉 --p → Password to encrypt/decrypt

⚡ Tips

    ❄️  Always use PNG as cover; JPEG will corrupt hidden data

    🔑  Keep passwords secure; without the password, extraction fails

    🤖  CLI mode is ideal for automation or scripting workflows

🤝 Contributing

Pull requests are welcome! 🎉
For major changes, open an issue first to discuss.

📜 License

MIT License © 2025 Pisethz

<div align="center">

💡 Built with ❤️ by Pisethz

</div> ```
