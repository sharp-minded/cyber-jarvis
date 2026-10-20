# Cyber Jarvis v6.0

Personal AI-powered ethical hacking assistant.

## Features
- 🎓 Full hacking teacher (English / Hinglish / Roman Urdu)
- 🎯 Autonomous pentesting (600+ Kali tools)
- 🧠 RAG + Neo4j + MITRE ATT&CK
- 🎤 Voice + Wake word ("Hey Jarvis")
- 📰 Daily CVE news
- 📱 WhatsApp notifications → +92 3132985274
- 📊 Professional reports (English only)
- 🚀 Auto-start on Windows boot

## Quick Start

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install pipwin && pipwin install pyaudio
playwright install chromium
copy .env.example .env
# Edit .env
python main_v5.py