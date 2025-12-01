# ⚡ VOLTAIC — ICS / OT Threat Intelligence Console  
Advanced OSINT, Threat Hunting & Incident Investigation Dashboard built with **Python + Streamlit**.

---

## 🚀 Overview  
VOLTAIC is a modern ICS/OT threat-intelligence platform designed for:

- ✔ OT Cyber Security Analysts  
- ✔ SOC Teams  
- ✔ Threat Hunters  
- ✔ Red/Blue Teams  
- ✔ Incident Responders  

---

### **What the dashboard provides:**  
- Global threat posture  
- ICS vulnerability intelligence  
- OSINT recon (IP / Domain / Hash)  
- Image forensics  
- CISA advisories  
- Threat actor mapping  
- Exportable investigation notebook  

---

## 🔥 Core Features

### 🛰 **Command Center Dashboard**
- Global threat posture  
- Active ICS CVEs (24H)  
- Threat actor clusters  
- Platform health  
- Operational world map  

---

### 🕵️ **OSINT / Threat Hunting Engine**  
- IP / Domain / Hash Intelligence  
- Risk scoring (0–100)  
- Open ports & banner detection  
- Auto-detect input type  
- Quick links:
  - VirusTotal  
  - Shodan  
  - AbuseIPDB  

---

### 📰 **ICS Advisory Feed (CISA Wire)**  
- Real-time ICS/CERT updates  
- RSS parsing  
- Severity-based tags  
- Vendor watchlist  
- Search + filtering  

---

### 🖼 **Image Intelligence Module**  
- EXIF metadata extraction  
- Steganography-support  
- Reverse-search helper links  
- Metadata viewer  

---

### 📝 **Investigation Notebook**  
- Auto-logs OSINT + image analysis  
- Manual notes  
- Export case report (.txt)  
- Useful for documentation  

---

## 🧪 Tech Stack  

| Component   | Purpose |
|------------|---------|
| Python     | Core logic |
| Streamlit  | UI framework |
| Plotly     | Charts & gauges |
| Folium     | Global threat maps |
| Feedparser | CISA advisory fetch |
| PIL        | Image metadata |
| Requests   | API calls |
| Regex      | Input detection |

---

## ⚙️ Installation & Setup  

### **1️⃣ Clone the repository**
```bash
git clone https://github.com/uv800/voltaic-ics-threat-intel.git
cd voltaic-ics-threat-intel
```

### **2️⃣ Install dependencies**
```bash
pip install -r requirements.txt
```

### **3️⃣ Run the dashboard**
```bash
streamlit run voltaic.py
```

---

## 🔑 API Keys (Optional)
Add keys inside the sidebar for:

- VirusTotal  
- Shodan  

Without keys → dashboard runs in **demo mode** (safe for GitHub).

---

## 🖼 Screenshots  

### Dashboard View  
[<img width="1512" height="982" alt="Screenshot 2025-12-02 at 12 13 56 AM" src="https://github.com/user-attachments/assets/6fb5a596-851c-4a46-a659-aeae889d2cff" />

### OSINT Search  
![OSINT](https://github.com/user-attachments/assets/40f71438-4df6-4a72-87aa-cefaf3e25941)

### CISA Feed  
![CISA](https://github.com/user-attachments/assets/2db09d8d-ebae-42ee-ad1d-26d2430d614b)

### Investigation Log  
![Investigate](https://github.com/user-attachments/assets/e99cbf86-5043-43ec-b151-da41cf41d8ff)

---

## ⭐ Highlights
- Applied ICS cyber defense concepts  
- Built end-to-end threat intelligence workflow  
- Combines multiple data sources into a unified dashboard  
- Visual analytics for OT threat posture  
- Demonstrates ability to engineer internal security tools


---
