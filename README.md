# ClamOrchestra - Centralized ClamAV Management

[![Node.js](https://img.shields.io/badge/Node.js-v18+-green)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-blue)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**ClamOrchestra** ist ein webbasiertes Verwaltungstool zur zentralisierten Verwaltung von ClamAV auf mehreren Linux-Servern (Debian/Ubuntu). Mit ClamOrchestra können Sie ClamAV auf Remote-Servern installieren, Scans planen, Logs automatisch abrufen und sich bei Virenfunden per E-Mail benachrichtigen lassen.

![CO Dashboard](https://github.com/bmetallica/ClamOrchestra/blob/main/co.png)

## 🎯 Features

### Kern-Funktionalität
- ✅ **Server-Verwaltung**: Zentrale Verwaltung mehrerer Server über SSH
- ✅ **ClamAV Installation**: Automatische Installation und Konfiguration via SSH
- ✅ **Scan-Scheduling**: Zentrale Verwaltung von automatischen Scan-Jobs (Cron-basiert)
- ✅ **Log-Abruf**: Automatische Abholung von ClamAV Scan-Logs von Remote-Servern
- ✅ **Threat Detection**: Automatische Erkennung und Tracking von Virenfunden
- ✅ **Email Alerting**: Sofortige E-Mail-Benachrichtigungen bei Bedrohungen
- ✅ **SSH-Key Management**: Verwaltung von Standard- und Server-spezifischen SSH-Keys
- ✅ **Benutzer-Auth**: JWT & Session-basierte Authentifizierung mit Admin-Rollen

### Dashboard & Reporting
- 📊 **Real-time Dashboard**: Live-Übersicht aller Server und Scans
- 📋 **Scan-Ergebnisse**: Detaillierte Scan-Berichte mit Detektionen
- 🔔 **Alert-Management**: Verwaltung und Verfolgung von Sicherheitswarnungen

## 📋 Voraussetzungen

### Server (Host)
- **OS**: Debian 11+ / Ubuntu 20.04+ (LTS empfohlen)
- **Node.js**: 18.0 oder höher
- **PostgreSQL**: 13 oder höher
- **RAM**: Mindestens 2 GB
- **Disk**: Mindestens 1 GB (für Logs und Datenbank)

### Zielserver (ClamAV)
- **OS**: Debian 10+ / Ubuntu 18.04+
- **SSH**: Aktiviert und erreichbar
- **Sudo**: Benutzer mit NOPASSWD-Berechtigung

### Browser
- Moderner Browser mit JavaScript (Chrome, Firefox, Safari, Edge)

## 🚀 Installation

### 1. Abhängigkeiten installieren

```bash
# System aktualisieren
sudo apt-get update
sudo apt-get upgrade -y

# PostgreSQL installieren
sudo apt-get install -y postgresql postgresql-contrib

# Node.js 18 LTS installieren
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### 2. PostgreSQL konfigurieren

```bash
# PostgreSQL starten
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Benutzer und Datenbank erstellen
sudo -u postgres psql <<EOF
CREATE USER clamorchestra WITH PASSWORD 'your_secure_password';
CREATE DATABASE clamorchestra OWNER clamorchestra;
GRANT ALL PRIVILEGES ON DATABASE clamorchestra TO clamorchestra;
EOF
```

### 3. ClamOrchestra klonen und installieren

```bash
# Projekt klonen
git clone https://github.com/yourusername/clamorchestra.git
cd clamorchestra

# Abhängigkeiten installieren
npm install

# Umgebungsvariablen konfigurieren
cp .env.example .env
nano .env  # Bearbeite die Konfiguration
```

### 4. .env konfigurieren

```env
# Server
NODE_ENV=production
PORT=3000
HOST=0.0.0.0

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=clamorchestra
DB_PASSWORD=your_secure_password
DB_NAME=clamorchestra

# JWT
JWT_SECRET=your_random_secret_at_least_32_chars
JWT_EXPIRATION=24h

# Session
SESSION_SECRET=your_random_session_secret_32_chars

# Logging
LOG_LEVEL=info
```

### 5. Anwendung starten

**Entwicklung** (mit Auto-Reload bei Code-Änderungen):
```bash
npm run dev
```

**Production** (direkter Start ohne Auto-Reload):
```bash
npm start
# oder:
node index.js
```

Die App läuft dann unter `http://localhost:3000`

Standard-Anmeldung:
- **Benutzer**: admin
- **Passwort**: admin

⚠️ **Ändere das Admin-Passwort sofort nach der ersten Anmeldung!**

### 6. Production Setup mit systemd

Erstelle Service-Datei:

```bash
sudo nano /etc/systemd/system/clamorchestra.service
```

```ini
[Unit]
Description=ClamOrchestra - Centralized ClamAV Management
After=network.target postgresql.service

[Service]
Type=simple
User=clamorchestra
WorkingDirectory=/opt/clamorchestra
Environment="NODE_ENV=production"
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Aktivieren und starten:

```bash
# Benutzer erstellen
sudo useradd -r -m -s /bin/bash clamorchestra

# Eigentümer setzen
sudo chown -R clamorchestra:clamorchestra /opt/clamorchestra

# Service aktivieren und starten
sudo systemctl daemon-reload
sudo systemctl enable clamorchestra
sudo systemctl start clamorchestra
sudo systemctl status clamorchestra

# Logs prüfen
sudo journalctl -u clamorchestra -f
```


### SSH-Key in ClamOrchestra hochladen (root oder sudo User)

1. Gehe zu **Settings > SSH Keys**
2. Klick auf **Neuen SSH-Schlüssel hochladen**
3. Gib folgende Informationen ein:
   - **Schlüssel-Name**: Z.B. "Default Key"
   - **Öffentlicher Schlüssel**: Inhalt von `id_rsa.pub`
   - **Privater Schlüssel**: Inhalt von `id_rsa`
   - **SSH-Benutzer**: `clam`
   - **Als Standard verwenden**: ✓ (für Standard-Key)

## 📖 Erste Schritte

### 1. Server hinzufügen

1. Gehe zu **Server**
2. Klick **Neuen Server hinzufügen**
3. Trage ein:
   - Servername
   - Hostname/IP
   - SSH-Port (Standard: 22)
   - Beschreibung (optional)

4. Klick **Test-Verbindung** zum Überprüfen

### 2. ClamAV installieren

1. Gehe zu **Server** → Wähle deinen Server
2. Klick **ClamAV installieren** (erfordert root oder sudo)
3. Warte auf die Installation

### 3. Scan-Job erstellen

1. Gehe zu **Scans**
2. Klick **Neuen Scan-Job erstellen**
3. Konfiguriere:
   - **Scan-Typ**: Quick oder Full
   - **Scan-Pfade**: Z.B. `/home`, `/var`, `/opt`
   - **Zeitplan**: Cron-Expression (z.B. `0 2 * * *` = täglich um 2 Uhr)

### 4. Email-Alerts konfigurieren

⚠️ **Wichtig**: SMTP-Einstellungen werden **nicht in .env** konfiguriert, sondern über die Web-UI in den Admin-Settings gespeichert!

1. Gehe zu **Settings** (nur Admin) → **Email Einstellungen**
2. Trage deine SMTP-Einstellungen ein:
   - **SMTP-Host**: z.B. smtp.gmail.com
   - **SMTP-Port**: normalerweise 587
   - **SMTP-Benutzer**: deine E-Mail-Adresse
   - **SMTP-Passwort**: App-spezifisches Passwort
   - **Von-Adresse**: z.B. noreply@clamorchestra.local
   - **Alert-E-Mail Empfänger**: E-Mail-Adresse für Benachrichtigungen
3. Teste mit dem **Test-Email Button**


## 📝 Lizenz

MIT License - siehe [LICENSE](LICENSE)

 

