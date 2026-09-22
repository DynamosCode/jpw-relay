# JPWBridge v4 — Render Deploy

## Step 1 — GitHub pe push karo
```bash
git init
git add .
git commit -m "JPWBridge v4"
git remote add origin https://github.com/YOUR_USERNAME/jpwbridge
git push -u origin main
```

## Step 2 — Render pe 2 services banao

### Service 1 — Relay Server (Web Service)
```
Name:          jpw-relay
Runtime:       Python
Build Command: pip install -r requirements.txt
Start Command: gunicorn relay_server:app -b 0.0.0.0:$PORT --workers 1
```
Copy the URL jo milega — example:
`https://jpw-relay.onrender.com`

### Service 2 — Telegram Bot (Background Worker)
```
Name:          jpw-bot
Runtime:       Python
Build Command: pip install -r requirements.txt
Start Command: python jpw_bot_v4.py
```

## Step 3 — Environment Variables set karo

### jpw-relay pe:
```
(kuch nahi chahiye — bas deploy karo)
```

### jpw-bot pe:
```
BOT_TOKEN       = your_telegram_bot_token
ACCESS_PASSWORD = Enc@1234
DEFAULT_LAT     = 28.6139
DEFAULT_LON     = 77.2090
RELAY_URL       = https://jpw-relay.onrender.com  ← Step 2 ka URL
JPW_APP_VERSION = 2.1.1
```

## Step 4 — Hook APK Config update karo
`Config.kt` mein:
```kotlin
const val RELAY_URL = "https://jpw-relay.onrender.com"
```
APK rebuild karo aur phone pe install karo.

## Step 5 — Verify
```bash
curl https://jpw-relay.onrender.com/health
# {"ok": true, "service": "jpwbridge-relay-v4"}

curl https://jpw-relay.onrender.com/status
# Token state dikhega
```

## ⚠️ Render Free Tier Warning
Free web service 15 min inactivity pe **sleep** ho jaata hai.
Fix — UptimeRobot se `/health` endpoint ping karo har 10 min mein.
`https://uptimerobot.com` → free account → monitor add karo.
