#!/bin/bash

export DISPLAY=:0

xrandr --output DSI-2 --rotate normal

sleep 2

xinput set-prop "pointer:Goodix Capacitive TouchScreen" \
"Coordinate Transformation Matrix" \
1 0 0 \
0 1 0 \
0 0 1

xset s off
xset -dpms
xset s noblank

unclutter -idle 0.5 -root &

openbox &

# Wait for NetSc0ut Flask to be ready
until curl -s http://127.0.0.1:5055 >/dev/null; do
  sleep 1
done

sleep 2

# Clear old Chromium crash/session popups
rm -rf /home/pi/.config/chromium/Singleton*
rm -rf /home/pi/.config/chromium/Default/Session*
rm -rf /home/pi/.config/chromium/Default/Sessions

exec chromium \
  --kiosk \
  --app=http://127.0.0.1:5055/loading.html \
  --noerrdialogs \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --disable-features=TranslateUI \
  --disable-pinch \
  --disable-restore-session-state \
  --disable-component-update \
  --check-for-update-interval=31536000 \
  --overscroll-history-navigation=0 \
  --no-first-run \
  --disable-features=TranslateUI,MediaRouter \
  --user-data-dir=/home/pi/.config/netscout-kiosk
