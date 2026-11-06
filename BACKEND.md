# Flutter and Python backend

## Start the backend

From PowerShell in the project directory, run the WebSocket backend used by Flutter:

```powershell
& .\.venv312\Scripts\python.exe backend_server.py
```

This starts the local WebSocket server on `127.0.0.1:8765` and starts USB serial discovery in a background thread. The serial port is discovered from the currently available devices; no COM number is fixed in the application. If more than one ESP32/USB-UART candidate is visible, the service refuses to guess and keeps retrying until the port list is unambiguous. Close any Arduino Serial Monitor or other program that has the receiver port open before starting the backend.

The first start initializes SQLite and applies additive alert metadata migrations. ESP32 events are validated and written to SQLite before being queued for WebSocket delivery. The Flutter Alerts screen refreshes its persisted history on live alert changes and after a WebSocket reconnection.

## Start Flutter

In another PowerShell window:

```powershell
flutter run -d windows
```

Create the first administrator from First Time Setup. Only two administrator accounts are permitted. Additional accounts are standard users unless an existing administrator explicitly creates the second administrator. Administrator account management requires administrator credentials.

## Hardware verification

Python serial messages must use the documented version 1 JSON event shape and identify `HALL-RECEIVER`. The repository currently contains no bedside or receiver firmware source, so LoRa packets, acknowledgements, USB forwarding, and LED behavior must be verified against the sketches actually flashed to the ESP32 boards. A passing software simulation does not establish physical hardware delivery.