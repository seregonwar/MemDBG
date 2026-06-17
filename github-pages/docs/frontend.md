## Connection

Enter the console or host IP address, confirm the TCP port, and press **Connect**. After the HELLO response the sidebar shows connection state, IP, port, and UDP status.

## Saved IP

In **Settings** you can save the IP address you use most often. Useful when the console has a static address or a DHCP reservation.

## Console log

The **Logs** screen shows UDP messages from the payload. If messages don't arrive, verify that the frontend is listening on the same UDP port configured in the payload.

## Telemetry

The **Telemetry** screen summarizes uptime, active connections, total reads/writes, and scanner cache performance. Use it to understand whether a trainer is writing too often.

## Crash logger

The frontend writes a `memdbg_crash.log` file next to the executable. It captures connection events, errors, and console-side log lines for offline diagnosis.

## Multi-language

The frontend supports 8 languages (English, Italian, German, French, Spanish, Portuguese, Russian, Japanese). Change the language in Settings or via the saved configuration.
