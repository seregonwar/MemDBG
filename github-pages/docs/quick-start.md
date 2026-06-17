## Build the payload

Build for your target platform, or use the host build for local testing.

```bash
make host
make payload-ps5 PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
```

## Start MemDBG

On host builds you can pass port, bind address, and log destination from the command line.

```bash
./build/memdbg-host --bind=0.0.0.0 --debug-port=9020 --udp-port=9023
```

## Open the frontend

Build and launch the native interface, then connect to the console or host IP.

```bash
make frontend
./build/frontend/memdbg_frontend
```
