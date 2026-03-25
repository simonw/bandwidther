# Bandwidther

SwiftUI menu bar app for monitoring application bandwidth use.

![Screenshot](https://github.com/simonw/bandwidther/raw/main/screenshot.png)

## Features

- Live per-process download/upload rates via `nettop`
- Internet vs LAN connection classification
- Reverse DNS resolution for remote destinations
- Sparkline bandwidth graph (last 60 seconds)
- Two-column popover panel from the menu bar

## Building

```bash
git clone https://github.com/simonw/bandwidther
cd bandwidther
swiftc -parse-as-library -framework SwiftUI -framework AppKit -o Bandwidther BandwidtherApp.swift
./Bandwidther
```

Requires macOS and Xcode command line tools (`xcode-select --install`).
