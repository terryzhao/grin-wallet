[![Build Status](https://img.shields.io/travis/gottstech/grin-wallet/master.svg)](https://travis-ci.org/gottstech/grin-wallet)

# Grin Wallet

This repo is NOT the "official" Grin Wallet implementation, but for the wallet application development service & libs, such as for mobile wallet Apps and so on.

# Main Difference

The main differences from the official Grin Wallet:
- Embedded [GrinRelay address service](https://github.com/gottstech/grinrelay/wiki), for easier grin transaction for common users.
- Embedded default node API service, to avoid to install a Grin node server which is not necessary for common wallet users.
- Provide mobile/desktop wallet APIs for App developer.
  - IOS Lib: https://github.com/gottstech/cocoa_grinwallet
  - Swift / ObjectiveC / React-Native [APIs for IOS](https://github.com/gottstech/cocoa_grinwallet/wiki)
  - Android (to be added)
  - Desktop NodeJS Lib: https://github.com/gottstech/grinwallet-nodejs
- The defaul wallet data folder is `~/.grin.w/`, instead of `~/.grin`.
- All kinds of improvements, experience it from here: https://github.com/gottstech/grin-wallet/releases

# User Guide

A typical Grin send command is as simple as
```sh
$ grin-wallet send -d gn1-qfy4n9rh-j8lfa7342rzcpt7-lj2sqgd4lryum25-ss2gnfa3t43z3a6-n8va0s 1.0
```

A typical Grin listen command for receiving Grin by GrinRelay address:
```sh
$ grin-wallet listen

INFO - Grin Relay listener started on addr: gn1-qfy4n9rh-j8lfa7342rzcpt7-lj2sqgd4lryum25-ss2gnfa3t43z3a6-n8va0s
```

The detailed user guide document is here: https://github.com/gottstech/grin-wallet/wiki

# API Guide

https://github.com/gottstech/grin-wallet/wiki

# License

Apache License v2.0

