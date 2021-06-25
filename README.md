# DigiFrame v0.1

[![Poject: DigiFrame](https://img.shields.io/badge/Project-DigiFrame-red.svg?style=flat-square)](https://github.com/awalon/DigiFrame/)
[![License: GPL](https://img.shields.io/badge/License-GPL-green?style=flat-square)](LICENSE.md)
[![GitHub issues](https://img.shields.io/github/issues/awalon/DigiFrame?style=flat-square)](https://github.com/awalon/DigiFrame/issues)
![Python version: 3](https://img.shields.io/badge/Version-3-informational?style=flat-square&logo=python)
[![GitHub forks](https://img.shields.io/github/forks/awalon/DigiFrame?style=flat-square)](https://github.com/awalon/DigiFrame/network)
[![GitHub stars](https://img.shields.io/github/stars/awalon/DigiFrame?style=flat-square)](https://github.com/awalon/DigiFrame/stargazers)

Digital image frame with small footprint based on lite version of Raspberry OS. Uses as less resources as Raspberry Pi
can be used with regular USB port as power supply.

Pictures can be played from external storage connected via USB, internal (Micro-) SD card or remote storage with 
automated synchronisation.

- Change picture folder via webpage
- Synchronize remote storage on startup and configurable interval 
- Transfer pictures with WinSCP or mount network path

An integrated web user interface can be used for configuration, administration and picture preview.


## Use cases / features
- Digital Photoframe
- Billboard
- Corporate advertising


## Planned features
- Artwork (Project Icon, Logo and Splash Screen)
- Picture upload via web user interface (without synchronization)
- Rsync Support


## License

100% FREE under [GPL](LICENSE.md) license


## Additional features

* **[GPL](LICENSE.md) License**
* **Tested** on Python 3.9
* **Tested** on [Raspberry Pi 3b and 4](README-RPI.MD)


## Minimal Requirements

### Hardware
- Raspberry Pi or another Linux based board
- Flat screen (old TV or PC monitor)
- Cables

### Software
- fim
- Python3
    - Flask
    - Flask-Login
    - Flask-Security
    - Waitress
    - TZ
    - PIL 
    - PiGPIO
    - PsUtil


## Optional Requirements

For automated synchronisation of local pictures, directly from your server or cloud storage:

- rclone
- rsync


## Prepare Raspberry Pi OS

[Raspberry Pi - Setup](README-RPI.MD)


## Install DigiFrame

[DigiFrame - Setup](README-SETUP.md)


## Authors

**Lead developer and Maintainer**: [Awalon](https://github.com/awalon) 

and [**Contributors**](https://github.com/awalonb/DigiFrame/graphs/contributors)

## Contact

[![GitHub issues](https://img.shields.io/github/issues/awalon/DigiFrame?style=flat-square)](https://github.com/awalon/DigiFrame/issues)

