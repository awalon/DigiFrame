# Raspberry Pi - Setup

## Install Raspberry Pi OS to (Micro-) SD card

### Option 1: With [Raspberry Pi Imager](http://rptl.io/imager) (Linux & Windows)
1. Select `Raspberry Pi OS Lite`
2. Select your (Micro-) SD card
3. Write

### Option 2: Manually (Linux)

1. Download `Raspberry Pi OS Lite` from [raspberrypi.org](https://www.raspberrypi.org/software/operating-systems/) ([images](https://downloads.raspberrypi.org/raspios_lite_armhf/images/))
   ```shell
   wget -O ~/Downloads/raspios-buster-armhf-lite.zip  "https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-05-28/2021-05-07-raspios-buster-armhf-lite.zip"
   ```
   
2. Unzip OS image:
   ```shell
   unzip -p  ~/Downloads/raspios-buster-armhf-lite.zip > ~/Downloads/raspios-buster-armhf-lite.img
   ```
   
3. Determine target device
   ```shell
   lsblk
   ```
   or as root before USB device (card reader or card) was plugged in:
   ```shell
   sudo dmesg --follow
   ```
   then plug in your USB device or card and check most recent messages (my card reader connected as `sda`):
   ```
   [261428.423017] sd 0:0:0:0: [sda] 30572544 512-byte logical blocks: (15.7 GB/14.6 GiB)
   ```
   check size of device to be sure that you use correct target device.
   
   **Attention**: If you select wrong target device, you will lose important data or destroy you local OS.
   
4. Write image to new/empty (Micro-) SD card as root:
   
   `if=` Source file [Raspberry OS image]
   
   `of=` Target device [(Micro-) SD card]: /dev/*"your target device"*
   
   **Attention**: Wrong target device will result in data loss
   
   ```shell
   sudo dd if=(readlink -f ~/Downloads/raspios-buster-armhf-lite.img) of=/dev/sda bs=4MB
   ```

## Configuration (including headless usage)
Prepare Raspberry Pi OS to be used without Keyboard and weak power source like regular USB port.

Re-plug your (Micro-) SD card and open `boot` partition (first partition with about 300 MB).
```shell
sudo mount /dev/sda1 /mnt
```

### Wi-Fi
Provide Wi-Fi credentials with file `wpa_supplicant.conf` to connect automatically on first boot:

`<Country ISO code>` [ISO/IEC alpha2 country code](https://www.nationsonline.org/oneworld/country_code_list.htm) in which the device is operating

`<SSID of your Wi-Fi>` SSID of your Wi-Fi

`<Passwort of your Wi-Fi>` Password of your Wi-Fi 

```txt
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=<Country ISO code, like 'DE'>

network={
        ssid="<SSID of your Wi-Fi>"
        psk="<Passwort of your Wi-Fi>"
}
```

Ex. create file via shell/bash from Linux command line:

```shell
cat <<EOF>/mnt/wpa_supplicant.conf
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=DE

network={
        ssid="MyWiFiNetwork"
        psk="MyVerySecureWiFiPassword"
}
EOF
```

### SSH

Create file "ssh.txt" with content "ssh" to automatically enable ssh server.

Ex. create file via shell/bash from Linux command line:

```shell
echo "ssh">/mnt/ssh.txt
```

### Silent boot (emit no messages)
1. Disable Raspberry OS splash screen by adding this snippet to existing file `config.txt` (`vi /mnt/config.txt`):
   ```txt
   # no color splash/test screen on boot
   disable_splash=1
   ```


### Adjust Framebuffer color mode
Modify existing file `config.txt` (`vi /mnt/config.txt`):
```txt
framebuffer_depth=32
framebuffer_ignore_alpha=1
gpu_mem_256=96
gpu_mem_512=128
gpu_mem_1024=196
```


### HDMI configuration
#### Overscan
Modify existing file `config.txt`  (`vi /mnt/config.txt`):
```txt
# uncomment this if your display has a black border of unused pixels visible
# and your display can output without overscan
disable_overscan=1
```

#### DMT (computer monitor) modes
Modify existing file `config.txt`  (`vi /mnt/config.txt`):
```txt
# uncomment to force a HDMI mode rather than DVI. This can make audio work in
# DMT (computer monitor) modes
hdmi_drive=2
```

### Power / Energy options

Disable some less important features by adding following section to existing file `config.txt` (`vi /mnt/config.txt`) 
(*German pages*: [Power Saving notes](https://buyzero.de/blogs/news/raspberry-pi-strom-sparen-tipps-tricks), 
[Power Saving](https://elektro.turanis.de/html/prj298/index.html)):

```
# Disable the ACT LED.
dtparam=act_led_trigger=none
dtparam=act_led_activelow=off

# Disable the PWR LED.
dtparam=pwr_led_trigger=none
dtparam=pwr_led_activelow=off

# Disable Bluetooth
dtoverlay=pi3-disable-bt
```

## Use prepared (Micro-) SD card
1. Unmount `boot` partition:  `sudo umnount /mnt`
2. Unplug your (Micro-) SD card
3. Plug (Micro-) SD card into your Raspberry Pi
4. Connect monitor to your Raspberry Pi
5. Connect Power Adapter or Connect Raspberry Pis power port to USB port of your monitor if available
6. After you can see `raspberrypi login:` prompt on monitor connected to Raspberry Pi, 
   connect via ssh to IP shown few lines above with line `My IP address is 192.168.[...]`:
   ```shell
   ssh pi@192.168.x.x
   ```
   If you get an error message like `Too many authentication failures` you can try:
   ```shell
   ssh -o PubkeyAuthentication=no pi@192.168.x.x
   ```
   **Hint**: Default password `raspberry`
7. Setup locales and Timezone: 
   1. Run Raspberry Configuration tool: `sudo raspi-config
   2. Goto `Localisation Options` -> `Locale`
   3. Select your locale like `de_DE.UTF-8` and press `Ok`
   4. Select default locale 'en_GB.UTF-8', or your previously selected locale
   5. Goto `Localisation Options` -> `Timezone`
   6. Select your Timezone like `Europe`\\`Berlin`
8. Install and setup some basic applications
   1. Install automated security updates and `vim`
      ```shell
      sudo apt update
      sudo apt -y full-upgrade 
      sudo apt -y install vim unattended-upgrades
      ```
   2. Setup automated updates
   
   
10. Proceed with [DigiFrame setup](README-SETUP.md)