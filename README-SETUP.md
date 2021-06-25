# DigiFrame - Setup

## Prepare Raspberry Pi
If not already prepared [setup and connect to your Raspberry Pi](README-RPI.MD)

## Create user and assign user groups
Create `digiframe` used for system services:
```shell
sudo adduser digiframe --disabled-password
```
For *Full Name* you could use 'DigiFrame Service'. 

Add user to additional groups *gpio* (GPIOs), *tty* (Console), *video* (Interact with Video device) and 
'lock' users password login:

```shell
sudo usermod -a -G gpio,tty,video digiframe
sudo usermod -L digiframe
```

## Install dependencies

### *fim*

Framebuffer image viewer

```shell
sudo apt -y install fim
``` 

### *rclone* for synchronisation [optional]

Install [*rclone*](https://rclone.org/) to synchronize local picture folder with remote/cloud source 
like [Nextcloud](https://nextcloud.com/) or [Google Drive](https://drive.google.com/). 

```shell
sudo apt -y install rclone
```

### *rsync* for synchronisation [optional]

Install *rsync* to synchronize local picture folder with remote linux server.

```shell
sudo apt -y install rsync
```

### Python3 modules

```shell
sudo apt -y install python3-flask python3-flask-security python3-flask-login
sudo apt -y install python3-waitress
sudo apt -y install python3-tz python3-pil python3-pigpio python3-psutil
```

## Setup synchronization

### With *rclone*

```shell
sudo -u digiframe rclone config
```

Test newly created **rclone remote**:

```shell
sudo -u digiframe rclone lsd <rclone remote>:
```

Initial synchronization:

**rclone remote**: Name of remote target as defined with `rclone config`

**remote folder**: Remote folder  

```shell
sudo -u digiframe mkdir /home/digiframe/pictures
sudo -u digiframe rclone sync <rclone remote>:<remote folder>
```

## Remove some noise (quite boot)

1. Write current IP address to system log instead to console. Replace current `/etc/rc.local` via:
    ```shell
    cat /dev/null | sudo tee /etc/rc.local
    sudo vi /etc/rc.local
    ```
    
    with new content:
    
    ```shell
    #!/bin/sh -e
    #
    # rc.local
    #
    # This script is executed at the end of each multiuser runlevel.
    # Make sure that the script will "exit 0" on success or any other
    # value on error.
    #
    # In order to enable or disable this script just change the execution
    # bits.
    #
    # By default this script does nothing.
    
    # Print the IP address
    _IP=$(hostname -I) || true
    if [ "$_IP" ]; then
      #printf "\n####################################################\n### My (`hostname`) IP address is %s\n####################################################\n\n"  "$_IP"
      logger "## My (`hostname`) IP address is $_IP"
    fi
    
    exit 0
    ```

2. Add `consoleblank=0 loglevel=1 quiet` (after `rootwait`) to existing file `cmdline.txt`, ex.:
   
   ```txt
   console=serial0,115200 console=tty1 root=PARTUUID=9730496b-02 rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait consoleblank=0 loglevel=1 quiet
   ```

   Ex. update file via shell/bash from Linux command line:

   ```shell
   sudo sed -ie "s/rootwait/rootwait consoleblank=0 loglevel=1 quiet/" /boot/cmdline.txt
   ```
   
3. Disable console:
   
    ```shell
    sudo systemctl disable getty@tty1
    ```
   
## Install DigiFrame from GitHub

1. Get *DigiFrame* from GitHub:
    ```shell
    wget -O DigiFrame-master.zip https://github.com/awalon/DigiFrame/archive/master.zip
    unzip DigiFrame-master.zip
    sudo mv DigiFrame-master /opt/digiframe
    rm DigiFrame-master.zip
    ```

2. Set user and group
   1. `/etc` structure
      ```shell
      sudo mkdir /etc/digiframe
      sudo chown -R digiframe:digiframe /etc/digiframe
      sudo ln -t /etc/default/ /opt/digiframe/etc/default/digiframe
      ```
      
   2. Application folder `/opt/digiframe`
       ```shell
       sudo chown -R digiframe:digiframe /opt/digiframe/
       sudo chown root:root /opt/digiframe/df_system.py
       ```
   
   3. Demo pictures 
      ```shell
      sudo -u digiframe mkdir /home/digiframe/pictures
      sudo -u digiframe mkdir /home/digiframe/cache
      sudo -u digiframe ln -s -T /opt/digiframe/pictures /home/digiframe/pictures/demo
      ```
   
3. Link systemd service files:

    ```shell
    sudo ln -st /etc/systemd/system/ /opt/digiframe/systemd/*
    ```
   
4. Reload systemd daemon

    ```shell
    sudo systemctl daemon-reload
    ```
5. Enable systemd services

   ```shell
   sudo systemctl enable digiframe-splash-start
   sudo systemctl enable digiframe-splash-shutdown
   sudo systemctl enable digiframe-console
   sudo systemctl enable digiframe-web
   sudo systemctl enable digiframe-system
   ```
   
   **Hints**:
   
   1. Restart core services:
      
      ```shell
      sudo systemctl restart digiframe-system digiframe-console digiframe-web
      ```
      
   2. Show complete service log:
      
      ```shell
      sudo journalctl -u digiframe-console
      ```
      
## Webpage

Open [http://digiframe/](http://digiframe/) in your Browser and login with default user `admin` and initial password `passw0rd`.
