#!/bin/bash

# Install Dependencies
apt update
apt install -y ansible nano man-db python3.13-venv zip net-tools rsync unminimize
yes | unminimize
pip3 uninstall Jinja2
