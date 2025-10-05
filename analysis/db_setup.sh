#!/bin/bash

apt update
apt install unzip postgresql postgresql-contrib python3.13-venv python3-pip libpq-dev
service postgresql start
passwd -d postgres
