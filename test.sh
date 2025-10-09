#!/bin/bash

ip neigh | grep '^10.' | awk '{ print $1, $3}' | sort | uniq