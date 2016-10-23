#!/bin/bash
for i in `ls *.json`; do echo $i&& ./run.py ../build/server $i; done
