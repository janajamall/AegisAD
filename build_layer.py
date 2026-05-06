"""
Downloads a pre-built reportlab Lambda layer
compatible with Python 3.12 on Linux (Lambda environment)
"""
import urllib.request
import os

# We'll use pip with the manylinux platform tag
# This downloads Linux-compatible wheels
os.system('pip install reportlab --platform manylinux2014_x86_64 --target lambdas/report --python-version 3.12 --only-binary=:all: --upgrade')

print("Done! Check lambdas/report for Linux-compatible reportlab")