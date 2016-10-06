rm -Rf testpip
virtualenv testpip
cd testpip
python3.5 setup.py sdist
pip install dist/mptc
