from setuptools import setup

setup(
    name='crlf',
    version='1.0',
    py_modules=['crlf', 'scanner'],
    install_requires=[
        'click',
        'colorama',
        'eventlet',
        'requests',
        'validators'
    ],
    entry_points='''
        [console_scripts]
        crlf=crlf:main
    ''',
)
