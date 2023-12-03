from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='har2csp',
    version='1.0.0',
    description='A library to generate CSP headers from HAR files',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='John Grimes',
    author_email='john@grimes.id.au',
    url='https://github.com/johngrimes/har2csp',
    packages=find_packages(),
    install_requires=[],
    entry_points={
        'console_scripts': [
            'har2csp=har2csp.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11'
    ],
)