from setuptools import setup, find_packages

setup(
    name="xrayauth",
    version="1.0.0",
    description="XRayAuth - Session Hijack Detection Tool",
    author="Akki",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "scapy",
    ],
    entry_points={
        'console_scripts': [
            'xrayauth = xrayauth.cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
