import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="picosnitch",
    version="0.1.0",
    description="See which processes make remote network connections",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/elesiuta/picosnitch",
    py_modules=["picosnitch"],
    entry_points={"console_scripts": ["picosnitch = picosnitch:main"]},
    install_requires=["plyer", "psutil", "python-daemon"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
