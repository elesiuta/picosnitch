import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="picosnitch",
    version="0.3.8",
    description="See which processes make remote network connections",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/elesiuta/picosnitch",
    py_modules=["picosnitch"],
    entry_points={"console_scripts": ["picosnitch = picosnitch:main"]},
    install_requires=["filelock", "plyer", "psutil", "python-daemon", "vt-py"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Monitoring",
        "Topic :: Security"
    ],
)
