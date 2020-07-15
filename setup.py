import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="microsnitch",
    version="0.0.4",
    description="See which processes make remote network connections",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/elesiuta/microsnitch",
    py_modules=["microsnitch"],
    entry_points={"console_scripts": ["microsnitch = microsnitch:main"]},
    install_requires=["psutil", "python-daemon"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
