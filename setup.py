import setuptools
import picosnitch

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="picosnitch",
    version=picosnitch.VERSION,
    description="See which processes make remote network connections",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/elesiuta/picosnitch",
    py_modules=["picosnitch"],
    entry_points={"console_scripts": ["picosnitch = picosnitch:start_daemon"]},
    install_requires=["psutil"],
    extras_require={
        "enable_notifications":  ["plyer"],
        "enable_virustotal":  ["vt-py"],
        "full":  ["plyer", "vt-py"]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Monitoring",
        "Topic :: Security"
    ],
)
