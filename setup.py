import setuptools
import picosnitch

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="picosnitch",
    version=picosnitch.VERSION,
    python_requires=">=3.8",
    description="Protect your privacy, see which processes make remote network connections",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://elesiuta.github.io/picosnitch",
    license="GPLv3",
    py_modules=["picosnitch"],
    entry_points={"console_scripts": ["picosnitch = picosnitch:start_picosnitch"]},
    install_requires=["psutil"],
    extras_require={
        "enable_notifications":  ["dbus-python"],
        "enable_virustotal":  ["requests"],
        "full":  ["dbus-python", "requests"]
    },
    classifiers=[
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Monitoring",
        "Topic :: Security"
    ],
)
