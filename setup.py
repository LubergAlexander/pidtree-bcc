import setuptools
from pidtree_bcc import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pidtree-bcc",
    version=__version__,
    author="Matt Carroll",
    author_email="mattc@yelp.com",
    description="eBPF-based intrusion detection and audit logging",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Yelp/pidtree-bcc",
    packages=setuptools.find_packages(),
    license='BSD 3-clause "New" or "Revised License"',
    scripts=['bin/pidtree-bcc'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: Linux",
    ],
)
