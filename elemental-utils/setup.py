from setuptools import setup, find_packages


def requirements(f):
    with open(f, "r") as fd:
        return fd.read()


setup(
    name="elemental_utils",
    version="0.9.19",
    description="Utilities for doing automation within the Elemental Project",
    url="https://gitlab.systems.cll.cloud/jclarke/elemental-utils",
    author="Joe Clarke",
    author_email="jclarke@cisco.com",
    license="MIT",
    setup_requires=["wheel"],
    install_requires=requirements("requirements.txt"),
    package_data={"elemental_utils": ["ansible/*"]},
    include_package_data=True,
    packages=find_packages(exclude=["tests", "tests.*"]),
    zip_safe=False,
    keywords=["Elemental"],
    python_requires=">=3.6",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
    ],
)
