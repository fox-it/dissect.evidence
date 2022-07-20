from setuptools import setup, find_packages

setup(
    name="dissect.evidence",
    packages=list(map(lambda v: "dissect." + v, find_packages("dissect"))),
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
    ],
    entry_points={
        "console_scripts": [
            "asdf-dd=dissect.evidence.tools.asdf.dd:main",
            "asdf-meta=dissect.evidence.tools.asdf.meta:main",
            "asdf-verify=dissect.evidence.tools.asdf.verify:main",
        ],
    },
)
