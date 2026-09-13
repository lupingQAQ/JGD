from setuptools import setup

setup(
    name="jgd",
    version="0.1.0",
    description="JavaGadgetDigger — autonomous Java deserialization "
                "gadget-chain mining",
    packages=["jgd", "jgd.mining", "jgd.verification", "jgd.poc", "jgd.infra"],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "jgd=jgd.cli:main",
            "jgd-tui=jgd.tui:main",
        ],
    },
)
