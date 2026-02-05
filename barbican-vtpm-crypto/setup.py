from setuptools import setup, find_packages

setup(
    name="barbican-vtpm-crypto",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "barbican>=14.0.0",
        "tpm2-pytss>=2.0.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        'barbican.crypto.plugin': [
            'vtpm = barbican_vtpm_crypto.plugin:VtpmCryptoPlugin',
        ],
    },
)