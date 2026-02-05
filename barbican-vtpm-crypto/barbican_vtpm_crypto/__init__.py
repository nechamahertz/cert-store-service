"""
Barbican vTPM Crypto Plugin

A production-ready crypto plugin that uses vTPM 2.0 for hardware-backed
secret encryption with master key protection.
"""

from barbican_vtpm_crypto.plugin import VtpmCryptoPlugin

__version__ = '1.0.0'
__all__ = ['VtpmCryptoPlugin']
