import base64
import os
import subprocess
import json
import tempfile
import struct
import time  # Added for retry logic

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from oslo_log import log as logging
from barbican.plugin.crypto import base

LOG = logging.getLogger(__name__)

class VtpmCryptoPlugin(base.CryptoPluginBase):
    """
    vTPM-backed Crypto Plugin for Barbican using ECC with ECDH and HKDF.
    Implements hybrid encryption: ECDH-derived KEK wraps DEK, DEK encrypts plaintext.
    Supports key rotation via recipient_key_id.
    Uses AES-256-GCM with AAD for KEK wrapping (recipient_key_id + ephemeral_pubkey + algorithm).
    Metadata stored in JSON blob.
    """

    is_long_running = True

    def __init__(self, conf=None):
        super(VtpmCryptoPlugin, self).__init__()
        self.conf = conf
        
        # Load configuration with defaults
        if conf and hasattr(conf, 'vtpm_plugin'):
            self.master_crypto_key_handle = conf.vtpm_plugin.master_key_handle
            self.tpm_timeout = conf.vtpm_plugin.timeout
            self.key_auth = os.environ.get('VTPM_KEY_AUTH', conf.vtpm_plugin.key_auth or '')
            self.primary_handle = conf.vtpm_plugin.primary_handle or '0x81000001'  # Default primary
            self.hierarchy_auth = conf.vtpm_plugin.hierarchy_auth or ''  # Hierarchy auth if needed
        else:
            self.master_crypto_key_handle = "0x81010002"
            self.tpm_timeout = 30
            self.key_auth = os.environ.get('VTPM_KEY_AUTH', '')
            self.primary_handle = '0x81000001'
            self.hierarchy_auth = ''

        # Ensure the static ECC key exists in the TPM
        self._ensure_static_key_exists()

        LOG.info(
            "vTPM2 Crypto Plugin initialized!!! (MasterCryptoKey handle=%s)",
            self.master_crypto_key_handle
        )

    def _ensure_static_key_exists(self):
        """Check if the static ECC key exists; create and persist if not."""
        try:
            self._run_tpm_command_with_retry(["tpm2_readpublic", "-c", self.master_crypto_key_handle])  # Added retry
            LOG.debug("Static ECC key at handle %s already exists.", self.master_crypto_key_handle)
        except RuntimeError:
            LOG.info("Static ECC key not found at handle %s; creating new one.", self.master_crypto_key_handle)
            self._create_static_ecc_key()

    def _create_static_ecc_key(self):
        """Create a static ECC key for ECDH in the TPM and make it persistent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            primary_ctx = os.path.join(tmpdir, "primary.ctx")
            key_pub = os.path.join(tmpdir, "key.pub")
            key_priv = os.path.join(tmpdir, "key.priv")
            key_ctx = os.path.join(tmpdir, "key.ctx")

            # Create primary key if needed (assuming owner hierarchy)
            primary_cmd = ["tpm2_createprimary", "-C", "o", "-c", primary_ctx, "-G", "ecc256"]
            if self.hierarchy_auth:
                primary_cmd.extend(["-P", self.hierarchy_auth])
            self._run_tpm_command_with_retry(primary_cmd)  # Added retry

            # Create ECC child key for ECDH (decrypt, unrestricted)
            # Attributes: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt
            attributes = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt"
            create_cmd = [
                "tpm2_create", "-C", primary_ctx, "-G", "ecc256:ecdh-sha256", "-a", attributes,
                "-u", key_pub, "-r", key_priv
            ]
            if self.key_auth:
                create_cmd.extend(["-p", self.key_auth])
            self._run_tpm_command_with_retry(create_cmd)  # Added retry

            # Load the key
            load_cmd = ["tpm2_load", "-C", primary_ctx, "-u", key_pub, "-r", key_priv, "-c", key_ctx]
            self._run_tpm_command_with_retry(load_cmd)  # Added retry

            # Evict to persistent handle
            evict_cmd = [
                "tpm2_evictcontrol", "-C", "o", "-c", key_ctx, self.master_crypto_key_handle
            ]
            if self.hierarchy_auth:
                evict_cmd.extend(["-P", self.hierarchy_auth])
            self._run_tpm_command_with_retry(evict_cmd)  # Added retry

        LOG.info("Created and persisted new static ECC key at handle %s.", self.master_crypto_key_handle)

    def get_plugin_name(self):
        return "vTPM2 ECC Crypto Plugin"

    def supports(self, type_enum, algorithm=None, bit_length=None, mode=None):
        if type_enum == base.PluginSupportTypes.ENCRYPT_DECRYPT:
            if algorithm and algorithm.lower() != 'aes':
                return False
            if mode and mode.lower() != 'gcm':
                return False
            if bit_length and bit_length not in (128, 256):
                return False
            return True
        # Add support for symmetric generation
        if type_enum == base.PluginSupportTypes.SYMMETRIC_KEY_GENERATION:
            return True
        # Asymmetric not yet supported
        return False

    def _run_tpm_command_with_retry(self, cmd, input_data=None, retries=3, backoff=1):
        """Run TPM command with retry logic."""
        for attempt in range(retries):
            try:
                return self._run_tpm_command(cmd, input_data)
            except RuntimeError as e:
                if attempt == retries - 1:
                    raise
                LOG.warning(f"TPM command failed (attempt {attempt+1}/{retries}): {str(e)}. Retrying after {backoff} seconds.")
                time.sleep(backoff)
                backoff *= 2  # Exponential backoff

    def _run_tpm_command(self, cmd, input_data=None):
        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            try:
                stdout, stderr = process.communicate(input=input_data, timeout=self.tpm_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                raise RuntimeError("TPM command timed out")

            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                raise RuntimeError(f"TPM Error (code {process.returncode}): {error_msg}")

            return stdout

        except Exception as e:
            LOG.error("TPM execution failed: %s", str(e))
            raise

    def _perform_ecdh_zgen(self, ephemeral_pub_point):
        """Perform TPM2_ECDH_ZGen to get shared secret point."""
        with tempfile.TemporaryDirectory() as tmpdir:
            in_point_file = os.path.join(tmpdir, "in_point")
            out_point_file = os.path.join(tmpdir, "out_point")

            # Extract x and y from uncompressed point (0x04 + x + y)
            if len(ephemeral_pub_point) != 65 or ephemeral_pub_point[0] != 0x04:
                raise ValueError("Invalid ephemeral public point")
            x = ephemeral_pub_point[1:33]
            y = ephemeral_pub_point[33:65]

            # Pack into TPM2B_ECC_POINT
            # TPM2B_ECC_POINT: UINT16 size (68) + TPM2B_ECC_PARAMETER x (UINT16 32 + 32 bytes) + TPM2B_ECC_PARAMETER y (UINT16 32 + 32 bytes)
            tpm_point = (
                struct.pack('>H', 68) +
                struct.pack('>H', 32) + x +
                struct.pack('>H', 32) + y
            )

            with open(in_point_file, "wb") as f:
                f.write(tpm_point)

            cmd = ["tpm2_ecdhzgen", "-c", self.master_crypto_key_handle, "-u", in_point_file, "-o", out_point_file]
            if self.key_auth:
                cmd.extend(["-p", self.key_auth])
            self._run_tpm_command_with_retry(cmd)  # Added retry

            with open(out_point_file, "rb") as f:
                z_data = f.read()

            if len(z_data) != 70:
                raise ValueError("Invalid Z point data length from TPM")

            total_size = struct.unpack('>H', z_data[0:2])[0]
            if total_size != 68:
                raise ValueError("Invalid Z point total size")

            x_size = struct.unpack('>H', z_data[2:4])[0]
            if x_size != 32:
                raise ValueError("Invalid Z x size")

            z_x = z_data[4:36]

            y_size = struct.unpack('>H', z_data[36:38])[0]
            if y_size != 32:
                raise ValueError("Invalid Z y size")

            # Shared secret is the x-coordinate
            shared_secret = z_x

            # Additional validation: check if z_x and y are valid (simple check for zero)
            if all(b == 0 for b in z_x) or all(b == 0 for b in z_data[38:70]):
                raise ValueError("Invalid Z point structure from TPM")

        return shared_secret

    def _derive_kek(self, shared_secret, salt, info):
        """Derive KEK using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit KEK
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def _generate_ephemeral_keypair(self):
        """Generate ephemeral ECC keypair on secp256r1."""
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_pub = ephemeral_priv.public_key()
        # Get uncompressed point: b'\x04' + x + y
        ephemeral_pub_point = ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # Explicitly clear ephemeral private key memory (defense in depth)
        ephemeral_priv = None  # Python GC will handle, but this forces it
        return None, ephemeral_pub_point  # Return None for priv to emphasize discard

    def _encrypt_with_kek(self, dek, kek, iv, aad):
        """Encrypt with AES-256-GCM using KEK, with AAD."""
        cipher = Cipher(
            algorithms.AES(kek),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(dek) + encryptor.finalize()
        return ciphertext, encryptor.tag

    def _decrypt_with_kek(self, ciphertext, tag, iv, kek, aad):
        """Decrypt with AES-256-GCM using KEK, with AAD."""
        cipher = Cipher(
            algorithms.AES(kek),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()

    def encrypt(self, encrypt_dto, kek_meta_dto, project_id):
        LOG.debug("vTPM2: Encrypting secret for project %s", project_id)
        plaintext = encrypt_dto.unencrypted
        
        algorithm = 'aes'
        bit_length = 256
        mode = 'gcm'

        try:
            # Generate DEK
            dek = os.urandom(bit_length // 8)

            # Generate ephemeral keypair (discard priv explicitly)
            _, ephemeral_pub_point = self._generate_ephemeral_keypair()

            # Perform ECDH to get shared secret
            shared_secret = self._perform_ecdh_zgen(ephemeral_pub_point)

            # Generate salt and info
            salt = os.urandom(16)
            recipient_key_id = self.master_crypto_key_handle.encode('utf-8')
            info = b"barbican-kek" + recipient_key_id + ephemeral_pub_point

            # Derive KEK
            kek = self._derive_kek(shared_secret, salt, info)

            # Encrypt DEK with KEK (AES-GCM with AAD: recipient_key_id + ephemeral_pubkey + algorithm)
            kek_aad = recipient_key_id + ephemeral_pub_point + algorithm.encode('utf-8')  # Updated to match spec
            iv = os.urandom(12)
            wrapped_dek, tag = self._encrypt_with_kek(dek, kek, iv, kek_aad)

            # Discard KEK explicitly
            kek = None

            # Encrypt plaintext with DEK (AES-GCM with AAD: project_id + purpose)
            dek_aad = project_id.encode('utf-8') + b'|data_encrypt'  # Added AAD for plaintext
            dek_iv = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(dek),
                modes.GCM(dek_iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(dek_aad)  # Added
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            package = {
                'algorithm': algorithm,
                'mode': mode,
                'bit_length': bit_length,
                'ephemeral_pub': base64.b64encode(ephemeral_pub_point).decode(),
                'salt': base64.b64encode(salt).decode(),
                'wrapped_dek': base64.b64encode(wrapped_dek).decode(),
                'wrapped_dek_iv': base64.b64encode(iv).decode(),
                'wrapped_dek_tag': base64.b64encode(tag).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'iv': base64.b64encode(dek_iv).decode(),
                'tag': base64.b64encode(encryptor.tag).decode(),
                'recipient_key_id': self.master_crypto_key_handle
            }

            return base.ResponseDTO(
                json.dumps(package).encode('utf-8'),
                None
            )

        except Exception as e:
            LOG.error("vTPM2 encryption failed for project %s: %s", project_id, str(e))
            raise base.CryptoKEKBindingException("Encryption service unavailable")

    def decrypt(self, decrypt_dto, kek_meta_dto, kek_meta_extended, project_id):
        LOG.debug("vTPM2: Decrypting secret for project %s", project_id)

        try:
            package = json.loads(decrypt_dto.encrypted.decode('utf-8'))

            ephemeral_pub_point = base64.b64decode(package['ephemeral_pub'])
            salt = base64.b64decode(package['salt'])
            wrapped_dek = base64.b64decode(package['wrapped_dek'])
            iv = base64.b64decode(package['wrapped_dek_iv'])
            tag = base64.b64decode(package['wrapped_dek_tag'])
            ciphertext = base64.b64decode(package['ciphertext'])
            dek_iv = base64.b64decode(package['iv'])
            dek_tag = base64.b64decode(package['tag'])
            recipient_key_id = package['recipient_key_id']
            algorithm = package['algorithm']

            # Verify recipient_key_id matches current (for rotation handling)
            if recipient_key_id != self.master_crypto_key_handle:
                raise ValueError("Key rotation detected; handle mismatch")

            # Perform ECDH to get shared secret
            shared_secret = self._perform_ecdh_zgen(ephemeral_pub_point)

            # Info same as encryption
            info = b"barbican-kek" + recipient_key_id.encode('utf-8') + ephemeral_pub_point

            # Derive KEK
            kek = self._derive_kek(shared_secret, salt, info)

            # Decrypt wrapped_dek to get DEK (with AAD: recipient_key_id + ephemeral_pubkey + algorithm)
            kek_aad = recipient_key_id.encode('utf-8') + ephemeral_pub_point + algorithm.encode('utf-8')  # Updated to match spec
            dek = self._decrypt_with_kek(wrapped_dek, tag, iv, kek, kek_aad)

            # Discard KEK explicitly
            kek = None

            # Decrypt ciphertext with DEK (with AAD)
            dek_aad = project_id.encode('utf-8') + b'|data_encrypt'  # Added
            cipher = Cipher(
                algorithms.AES(dek),
                modes.GCM(dek_iv, dek_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(dek_aad)  # Added
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return plaintext

        except Exception as e:
            LOG.error("vTPM2 decryption failed for project %s: %s", project_id, str(e))
            raise base.CryptoKEKBindingException("Decryption service unavailable")

    def bind_kek_metadata(self, kek_meta_dto):
        return kek_meta_dto

    def generate_symmetric(self, generate_dto, kek_meta_dto, project_id):
        """Generate symmetric key using TPM randomness if possible, fallback to os.urandom."""
        bit_length = generate_dto.bit_length
        if bit_length not in (128, 192, 256):
            raise ValueError("Unsupported bit length for symmetric key")
        
        try:
            # Use TPM for randomness: tpm2_getrandom
            cmd = ["tpm2_getrandom", "--hex", str(bit_length // 8)]
            key = self._run_tpm_command_with_retry(cmd).strip()  # Added retry
            key_bytes = bytes.fromhex(key)
        except Exception as e:
            LOG.warning("TPM random generation failed; falling back to os.urandom: %s", str(e))
            key_bytes = os.urandom(bit_length // 8)
        
        # Now encrypt the generated key as if it were a secret
        encrypt_dto = base.EncryptDTO(key_bytes)
        response = self.encrypt(encrypt_dto, kek_meta_dto, project_id)
        return response.cypher_text, kek_meta_dto  # Return encrypted key and metadata

    def generate_asymmetric(self, generate_dto, kek_meta_dto, project_id):
        raise NotImplementedError("Asymmetric key generation not implemented")