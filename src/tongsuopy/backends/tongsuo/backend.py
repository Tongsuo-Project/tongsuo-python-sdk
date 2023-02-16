# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import collections
import typing
from contextlib import contextmanager

from tongsuopy.backends.tongsuo import aead, binding
from tongsuopy.backends.tongsuo.ciphers import _CipherContext
from tongsuopy.backends.tongsuo.ec import (
    _EllipticCurvePrivateKey,
    _EllipticCurvePublicKey,
)
from tongsuopy.backends.tongsuo.hashes import _HashContext
from tongsuopy.crypto import hashes, serialization, utils
from tongsuopy.crypto.asymciphers import ec
from tongsuopy.crypto.asymciphers.types import (
    PRIVATE_KEY_TYPES,
    PUBLIC_KEY_TYPES,
)
from tongsuopy.crypto.cipheralgorithm import CipherAlgorithm
from tongsuopy.crypto.ciphers.algorithms import SM4
from tongsuopy.crypto.ciphers.modes import (
    CBC,
    CFB,
    CTR,
    ECB,
    GCM,
    Mode,
    OFB,
)
from tongsuopy.crypto.exceptions import UnsupportedAlgorithm, _Reasons


_MemoryBIO = collections.namedtuple("_MemoryBIO", ["bio", "char_ptr"])


class Backend:
    """
    Tongsuo API binding interfaces.
    """

    name = "tongsuo"

    def __init__(self):
        self._binding = binding.Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib
        self._fips_enabled = False

        self._cipher_registry = {}
        self._register_default_ciphers()

    def __repr__(self) -> str:
        return "<TongsuoBackend(version: {}, Legacy: {})>".format(
            self.openssl_version_text(),
            self._binding._legacy_provider_loaded,
        )

    def openssl_assert(
        self,
        ok: bool,
        errors: typing.Optional[typing.List[binding._OpenSSLError]] = None,
    ) -> None:
        return binding._openssl_assert(self._lib, ok, errors=errors)

    def openssl_version_text(self) -> str:
        """
        Friendly string name of the loaded OpenSSL library. This is not
        necessarily the same version as it was compiled against.

        Example: OpenSSL 1.1.1d  10 Sep 2019
        """
        return self._ffi.string(
            self._lib.OpenSSL_version(self._lib.OPENSSL_VERSION)
        ).decode("ascii")

    def openssl_version_number(self) -> int:
        return self._lib.OpenSSL_version_num()

    def create_symmetric_encryption_ctx(
        self, cipher: CipherAlgorithm, mode: Mode
    ) -> _CipherContext:
        return _CipherContext(self, cipher, mode, _CipherContext._ENCRYPT)

    def create_symmetric_decryption_ctx(
        self, cipher: CipherAlgorithm, mode: Mode
    ) -> _CipherContext:
        return _CipherContext(self, cipher, mode, _CipherContext._DECRYPT)

    def cipher_supported(self, cipher: CipherAlgorithm, mode: Mode) -> bool:
        try:
            adapter = self._cipher_registry[type(cipher), type(mode)]
        except KeyError:
            return False
        evp_cipher = adapter(self, cipher, mode)
        return self._ffi.NULL != evp_cipher

    def register_cipher_adapter(self, cipher_cls, mode_cls, adapter):
        if (cipher_cls, mode_cls) in self._cipher_registry:
            raise ValueError(
                "Duplicate registration for: {} {}.".format(
                    cipher_cls, mode_cls
                )
            )
        self._cipher_registry[cipher_cls, mode_cls] = adapter

    def _register_default_ciphers(self) -> None:
        for mode_cls in [ECB, CBC, OFB, CFB, CTR, GCM]:
            self.register_cipher_adapter(
                SM4, mode_cls, GetCipherByName("sm4-{mode.name}")
            )

    def _consume_errors(self) -> typing.List[binding._OpenSSLError]:
        return binding._consume_errors(self._lib)

    def _consume_errors_with_text(
        self,
    ) -> typing.List[binding._OpenSSLErrorWithText]:
        return binding._consume_errors_with_text(self._lib)

    def aead_cipher_supported(self, cipher) -> bool:
        cipher_name = aead._aead_cipher_name(cipher)

        return self._lib.EVP_get_cipherbyname(cipher_name) != self._ffi.NULL

    def _evp_md_from_algorithm(self, algorithm: hashes.HashAlgorithm):
        alg = algorithm.name.encode("ascii")
        evp_md = self._lib.EVP_get_digestbyname(alg)
        return evp_md

    def _evp_md_non_null_from_algorithm(self, algorithm: hashes.HashAlgorithm):
        evp_md = self._evp_md_from_algorithm(algorithm)
        self.openssl_assert(evp_md != self._ffi.NULL)
        return evp_md

    def hash_supported(self, algorithm: hashes.HashAlgorithm) -> bool:
        evp_md = self._evp_md_from_algorithm(algorithm)
        return evp_md != self._ffi.NULL

    def create_hash_ctx(
        self, algorithm: hashes.HashAlgorithm
    ) -> hashes.HashContext:
        return _HashContext(self, algorithm)

    def _bytes_to_bio(self, data: bytes):
        """
        Return a _MemoryBIO namedtuple of (BIO, char*).

        The char* is the storage for the BIO and it must stay alive until the
        BIO is finished with.
        """
        data_ptr = self._ffi.from_buffer(data)
        bio = self._lib.BIO_new_mem_buf(data_ptr, len(data))
        self.openssl_assert(bio != self._ffi.NULL)

        return _MemoryBIO(self._ffi.gc(bio, self._lib.BIO_free), data_ptr)

    def load_pem_private_key(
        self,
        data: bytes,
        password: typing.Optional[bytes],
        unsafe_skip_rsa_key_validation: bool,
    ) -> PRIVATE_KEY_TYPES:
        return self._load_key(
            self._lib.PEM_read_bio_PrivateKey,
            data,
            password,
            unsafe_skip_rsa_key_validation,
        )

    def load_pem_public_key(self, data: bytes) -> PUBLIC_KEY_TYPES:
        mem_bio = self._bytes_to_bio(data)
        # In OpenSSL 3.0.x the PEM_read_bio_PUBKEY function will invoke
        # the default password callback if you pass an encrypted private
        # key. This is very, very, very bad as the default callback can
        # trigger an interactive console prompt, which will hang the
        # Python process. We therefore provide our own callback to
        # catch this and error out properly.
        userdata = self._ffi.new("CRYPTOGRAPHY_PASSWORD_DATA *")
        evp_pkey = self._lib.PEM_read_bio_PUBKEY(
            mem_bio.bio,
            self._ffi.NULL,
            self._ffi.addressof(
                self._lib._original_lib, "Cryptography_pem_password_cb"
            ),
            userdata,
        )
        if evp_pkey != self._ffi.NULL:
            evp_pkey = self._ffi.gc(evp_pkey, self._lib.EVP_PKEY_free)

            if self._lib.EVP_PKEY_is_sm2(evp_pkey):
                self._lib.EVP_PKEY_set_alias_type(
                    evp_pkey, self._lib.EVP_PKEY_SM2
                )
            return self._evp_pkey_to_public_key(evp_pkey)
        else:
            self._handle_key_loading_error()

    def _create_mem_bio_gc(self):
        """
        Creates an empty memory BIO.
        """
        bio_method = self._lib.BIO_s_mem()
        self.openssl_assert(bio_method != self._ffi.NULL)
        bio = self._lib.BIO_new(bio_method)
        self.openssl_assert(bio != self._ffi.NULL)
        bio = self._ffi.gc(bio, self._lib.BIO_free)
        return bio

    def _read_mem_bio(self, bio) -> bytes:
        """
        Reads a memory BIO. This only works on memory BIOs.
        """
        buf = self._ffi.new("char **")
        buf_len = self._lib.BIO_get_mem_data(bio, buf)
        self.openssl_assert(buf_len > 0)
        self.openssl_assert(buf[0] != self._ffi.NULL)
        bio_data = self._ffi.buffer(buf[0], buf_len)[:]
        return bio_data

    def _evp_pkey_to_private_key(
        self, evp_pkey, unsafe_skip_rsa_key_validation: bool
    ) -> PRIVATE_KEY_TYPES:
        """
        Return the appropriate type of PrivateKey given an evp_pkey cdata
        pointer.
        """

        key_type = self._lib.EVP_PKEY_id(evp_pkey)

        if (
            key_type == self._lib.EVP_PKEY_EC
            or key_type == self._lib.EVP_PKEY_SM2
        ):
            ec_cdata = self._lib.EVP_PKEY_get1_EC_KEY(evp_pkey)
            self.openssl_assert(ec_cdata != self._ffi.NULL)
            ec_cdata = self._ffi.gc(ec_cdata, self._lib.EC_KEY_free)
            return _EllipticCurvePrivateKey(self, ec_cdata, evp_pkey)
        else:
            raise UnsupportedAlgorithm("Unsupported key type.")

    def _evp_pkey_to_public_key(self, evp_pkey) -> PUBLIC_KEY_TYPES:
        """
        Return the appropriate type of PublicKey given an evp_pkey cdata
        pointer.
        """

        key_type = self._lib.EVP_PKEY_id(evp_pkey)

        if (
            key_type == self._lib.EVP_PKEY_EC
            or key_type == self._lib.EVP_PKEY_SM2
        ):
            ec_cdata = self._lib.EVP_PKEY_get1_EC_KEY(evp_pkey)
            if ec_cdata == self._ffi.NULL:
                errors = self._consume_errors_with_text()
                raise ValueError("Unable to load EC key", errors)
            ec_cdata = self._ffi.gc(ec_cdata, self._lib.EC_KEY_free)
            return _EllipticCurvePublicKey(self, ec_cdata, evp_pkey)
        else:
            raise UnsupportedAlgorithm("Unsupported key type.")

    def load_der_private_key(
        self,
        data: bytes,
        password: typing.Optional[bytes],
        unsafe_skip_rsa_key_validation: bool,
    ) -> PRIVATE_KEY_TYPES:
        # OpenSSL has a function called d2i_AutoPrivateKey that in theory
        # handles this automatically, however it doesn't handle encrypted
        # private keys. Instead we try to load the key two different ways.
        # First we'll try to load it as a traditional key.
        bio_data = self._bytes_to_bio(data)
        key = self._evp_pkey_from_der_traditional_key(bio_data, password)
        if key:
            return self._evp_pkey_to_private_key(
                key, unsafe_skip_rsa_key_validation
            )
        else:
            # Finally we try to load it with the method that handles encrypted
            # PKCS8 properly.
            return self._load_key(
                self._lib.d2i_PKCS8PrivateKey_bio,
                data,
                password,
                unsafe_skip_rsa_key_validation,
            )

    def _evp_pkey_from_der_traditional_key(self, bio_data, password):
        key = self._lib.d2i_PrivateKey_bio(bio_data.bio, self._ffi.NULL)
        if key != self._ffi.NULL:
            key = self._ffi.gc(key, self._lib.EVP_PKEY_free)
            if self._lib.EVP_PKEY_is_sm2(key):
                self._lib.EVP_PKEY_set_alias_type(key, self._lib.EVP_PKEY_SM2)

            if password is not None:
                raise TypeError(
                    "Password was given but private key is not encrypted."
                )

            return key
        else:
            self._consume_errors()
            return None

    def load_der_public_key(self, data: bytes) -> PUBLIC_KEY_TYPES:
        mem_bio = self._bytes_to_bio(data)
        evp_pkey = self._lib.d2i_PUBKEY_bio(mem_bio.bio, self._ffi.NULL)
        if evp_pkey != self._ffi.NULL:
            evp_pkey = self._ffi.gc(evp_pkey, self._lib.EVP_PKEY_free)
            if self._lib.EVP_PKEY_is_sm2(evp_pkey):
                self._lib.EVP_PKEY_set_alias_type(
                    evp_pkey, self._lib.EVP_PKEY_SM2
                )
            return self._evp_pkey_to_public_key(evp_pkey)
        else:
            self._handle_key_loading_error()

    def _load_key(
        self, openssl_read_func, data, password, unsafe_skip_rsa_key_validation
    ):
        mem_bio = self._bytes_to_bio(data)

        userdata = self._ffi.new("CRYPTOGRAPHY_PASSWORD_DATA *")
        if password is not None:
            utils._check_byteslike("password", password)
            password_ptr = self._ffi.from_buffer(password)
            userdata.password = password_ptr
            userdata.length = len(password)

        evp_pkey = openssl_read_func(
            mem_bio.bio,
            self._ffi.NULL,
            self._ffi.addressof(
                self._lib._original_lib, "Cryptography_pem_password_cb"
            ),
            userdata,
        )

        if evp_pkey == self._ffi.NULL:
            if userdata.error != 0:
                self._consume_errors()
                if userdata.error == -1:
                    raise TypeError(
                        "Password was not given but private key is encrypted"
                    )
                else:
                    assert userdata.error == -2
                    raise ValueError(
                        "Passwords longer than {} bytes are not supported "
                        "by this backend.".format(userdata.maxsize - 1)
                    )
            else:
                self._handle_key_loading_error()

        evp_pkey = self._ffi.gc(evp_pkey, self._lib.EVP_PKEY_free)

        if self._lib.EVP_PKEY_is_sm2(evp_pkey):
            self._lib.EVP_PKEY_set_alias_type(evp_pkey, self._lib.EVP_PKEY_SM2)

        if password is not None and userdata.called == 0:
            raise TypeError(
                "Password was given but private key is not encrypted."
            )

        assert (
            password is not None and userdata.called == 1
        ) or password is None

        return self._evp_pkey_to_private_key(
            evp_pkey, unsafe_skip_rsa_key_validation
        )

    def _handle_key_loading_error(self) -> typing.NoReturn:
        errors = self._consume_errors()

        if not errors:
            raise ValueError(
                "Could not deserialize key data. The data may be in an "
                "incorrect format or it may be encrypted with an unsupported "
                "algorithm."
            )

        elif (
            errors[0]._lib_reason_match(
                self._lib.ERR_LIB_EVP, self._lib.EVP_R_BAD_DECRYPT
            )
            or errors[0]._lib_reason_match(
                self._lib.ERR_LIB_PKCS12,
                self._lib.PKCS12_R_PKCS12_CIPHERFINAL_ERROR,
            )
            or (
                self._lib.Cryptography_HAS_PROVIDERS
                and errors[0]._lib_reason_match(
                    self._lib.ERR_LIB_PROV,
                    self._lib.PROV_R_BAD_DECRYPT,
                )
            )
        ):
            raise ValueError("Bad decrypt. Incorrect password?")

        elif any(
            error._lib_reason_match(
                self._lib.ERR_LIB_EVP,
                self._lib.EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM,
            )
            for error in errors
        ):
            raise ValueError("Unsupported public key algorithm.")

        else:
            errors_with_text = binding._errors_with_text(errors)
            raise ValueError(
                "Could not deserialize key data. The data may be in an "
                "incorrect format, it may be encrypted with an unsupported "
                "algorithm, or it may be an unsupported key type (e.g. EC "
                "curves with explicit parameters).",
                errors_with_text,
            )

    def _bn_to_int(self, bn) -> int:
        assert bn != self._ffi.NULL
        self.openssl_assert(not self._lib.BN_is_negative(bn))

        bn_num_bytes = self._lib.BN_num_bytes(bn)
        bin_ptr = self._ffi.new("unsigned char[]", bn_num_bytes)
        bin_len = self._lib.BN_bn2bin(bn, bin_ptr)
        # A zero length means the BN has value 0
        self.openssl_assert(bin_len >= 0)
        val = int.from_bytes(self._ffi.buffer(bin_ptr)[:bin_len], "big")
        return val

    def _int_to_bn(self, num: int, bn=None):
        """
        Converts a python integer to a BIGNUM. The returned BIGNUM will not
        be garbage collected (to support adding them to structs that take
        ownership of the object). Be sure to register it for GC if it will
        be discarded after use.
        """
        assert bn is None or bn != self._ffi.NULL

        if bn is None:
            bn = self._ffi.NULL

        binary = num.to_bytes(int(num.bit_length() / 8.0 + 1), "big")
        bn_ptr = self._lib.BN_bin2bn(binary, len(binary), bn)
        self.openssl_assert(bn_ptr != self._ffi.NULL)
        return bn_ptr

    def _ec_cdata_to_evp_pkey(self, ec_cdata):
        evp_pkey = self._create_evp_pkey_gc()
        res = self._lib.EVP_PKEY_set1_EC_KEY(evp_pkey, ec_cdata)
        self.openssl_assert(res == 1)

        if self._lib.EVP_PKEY_is_sm2(evp_pkey):
            self._lib.EVP_PKEY_set_alias_type(evp_pkey, self._lib.EVP_PKEY_SM2)

        return evp_pkey

    def _elliptic_curve_to_nid(self, curve: ec.EllipticCurve) -> int:
        """
        Get the NID for a curve name.
        """

        curve_aliases = {"secp192r1": "prime192v1", "secp256r1": "prime256v1"}

        curve_name = curve_aliases.get(curve.name, curve.name)

        curve_nid = self._lib.OBJ_sn2nid(curve_name.encode())
        if curve_nid == self._lib.NID_undef:
            raise UnsupportedAlgorithm(
                "{} is not a supported elliptic curve".format(curve.name),
                _Reasons.UNSUPPORTED_ELLIPTIC_CURVE,
            )
        return curve_nid

    def elliptic_curve_supported(self, curve: ec.EllipticCurve) -> bool:
        try:
            curve_nid = self._elliptic_curve_to_nid(curve)
        except UnsupportedAlgorithm:
            curve_nid = self._lib.NID_undef

        group = self._lib.EC_GROUP_new_by_curve_name(curve_nid)

        if group == self._ffi.NULL:
            self._consume_errors()
            return False
        else:
            self.openssl_assert(curve_nid != self._lib.NID_undef)
            self._lib.EC_GROUP_free(group)
            return True

    def elliptic_curve_signature_algorithm_supported(
        self,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
        curve: ec.EllipticCurve,
    ) -> bool:
        # We only support ECDSA right now.
        if not isinstance(signature_algorithm, ec.ECDSA):
            return False

        return self.elliptic_curve_supported(curve)

    def generate_elliptic_curve_private_key(
        self, curve: ec.EllipticCurve
    ) -> ec.EllipticCurvePrivateKey:
        """
        Generate a new private key on the named curve.
        """

        if self.elliptic_curve_supported(curve):
            ec_cdata = self._ec_key_new_by_curve(curve)

            res = self._lib.EC_KEY_generate_key(ec_cdata)
            self.openssl_assert(res == 1)

            evp_pkey = self._ec_cdata_to_evp_pkey(ec_cdata)

            return _EllipticCurvePrivateKey(self, ec_cdata, evp_pkey)
        else:
            raise UnsupportedAlgorithm(
                "Backend object does not support {}.".format(curve.name),
                _Reasons.UNSUPPORTED_ELLIPTIC_CURVE,
            )

    def load_elliptic_curve_private_numbers(
        self, numbers: ec.EllipticCurvePrivateNumbers
    ) -> ec.EllipticCurvePrivateKey:
        public = numbers.public_numbers

        ec_cdata = self._ec_key_new_by_curve(public.curve)

        private_value = self._ffi.gc(
            self._int_to_bn(numbers.private_value), self._lib.BN_clear_free
        )
        res = self._lib.EC_KEY_set_private_key(ec_cdata, private_value)
        if res != 1:
            self._consume_errors()
            raise ValueError("Invalid EC key.")

        self._ec_key_set_public_key_affine_coordinates(
            ec_cdata, public.x, public.y
        )

        evp_pkey = self._ec_cdata_to_evp_pkey(ec_cdata)

        return _EllipticCurvePrivateKey(self, ec_cdata, evp_pkey)

    def load_elliptic_curve_public_numbers(
        self, numbers: ec.EllipticCurvePublicNumbers
    ) -> ec.EllipticCurvePublicKey:
        ec_cdata = self._ec_key_new_by_curve(numbers.curve)
        self._ec_key_set_public_key_affine_coordinates(
            ec_cdata, numbers.x, numbers.y
        )
        evp_pkey = self._ec_cdata_to_evp_pkey(ec_cdata)

        return _EllipticCurvePublicKey(self, ec_cdata, evp_pkey)

    def load_elliptic_curve_public_bytes(
        self, curve: ec.EllipticCurve, point_bytes: bytes
    ) -> ec.EllipticCurvePublicKey:
        ec_cdata = self._ec_key_new_by_curve(curve)
        group = self._lib.EC_KEY_get0_group(ec_cdata)
        self.openssl_assert(group != self._ffi.NULL)
        point = self._lib.EC_POINT_new(group)
        self.openssl_assert(point != self._ffi.NULL)
        point = self._ffi.gc(point, self._lib.EC_POINT_free)
        with self._tmp_bn_ctx() as bn_ctx:
            res = self._lib.EC_POINT_oct2point(
                group, point, point_bytes, len(point_bytes), bn_ctx
            )
            if res != 1:
                self._consume_errors()
                raise ValueError("Invalid public bytes for the given curve")

        res = self._lib.EC_KEY_set_public_key(ec_cdata, point)
        self.openssl_assert(res == 1)
        evp_pkey = self._ec_cdata_to_evp_pkey(ec_cdata)
        return _EllipticCurvePublicKey(self, ec_cdata, evp_pkey)

    def derive_elliptic_curve_private_key(
        self, private_value: int, curve: ec.EllipticCurve
    ) -> ec.EllipticCurvePrivateKey:
        ec_cdata = self._ec_key_new_by_curve(curve)

        get_func, group = self._ec_key_determine_group_get_func(ec_cdata)

        point = self._lib.EC_POINT_new(group)
        self.openssl_assert(point != self._ffi.NULL)
        point = self._ffi.gc(point, self._lib.EC_POINT_free)

        value = self._int_to_bn(private_value)
        value = self._ffi.gc(value, self._lib.BN_clear_free)

        with self._tmp_bn_ctx() as bn_ctx:
            res = self._lib.EC_POINT_mul(
                group, point, value, self._ffi.NULL, self._ffi.NULL, bn_ctx
            )
            self.openssl_assert(res == 1)

            bn_x = self._lib.BN_CTX_get(bn_ctx)
            bn_y = self._lib.BN_CTX_get(bn_ctx)

            res = get_func(group, point, bn_x, bn_y, bn_ctx)
            if res != 1:
                self._consume_errors()
                raise ValueError("Unable to derive key from private_value")

        res = self._lib.EC_KEY_set_public_key(ec_cdata, point)
        self.openssl_assert(res == 1)
        private = self._int_to_bn(private_value)
        private = self._ffi.gc(private, self._lib.BN_clear_free)
        res = self._lib.EC_KEY_set_private_key(ec_cdata, private)
        self.openssl_assert(res == 1)

        evp_pkey = self._ec_cdata_to_evp_pkey(ec_cdata)

        return _EllipticCurvePrivateKey(self, ec_cdata, evp_pkey)

    def _ec_key_new_by_curve(self, curve: ec.EllipticCurve):
        curve_nid = self._elliptic_curve_to_nid(curve)
        return self._ec_key_new_by_curve_nid(curve_nid)

    def _ec_key_new_by_curve_nid(self, curve_nid: int):
        ec_cdata = self._lib.EC_KEY_new_by_curve_name(curve_nid)
        self.openssl_assert(ec_cdata != self._ffi.NULL)
        return self._ffi.gc(ec_cdata, self._lib.EC_KEY_free)

    def elliptic_curve_exchange_algorithm_supported(
        self, algorithm: ec.ECDH, curve: ec.EllipticCurve
    ) -> bool:
        return self.elliptic_curve_supported(curve) and isinstance(
            algorithm, ec.ECDH
        )

    def _create_evp_pkey_gc(self):
        evp_pkey = self._lib.EVP_PKEY_new()
        self.openssl_assert(evp_pkey != self._ffi.NULL)
        evp_pkey = self._ffi.gc(evp_pkey, self._lib.EVP_PKEY_free)
        return evp_pkey

    def _ec_key_determine_group_get_func(self, ctx):
        """
        Given an EC_KEY determine the group and what function is required to
        get point coordinates.
        """
        self.openssl_assert(ctx != self._ffi.NULL)

        nid_two_field = self._lib.OBJ_sn2nid(b"characteristic-two-field")
        self.openssl_assert(nid_two_field != self._lib.NID_undef)

        group = self._lib.EC_KEY_get0_group(ctx)
        self.openssl_assert(group != self._ffi.NULL)

        method = self._lib.EC_GROUP_method_of(group)
        self.openssl_assert(method != self._ffi.NULL)

        nid = self._lib.EC_METHOD_get_field_type(method)
        self.openssl_assert(nid != self._lib.NID_undef)

        if nid == nid_two_field and self._lib.Cryptography_HAS_EC2M:
            get_func = self._lib.EC_POINT_get_affine_coordinates_GF2m
        else:
            get_func = self._lib.EC_POINT_get_affine_coordinates_GFp

        assert get_func

        return get_func, group

    @contextmanager
    def _tmp_bn_ctx(self):
        bn_ctx = self._lib.BN_CTX_new()
        self.openssl_assert(bn_ctx != self._ffi.NULL)
        bn_ctx = self._ffi.gc(bn_ctx, self._lib.BN_CTX_free)
        self._lib.BN_CTX_start(bn_ctx)
        try:
            yield bn_ctx
        finally:
            self._lib.BN_CTX_end(bn_ctx)

    def _ec_key_set_public_key_affine_coordinates(self, ctx, x: int, y: int):
        """
        Sets the public key point in the EC_KEY context to the affine x and y
        values.
        """

        if x < 0 or y < 0:
            raise ValueError(
                "Invalid EC key. Both x and y must be non-negative."
            )

        x = self._ffi.gc(self._int_to_bn(x), self._lib.BN_free)
        y = self._ffi.gc(self._int_to_bn(y), self._lib.BN_free)
        res = self._lib.EC_KEY_set_public_key_affine_coordinates(ctx, x, y)
        if res != 1:
            self._consume_errors()
            raise ValueError("Invalid EC key.")

    def _private_key_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
        key,
        evp_pkey,
        cdata,
    ) -> bytes:
        # validate argument types
        if not isinstance(encoding, serialization.Encoding):
            raise TypeError("encoding must be an item from the Encoding enum")
        if not isinstance(format, serialization.PrivateFormat):
            raise TypeError(
                "format must be an item from the PrivateFormat enum"
            )
        if not isinstance(
            encryption_algorithm, serialization.KeySerializationEncryption
        ):
            raise TypeError(
                "Encryption algorithm must be a KeySerializationEncryption "
                "instance"
            )

        # validate password
        if isinstance(encryption_algorithm, serialization.NoEncryption):
            password = b""
        elif isinstance(
            encryption_algorithm, serialization.BestAvailableEncryption
        ):
            password = encryption_algorithm.password
            if len(password) > 1023:
                raise ValueError(
                    "Passwords longer than 1023 bytes are not supported by "
                    "this backend"
                )
        elif (
            isinstance(
                encryption_algorithm, serialization._KeySerializationEncryption
            )
            and encryption_algorithm._format
            is format
            is serialization.PrivateFormat.OpenSSH
        ):
            password = encryption_algorithm.password
        else:
            raise ValueError("Unsupported encryption type")

        # PKCS8 + PEM/DER
        if format is serialization.PrivateFormat.PKCS8:
            if encoding is serialization.Encoding.PEM:
                write_bio = self._lib.PEM_write_bio_PKCS8PrivateKey
            elif encoding is serialization.Encoding.DER:
                write_bio = self._lib.i2d_PKCS8PrivateKey_bio
            else:
                raise ValueError("Unsupported encoding for PKCS8")
            return self._private_key_bytes_via_bio(
                write_bio, evp_pkey, password
            )

        # TraditionalOpenSSL + PEM/DER
        if format is serialization.PrivateFormat.TraditionalOpenSSL:
            if self._fips_enabled and not isinstance(
                encryption_algorithm, serialization.NoEncryption
            ):
                raise ValueError(
                    "Encrypted traditional OpenSSL format is not "
                    "supported in FIPS mode."
                )
            key_type = self._lib.EVP_PKEY_id(evp_pkey)

            if encoding is serialization.Encoding.PEM:
                if key_type == self._lib.EVP_PKEY_RSA:
                    write_bio = self._lib.PEM_write_bio_RSAPrivateKey
                elif key_type == self._lib.EVP_PKEY_DSA:
                    write_bio = self._lib.PEM_write_bio_DSAPrivateKey
                elif (
                    key_type == self._lib.EVP_PKEY_EC
                    or key_type == self._lib.EVP_PKEY_SM2
                ):
                    write_bio = self._lib.PEM_write_bio_ECPrivateKey
                else:
                    raise ValueError(
                        "Unsupported key type for TraditionalOpenSSL"
                    )
                return self._private_key_bytes_via_bio(
                    write_bio, cdata, password
                )

            if encoding is serialization.Encoding.DER:
                if password:
                    raise ValueError(
                        "Encryption is not supported for DER encoded "
                        "traditional OpenSSL keys"
                    )
                if key_type == self._lib.EVP_PKEY_RSA:
                    write_bio = self._lib.i2d_RSAPrivateKey_bio
                elif (
                    key_type == self._lib.EVP_PKEY_EC
                    or key_type == self._lib.EVP_PKEY_SM2
                ):
                    write_bio = self._lib.i2d_ECPrivateKey_bio
                elif key_type == self._lib.EVP_PKEY_DSA:
                    write_bio = self._lib.i2d_DSAPrivateKey_bio
                else:
                    raise ValueError(
                        "Unsupported key type for TraditionalOpenSSL"
                    )
                return self._bio_func_output(write_bio, cdata)

            raise ValueError("Unsupported encoding for TraditionalOpenSSL")

        # Anything that key-specific code was supposed to handle earlier,
        # like Raw.
        raise ValueError("format is invalid with this key")

    def _private_key_bytes_via_bio(self, write_bio, evp_pkey, password):
        if not password:
            evp_cipher = self._ffi.NULL
        else:
            # This is a curated value that we will update over time.
            evp_cipher = self._lib.EVP_get_cipherbyname(b"sm4-cbc")

        return self._bio_func_output(
            write_bio,
            evp_pkey,
            evp_cipher,
            password,
            len(password),
            self._ffi.NULL,
            self._ffi.NULL,
        )

    def _bio_func_output(self, write_bio, *args):
        bio = self._create_mem_bio_gc()
        res = write_bio(bio, *args)
        self.openssl_assert(res == 1)
        return self._read_mem_bio(bio)

    def _public_key_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
        key,
        evp_pkey,
        cdata,
    ) -> bytes:
        if not isinstance(encoding, serialization.Encoding):
            raise TypeError("encoding must be an item from the Encoding enum")
        if not isinstance(format, serialization.PublicFormat):
            raise TypeError(
                "format must be an item from the PublicFormat enum"
            )

        # SubjectPublicKeyInfo + PEM/DER
        if format is serialization.PublicFormat.SubjectPublicKeyInfo:
            if encoding is serialization.Encoding.PEM:
                write_bio = self._lib.PEM_write_bio_PUBKEY
            elif encoding is serialization.Encoding.DER:
                write_bio = self._lib.i2d_PUBKEY_bio
            else:
                raise ValueError(
                    "SubjectPublicKeyInfo works only with PEM or DER encoding"
                )
            return self._bio_func_output(write_bio, evp_pkey)

        # PKCS1 + PEM/DER
        if format is serialization.PublicFormat.PKCS1:
            # Only RSA is supported here.
            key_type = self._lib.EVP_PKEY_id(evp_pkey)
            if key_type != self._lib.EVP_PKEY_RSA:
                raise ValueError("PKCS1 format is supported only for RSA keys")

            if encoding is serialization.Encoding.PEM:
                write_bio = self._lib.PEM_write_bio_RSAPublicKey
            elif encoding is serialization.Encoding.DER:
                write_bio = self._lib.i2d_RSAPublicKey_bio
            else:
                raise ValueError("PKCS1 works only with PEM or DER encoding")
            return self._bio_func_output(write_bio, cdata)

        # Anything that key-specific code was supposed to handle earlier,
        # like Raw, CompressedPoint, UncompressedPoint
        raise ValueError("format is invalid with this key")

    def new_ecdsa_sig(self, r: int, s: int) -> bytes:
        """
        Create an ECDSA_SIG, sets ECDSA_SIG with r and s
        """
        sig = self._lib.ECDSA_SIG_new()
        self.openssl_assert(sig != self._ffi.NULL)
        sig = self._ffi.gc(sig, self._lib.ECDSA_SIG_free)

        res = self._lib.ECDSA_SIG_set0(
            sig, self._int_to_bn(r), self._int_to_bn(s)
        )
        if res != 1:
            self._consume_errors()
            raise ValueError("Invalid r or s.")

        ppout = self._ffi.new("unsigned char *[1]")
        buf_len = self._lib.i2d_ECDSA_SIG(sig, self._ffi.NULL)
        if buf_len < 0:
            errors = self._consume_errors_with_text()
            raise ValueError("Unable to encode ECDSA signature", errors)

        buf = self._ffi.new("unsigned char[]", buf_len)
        ppout[0] = buf
        buf_len = self._lib.i2d_ECDSA_SIG(sig, ppout)
        if buf_len < 0:
            errors = self._consume_errors_with_text()
            raise ValueError("Unable to encode ECDSA signature", errors)

        return self._ffi.buffer(buf)[:buf_len]


class GetCipherByName:
    def __init__(self, fmt: str):
        self._fmt = fmt

    def __call__(self, backend: Backend, cipher: CipherAlgorithm, mode: Mode):
        cipher_name = self._fmt.format(cipher=cipher, mode=mode).lower()
        evp_cipher = backend._lib.EVP_get_cipherbyname(
            cipher_name.encode("ascii")
        )

        # try EVP_CIPHER_fetch if present
        if (
            evp_cipher == backend._ffi.NULL
            and backend._lib.Cryptography_HAS_300_EVP_CIPHER
        ):
            evp_cipher = backend._lib.EVP_CIPHER_fetch(
                backend._ffi.NULL,
                cipher_name.encode("ascii"),
                backend._ffi.NULL,
            )

        backend._consume_errors()
        return evp_cipher


backend = Backend()
