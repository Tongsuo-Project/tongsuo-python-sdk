# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

import abc
import typing

from tongsuopy.crypto import utils
from tongsuopy.crypto.exceptions import (
    AlreadyFinalized,
)


class HashAlgorithm(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def name(self) -> str:
        """
        A string naming this algorithm (e.g. "sha256", "md5").
        """

    @abc.abstractproperty
    def digest_size(self) -> int:
        """
        The size of the resulting digest in bytes.
        """

    @abc.abstractproperty
    def block_size(self) -> typing.Optional[int]:
        """
        The internal block size of the hash function, or None if the hash
        function does not use blocks internally (e.g. SHA3).
        """


class HashContext(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def algorithm(self) -> HashAlgorithm:
        """
        A HashAlgorithm that will be used by this context.
        """

    @abc.abstractmethod
    def update(self, data: bytes) -> None:
        """
        Processes the provided bytes through the hash.
        """

    @abc.abstractmethod
    def finalize(self) -> bytes:
        """
        Finalizes the hash context and returns the hash digest as bytes.
        """

    @abc.abstractmethod
    def copy(self) -> "HashContext":
        """
        Return a HashContext that is a copy of the current context.
        """


class ExtendableOutputFunction(metaclass=abc.ABCMeta):
    """
    An interface for extendable output functions.
    """


class Hash(HashContext):
    _ctx: typing.Optional[HashContext]

    def __init__(
        self,
        algorithm: HashAlgorithm,
        backend: typing.Any = None,
        ctx: typing.Optional["HashContext"] = None,
    ):
        if not isinstance(algorithm, HashAlgorithm):
            raise TypeError("Expected instance of hashes.HashAlgorithm.")
        self._algorithm = algorithm

        if ctx is None:
            from tongsuopy.backends.tongsuo import backend as ossl

            self._ctx = ossl.create_hash_ctx(self.algorithm)
        else:
            self._ctx = ctx

    @property
    def algorithm(self) -> HashAlgorithm:
        return self._algorithm

    def update(self, data: bytes) -> None:
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        utils._check_byteslike("data", data)
        self._ctx.update(data)

    def copy(self) -> "Hash":
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        return Hash(self.algorithm, ctx=self._ctx.copy())

    def finalize(self) -> bytes:
        if self._ctx is None:
            raise AlreadyFinalized("Context was already finalized.")
        digest = self._ctx.finalize()
        self._ctx = None
        return digest


class SM3(HashAlgorithm):
    name = "sm3"
    digest_size = 32
    block_size = 64
