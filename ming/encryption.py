from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, Generic, Callable

from ming.utils import classproperty
from ming.base import Object as BaseObject
import ming.schema

if TYPE_CHECKING:
    import ming.datastore
    from ming.metadata import Field
    from ming.odm.property import FieldProperty


class MingEncryptionError(Exception):
    pass


class EncryptedObject(BaseObject):
    """A dict-like object that supports DecryptedField behavior for nested encrypted fields.
    
    This class extends :class:`ming.base.Object` and provides automatic decryption/encryption
    when accessing fields that have a corresponding encrypted counterpart.
    """
    
    __slots__ = ('_decrypted_fields', '_encr_func', '_decr_func')
    
    def __init__(self, data=None, decrypted_fields=None, encr_func=None, decr_func=None):
        """
        :param data: Initial data for the object
        :param decrypted_fields: Dict mapping decrypted field names to their DecryptedField instances
        :param encr_func: Function to encrypt values (datastore.encr)
        :param decr_func: Function to decrypt values (datastore.decr)
        """
        super().__init__(data or {})
        object.__setattr__(self, '_decrypted_fields', decrypted_fields or {})
        object.__setattr__(self, '_encr_func', encr_func)
        object.__setattr__(self, '_decr_func', decr_func)
    
    def __getattr__(self, name):
        # Check if this is a decrypted field
        decrypted_fields = object.__getattribute__(self, '_decrypted_fields')
        if name in decrypted_fields:
            decr_func = object.__getattribute__(self, '_decr_func')
            decrypted_field = decrypted_fields[name]
            encrypted_value = self.get(decrypted_field.encrypted_field)
            if decr_func is not None and encrypted_value is not None:
                return decr_func(encrypted_value)
            return encrypted_value
        
        # Fall back to standard Object behavior
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)
    
    def __setattr__(self, name, value):
        # Check if this is a decrypted field
        decrypted_fields = object.__getattribute__(self, '_decrypted_fields')
        if name in decrypted_fields:
            encr_func = object.__getattribute__(self, '_encr_func')
            decrypted_field = decrypted_fields[name]
            
            # Type check
            if value is not None and not isinstance(value, decrypted_field.field_type):
                raise TypeError(f'not {decrypted_field.field_type}, got {value!r}')
            
            # Encrypt and store
            if encr_func is not None and value is not None:
                encrypted_value = encr_func(value)
            else:
                encrypted_value = value
            self[decrypted_field.encrypted_field] = encrypted_value
            return
        
        # Fall back to standard Object behavior
        if name in self.__class__.__dict__:
            super().__setattr__(name, value)
        else:
            self[name] = value
    
    def __getitem__(self, name):
        # Check if this is a decrypted field accessed via dict notation
        decrypted_fields = object.__getattribute__(self, '_decrypted_fields')
        if name in decrypted_fields:
            decr_func = object.__getattribute__(self, '_decr_func')
            decrypted_field = decrypted_fields[name]
            encrypted_value = dict.__getitem__(self, decrypted_field.encrypted_field) if decrypted_field.encrypted_field in self else None
            if decr_func is not None and encrypted_value is not None:
                return decr_func(encrypted_value)
            return encrypted_value
        return dict.__getitem__(self, name)
    
    def __setitem__(self, name, value):
        # Check if this is a decrypted field accessed via dict notation
        decrypted_fields = object.__getattribute__(self, '_decrypted_fields')
        if name in decrypted_fields:
            encr_func = object.__getattribute__(self, '_encr_func')
            decrypted_field = decrypted_fields[name]
            
            # Type check
            if value is not None and not isinstance(value, decrypted_field.field_type):
                raise TypeError(f'not {decrypted_field.field_type}, got {value!r}')
            
            # Encrypt and store
            if encr_func is not None and value is not None:
                encrypted_value = encr_func(value)
            else:
                encrypted_value = value
            dict.__setitem__(self, decrypted_field.encrypted_field, encrypted_value)
            return
        dict.__setitem__(self, name, value)


class EncryptionConfig:
    """
    A class to hold the encryption configuration for a ming datastore.

    :param config: a dictionary that closely resembles various features of the MongoDB
        encryption that we support.
    """
    
    def __init__(self, config: dict):
        self._encryption_config = config

    @property
    def kms_providers(self) -> dict:
        """
        Returns the kms providers used in this configuration. These values are passed directly to pymongo.

        See the documentation for the :class:`pymongo.encryption.ClientEncryption` constructor
        for more information on valid values for kms_providers.

        A typical example of the kms_providers field using the `local` provider would look like this:
        
        .. :code-block: json
            
                {
                    "local": {   
                        "key": "<base64-encoded-key>",
                    }
                }

        """
        return self._encryption_config.get('kms_providers')

    @property
    def provider_options(self) -> dict:
        """
        Returns all of the provider options used by this configuration when calling the underlying 
        :meth:`pymongo.encryption.ClientEncryption.create_data_key` method.

        See the documentation for pymongo's :meth:`pymongo.encryption.ClientEncryption.create_data_key`
        method for more information on valid values for ``provider_options``.

        A typical example of the ``provider_options`` field using the ``local`` provider would look like this:
        
        .. :code-block: json
            
                {
                    "local": {   
                        "key_alt_names": ["datakey_test1", "datakey_test2"]
                    },
                    "gcp": { ... },
                    ...
                }

        """
        return self._encryption_config.get('provider_options')

    def _get_key_alt_name(self, provider='local') -> str:
        return self.provider_options.get(provider)['key_alt_names'][0]

    @property
    def key_vault_namespace(self) -> str:
        """Describes which mongodb database/collection combo your auto-generated 
        encryption data keys will be stored.

        This is a string in the format ``<database>.<collection>``.
        """
        return self._encryption_config.get('key_vault_namespace')


T = TypeVar('T')


class DecryptedField(Generic[T]):

    def __init__(self, field_type: type[T], encrypted_field: str):
        """
        Creates a field that acts as an automatic getter/setter for the target
        field name specified ``encrypted_field``.

        .. note::

            Interally :class:``.DecryptedField`` uses getattr and setattr on ``self`` using the ``encrypted_field`` name.

        .. code-block:: python

            class MyDocument(Document):
                email_encrypted = Field(ming.schema.Binary)
                email = DecryptedField(str, 'email_encrypted')

        :param field_type: The Type of the decrypted field
        :param encrypted_field: The name of the encrypted attribute to operate on
        """
        self.field_type = field_type
        self.encrypted_field = encrypted_field

    def __get__(self, instance: EncryptedMixin, owner) -> T:
        if instance is None:
            return self
        return instance.decr(getattr(instance, self.encrypted_field))

    def __set__(self, instance: EncryptedMixin, value: T):
        # allow None, because most normal fields do not have required=True set, nor the (undocumented) allow_none
        if value is not None and not isinstance(value, self.field_type):
            raise TypeError(f'not {self.field_type}, got {value!r}')
        setattr(instance, self.encrypted_field, instance.encr(value))


class EncryptedMixin:
    """A mixin intended to be used with :class:`~ming.declarative.Document`
    or :class:`~ming.odm.declarative.MappedClass` to provide encryption.
    All configuration is handled by an instance of a :class:`ming.encryption.EncryptionConfig`
    that is passed to the :class:`ming.datastore.DataStore` instance that the Document/MappedClass is bound to.

    Generally, don't use this directly, but instead call the methods on the Document/MappedClass you're working with.
    """

    @classproperty
    def _datastore(cls) -> ming.datastore.DataStore:
        from ming.declarative import Document
        from ming.odm.declarative import MappedClass
        if issubclass(cls, Document):
            return cls.m.session.bind
        if issubclass(cls, MappedClass):
            return cls.query.session.bind
        raise NotImplementedError("Unexpected class type. You must implement `datastore` as a @classproperty in your mixin implementation.")
    
    @classproperty
    def _field_names(cls) -> list[str]:
        from ming.declarative import Document
        from ming.odm.declarative import MappedClass
        if issubclass(cls, Document):
            fields: list[tuple[str, Field]] = list(cls.m.field_index.items())
            field_names = []
            for (k, v) in fields:
                if v.type in (ming.schema.Deprecated,):
                    continue
                field_names.append(k)
            return field_names
        if issubclass(cls, MappedClass):
            fields: list[tuple[str, FieldProperty]] = list(cls.query.mapper.property_index.items())
            field_names = []
            for (k, v) in fields:
                if v.field.type in (ming.schema.Deprecated,):
                    continue
                field_names.append(k)
            return field_names
        raise NotImplementedError("Unexpected class type. You must implement `field_names` as a @classproperty in your mixin implementation.")

    @classmethod
    def encr(cls, s: str | None, provider='local') -> bytes | None:
        """Encrypts a string using the encryption configuration of the ming datastore that this class is bound to.
        Most of the time, you won't need to call this directly, as it is used by the :meth:`ming.encryption.EncryptedDocumentMixin.encrypt_some_fields` method.
        """
        return cls._datastore.encr(s, provider=provider)

    @classmethod
    def decr(cls, b: bytes | None) -> str | None:
        """Decrypts a string using the encryption configuration of the ming datastore that this class is bound to.
        """
        return cls._datastore.decr(b)

    @classmethod
    def decrypted_field_names(cls) -> list[str]:
        """
        Returns a list of field names that have ``_encrypted`` counterts.

        For example, if a class has fields ``email`` and ``email_encrypted``, this method would return ``['email']``.
        """
        return [fld.replace('_encrypted', '')
                for fld in cls.encrypted_field_names()]

    @classmethod
    def encrypted_field_names(cls) -> list[str]:
        """
        Returns the field names of all encrypted fields. Fields are assumed to be encrypted if they end with ``_encrypted``.

        For example if a class has fields ``email`` and ``email_encrypted``, this method would return ``['email_encrypted']``.
        """
        return [fld for fld in cls._field_names
                if fld.endswith('_encrypted')]

    @classmethod
    def encrypt_some_fields(cls, data: dict) -> dict:
        """Encrypts some fields in a dictionary using the encryption configuration of the ming datastore that this class is bound to.

        :param data: a dictionary of data to be encrypted
        :return: a modified copy of the ``data`` param with the currently-unencrypted-but-encryptable fields replaced with ``_encrypted`` counterparts.
        """
        encrypted_data = data.copy()
        for fld in cls.decrypted_field_names():
            if fld in encrypted_data:
                val = encrypted_data.pop(fld)
                encrypted_data[f'{fld}_encrypted'] = cls.encr(val)
        return encrypted_data

    def decrypt_some_fields(self) -> dict:
        """
        Returns a `dict` with raw data. Removes encrypted fields and replaces them with decrypted data. Useful for json.
        """
        decrypted_data = dict()
        for k in self._field_names:
            if k.endswith('_encrypted'):
                k_decrypted = k.replace('_encrypted', '')
                decrypted_data[k_decrypted] = getattr(self, k_decrypted)
            else:
                decrypted_data[k] = getattr(self, k)
        return decrypted_data
