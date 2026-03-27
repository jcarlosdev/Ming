from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, Generic, Any

from ming.utils import classproperty
import ming.schema

if TYPE_CHECKING:
    import ming.datastore
    from ming.metadata import Field
    from ming.odm.property import FieldProperty


class MingEncryptionError(Exception):
    pass


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


class EncryptedObject(dict):
    """A dict-like wrapper that handles encryption/decryption for nested fields.
    
    This class wraps a regular dict and provides transparent encryption/decryption
    when accessing fields that have _encrypted counterparts.
    
    This is automatically applied to dict fields that contain encrypted fields,
    enabling nested field-level encryption in MongoDB documents.
    
    **Example Usage:**
    
    Define a document with nested encrypted fields:
    
    .. code-block:: python
    
        class User(Document):
            class __mongometa__:
                name = 'user'
                session = my_session
            
            _id = Field(schema.ObjectId)
            username = Field(str)
            # Dict field with encrypted nested fields
            full_name = Field(dict(
                first_name_encrypted=schema.Binary,
                last_name_encrypted=schema.Binary
            ))
    
    Create a document with unencrypted nested data:
    
    .. code-block:: python
    
        user = User.make_encr({
            '_id': ObjectId(),
            'username': 'jdoe',
            'full_name': {
                'first_name': 'John',
                'last_name': 'Doe'
            }
        })
        user.m.save()
    
    Access decrypted values using dict notation:
    
    .. code-block:: python
    
        # Get decrypted values
        print(user.full_name['first_name'])  # 'John'
        print(user.full_name['last_name'])   # 'Doe'
        
        # Set new encrypted values
        user.full_name['first_name'] = 'Johnny'
        user.m.save()
    
    **How it Works:**
    
    1. When you define a dict field with fields ending in ``_encrypted`` (e.g., ``first_name_encrypted``),
       the system recognizes these as encrypted fields.
    
    2. When creating a document with ``make_encr()``, any nested fields that have corresponding
       ``_encrypted`` fields in the schema are automatically encrypted.
    
    3. When you access a field without the ``_encrypted`` suffix (e.g., ``'first_name'``),
       EncryptedObject automatically decrypts the value from the ``first_name_encrypted`` field.
    
    4. When you set a field without the ``_encrypted`` suffix, EncryptedObject automatically
       encrypts the value and stores it in the corresponding ``_encrypted`` field.
    
    **Multi-level Nesting:**
    
    This works recursively for any level of nesting:
    
    .. code-block:: python
    
        class Profile(Document):
            personal_info = Field(dict(
                address=dict(
                    street_encrypted=schema.Binary,
                    city_encrypted=schema.Binary
                )
            ))
        
        # Access deeply nested encrypted fields
        profile.personal_info['address']['street'] = '123 Main St'
    
    :param data: The underlying dict data
    :param encr_func: Function to encrypt data (str -> bytes)
    :param decr_func: Function to decrypt data (bytes -> str)
    :param field_schema: Dict mapping field names to their schemas (for nested dicts)
    """
    
    def __init__(self, data: dict, encr_func, decr_func, field_schema: dict = None):
        """
        :param data: The underlying dict data
        :param encr_func: Function to encrypt data (str -> bytes)
        :param decr_func: Function to decrypt data (bytes -> str)
        :param field_schema: Dict mapping field names to their schemas (for nested dicts)
        """
        super().__init__(data)
        self._encr_func = encr_func
        self._decr_func = decr_func
        self._field_schema = field_schema or {}
        
        # Wrap any nested dicts that have encrypted fields
        self._wrap_nested_dicts()
    
    def _wrap_nested_dicts(self):
        """Wrap nested dicts with EncryptedObject if they contain encrypted fields."""
        for key, value in self.items():
            if isinstance(value, dict) and not isinstance(value, EncryptedObject):
                # Check if this dict has any encrypted fields
                if self._has_encrypted_fields(value):
                    nested_schema = self._field_schema.get(key, {})
                    self[key] = EncryptedObject(value, self._encr_func, self._decr_func, nested_schema)
    
    def _has_encrypted_fields(self, d: dict) -> bool:
        """Check if a dict has any fields ending with _encrypted."""
        return any(k.endswith('_encrypted') for k in d.keys())
    
    def _get_encrypted_field_name(self, key: str) -> str:
        """Get the encrypted field name for a decrypted field."""
        return f"{key}_encrypted"
    
    def _is_encrypted_field(self, key: str) -> bool:
        """Check if a field is an encrypted field (ends with _encrypted)."""
        return key.endswith('_encrypted')
    
    def _get_decrypted_field_name(self, key: str) -> str:
        """Get the decrypted field name from an encrypted field."""
        if key.endswith('_encrypted'):
            return key[:-10]  # Remove '_encrypted' suffix
        return key
    
    def __getitem__(self, key: str) -> Any:
        """Get item with automatic decryption if accessing a decrypted field."""
        # If accessing an encrypted field directly, return as-is
        if self._is_encrypted_field(key):
            return super().__getitem__(key)
        
        # Check if there's an encrypted counterpart
        encrypted_key = self._get_encrypted_field_name(key)
        if encrypted_key in self:
            # This is a decrypted field - decrypt the encrypted value
            encrypted_value = super().__getitem__(encrypted_key)
            return self._decr_func(encrypted_value)
        
        # Regular field access
        value = super().__getitem__(key)
        
        # If the value is a dict with encrypted fields, wrap it
        if isinstance(value, dict) and not isinstance(value, EncryptedObject):
            if self._has_encrypted_fields(value):
                nested_schema = self._field_schema.get(key, {})
                value = EncryptedObject(value, self._encr_func, self._decr_func, nested_schema)
                super().__setitem__(key, value)
        
        return value
    
    def __setitem__(self, key: str, value: Any):
        """Set item with automatic encryption if setting a decrypted field."""
        # If setting an encrypted field directly, set as-is
        if self._is_encrypted_field(key):
            super().__setitem__(key, value)
            return
        
        # Check if there's an encrypted counterpart
        encrypted_key = self._get_encrypted_field_name(key)
        if encrypted_key in self:
            # This is a decrypted field - encrypt the value and store in encrypted field
            if value is not None:
                encrypted_value = self._encr_func(value)
                super().__setitem__(encrypted_key, encrypted_value)
            else:
                super().__setitem__(encrypted_key, None)
            # Don't store the decrypted value
            return
        
        # Regular field - just set it
        # If value is a dict with encrypted fields, wrap it
        if isinstance(value, dict) and not isinstance(value, EncryptedObject):
            if self._has_encrypted_fields(value):
                nested_schema = self._field_schema.get(key, {})
                value = EncryptedObject(value, self._encr_func, self._decr_func, nested_schema)
        
        super().__setitem__(key, value)
    
    def get(self, key: str, default=None) -> Any:
        """Get with default, handling decryption."""
        try:
            return self[key]
        except KeyError:
            return default
    
    def __getattr__(self, name: str) -> Any:
        """Support attribute access like obj.field_name."""
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)
    
    def __setattr__(self, name: str, value: Any):
        """Support attribute setting like obj.field_name = value."""
        # Handle internal attributes
        if name.startswith('_'):
            super().__setattr__(name, value)
        else:
            self[name] = value


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
    
    # Make EncryptedObject accessible as a class attribute
    EncryptedObject = EncryptedObject

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
        
        # Encrypt top-level decrypted fields
        for fld in cls.decrypted_field_names():
            if fld in encrypted_data:
                val = encrypted_data.pop(fld)
                encrypted_data[f'{fld}_encrypted'] = cls.encr(val)
        
        # Handle nested dicts - recursively encrypt fields in dict values
        if hasattr(cls, 'm') and hasattr(cls.m, 'field_index') and cls.m.field_index:
            for key, value in encrypted_data.items():
                if isinstance(value, dict) and key in cls.m.field_index:
                    field = cls.m.field_index[key]
                    if hasattr(field, 'schema') and hasattr(field.schema, 'fields'):
                        # This is an Object schema with defined fields
                        encrypted_data[key] = cls._encrypt_nested_dict(value, field.schema.fields)
        
        return encrypted_data
    
    @classmethod
    def _encrypt_nested_dict(cls, data: dict, schema_fields: dict) -> dict:
        """Recursively encrypt fields in a nested dict based on schema.
        
        :param data: The dict data to encrypt
        :param schema_fields: The schema fields definition for this dict level
        """
        encrypted_data = data.copy()
        
        # Find which fields in the schema are encrypted fields (end with _encrypted)
        encrypted_field_names = [k for k in schema_fields.keys() if k.endswith('_encrypted')]
        
        # For each encrypted field, check if we have the decrypted version in data
        for encrypted_field in encrypted_field_names:
            decrypted_field = encrypted_field[:-10]  # Remove '_encrypted'
            
            if decrypted_field in encrypted_data:
                # We have the decrypted version - encrypt it
                val = encrypted_data.pop(decrypted_field)
                encrypted_data[encrypted_field] = cls.encr(val)
        
        # Recursively handle nested dicts
        for key, value in encrypted_data.items():
            if isinstance(value, dict) and key in schema_fields:
                nested_schema = schema_fields[key]
                if hasattr(nested_schema, 'fields'):
                    encrypted_data[key] = cls._encrypt_nested_dict(value, nested_schema.fields)
        
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
