from __future__ import annotations

import copy
from typing import TYPE_CHECKING, TypeVar, Generic, Iterator

from ming.base import Object as BaseObject
from ming.utils import classproperty
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

    def __getitem__(self, name):
        # Check if this is a decrypted field accessed via dict notation
        decrypted_fields = object.__getattribute__(self, '_decrypted_fields')
        if name in decrypted_fields:
            decr_func = object.__getattribute__(self, '_decr_func')
            encrypted_value = dict.__getitem__(self, f'{name}_encrypted')
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


class EncryptedArray(list):
    """A list-like object that supports encryption/decryption for array elements.

    This class extends :class:`list` and provides automatic decryption/encryption
    when accessing elements. It supports arrays of encrypted strings or encrypted dicts.

    The element_type determines how elements are handled:
    - 'string': Elements are encrypted/decrypted strings (stored as Binary)
    - 'dict': Elements are EncryptedObject instances with their own encrypted fields
    """

    __slots__ = ("_element_type", "_encr_func", "_decr_func", "_decrypted_fields")

    def __new__(cls, data=None, element_type="string", decrypted_fields=None, encr_func=None, decr_func=None):
        instance = super().__new__(cls)
        return instance

    def __init__(self, data=None, element_type="string", decrypted_fields=None, encr_func=None, decr_func=None):
        """
        :param data: Initial data for the array
        :param element_type: Type of elements ('string' or 'dict')
        :param decrypted_fields: For dict elements, list of field names that have encrypted counterparts
        :param encr_func: Function to encrypt values (datastore.encr)
        :param decr_func: Function to decrypt values (datastore.decr)
        """
        super().__init__(data or [])
        object.__setattr__(self, "_element_type", element_type)
        object.__setattr__(self, "_decrypted_fields", decrypted_fields or [])
        object.__setattr__(self, "_encr_func", encr_func)
        object.__setattr__(self, "_decr_func", decr_func)

    def __getitem__(self, index):
        value = list.__getitem__(self, index)
        element_type = object.__getattribute__(self, "_element_type")
        decr_func = object.__getattribute__(self, "_decr_func")

        if element_type == "string":
            # For string arrays, elements are stored encrypted, decrypt on access
            if decr_func is not None and value is not None:
                return decr_func(value)
            return value
        else:
            # For dict arrays, elements are EncryptedObject instances
            return value

    def __setitem__(self, index, value):
        element_type = object.__getattribute__(self, "_element_type")
        encr_func = object.__getattribute__(self, "_encr_func")

        if element_type == "string":
            # For string arrays, encrypt the value before storing
            if encr_func is not None and value is not None:
                value = encr_func(value)
            list.__setitem__(self, index, value)
        else:
            # For dict arrays, value should be an EncryptedObject or dict
            list.__setitem__(self, index, value)

    def append(self, value):
        element_type = object.__getattribute__(self, "_element_type")
        encr_func = object.__getattribute__(self, "_encr_func")

        if element_type == "string":
            if encr_func is not None and value is not None:
                value = encr_func(value)
        list.append(self, value)

    def extend(self, values):
        for value in values:
            self.append(value)

    def insert(self, index, value):
        element_type = object.__getattribute__(self, "_element_type")
        encr_func = object.__getattribute__(self, "_encr_func")

        if element_type == "string":
            if encr_func is not None and value is not None:
                value = encr_func(value)
        list.insert(self, index, value)

    def get_raw(self, index):
        """Get raw (encrypted) value without decryption."""
        return list.__getitem__(self, index)

    def __iter__(self):
        """Iterate over elements, decrypting string elements."""
        element_type = object.__getattribute__(self, "_element_type")
        decr_func = object.__getattribute__(self, "_decr_func")

        for i in range(len(self)):
            value = list.__getitem__(self, i)
            if element_type == "string" and decr_func is not None and value is not None:
                yield decr_func(value)
            else:
                yield value


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
                if isinstance(v.type, dict):
                    for flat_key in cls._flatten_dict_keys(v.type, k):
                        field_names.append(flat_key)
            return field_names
        if issubclass(cls, MappedClass):
            fields: list[tuple[str, FieldProperty]] = list(cls.query.mapper.property_index.items())
            field_names = []
            for k, v in fields:
                if v.field.type in (ming.schema.Deprecated,):
                    continue
                field_names.append(k)
            return field_names
        raise NotImplementedError("Unexpected class type. You must implement `field_names` as a @classproperty in your mixin implementation.")

    @classmethod
    def _flatten_dict_keys(cls, d: dict | ming.schema.Object, current_path: str = '') -> Iterator[str]:
        if not isinstance(d, dict):
            raise ValueError(f'Value must be a dict, got {d!r}')

        for k, v in d.items():
            if current_path:
                new_path = f'{current_path}.{k}'
            else:
                new_path = k
            yield new_path
            if isinstance(v, dict):
                yield from cls._flatten_dict_keys(v, new_path)

    @classproperty
    def _array_encrypted_field_map(cls) -> dict[str, set[str]]:
        """Returns a mapping of array field paths to sets of encrypted field names within those arrays.

        For example, if a Document has:
            contacts = Field([{'name': str, 'email': str, 'email_encrypted': S.Binary}])

        This method would return:
            {'contacts': {'email'}}

        Which tells encrypt_some_fields to encrypt the 'email' field in each element of the 'contacts' array.
        """
        from ming.declarative import Document
        from ming.odm.declarative import MappedClass

        result: dict[str, set[str]] = {}

        if issubclass(cls, Document):
            fields: list[tuple[str, Field]] = list(cls.m.field_index.items())
            for field_name, field_obj in fields:
                cls._collect_array_encrypted_fields(field_name, field_obj.type, result)
        elif issubclass(cls, MappedClass):
            # MappedClass uses FieldProperty which wraps Field
            from ming.odm.property import FieldProperty

            fields = list(cls.query.mapper.property_index.items())
            for field_name, prop in fields:
                if isinstance(prop, FieldProperty):
                    cls._collect_array_encrypted_fields(
                        field_name, prop.field.type, result
                    )
        return result

    @classmethod
    def _collect_array_encrypted_fields(
        cls, path: str, schema_type, result: dict[str, set[str]]
    ):
        """Recursively collect encrypted fields within array schemas.

        :param path: Current path to this schema element
        :param schema_type: The schema type (could be list, dict, etc.)
        :param result: Dictionary to populate with path -> encrypted fields mapping
        """
        if isinstance(schema_type, list) and schema_type:
            # Array schema - examine element type
            elem_type = schema_type[0]
            if isinstance(elem_type, dict):
                # Array of dicts - find encrypted fields
                encrypted_fields = set()
                for k in elem_type.keys():
                    if k.endswith("_encrypted"):
                        decrypted_key = k.replace("_encrypted", "")
                        encrypted_fields.add(decrypted_key)
                if encrypted_fields:
                    result[path] = encrypted_fields
                # Also recurse into nested arrays within the dict schema
                for k, v in elem_type.items():
                    cls._collect_array_encrypted_fields(f"{path}[].{k}", v, result)
        elif isinstance(schema_type, dict):
            # Dict schema - recurse into it looking for nested arrays
            for k, v in schema_type.items():
                nested_path = f"{path}.{k}" if path else k
                cls._collect_array_encrypted_fields(nested_path, v, result)

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
        encrypted_data = copy.deepcopy(data)
        for fld in cls.decrypted_field_names():
            if fld in encrypted_data:
                val = encrypted_data.pop(fld)
                if isinstance(val, list):
                    # Handle array of values to encrypt
                    encrypted_data[f"{fld}_encrypted"] = cls._encrypt_array(val)
                else:
                    encrypted_data[f"{fld}_encrypted"] = cls.encr(val)
            else:
                val = cls._pop_dict_path_value(encrypted_data, fld)
                if val is not None:
                    if isinstance(val, list):
                        cls._set_dict_path_value(
                            encrypted_data, f"{fld}_encrypted", cls._encrypt_array(val)
                        )
                    else:
                        cls._set_dict_path_value(
                            encrypted_data, f"{fld}_encrypted", cls.encr(val)
                        )

        # Also process nested arrays with encrypted dict elements
        cls._encrypt_nested_arrays(encrypted_data)
        return encrypted_data

    @classmethod
    def _encrypt_array(cls, arr: list) -> list:
        """Encrypt all elements in an array.

        :param arr: List of values to encrypt (strings or dicts with encrypted fields)
        :return: List of encrypted values
        """
        if not arr:
            return arr

        first_elem = arr[0]
        if isinstance(first_elem, str):
            # Array of strings - encrypt each
            return [cls.encr(val) if val is not None else None for val in arr]
        elif isinstance(first_elem, dict):
            # Array of dicts - recursively encrypt fields in each dict
            return [
                cls.encrypt_some_fields(val) if isinstance(val, dict) else val
                for val in arr
            ]
        else:
            return arr

    @classmethod
    def _encrypt_nested_arrays(cls, data: dict, current_path: str = ""):
        """Recursively process nested dictionaries and arrays to encrypt fields.

        :param data: Dictionary to process in place
        :param current_path: The current path in the data structure (for looking up array schemas)
        """
        array_field_map = cls._array_encrypted_field_map

        for key, val in list(data.items()):
            # Build the full path for this key
            if current_path:
                full_path = f"{current_path}.{key}"
            else:
                full_path = key

            if isinstance(val, dict):
                # Process encrypted fields in nested dicts
                cls._encrypt_dict_fields(val, full_path, array_field_map)
                cls._encrypt_nested_arrays(val, full_path)
            elif isinstance(val, list) and val:
                first_elem = val[0]
                if isinstance(first_elem, dict):
                    # Array of dicts - look up which fields should be encrypted from schema
                    encrypted_fields = array_field_map.get(full_path, set())

                    # Encrypt fields in each dict element
                    for i, item in enumerate(val):
                        if isinstance(item, dict):
                            cls._encrypt_dict_fields_with_map(item, encrypted_fields)
                            # Recurse into nested structures within array elements
                            # Use full_path as the base for looking up nested arrays
                            cls._encrypt_nested_arrays_in_dict(
                                item, full_path, array_field_map
                            )

    @classmethod
    def _encrypt_nested_arrays_in_dict(
        cls, data: dict, array_path: str, array_field_map: dict[str, set[str]]
    ):
        """Recursively encrypt nested arrays within a dict that is inside an array.

        :param data: Dictionary (element of an array) to process in place
        :param array_path: The path to the parent array
        :param array_field_map: Map of array paths to their encrypted fields
        """
        for key, val in list(data.items()):
            # For nested arrays, the path pattern is "parent_array[].key"
            nested_path = f"{array_path}[].{key}"

            if isinstance(val, dict):
                # Process encrypted fields in nested dicts
                cls._encrypt_dict_fields(val, nested_path, array_field_map)
                # Continue recursing
                for k2, v2 in list(val.items()):
                    if isinstance(v2, list) and v2 and isinstance(v2[0], dict):
                        inner_path = f"{nested_path}.{k2}"
                        encrypted_fields = array_field_map.get(inner_path, set())
                        for item in v2:
                            if isinstance(item, dict):
                                cls._encrypt_dict_fields_with_map(
                                    item, encrypted_fields
                                )
            elif isinstance(val, list) and val:
                first_elem = val[0]
                if isinstance(first_elem, dict):
                    # Nested array of dicts
                    encrypted_fields = array_field_map.get(nested_path, set())
                    for item in val:
                        if isinstance(item, dict):
                            cls._encrypt_dict_fields_with_map(item, encrypted_fields)

    @classmethod
    def _encrypt_dict_fields(
        cls, d: dict, path: str = "", array_field_map: dict[str, set[str]] | None = None
    ):
        """Encrypt fields in a dictionary that have '_encrypted' counterparts.

        This method modifies the dictionary in place.

        :param d: Dictionary to process
        :param path: Current path in the structure (for looking up nested arrays in schema)
        :param array_field_map: Map of array paths to their encrypted fields
        """
        # Find the encrypted field map for this dict by looking at the data itself
        # (for nested dicts that might have _encrypted keys)
        encrypted_fields = set()
        for key in list(d.keys()):
            if key.endswith("_encrypted"):
                decrypted_key = key.replace("_encrypted", "")
                encrypted_fields.add(decrypted_key)

        cls._encrypt_dict_fields_with_map(d, encrypted_fields)

    @classmethod
    def _encrypt_dict_fields_with_map(cls, d: dict, encrypted_fields: set):
        """Encrypt specified fields in a dictionary.

        This method modifies the dictionary in place.

        :param d: Dictionary to process
        :param encrypted_fields: Set of decrypted field names that should be encrypted
        """
        for decrypted_key in encrypted_fields:
            if decrypted_key in d:
                val = d.pop(decrypted_key)
                encrypted_key = f"{decrypted_key}_encrypted"
                d[encrypted_key] = cls.encr(val) if val is not None else None

    def decrypt_some_fields(self) -> dict:
        """
        Returns a `dict` with raw data. Removes encrypted fields and replaces them with decrypted data. Useful for json.
        """
        decrypted_data = dict()
        encrypted_field_names = set(self.encrypted_field_names())
        decrypted_field_names = set(self.decrypted_field_names())

        for k in self._field_names:
            if "." in k:
                # Skip nested fields - they are handled when processing their parent
                continue

            if k.endswith("_encrypted"):
                # Top-level encrypted field: add decrypted version
                k_decrypted = k.replace("_encrypted", "")
                val = getattr(self, k)
                if isinstance(val, (list, EncryptedArray)):
                    # Handle encrypted array - decrypt each element
                    decrypted_data[k_decrypted] = self._decrypt_array(val)
                else:
                    decrypted_data[k_decrypted] = getattr(self, k_decrypted)
            else:
                val = getattr(self, k)
                if isinstance(val, dict):
                    # Handle nested dictionaries - need to decrypt nested encrypted fields
                    decrypted_data[k] = self._decrypt_nested_dict(
                        val, k, encrypted_field_names, decrypted_field_names
                    )
                elif isinstance(val, (list, EncryptedArray)):
                    # Handle arrays - may contain encrypted dicts
                    decrypted_data[k] = self._decrypt_array_field(
                        val, k, encrypted_field_names, decrypted_field_names
                    )
                else:
                    decrypted_data[k] = val
        return decrypted_data

    def _decrypt_array(self, arr: list) -> list:
        """Decrypt an array of encrypted values.

        :param arr: List of encrypted values (Binary for strings, or EncryptedObjects)
        :return: List of decrypted values
        """
        if not arr:
            return arr

        result = []
        for val in arr:
            if isinstance(val, bytes):
                # Encrypted string
                result.append(self.decr(val) if val is not None else None)
            elif isinstance(val, (dict, EncryptedObject)):
                # Dict with encrypted fields - recursively decrypt
                encrypted_field_names = set(self.encrypted_field_names())
                decrypted_field_names = set(self.decrypted_field_names())
                result.append(
                    self._decrypt_nested_dict(
                        val, "", encrypted_field_names, decrypted_field_names
                    )
                )
            else:
                result.append(val)
        return result

    def _decrypt_array_field(
        self,
        arr: list,
        parent_path: str,
        encrypted_field_names: set,
        decrypted_field_names: set,
    ) -> list:
        """Decrypt an array field that may contain dicts with encrypted fields.

        :param arr: The array to process
        :param parent_path: The dot-separated path to this array from the root
        :param encrypted_field_names: set of all encrypted field names
        :param decrypted_field_names: set of all decrypted field names
        :return: List of decrypted values
        """
        if not arr:
            return arr

        result = []
        for val in arr:
            if isinstance(val, (dict, EncryptedObject)):
                result.append(
                    self._decrypt_nested_dict(
                        val, parent_path, encrypted_field_names, decrypted_field_names
                    )
                )
            else:
                result.append(val)
        return result

    def _decrypt_nested_dict(
        self,
        data: dict,
        parent_path: str,
        encrypted_field_names: set,
        decrypted_field_names: set,
    ) -> dict:
        """
        Recursively processes a nested dictionary, decrypting encrypted fields and
        excluding the encrypted versions from the output.

        :param data: the nested dictionary to process
        :param parent_path: the dot-separated path to this dictionary from the root
        :param encrypted_field_names: set of all encrypted field names (with dotted paths)
        :param decrypted_field_names: set of all decrypted field names (with dotted paths)
        :return: a new dictionary with encrypted fields replaced by their decrypted counterparts
        """
        result = {}
        for key, val in data.items():
            if parent_path:
                full_path = f"{parent_path}.{key}"
            else:
                full_path = key

            if full_path in encrypted_field_names:
                # This is an encrypted field - add decrypted version instead
                decrypted_key = key.replace("_encrypted", "")
                if isinstance(val, (list, EncryptedArray)):
                    # Encrypted array
                    result[decrypted_key] = self._decrypt_array(val)
                else:
                    decrypted_val = self.decr(val) if val is not None else None
                    result[decrypted_key] = decrypted_val
            elif full_path in decrypted_field_names:
                # Skip decrypted field placeholders (they don't exist in stored data)
                continue
            elif key.endswith("_encrypted"):
                # Handle encrypted fields that might not be in the field_names set
                # (e.g., in nested dicts of arrays)
                decrypted_key = key.replace("_encrypted", "")
                if isinstance(val, (list, EncryptedArray)):
                    result[decrypted_key] = self._decrypt_array(val)
                else:
                    decrypted_val = self.decr(val) if val is not None else None
                    result[decrypted_key] = decrypted_val
            elif isinstance(val, dict):
                # Recurse into nested dictionaries
                result[key] = self._decrypt_nested_dict(
                    val, full_path, encrypted_field_names, decrypted_field_names
                )
            elif isinstance(val, (list, EncryptedArray)):
                # Handle arrays within nested dicts
                result[key] = self._decrypt_array_field(
                    val, full_path, encrypted_field_names, decrypted_field_names
                )
            else:
                # Regular field - copy as-is
                result[key] = val
        return result

    @classmethod
    def _get_dict_path_value(cls, data: dict, path: str):
        """
        Given a dictionary and a dot-separated path, returns the value at that path without removing it.

        :param data: a dictionary to search
        :param path: a dot-separated path to the value to return
        :return: the value at the specified path, or None if not found
        """
        keys = path.split(".")
        val = data
        try:
            for key in keys:
                val = val[key]
            return val
        except (KeyError, TypeError):
            return None

    @classmethod
    def _pop_dict_path_value(cls, data: dict, path: str):
        """
        Given a dictionary and a dot-separated path, returns the value at that path.

        :param data: a dictionary to search
        :param path: a dot-separated path to the value to return
        :return: the value at the specified path
        """
        keys = path.split(".")
        val = data
        try:
            for key in keys[:-1]:
                val = val[key]

            v = val.pop(keys[-1])
            return v
        except KeyError:
            return None

    @classmethod
    def _set_dict_path_value(cls, data: dict, path: str, value):
        """
        Given a dictionary and a dot-separated path, sets the value at that path.

        :param data: a dictionary to modify
        :param path: a dot-separated path to the value to set
        :param value: the value to set at the specified path
        """
        if "." not in path:
            data[path] = value
            return
        keys = path.split(".")
        d = data
        for key in keys[:-1]:
            if key not in d or not isinstance(d[key], dict):
                d[key] = {}
            d = d[key]
        d[keys[-1]] = value
