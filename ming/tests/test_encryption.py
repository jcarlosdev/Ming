from configparser import ConfigParser
import os
from unittest import SkipTest, TestCase

import ming
from ming import create_datastore, Document, Field, schema as S
from ming.odm import (
    session,
    ODMSession,
    Mapper,
    MappedClass,
    FieldProperty,
    DecryptedProperty,
)
from ming.encryption import DecryptedField
from ming.odm.odmsession import ThreadLocalODMSession

from . import make_encryption_key

InvalidClass = Exception


def import_formencode():
    try:
        from formencode import Invalid

        global InvalidClass
        InvalidClass = Invalid
    except ImportError:
        raise SkipTest("Need to install FormEncode to use ``ming.configure``")


class TestEncryptionConfig(TestCase):
    LOCAL_KEY = make_encryption_key("test local key")

    def setUp(self):
        import_formencode()

    def _parse_config(self, body: str):
        config_lines = [
            l.strip()
            for l in [
                "[app:main]",
            ]
            + body.split("\n")
            if l
        ]

        config = ConfigParser()
        config.read_string("\n".join(config_lines))
        ming.configure(**config["app:main"])
        return config

    def test_validation_good(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
        """

        self._parse_config(config_str)
        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertIsNotNone(encryption)
        self.assertEqual(encryption.kms_providers, {"local": {"key": self.LOCAL_KEY}})
        self.assertEqual(encryption.key_vault_namespace, "encryption_test.dataKeyVault")
        self.assertEqual(
            encryption.provider_options, {"local": {"key_alt_names": ["datakey_test1"]}}
        )

    def test_validation_key_alt_names(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = ["datakey_test1"]
        """

        self._parse_config(config_str)
        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertEqual(
            encryption.provider_options, {"local": {"key_alt_names": ["datakey_test1"]}}
        )

    def test_validation_key_alt_names2(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = ["datakey_test1", "datakey_test2"]
        """

        self._parse_config(config_str)
        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertEqual(
            encryption.provider_options,
            {"local": {"key_alt_names": ["datakey_test1", "datakey_test2"]}},
        )

    def test_validation_key_alt_names3(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1, datakey_test2
        """

        self._parse_config(config_str)
        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertEqual(
            encryption.provider_options,
            {"local": {"key_alt_names": ["datakey_test1", "datakey_test2"]}},
        )

    def test_validation_key_alt_names4(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = "datakey_test1", "datakey_test2"
        """

        self._parse_config(config_str)
        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertEqual(
            encryption.provider_options,
            {"local": {"key_alt_names": ["datakey_test1", "datakey_test2"]}},
        )

    def test_validation_empty(self):
        self._parse_config(f"""ming.maindb.uri = mongo://host/maindb""")

        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertIsNone(encryption)

    def test_validation_empty_mim_auto_encryption(self):
        self._parse_config(f"""ming.maindb.uri = mim://host/maindb""")

        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertIsNotNone(encryption.kms_providers["local"]["key"])
        self.assertEqual(
            encryption.key_vault_namespace, "encryption_test.coll_key_vault_test"
        )
        self.assertEqual(
            encryption.provider_options, {"local": {"key_alt_names": ["datakeyName"]}}
        )

    def test_validation_bad_missing(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(
            set(["key_vault_namespace", "provider_options"]), set(error_dict.keys())
        )
        self.assertIn(
            "Missing required encryption configuration field ",
            str(error_dict["key_vault_namespace"]),
        )
        self.assertIn(
            "Missing required encryption configuration field ",
            str(error_dict["provider_options"]),
        )

    def test_validation_bad_missing2(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(
            set(["kms_providers", "provider_options"]), set(error_dict.keys())
        )
        self.assertIn(
            "Missing required encryption configuration field ",
            str(error_dict["kms_providers"]),
        )
        self.assertIn(
            "Missing required encryption configuration field ",
            str(error_dict["provider_options"]),
        )

    def test_validation_bad_missing3(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(
            set(["kms_providers", "key_vault_namespace"]), set(error_dict.keys())
        )
        self.assertIn(
            "Missing required encryption configuration field ",
            str(error_dict["kms_providers"]),
        )
        self.assertIn(
            "Missing required encryption configuration field ",
            str(error_dict["key_vault_namespace"]),
        )

    def test_validation_bad_extra(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.extra_nonsense = foo
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(set(["extra_nonsense"]), set(error_dict.keys()))
        self.assertIn(
            "Unexpected encryption configuration field 'extra_nonsense'",
            str(error_dict["extra_nonsense"]),
        )

    def test_validation_bad_empty(self):
        self._parse_config(f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers = 
            ming.maindb.encryption.key_vault_namespace = 
            ming.maindb.encryption.provider_options = 
        """)
        encryption = ming.Session.by_name("maindb").bind.encryption
        self.assertEqual(encryption.kms_providers, "")
        self.assertEqual(encryption.provider_options, "")
        self.assertEqual(encryption.provider_options, "")

    def test_validation_bad_kms_providers(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.BAD.key = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(set(["kms_providers"]), set(error_dict.keys()))
        self.assertIn("Invalid kms_provider(s)", str(error_dict["kms_providers"]))

    def test_validation_bad_kms_provider_local(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.foo = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(set(["kms_providers"]), set(error_dict.keys()))
        self.assertIn("kms_provider 'local' requires", str(error_dict["kms_providers"]))

    def test_validation_bad_provider_options_local(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
                ming.maindb.encryption.provider_options.local.foo = bar'
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(set(["provider_options"]), set(error_dict.keys()))
        self.assertIn("requires provider_options", str(error_dict["provider_options"]))

    def test_validation_bad_key_vault_namespace(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f"""
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test_dataKeyVault
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            """)
        error_dict = e.exception.error_dict["encryption"].error_dict
        self.assertEqual(set(["key_vault_namespace"]), set(error_dict.keys()))
        self.assertIn(
            "Invalid key_vault_namespace", str(error_dict["key_vault_namespace"])
        )


class TestDocumentEncryption(TestCase):
    DATASTORE = "mim://host/test_db"

    def setUp(self):
        import_formencode()

        ming.configure(
            **{
                "ming.test_db.uri": self.DATASTORE,
                "ming.test_db.encryption.kms_providers.local.key": make_encryption_key(
                    self.__class__.__name__
                ),
                "ming.test_db.encryption.key_vault_namespace": "encryption_test.coll_key_vault_test",
                "ming.test_db.encryption.provider_options.local.key_alt_names": '["test_datakey_1"]',
            }
        )

    def tearDown(self):
        session = ming.Session.by_name("test_db")
        session.bind.conn.drop_database("test_db")
        session.bind.conn.drop_database("encryption_test")

    def test_document(self):
        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc"
                session = ming.Session.by_name("test_db")
                indexes = [("name_encrypted",)]

            _id = Field(S.Anything)
            name = DecryptedField(str, "name_encrypted")
            name_encrypted = Field(S.Binary)
            other = Field(str)
            deprecated = FieldProperty(S.Deprecated)

        doc = TestDoc.make_encr(dict(_id=1, name="Jerome", other="foo"))
        doc.m.save()

        self.assertEqual(doc.name, "Jerome")
        self.assertIsInstance(doc.name, str)
        self.assertIsInstance(doc.name_encrypted, bytes)
        self.assertEqual(doc.name_encrypted, TestDoc.encr("Jerome"))
        self.assertEqual(doc.name, TestDoc.decr(doc.name_encrypted))

        doc.name = "Jessie"
        doc.m.save()
        self.assertEqual(doc.name, "Jessie")
        self.assertEqual(doc.name_encrypted, TestDoc.encr("Jessie"))
        self.assertEqual(doc.name, TestDoc.decr(doc.name_encrypted))

        self.assertEqual(
            doc.decrypt_some_fields(), {"_id": 1, "name": "Jessie", "other": "foo"}
        )
        self.assertIsNotNone(TestDoc.m.get(name_encrypted=TestDoc.encr("Jessie")))

        self.assertEqual(set(doc.encrypted_field_names()), set(["name_encrypted"]))
        self.assertEqual(set(doc.decrypted_field_names()), set(["name"]))
        self.assertEqual(set(doc._field_names), set(["_id", "name_encrypted", "other"]))

        # allowed to save None to it
        doc.name = None
        doc.m.save()
        self.assertEqual(doc.name, None)
        self.assertEqual(doc.name_encrypted, None)


class TestDocumentEncryptionMimAutoSettings(TestDocumentEncryption):
    def setUp(self):
        # replace super() NOT using it
        import_formencode()

        ming.configure(
            **{
                "ming.test_db.uri": self.DATASTORE,
                # mim encryption settings should come automatically from configure_from_nested_dict
            }
        )


class TestDocumentEncryptionReal(TestDocumentEncryption):
    DATASTORE = f"mongodb://localhost/test_ming_TestDocumentReal_{os.getpid()}?serverSelectionTimeoutMS=100"


class TestDictFieldEncryption(TestCase):
    """Tests for encrypt_some_fields and decrypt_some_fields with nested dictionary fields."""

    DATASTORE = "mim://host/test_db"

    def setUp(self):
        import_formencode()

        ming.configure(
            **{
                "ming.test_db.uri": self.DATASTORE,
                "ming.test_db.encryption.kms_providers.local.key": make_encryption_key(
                    self.__class__.__name__
                ),
                "ming.test_db.encryption.key_vault_namespace": "encryption_test.coll_key_vault_test",
                "ming.test_db.encryption.provider_options.local.key_alt_names": '["test_datakey_1"]',
            }
        )

    def tearDown(self):
        session = ming.Session.by_name("test_db")
        session.bind.conn.drop_database("test_db")
        session.bind.conn.drop_database("encryption_test")

    def test_encrypt_some_fields_top_level(self):
        """Test encrypt_some_fields with a top-level dict field containing encrypted fields."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_top_level"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "email": DecryptedField(str, "email_encrypted"),
                    "email_encrypted": Field(S.Binary),
                    "display_name": str,
                }
            )

        # Test encrypting field inside a dict
        data = {
            "_id": 1,
            "profile": {"email": "alice@example.com", "display_name": "Alice"},
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)

        self.assertNotIn("email", encrypted_data["profile"])
        self.assertIn("email_encrypted", encrypted_data["profile"])
        self.assertEqual(
            encrypted_data["profile"]["email_encrypted"],
            TestDoc.encr("alice@example.com"),
        )
        self.assertEqual(encrypted_data["profile"]["display_name"], "Alice")
        self.assertEqual(encrypted_data["_id"], 1)

    def test_encrypt_some_fields_nested_one_level(self):
        """Test encrypt_some_fields with two levels of nested dictionary."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_nested"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "contact": {
                        "email": DecryptedField(str, "email_encrypted"),
                        "email_encrypted": Field(S.Binary),
                        "phone": str,
                    },
                }
            )

        # Test encrypting field nested two levels deep
        data = {
            "_id": 1,
            "company": {
                "name": "Acme Corp",
                "contact": {"email": "info@acme.com", "phone": "555-1234"},
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)

        self.assertNotIn("email", encrypted_data["company"]["contact"])
        self.assertIn("email_encrypted", encrypted_data["company"]["contact"])
        self.assertEqual(
            encrypted_data["company"]["contact"]["email_encrypted"],
            TestDoc.encr("info@acme.com"),
        )
        self.assertEqual(encrypted_data["company"]["contact"]["phone"], "555-1234")
        self.assertEqual(encrypted_data["company"]["name"], "Acme Corp")
        self.assertEqual(encrypted_data["_id"], 1)

    def test_decrypt_some_fields_top_level(self):
        """Test decrypt_some_fields with a top-level dict field containing encrypted fields."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_decrypt_top"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "email": DecryptedField(str, "email_encrypted"),
                    "email_encrypted": Field(S.Binary),
                    "display_name": str,
                }
            )

        # Create document with encrypted nested field
        data = {
            "_id": 1,
            "profile": {"email": "bob@example.com", "display_name": "Bob"},
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)
        doc = TestDoc(encrypted_data)
        doc.m.save()

        # Reload the document
        doc = TestDoc.m.get(_id=1)

        # Test decrypting nested field
        decrypted_data = doc.decrypt_some_fields()

        self.assertIn("profile", decrypted_data)
        profile = decrypted_data["profile"]
        self.assertIn("email", profile)
        self.assertNotIn("email_encrypted", profile)
        self.assertEqual(profile["email"], "bob@example.com")
        self.assertEqual(profile["display_name"], "Bob")
        self.assertEqual(decrypted_data["_id"], 1)

    def test_decrypt_some_fields_nested_one_level(self):
        """Test decrypt_some_fields with two levels of nested dictionary."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_decrypt_nested"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "contact": {
                        "email": DecryptedField(str, "email_encrypted"),
                        "email_encrypted": Field(S.Binary),
                        "phone": str,
                    },
                }
            )

        # Create document with encrypted nested field
        data = {
            "_id": 1,
            "company": {
                "name": "Acme Corp",
                "contact": {"email": "info@acme.com", "phone": "555-1234"},
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)
        doc = TestDoc(encrypted_data)
        doc.m.save()

        # Reload the document
        doc = TestDoc.m.get(_id=1)

        # Test decrypting nested field
        decrypted_data = doc.decrypt_some_fields()

        self.assertIn("company", decrypted_data)
        self.assertEqual(decrypted_data["company"]["name"], "Acme Corp")
        contact = decrypted_data["company"]["contact"]
        self.assertIn("email", contact)
        self.assertNotIn("email_encrypted", contact)
        self.assertEqual(contact["email"], "info@acme.com")
        self.assertEqual(contact["phone"], "555-1234")

    def test_encrypt_decrypt_roundtrip_top_level(self):
        """Test that encrypt then decrypt returns original data for a dict field."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_roundtrip_top"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            settings = Field(
                {
                    "api_key": DecryptedField(str, "api_key_encrypted"),
                    "api_key_encrypted": Field(S.Binary),
                    "enabled": bool,
                }
            )

        original_api_key = "secret-api-key-123"
        original_enabled = True
        original_data = {
            "_id": 1,
            "settings": {"api_key": original_api_key, "enabled": original_enabled},
        }

        # Encrypt, save, reload, decrypt
        encrypted_data = TestDoc.encrypt_some_fields(original_data)
        doc = TestDoc(encrypted_data)
        doc.m.save()
        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(decrypted_data["settings"]["api_key"], original_api_key)
        self.assertEqual(decrypted_data["settings"]["enabled"], original_enabled)
        self.assertEqual(decrypted_data["_id"], original_data["_id"])

    def test_encrypt_decrypt_roundtrip_nested(self):
        """Test that encrypt then decrypt returns original data for two levels of nesting."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_roundtrip_nested"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            organization = Field(
                {
                    "name": str,
                    "admin": {
                        "username": str,
                        "password": DecryptedField(str, "password_encrypted"),
                        "password_encrypted": Field(S.Binary),
                    },
                }
            )

        original_name = "TechCorp"
        original_username = "admin"
        original_password = "super-secret-password"
        original_data = {
            "_id": 1,
            "organization": {
                "name": original_name,
                "admin": {"username": original_username, "password": original_password},
            },
        }

        # Encrypt, save, reload, decrypt
        encrypted_data = TestDoc.encrypt_some_fields(original_data)
        doc = TestDoc(encrypted_data)
        doc.m.save()
        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(decrypted_data["organization"]["name"], original_name)
        self.assertEqual(
            decrypted_data["organization"]["admin"]["username"], original_username
        )
        self.assertEqual(
            decrypted_data["organization"]["admin"]["password"], original_password
        )

    def test_encrypt_some_fields_with_none_value(self):
        """Test encrypt_some_fields handles None values correctly."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_none"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            name = DecryptedField(str, "name_encrypted")
            name_encrypted = Field(S.Binary)

        data = {"_id": 1, "name": None}
        encrypted_data = TestDoc.encrypt_some_fields(data)

        self.assertNotIn("name", encrypted_data)
        self.assertIn("name_encrypted", encrypted_data)
        self.assertIsNone(encrypted_data["name_encrypted"])

    def test_decrypt_some_fields_with_none_value(self):
        """Test decrypt_some_fields handles None values correctly."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_decrypt_none"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            name = DecryptedField(str, "name_encrypted")
            name_encrypted = Field(S.Binary)

        doc = TestDoc.make_encr(dict(_id=1, name=None))
        doc.m.save()

        decrypted_data = doc.decrypt_some_fields()
        self.assertIn("name", decrypted_data)
        self.assertIsNone(decrypted_data["name"])


class TestArrayFieldEncryption(TestCase):
    """Tests for encrypt_some_fields and decrypt_some_fields with array fields."""

    DATASTORE = "mim://host/test_db"

    def setUp(self):
        import_formencode()

        ming.configure(
            **{
                "ming.test_db.uri": self.DATASTORE,
                "ming.test_db.encryption.kms_providers.local.key": make_encryption_key(
                    self.__class__.__name__
                ),
                "ming.test_db.encryption.key_vault_namespace": "encryption_test.coll_key_vault_test",
                "ming.test_db.encryption.provider_options.local.key_alt_names": '["test_datakey_1"]',
            }
        )

    def tearDown(self):
        session = ming.Session.by_name("test_db")
        session.bind.conn.drop_database("test_db")
        session.bind.conn.drop_database("encryption_test")

    # ========== Array of strings - one level of nesting ==========

    def test_encrypt_some_fields_array_strings_one_level(self):
        """Test encrypt_some_fields with array of strings inside a dict field."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_str_1"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "name": str,
                    "emails": DecryptedField(list, "emails_encrypted"),
                    "emails_encrypted": Field([S.Binary]),
                }
            )

        data = {
            "_id": 1,
            "profile": {
                "name": "Alice",
                "emails": ["alice@example.com", "alice.work@example.com"],
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)

        self.assertNotIn("emails", encrypted_data["profile"])
        self.assertIn("emails_encrypted", encrypted_data["profile"])
        self.assertIsInstance(encrypted_data["profile"]["emails_encrypted"], list)
        self.assertEqual(len(encrypted_data["profile"]["emails_encrypted"]), 2)
        self.assertEqual(
            encrypted_data["profile"]["emails_encrypted"][0],
            TestDoc.encr("alice@example.com"),
        )
        self.assertEqual(
            encrypted_data["profile"]["emails_encrypted"][1],
            TestDoc.encr("alice.work@example.com"),
        )
        self.assertEqual(encrypted_data["profile"]["name"], "Alice")

    def test_decrypt_some_fields_array_strings_one_level(self):
        """Test decrypt_some_fields with array of strings inside a dict field."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_str_decrypt_1"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "name": str,
                    "emails": DecryptedField(list, "emails_encrypted"),
                    "emails_encrypted": Field([S.Binary]),
                }
            )

        data = {
            "_id": 1,
            "profile": {
                "name": "Bob",
                "emails": ["bob@example.com", "bob.work@example.com"],
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)
        doc = TestDoc(encrypted_data)
        doc.m.save()

        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertIn("profile", decrypted_data)
        profile = decrypted_data["profile"]
        self.assertIn("emails", profile)
        self.assertNotIn("emails_encrypted", profile)
        self.assertEqual(profile["emails"], ["bob@example.com", "bob.work@example.com"])
        self.assertEqual(profile["name"], "Bob")

    def test_encrypt_decrypt_roundtrip_array_strings_one_level(self):
        """Test roundtrip for array of strings inside a dict field."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_str_rt_1"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "name": str,
                    "emails": DecryptedField(list, "emails_encrypted"),
                    "emails_encrypted": Field([S.Binary]),
                }
            )

        original_emails = ["charlie@example.com", "charlie.work@example.com"]
        original_data = {
            "_id": 1,
            "profile": {"name": "Charlie", "emails": original_emails},
        }

        encrypted_data = TestDoc.encrypt_some_fields(original_data)
        doc = TestDoc(encrypted_data)
        doc.m.save()
        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(decrypted_data["profile"]["emails"], original_emails)
        self.assertEqual(decrypted_data["profile"]["name"], "Charlie")

    # ========== Array of strings - two levels of nesting ==========

    def test_encrypt_some_fields_array_strings_two_levels(self):
        """Test encrypt_some_fields with array of strings inside nested dicts."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_str_2"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "contact": {
                        "emails": DecryptedField(list, "emails_encrypted"),
                        "emails_encrypted": Field([S.Binary]),
                        "phone": str,
                    },
                }
            )

        data = {
            "_id": 1,
            "company": {
                "name": "Acme Corp",
                "contact": {
                    "emails": ["info@acme.com", "support@acme.com"],
                    "phone": "555-1234",
                },
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)

        self.assertNotIn("emails", encrypted_data["company"]["contact"])
        self.assertIn("emails_encrypted", encrypted_data["company"]["contact"])
        self.assertEqual(
            len(encrypted_data["company"]["contact"]["emails_encrypted"]), 2
        )
        self.assertEqual(
            encrypted_data["company"]["contact"]["emails_encrypted"][0],
            TestDoc.encr("info@acme.com"),
        )
        self.assertEqual(
            encrypted_data["company"]["contact"]["emails_encrypted"][1],
            TestDoc.encr("support@acme.com"),
        )
        self.assertEqual(encrypted_data["company"]["contact"]["phone"], "555-1234")
        self.assertEqual(encrypted_data["company"]["name"], "Acme Corp")

    def test_decrypt_some_fields_array_strings_two_levels(self):
        """Test decrypt_some_fields with array of strings inside nested dicts."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_str_decrypt_2"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "contact": {
                        "emails": DecryptedField(list, "emails_encrypted"),
                        "emails_encrypted": Field([S.Binary]),
                        "phone": str,
                    },
                }
            )

        data = {
            "_id": 1,
            "company": {
                "name": "TechCorp",
                "contact": {
                    "emails": ["info@tech.com", "support@tech.com"],
                    "phone": "555-5678",
                },
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)
        doc = TestDoc(encrypted_data)
        doc.m.save()

        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        contact = decrypted_data["company"]["contact"]
        self.assertIn("emails", contact)
        self.assertNotIn("emails_encrypted", contact)
        self.assertEqual(contact["emails"], ["info@tech.com", "support@tech.com"])
        self.assertEqual(contact["phone"], "555-5678")
        self.assertEqual(decrypted_data["company"]["name"], "TechCorp")

    def test_encrypt_decrypt_roundtrip_array_strings_two_levels(self):
        """Test roundtrip for array of strings inside nested dicts."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_str_rt_2"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "contact": {
                        "emails": DecryptedField(list, "emails_encrypted"),
                        "emails_encrypted": Field([S.Binary]),
                        "phone": str,
                    },
                }
            )

        original_emails = ["sales@startup.com", "dev@startup.com"]
        original_data = {
            "_id": 1,
            "company": {
                "name": "Startup Inc",
                "contact": {"emails": original_emails, "phone": "555-9999"},
            },
        }

        encrypted_data = TestDoc.encrypt_some_fields(original_data)
        doc = TestDoc(encrypted_data)
        doc.m.save()
        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(
            decrypted_data["company"]["contact"]["emails"], original_emails
        )
        self.assertEqual(decrypted_data["company"]["contact"]["phone"], "555-9999")
        self.assertEqual(decrypted_data["company"]["name"], "Startup Inc")

    # ========== Array of dicts - one level of nesting ==========

    def test_encrypt_some_fields_array_dicts_one_level(self):
        """Test encrypt_some_fields with array of dicts containing encrypted fields inside a dict."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_dict_1"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "name": str,
                    "contacts": [
                        {
                            "email": DecryptedField(str, "email_encrypted"),
                            "email_encrypted": Field(S.Binary),
                            "phone": str,
                        }
                    ],
                }
            )

        data = {
            "_id": 1,
            "profile": {
                "name": "Alice",
                "contacts": [
                    {"email": "alice@home.com", "phone": "555-1111"},
                    {"email": "alice@work.com", "phone": "555-2222"},
                ],
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)

        self.assertEqual(encrypted_data["profile"]["name"], "Alice")
        self.assertIsInstance(encrypted_data["profile"]["contacts"], list)
        self.assertEqual(len(encrypted_data["profile"]["contacts"]), 2)

        for i, contact in enumerate(encrypted_data["profile"]["contacts"]):
            self.assertNotIn("email", contact)
            self.assertIn("email_encrypted", contact)
            self.assertIn("phone", contact)

        self.assertEqual(
            encrypted_data["profile"]["contacts"][0]["email_encrypted"],
            TestDoc.encr("alice@home.com"),
        )
        self.assertEqual(encrypted_data["profile"]["contacts"][0]["phone"], "555-1111")
        self.assertEqual(
            encrypted_data["profile"]["contacts"][1]["email_encrypted"],
            TestDoc.encr("alice@work.com"),
        )
        self.assertEqual(encrypted_data["profile"]["contacts"][1]["phone"], "555-2222")

    def test_decrypt_some_fields_array_dicts_one_level(self):
        """Test decrypt_some_fields with array of dicts containing encrypted fields inside a dict."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_dict_decrypt_1"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "name": str,
                    "contacts": [
                        {
                            "email": DecryptedField(str, "email_encrypted"),
                            "email_encrypted": Field(S.Binary),
                            "phone": str,
                        }
                    ],
                }
            )

        data = {
            "_id": 1,
            "profile": {
                "name": "Bob",
                "contacts": [
                    {"email": "bob@home.com", "phone": "555-3333"},
                    {"email": "bob@work.com", "phone": "555-4444"},
                ],
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)
        doc = TestDoc(encrypted_data)
        doc.m.save()

        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(decrypted_data["profile"]["name"], "Bob")
        contacts = decrypted_data["profile"]["contacts"]
        self.assertEqual(len(contacts), 2)

        for contact in contacts:
            self.assertIn("email", contact)
            self.assertNotIn("email_encrypted", contact)
            self.assertIn("phone", contact)

        self.assertEqual(contacts[0]["email"], "bob@home.com")
        self.assertEqual(contacts[0]["phone"], "555-3333")
        self.assertEqual(contacts[1]["email"], "bob@work.com")
        self.assertEqual(contacts[1]["phone"], "555-4444")

    def test_encrypt_decrypt_roundtrip_array_dicts_one_level(self):
        """Test roundtrip for array of dicts containing encrypted fields inside a dict."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_dict_rt_1"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            profile = Field(
                {
                    "name": str,
                    "contacts": [
                        {
                            "email": DecryptedField(str, "email_encrypted"),
                            "email_encrypted": Field(S.Binary),
                            "phone": str,
                        }
                    ],
                }
            )

        original_contacts = [
            {"email": "charlie@home.com", "phone": "555-5555"},
            {"email": "charlie@work.com", "phone": "555-6666"},
        ]
        original_data = {
            "_id": 1,
            "profile": {"name": "Charlie", "contacts": original_contacts},
        }

        encrypted_data = TestDoc.encrypt_some_fields(original_data)
        doc = TestDoc(encrypted_data)
        doc.m.save()
        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(decrypted_data["profile"]["name"], "Charlie")
        contacts = decrypted_data["profile"]["contacts"]
        self.assertEqual(len(contacts), 2)
        self.assertEqual(contacts[0]["email"], original_contacts[0]["email"])
        self.assertEqual(contacts[0]["phone"], original_contacts[0]["phone"])
        self.assertEqual(contacts[1]["email"], original_contacts[1]["email"])
        self.assertEqual(contacts[1]["phone"], original_contacts[1]["phone"])

    # ========== Array of dicts - two levels of nesting ==========

    def test_encrypt_some_fields_array_dicts_two_levels(self):
        """Test encrypt_some_fields with array of dicts inside nested dicts."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_dict_2"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "department": {
                        "employees": [
                            {
                                "ssn": DecryptedField(str, "ssn_encrypted"),
                                "ssn_encrypted": Field(S.Binary),
                                "name": str,
                            }
                        ],
                    },
                }
            )

        data = {
            "_id": 1,
            "company": {
                "name": "Acme Corp",
                "department": {
                    "employees": [
                        {"ssn": "123-45-6789", "name": "Alice"},
                        {"ssn": "987-65-4321", "name": "Bob"},
                    ],
                },
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)

        self.assertEqual(encrypted_data["company"]["name"], "Acme Corp")
        employees = encrypted_data["company"]["department"]["employees"]
        self.assertEqual(len(employees), 2)

        for emp in employees:
            self.assertNotIn("ssn", emp)
            self.assertIn("ssn_encrypted", emp)
            self.assertIn("name", emp)

        self.assertEqual(employees[0]["ssn_encrypted"], TestDoc.encr("123-45-6789"))
        self.assertEqual(employees[0]["name"], "Alice")
        self.assertEqual(employees[1]["ssn_encrypted"], TestDoc.encr("987-65-4321"))
        self.assertEqual(employees[1]["name"], "Bob")

    def test_decrypt_some_fields_array_dicts_two_levels(self):
        """Test decrypt_some_fields with array of dicts inside nested dicts."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_dict_decrypt_2"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "department": {
                        "employees": [
                            {
                                "ssn": DecryptedField(str, "ssn_encrypted"),
                                "ssn_encrypted": Field(S.Binary),
                                "name": str,
                            }
                        ],
                    },
                }
            )

        data = {
            "_id": 1,
            "company": {
                "name": "TechCorp",
                "department": {
                    "employees": [
                        {"ssn": "111-22-3333", "name": "Charlie"},
                        {"ssn": "444-55-6666", "name": "Diana"},
                    ],
                },
            },
        }
        encrypted_data = TestDoc.encrypt_some_fields(data)
        doc = TestDoc(encrypted_data)
        doc.m.save()

        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(decrypted_data["company"]["name"], "TechCorp")
        employees = decrypted_data["company"]["department"]["employees"]
        self.assertEqual(len(employees), 2)

        for emp in employees:
            self.assertIn("ssn", emp)
            self.assertNotIn("ssn_encrypted", emp)
            self.assertIn("name", emp)

        self.assertEqual(employees[0]["ssn"], "111-22-3333")
        self.assertEqual(employees[0]["name"], "Charlie")
        self.assertEqual(employees[1]["ssn"], "444-55-6666")
        self.assertEqual(employees[1]["name"], "Diana")

    def test_encrypt_decrypt_roundtrip_array_dicts_two_levels(self):
        """Test roundtrip for array of dicts inside nested dicts."""

        class TestDoc(Document):
            class __mongometa__:
                name = "test_doc_array_dict_rt_2"
                session = ming.Session.by_name("test_db")

            _id = Field(S.Anything)
            company = Field(
                {
                    "name": str,
                    "department": {
                        "employees": [
                            {
                                "ssn": DecryptedField(str, "ssn_encrypted"),
                                "ssn_encrypted": Field(S.Binary),
                                "name": str,
                            }
                        ],
                    },
                }
            )

        original_employees = [
            {"ssn": "777-88-9999", "name": "Eve"},
            {"ssn": "000-11-2222", "name": "Frank"},
        ]
        original_data = {
            "_id": 1,
            "company": {
                "name": "Startup Inc",
                "department": {"employees": original_employees},
            },
        }

        encrypted_data = TestDoc.encrypt_some_fields(original_data)
        doc = TestDoc(encrypted_data)
        doc.m.save()
        doc = TestDoc.m.get(_id=1)
        decrypted_data = doc.decrypt_some_fields()

        self.assertEqual(decrypted_data["company"]["name"], "Startup Inc")
        employees = decrypted_data["company"]["department"]["employees"]
        self.assertEqual(len(employees), 2)
        self.assertEqual(employees[0]["ssn"], original_employees[0]["ssn"])
        self.assertEqual(employees[0]["name"], original_employees[0]["name"])
        self.assertEqual(employees[1]["ssn"], original_employees[1]["ssn"])
        self.assertEqual(employees[1]["name"], original_employees[1]["name"])


class TestMapping(TestCase):
    DATASTORE = "mim:///test_db"

    def setUp(self):
        Mapper._mapper_by_classname.clear()
        ming.configure(
            **{
                "ming.test_db.uri": self.DATASTORE,
                "ming.test_db.encryption.kms_providers.local.key": make_encryption_key(
                    self.__class__.__name__
                ),
                "ming.test_db.encryption.key_vault_namespace": "encryption_test.coll_key_vault_test",
                "ming.test_db.encryption.provider_options.local.key_alt_names": '["test_datakey_1"]',
            }
        )
        # self.datastore = create_datastore(self.DATASTORE)
        self.datastore = ming.Session._datastores.get("test_db")
        self.session = ODMSession(bind=self.datastore)

    def tearDown(self):
        self.session.clear()
        try:
            self.datastore.conn.drop_all()
        except TypeError:
            self.datastore.conn.drop_database(self.datastore.db)
            self.datastore.conn.drop_database("encryption_test")
        Mapper._mapper_by_classname.clear()

    def test(self):
        class TestMapped(MappedClass):
            class __mongometa__:
                name = "test_mapped"
                session = self.session

            _id = FieldProperty(S.ObjectId)
            name = DecryptedProperty(str, "name_encrypted")
            name_encrypted = FieldProperty(S.Binary)
            other = FieldProperty(str)
            deprecated = FieldProperty(S.Deprecated)

        u = TestMapped(_id=None, name="Jerome", other="foo")
        self.session.flush()
        self.assertEqual(
            u.decrypt_some_fields(), {"_id": None, "name": "Jerome", "other": "foo"}
        )
        self.assertEqual(u.name, "Jerome")
        self.assertIsInstance(u.name, str)
        self.assertIsInstance(u.name_encrypted, bytes)
        self.assertEqual(u.name_encrypted, TestMapped.encr("Jerome"))
        self.assertEqual(u.name, TestMapped.decr(u.name_encrypted))

        u2 = TestMapped.query.find(
            {"name_encrypted": TestMapped.encr("Jerome")}
        ).first()
        self.assertEqual(u._id, u2._id)

        u.name = "Jessie"
        self.session.flush()
        self.assertEqual(u.name, "Jessie")
        self.assertEqual(u.name_encrypted, TestMapped.encr("Jessie"))
        self.assertEqual(
            u.decrypt_some_fields(), {"_id": None, "name": "Jessie", "other": "foo"}
        )
        self.assertIsNotNone(
            TestMapped.query.get(name_encrypted=TestMapped.encr("Jessie"))
        )

        u.name_encrypted = TestMapped.encr("James")
        self.session.flush()
        self.assertEqual(u.name, "James")
        self.assertEqual(u.name_encrypted, TestMapped.encr("James"))

        self.assertEqual(set(u.encrypted_field_names()), set(["name_encrypted"]))
        self.assertEqual(set(u.decrypted_field_names()), set(["name"]))
        self.assertEqual(set(u._field_names), set(["_id", "name_encrypted", "other"]))


class TestMappingReal(TestMapping):
    DATASTORE = f"mongodb://localhost/test_ming_TestDocumentReal_{os.getpid()}?serverSelectionTimeoutMS=100"
