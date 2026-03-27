from configparser import ConfigParser
import os
from unittest import SkipTest, TestCase

import ming
from ming import create_datastore, Document, Field, schema as S
from ming.odm import session, ODMSession, Mapper, MappedClass, FieldProperty, DecryptedProperty
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

    LOCAL_KEY = make_encryption_key('test local key')

    def setUp(self):
        import_formencode()

    def _parse_config(self, body: str):
        config_lines = [
            l.strip() for l in 
            [
                '[app:main]',
            ] + body.split('\n')
            if l
        ]

        config = ConfigParser()
        config.read_string('\n'.join(config_lines))
        ming.configure(**config['app:main'])
        return config

    def test_validation_good(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
        """
        
        self._parse_config(config_str)
        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertIsNotNone(encryption)
        self.assertEqual(encryption.kms_providers, {'local': {'key': self.LOCAL_KEY}})
        self.assertEqual(encryption.key_vault_namespace, 'encryption_test.dataKeyVault')
        self.assertEqual(encryption.provider_options, {'local': {'key_alt_names': ['datakey_test1']}})

    def test_validation_key_alt_names(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = ["datakey_test1"]
        """
        
        self._parse_config(config_str)
        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertEqual(encryption.provider_options, {'local': {'key_alt_names': ['datakey_test1']}})

    def test_validation_key_alt_names2(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = ["datakey_test1", "datakey_test2"]
        """
        
        self._parse_config(config_str)
        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertEqual(encryption.provider_options, {'local': {'key_alt_names': ['datakey_test1', 'datakey_test2']}})

    def test_validation_key_alt_names3(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1, datakey_test2
        """
        
        self._parse_config(config_str)
        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertEqual(encryption.provider_options, {'local': {'key_alt_names': ['datakey_test1', 'datakey_test2']}})

    def test_validation_key_alt_names4(self):
        config_str = f"""
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ming.maindb.encryption.provider_options.local.key_alt_names = "datakey_test1", "datakey_test2"
        """
        
        self._parse_config(config_str)
        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertEqual(encryption.provider_options, {'local': {'key_alt_names': ['datakey_test1', 'datakey_test2']}})

    def test_validation_empty(self):
        self._parse_config(f'''ming.maindb.uri = mongo://host/maindb''')

        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertIsNone(encryption)

    def test_validation_empty_mim_auto_encryption(self):
        self._parse_config(f'''ming.maindb.uri = mim://host/maindb''')

        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertIsNotNone(encryption.kms_providers['local']['key'])
        self.assertEqual(encryption.key_vault_namespace, 'encryption_test.coll_key_vault_test')
        self.assertEqual(encryption.provider_options, {'local': {'key_alt_names': ['datakeyName']}})

    def test_validation_bad_missing(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['key_vault_namespace', 'provider_options']), set(error_dict.keys()))
        self.assertIn('Missing required encryption configuration field ', str(error_dict['key_vault_namespace']))
        self.assertIn('Missing required encryption configuration field ', str(error_dict['provider_options']))

    def test_validation_bad_missing2(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['kms_providers', 'provider_options']), set(error_dict.keys()))
        self.assertIn('Missing required encryption configuration field ', str(error_dict['kms_providers']))
        self.assertIn('Missing required encryption configuration field ', str(error_dict['provider_options']))

    def test_validation_bad_missing3(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['kms_providers', 'key_vault_namespace']), set(error_dict.keys()))
        self.assertIn('Missing required encryption configuration field ', str(error_dict['kms_providers']))
        self.assertIn('Missing required encryption configuration field ', str(error_dict['key_vault_namespace']))

    def test_validation_bad_extra(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.extra_nonsense = foo
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['extra_nonsense']), set(error_dict.keys()))
        self.assertIn("Unexpected encryption configuration field 'extra_nonsense'", str(error_dict['extra_nonsense']))

    def test_validation_bad_empty(self):
        self._parse_config(f'''
            ming.maindb.uri = mim://host/maindb
            ming.maindb.encryption.kms_providers = 
            ming.maindb.encryption.key_vault_namespace = 
            ming.maindb.encryption.provider_options = 
        ''')
        encryption = ming.Session.by_name('maindb').bind.encryption
        self.assertEqual(encryption.kms_providers, '')
        self.assertEqual(encryption.provider_options, '')
        self.assertEqual(encryption.provider_options, '')

    def test_validation_bad_kms_providers(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.BAD.key = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['kms_providers']), set(error_dict.keys()))
        self.assertIn("Invalid kms_provider(s)", str(error_dict['kms_providers']))

    def test_validation_bad_kms_provider_local(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.foo = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['kms_providers']), set(error_dict.keys()))
        self.assertIn("kms_provider 'local' requires", str(error_dict['kms_providers']))

    def test_validation_bad_provider_options_local(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test.dataKeyVault
                ming.maindb.encryption.provider_options.local.foo = bar'
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['provider_options']), set(error_dict.keys()))
        self.assertIn('requires provider_options', str(error_dict['provider_options']))

    def test_validation_bad_key_vault_namespace(self):
        with self.assertRaises(InvalidClass) as e:
            self._parse_config(f'''
                ming.maindb.uri = mim://host/maindb
                ming.maindb.encryption.kms_providers.local.key = {self.LOCAL_KEY}
                ming.maindb.encryption.key_vault_namespace = encryption_test_dataKeyVault
                ming.maindb.encryption.provider_options.local.key_alt_names = datakey_test1
            ''')
        error_dict = e.exception.error_dict['encryption'].error_dict
        self.assertEqual(set(['key_vault_namespace']), set(error_dict.keys()))
        self.assertIn('Invalid key_vault_namespace', str(error_dict['key_vault_namespace']))


class TestDocumentEncryption(TestCase):
    DATASTORE = "mim://host/test_db"

    def setUp(self):
        import_formencode()

        ming.configure(**{
            'ming.test_db.uri': self.DATASTORE,
            'ming.test_db.encryption.kms_providers.local.key': make_encryption_key(self.__class__.__name__),
            'ming.test_db.encryption.key_vault_namespace': 'encryption_test.coll_key_vault_test',
            'ming.test_db.encryption.provider_options.local.key_alt_names': '["test_datakey_1"]'
        })

    def tearDown(self):
        session = ming.Session.by_name('test_db')
        session.bind.conn.drop_database('test_db')
        session.bind.conn.drop_database('encryption_test')

    def test_document(self):
        class TestDoc(Document):
            class __mongometa__:
                name='test_doc'
                session = ming.Session.by_name('test_db')
                indexes = [ ('name_encrypted',) ]
            _id = Field(S.Anything)
            name = DecryptedField(str, 'name_encrypted')
            name_encrypted = Field(S.Binary)
            other = Field(str)
            deprecated = FieldProperty(S.Deprecated)

        doc = TestDoc.make_encr(dict(_id=1, name='Jerome', other='foo'))
        doc.m.save()

        self.assertEqual(doc.name, 'Jerome')
        self.assertIsInstance(doc.name, str)
        self.assertIsInstance(doc.name_encrypted, bytes)
        self.assertEqual(doc.name_encrypted, TestDoc.encr('Jerome'))
        self.assertEqual(doc.name, TestDoc.decr(doc.name_encrypted))

        doc.name = 'Jessie'
        doc.m.save()
        self.assertEqual(doc.name, 'Jessie')
        self.assertEqual(doc.name_encrypted, TestDoc.encr('Jessie'))
        self.assertEqual(doc.name, TestDoc.decr(doc.name_encrypted))

        self.assertEqual(doc.decrypt_some_fields(), {'_id': 1, 'name': 'Jessie', 'other': 'foo'})
        self.assertIsNotNone(TestDoc.m.get(name_encrypted=TestDoc.encr('Jessie')))

        self.assertEqual(set(doc.encrypted_field_names()), set(['name_encrypted']))
        self.assertEqual(set(doc.decrypted_field_names()), set(['name']))
        self.assertEqual(set(doc._field_names), set(['_id', 'name_encrypted', 'other']))

        # allowed to save None to it
        doc.name = None
        doc.m.save()
        self.assertEqual(doc.name, None)
        self.assertEqual(doc.name_encrypted, None)

    def test_nested_dict_encryption(self):
        """Test encryption of fields nested in dict fields."""
        from bson import ObjectId
        
        class UserDoc(Document):
            class __mongometa__:
                name = 'user_doc'
                session = ming.Session.by_name('test_db')
            
            _id = Field(S.ObjectId)
            username = Field(str)
            # Dict field with encrypted nested fields
            full_name = Field(dict(
                first_name_encrypted=S.Binary,
                last_name_encrypted=S.Binary
            ))
        
        # Create document with unencrypted nested data
        doc = UserDoc.make_encr({
            '_id': ObjectId(),
            'username': 'jdoe',
            'full_name': {
                'first_name': 'John',
                'last_name': 'Doe'
            }
        })
        doc.m.save()
        
        # Verify encrypted fields exist in storage
        self.assertIn('first_name_encrypted', doc.full_name)
        self.assertIn('last_name_encrypted', doc.full_name)
        self.assertIsInstance(doc.full_name['first_name_encrypted'], bytes)
        self.assertIsInstance(doc.full_name['last_name_encrypted'], bytes)
        
        # Verify decryption works through dict access
        self.assertEqual(doc.full_name['first_name'], 'John')
        self.assertEqual(doc.full_name['last_name'], 'Doe')
        
        # Verify we can set nested encrypted fields
        doc.full_name['first_name'] = 'Johnny'
        self.assertEqual(doc.full_name['first_name'], 'Johnny')
        self.assertNotEqual(doc.full_name['first_name_encrypted'], UserDoc.encr('John'))
        self.assertEqual(doc.full_name['first_name_encrypted'], UserDoc.encr('Johnny'))
        
        # Verify the document can be saved and retrieved
        doc.m.save()
        retrieved = UserDoc.m.get(_id=doc._id)
        self.assertEqual(retrieved.full_name['first_name'], 'Johnny')
        self.assertEqual(retrieved.full_name['last_name'], 'Doe')
    
    def test_nested_dict_encryption_multiple_levels(self):
        """Test encryption of fields nested multiple levels deep."""
        from bson import ObjectId
        
        class ProfileDoc(Document):
            class __mongometa__:
                name = 'profile_doc'
                session = ming.Session.by_name('test_db')
            
            _id = Field(S.ObjectId)
            # Nested dict with encrypted fields
            personal_info = Field(dict(
                address=dict(
                    street_encrypted=S.Binary,
                    city_encrypted=S.Binary
                )
            ))
        
        # Create document with multi-level nested unencrypted data
        doc = ProfileDoc.make_encr({
            '_id': ObjectId(),
            'personal_info': {
                'address': {
                    'street': '123 Main St',
                    'city': 'Springfield'
                }
            }
        })
        doc.m.save()
        
        # Verify nested encrypted fields exist
        self.assertIn('street_encrypted', doc.personal_info['address'])
        self.assertIn('city_encrypted', doc.personal_info['address'])
        
        # Verify decryption works at multiple levels
        self.assertEqual(doc.personal_info['address']['street'], '123 Main St')
        self.assertEqual(doc.personal_info['address']['city'], 'Springfield')
        
        # Verify setting nested values works
        doc.personal_info['address']['city'] = 'Shelbyville'
        self.assertEqual(doc.personal_info['address']['city'], 'Shelbyville')
        
        doc.m.save()
        retrieved = ProfileDoc.m.get(_id=doc._id)
        self.assertEqual(retrieved.personal_info['address']['city'], 'Shelbyville')
    
    def test_nested_dict_mixed_encrypted_and_plain_fields(self):
        """Test dict with both encrypted and plain fields."""
        from bson import ObjectId
        
        class ContactDoc(Document):
            class __mongometa__:
                name = 'contact_doc'
                session = ming.Session.by_name('test_db')
            
            _id = Field(S.ObjectId)
            contact = Field(dict(
                email_encrypted=S.Binary,
                phone_encrypted=S.Binary,
                public_name=str  # This field is not encrypted
            ))
        
        doc = ContactDoc.make_encr({
            '_id': ObjectId(),
            'contact': {
                'email': 'john@example.com',
                'phone': '555-1234',
                'public_name': 'John D.'
            }
        })
        doc.m.save()
        
        # Verify encrypted fields work
        self.assertEqual(doc.contact['email'], 'john@example.com')
        self.assertEqual(doc.contact['phone'], '555-1234')
        
        # Verify plain field works normally
        self.assertEqual(doc.contact['public_name'], 'John D.')
        
        # Verify setting works for both types
        doc.contact['email'] = 'john.doe@example.com'
        doc.contact['public_name'] = 'Johnny D.'
        
        self.assertEqual(doc.contact['email'], 'john.doe@example.com')
        self.assertEqual(doc.contact['public_name'], 'Johnny D.')

class TestDocumentEncryptionMimAutoSettings(TestDocumentEncryption):
    def setUp(self):
        # replace super() NOT using it
        import_formencode()

        ming.configure(**{
            'ming.test_db.uri': self.DATASTORE,
            # mim encryption settings should come automatically from configure_from_nested_dict
        })

class TestDocumentEncryptionReal(TestDocumentEncryption):
    DATASTORE = f"mongodb://localhost/test_ming_TestDocumentReal_{os.getpid()}?serverSelectionTimeoutMS=100"

class TestMapping(TestCase):
    DATASTORE = 'mim:///test_db'

    def setUp(self):
        Mapper._mapper_by_classname.clear()
        ming.configure(**{
            'ming.test_db.uri': self.DATASTORE,
            'ming.test_db.encryption.kms_providers.local.key': make_encryption_key(self.__class__.__name__),
            'ming.test_db.encryption.key_vault_namespace': 'encryption_test.coll_key_vault_test',
            'ming.test_db.encryption.provider_options.local.key_alt_names': '["test_datakey_1"]'
        })
        # self.datastore = create_datastore(self.DATASTORE)
        self.datastore = ming.Session._datastores.get('test_db')
        self.session = ODMSession(bind=self.datastore)

    def tearDown(self):
        self.session.clear()
        try:
            self.datastore.conn.drop_all()
        except TypeError:
            self.datastore.conn.drop_database(self.datastore.db)
            self.datastore.conn.drop_database('encryption_test')
        Mapper._mapper_by_classname.clear()

    def test(self):
        class TestMapped(MappedClass):
            class __mongometa__:
                name = "test_mapped"
                session = self.session

            _id = FieldProperty(S.ObjectId)
            name = DecryptedProperty(str, 'name_encrypted')
            name_encrypted = FieldProperty(S.Binary)
            other = FieldProperty(str)
            deprecated = FieldProperty(S.Deprecated)

        u = TestMapped(_id=None, name="Jerome", other='foo')
        self.session.flush()
        self.assertEqual(u.decrypt_some_fields(), {'_id': None, 'name': 'Jerome', 'other': 'foo'})
        self.assertEqual(u.name, 'Jerome')
        self.assertIsInstance(u.name, str)
        self.assertIsInstance(u.name_encrypted, bytes)
        self.assertEqual(u.name_encrypted, TestMapped.encr('Jerome'))
        self.assertEqual(u.name, TestMapped.decr(u.name_encrypted))

        u2 = TestMapped.query.find({"name_encrypted": TestMapped.encr("Jerome")}).first()
        self.assertEqual(u._id, u2._id)

        u.name = 'Jessie'
        self.session.flush()
        self.assertEqual(u.name, 'Jessie')
        self.assertEqual(u.name_encrypted, TestMapped.encr('Jessie'))
        self.assertEqual(u.decrypt_some_fields(), {'_id': None, 'name': 'Jessie', 'other': 'foo'})
        self.assertIsNotNone(TestMapped.query.get(name_encrypted=TestMapped.encr('Jessie')))

        u.name_encrypted = TestMapped.encr('James')
        self.session.flush()
        self.assertEqual(u.name, 'James')
        self.assertEqual(u.name_encrypted, TestMapped.encr('James'))

        self.assertEqual(set(u.encrypted_field_names()), set(['name_encrypted']))
        self.assertEqual(set(u.decrypted_field_names()), set(['name']))
        self.assertEqual(set(u._field_names), set(['_id', 'name_encrypted', 'other']))


class TestMappingReal(TestMapping):
    DATASTORE = f"mongodb://localhost/test_ming_TestDocumentReal_{os.getpid()}?serverSelectionTimeoutMS=100"
