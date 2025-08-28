"""Imported Modules for vault"""
#Local modules
from vaultContents.password_info import PasswordInfo
from Authentication.hashing import rand_salt
from Authentication.hashing import derive_key
from Authentication.hashing import verify_pwd
from Authentication.MFA import setup_2fa, check_password

#Standard Library
import os
import hmac
import hashlib
import base64
import json

#Third Party
from cryptography.fernet import Fernet

class Vault:
    """
    Represents a secure vault for storing the password info entries from the user
    """
    def __init__(self):
        """
        Intializes vault object
        
        Attributes
        --------------
        _salt: bytes
            16 bytes salt used for making encryption key
        _key: bytes
            the key used for both encryption and decryption derived from the master password
        _HMAC: bytes
            HMAC object stored in json file to check for tampering
        test_obj: bytes
            test object stored in json for master password checking
        file: string
            name of the json file where data is stored
        _manager: list
            list where password info objects are stored before being written to json file
        
        """
        #Generates key for encryption
        #Encryption key is saved as bytes not as a string
        self._salt  = None
        self._key = None
        self._HMAC = None
        self.test_obj = None
        self.file = 'vault.json'
        self._manager = []
        
        #Checks if the file exists and if it does it reads the contents and updates vaules
        if os.path.exists(self.file):
            self.read_json()

    def check_master_pwd(self,attempt_pwd: str, key):
        """
        Calss verify_pwd to check master password and MFA

        Attributes
        -------------
        attempted_pwd: str
            The attempted password from teh user
        key: bytes
            key used for encryption and decryption

        Returns
        ------------
        returns: bool
            returns true if passwords and MFA are verified, returns false otherwise
        """
        if not self._salt:
            self.read_json()
        
        if verify_pwd(attempt=attempt_pwd, salt=self._salt, test_obj=self.test_obj):
            self._key = derive_key(attempt_pwd, salt=self._salt)

            if not check_password(key):
                return False
            return True
        else:
            return False

    def encrypt(self,password):
        """
        Encrypts data from vault's manager list

        Attributes
        -------------
        password: str
            The users master password

        Returns
        -------------
        return: str
            returns the encrypted password as a string after decoding it from bytes
        """
        #Creates encryption object
        f = Fernet(self._key)
        #Encrypts password
        #The encrypt requires bytes not string
        #Encode turns strings to bytes
        encrypted_password = f.encrypt(password.encode('latin-1'))
        #Returns encrytped bytes as decode string
        return encrypted_password.decode('latin-1')

    def decrypt(self, encrypted_password):
        """
        Decrypts the encrypted data read from the json file

        Attributes
        -------------
        encrypted_password: str
            the encrypted password from the read from json file

        Returns
        ----------
        return: str
            returns the decrypted password
        """
        f = Fernet(self._key)
        #Decrypts the password recieved
        #Returned to original encrypted bytes
        decrypted_bytes = encrypted_password.encode('latin-1')
        #Decryptd to original string
        decrypted_password = f.decrypt(decrypted_bytes).decode('latin-1')
        return decrypted_password

    def add(self, info):
        """
        Adds password info object to the manager and then writes it to the json file

        Attributes
        ------------
        info: class object
            the password info object containing services information
        """
        print('Adding info...')
        self._manager.append(info)
        #Writes the added password infor to json file
        self.write_json()

    def remove(self, service_name):
        """
        Removes object the vaults manager and then writes the json file

        Attributes
        -------------
        service_name: str
            the service name of a password_info object
        """
        for info in self._manager:
            if service_name.lower().strip() == info.service.lower().strip():
                #Changes password to x's before deleting
                info.__del__()
                self._manager.remove(info)
                #Rewrites the json file to one that doesn't have the password
                self.write_json()
                print('Services Information Being Removed...')
                return 1

    #Writes to the json file called vault
    def write_json(self):
        """Writes data from vault's manager to a json file as well as hmac object, test object, and salt"""
        data = {
            'Information':[vars(i) for i in self._manager],
            #This decodes the key from bytes to a string to save to the json file
            'Salt':self._salt.decode('latin-1'),
            'Test':self.encrypt('Test_case')
            }
        
        #Creates hmac to verify data is changed when reading from file
        json_str = json.dumps(data, sort_keys=True)
        hmac_key = hashlib.sha256(b'Secure_pepper' + self._salt).digest()
        hmac_obj = hmac.new(hmac_key, msg=json_str.encode('latin-1'), digestmod=hashlib.sha256)
        data['HMAC'] = hmac_obj.hexdigest()

        with open(self.file , 'w') as f:
            json.dump(data,f,indent=3)

    def read_json(self):
        """
        Checks HMAC for tampering of json file data
        Reads data from json file and appends it to the vaults manager
        If there is a problem it creates a new vault
        """
        try:
            with open(self.file,'r') as f:
                data= json.load(f)

                self._salt = data['Salt'].encode('latin-1')                                
                hmac_key = hashlib.sha256(b'Secure_pepper' + self._salt).digest()

                #Gets hmac in file
                received_hmac = data.pop('HMAC')
                #Creates new hmac from the file with the contents read from file
                json_str = json.dumps(data, sort_keys=True)
                new_hmac = hmac.new(hmac_key, msg=json_str.encode('latin-1'), digestmod=hashlib.sha256)

                #If the hmac do not match that means the contents of the file are not the same as when writing it to file
                if not hmac.compare_digest(new_hmac.hexdigest(), received_hmac):
                    raise ValueError('HMAC Verification Failed - Your Information May Have Been Tampered With')
                
                self._manager = [PasswordInfo(**i) for i in data['Information']]
                #Returns the key to bytes
                self.test_obj = data['Test'].encode('latin-1')

            
        except (FileNotFoundError, json.JSONDecodeError, KeyError, AttributeError) as e:
            #Tells you the type of error
            print(f'Warning {type(e).__name__} - {str(e)}')
            self._key = None 
            self.make_new_vault()

    def make_new_vault(self):
        """Makes a new vault and sets the key and test_obj to none"""
        self._salt = rand_salt()
        self._manager = []

        if hasattr(self, '_key') and self._key:
            self._key = None
        
        if hasattr(self, 'test_obj') and self.test_obj:
            if isinstance(self.test_obj, bytes):
                self.test_obj = b'x'*len(self.test_obj)
            self.test_obj = None


    def make_key(self, password: str):
        """
        Generates an encryption key

        Attributes
        -------------
        password: str
            users master password
        """
        self._key = derive_key(password,self._salt)

    def search(self, service_name):
        """
        Searches through the vault's manager for a password_info object with a certain service name

        Attributes:
        -------------
        service_name: str
            The service name of a particular password_info object

        Returns
        -----------
        return: bool
            returns true if service name is found, otherwise returns false
        """
        for info in self._manager:
            if info.service.lower().strip() == service_name.lower().strip():
                password = self.decrypt(info._encryptedpassword)
                print(40*'-')
                print(f'Username: {info.username} Password: {password}')
                print(40*'-')
                return True
            
        return False