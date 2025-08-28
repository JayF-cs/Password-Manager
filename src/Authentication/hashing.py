"""Modueles for hashing"""
#Standard library
import base64
#Third party
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def rand_salt():
    """
    Generates a random 16 byte salt used for key derivation
    
    Returns
    --------
    returns: bytes
        returns the random 16 byte salt
    
    """
    import os

    salt = os.urandom(16)
    return salt

def derive_key(password: str, salt: bytes):
    """
    Derives the encryption key from the salt and password using PBKDF2

    Parameters
    -------------
    password: str
        The master password obtained from user/the generator
    salt: bytes
        The random generated 16 byte code used for key derivation

    Returns
    -------------
    return: bytes
        returns a base 64 encoded key used for Fernet encryption in the vault
    """


    dsalt = salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=dsalt,
        iterations=100_000
    )
    #Creates key using the random salt generatedd and the master pwd
    key = kdf.derive(password.encode('latin-1'))
    return base64.urlsafe_b64encode(key)

def verify_pwd(attempt: str, salt: bytes, test_obj):

    """
    Checks users password attempt to see if it can decode the test object

    Parameters
    ------------
    attempt: str
        The users password attempt
    salt: bytes
        The random 16 byte salt
    test_obj: bytes
        The encrypted string contained within the json file for testing user attempted password

    Return
    ----------
    return: bool
        returns true or false depending whether test_obj is correctly decrypted
    """

    #Takes the attempted pwd and given salt if the match master pwd and the salt the returns true
    attempted_key = derive_key(attempt, salt)

    try:
        f = Fernet(attempted_key)
        decrypted_test =  f.decrypt(test_obj).decode('latin-1')
        return decrypted_test == 'Test_case'
    except:
        return False    