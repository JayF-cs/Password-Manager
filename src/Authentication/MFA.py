"""Modules for multiy factor authentication"""
#Third Party
import pyotp
import qrcode
from PIL import Image

def setup_2fa():
    """
    Generates a TOTP secret and qrcode for MFA

    Returns
    ----------
    return: str
        returns TOTP key
    """

    key = pyotp.random_base32()
    url = pyotp.totp.TOTP(key).provisioning_uri('MyVault', 'PasswordManager')

    qr_img = qrcode.make(url)
    qr_img.show()  # No need to save or reopen

    return key

def check_password(key):
    """
    Checks if MFA code is correct

    Attributes
    -----------
    key: str
        The TOTP key used to generate valid codes

    Returns
    -------
    return: bool
        returns true is key matches, else returns false
    """
    
    print('Scan this qrcode with google authnticator')
    totp = pyotp.TOTP(key)
    mfa_password = input('Input your 6 digit code here: ')
    if totp.verify(mfa_password):
        print('Access Granted')
        return True
    else:
        print('Invalid code!')
        return False
