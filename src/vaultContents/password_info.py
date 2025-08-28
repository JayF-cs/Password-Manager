class PasswordInfo:

    """Represents the stored password information of a given service """
    
    def __init__(self, service: str, username: str, _encryptedpassword: str):
        """
        Initialize a password info object to store a service info

        Attributes
        ----------

        service: str
            The name of a service
        username: str
            The user name used for that service
        _encryptedpassword: str
            The password to your profile on that service, this will not be stored as plain text

        """

        self.service = service
        self.username = username
        self._encryptedpassword = _encryptedpassword

    def __repr__(self):
        """Returns string of object properties for debugging"""
        return f'Site: {self.service} Username: {self.username} Password: {self._encryptedpassword}'
    
    def __del__(self):
        """Overwirtes the passwords characters to X's before deleting to reduce exposure within memory"""
        if hasattr(self, '_encryptedpassword'):
            self._encryptedpassword = 'x'*len(self._encryptedpassword)