def generate_password(pwd_len, copy_pwd=False):
    """
    Generates a password for the user (12 character length minimum),
    using lower and upper case letters, numbers and symbols,
    and allows user to copy it to their clipboard for 60 seconds.

    Attributes
    ----------
    pwd_len: int
        The length the user wants the password to be
    """
    import secrets
    import pyperclip

    if pwd_len < 12:
        print('Password length is too short. Minimum length is 12 characters.')
        pwd_len = 12

    l_letters = 'abcdefghijklmnopqrstuvwxz'
    u_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    nums = '1234567890'
    sym = '!@#$%^&*'
    password = []

    for i in range(pwd_len):
        rand = secrets.randbelow(4)
        while True:
            if rand == 0:
                rand_char = secrets.choice(l_letters)
                if len(password) == 0 or rand_char != password[-1]:
                    password.append(rand_char)
                    break
            elif rand == 1:
                rand_char = secrets.choice(u_letters)
                if len(password) == 0 or rand_char != password[-1]:
                    password.append(rand_char)
                    break
            elif rand == 2:
                rand_char = secrets.choice(nums)
                if len(password) == 0 or rand_char != password[-1]:
                    password.append(rand_char)
                    break
            elif rand == 3:
                rand_char = secrets.choice(sym)
                if len(password) == 0 or rand_char != password[-1]:
                    password.append(rand_char)
                    break

    if not any(c.islower() for c in password):
        password[-1] = secrets.choice(l_letters)
    if not any(c.isupper() for c in password):
        password[-1] = secrets.choice(u_letters)
    if not any(c.isdigit() for c in password):
        password[-1] = secrets.choice(nums)
    if not any(c in sym for c in password):
        password[-1] = secrets.choice(sym)

    gen_rand = secrets.SystemRandom()
    gen_rand.shuffle(password)
    password_str = ''.join(password)

    print('Password: ' + password_str)

    if copy_pwd:
        try:
            pyperclip.copy(password_str)
            print('Copied to clipboard')
            print('Information will be cleared after 60 seconds')
        except Exception as e:
            print(f'Could not copy to clipboard: {str(e)}')