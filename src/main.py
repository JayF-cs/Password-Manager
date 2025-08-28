"""Modules for main function"""
#Local modules
from vaultContents.password_info import PasswordInfo
from vaultContents.vault import Vault
from utilities.password_generator import generate_password
from Authentication.MFA import setup_2fa

#Standard libraries
import msvcrt
import sys
import time
import os
from threading import Lock
import threading

#Third party
import pyperclip
from pynput import keyboard, mouse

last_active = time.time()
time_threshold = 100
lock = Lock()

def main():

    """
    Entry point for the Password Manager application.

    Handles:
    - Authentication of the master password
    - Two-factor authentication (2FA)
    - Vault initialization and interaction
    - Password generation and retrieval
    """

    try:
        vault = Vault()
    except ValueError as e:
        print(f'Security Alert! {str(e)}')
        print('Deleting Vault and Making New Vault')
    
        try:
            os.remove('./vault.json')
            print('Corrupted File Removed')
        except Exception as delete_error:
            print(f'Error deleting vault: {str(delete_error)}')
            vault = Vault()
            vault.make_new_vault()

    if os.path.exists('vault.json'):
        print('=========== Unlock Vault ===========')
        attempts = 3
        key = setup_2fa()
        while attempts > 0:
            master_pwd = getpass_w_astriks('Input your password: ')
            if vault.check_master_pwd(master_pwd, key):
                print('Vault Unlocked....')
                break
            else:
                attempts -= 1
                delay = 2*(3-attempts)
                print(f'Incorrect Password. Wait {delay}s. {attempts} attempts left')
                time.sleep(delay)

            if attempts == 0:
                print('You have ran out of attempts please try again later.')
                sys.exit()

        if os.path.exists('vault_2fa.png'):
            os.remove('vault_2fa.png')
    else:
        print('=========== Set Up Vault ===========')
        master_pwd = get_master_pwd()
        vault.make_new_vault()
        vault.make_key(master_pwd)
        print('New Vault Created')

    while True:
        print('='*40)
        print('Password Manager')
        print()
        print('1. Add password')
        print('2. Remove passowrd information')
        print('3. Search for password information')
        print('4. Generate random secure password')
        print('5. Exit')
       
        try:
            option = int(input('What would you like to do? > '))
        except ValueError:
            print("Please enter a valid number (1-4)")
            continue

        match option:

            case 1:
                while True:   
                    service = input('What is the information for? > ')
                    username = input('What is your username? > ')
                    password = input('What is your password? > ')
                    password = vault.encrypt(password)
                    info = PasswordInfo(service,username,password)
                    vault.add(info)

                    while True:
                        another = input('Would you like to add another service information (Y,N) > ')
                        if another.lower().strip() in ['y','n']:
                                break

                    if another.lower().strip() == 'n':
                        break

            case 2:
                while True:
                    service = input('What service password would you like to remove? > ')
                    if vault.remove(service):
                        while True:
                            another = input('Would you like to remove another services information (Y,N) > ')
                            if another.lower().strip() in ['y','n']:
                                break
                    else:
                        print('No password found for that service')
                        while True:
                            another = input('Would you like to remove another services inforamtion (Y,N) > ')
                            if another.lower().strip() in ['y','n']:
                                break

                    if another.lower().strip() == 'n':
                        break

            case 3:
                while True:
                    
                    if vault._manager == []:
                        print('You have no saved password information')
                        print()
                        break

                    else:
                    
                        service = input('What service password are you searching for? > ')

                        if vault.search(service):
                            while True:
                                another = input('Would you like to search for another services information (Y,N) > ')
                                if another.lower().strip() in ['y','n']:
                                    break
                        else:
                            print('No password found for that service')
                            while True:
                                another = input('Would you like to search for another services inforamtion (Y,N) > ')
                                if another.lower().strip() in ['y','n']:
                                    break

                        if another.lower().strip() == 'n':
                                break
                        
            case 4:
                while True:
                    try:
                        len = int(input('How long would you like you password to be? > ').strip())
                        break
                    except ValueError:
                        print('Please answer with a number')
                        print()
                
                while True:
                    copy = input('Would you like to copy the generated password (Y,N) > ')
                    if copy.lower().strip() in ['y','n']:
                        break

                if copy.lower().strip() == 'y':
                    generate_password(len, True)
                else:
                    generate_password(len)

                thread_clear = threading.Thread(target=clear_clipboard, daemon= True)
                thread_clear.start()

            case 5:
                print('Goodbye...')
                sys.exit()

            case _:
                print('Invalid input please choose one of the available options.')
                    
def get_master_pwd():

    """
    Prompt the user to set a master password with confirmation.

    Enforces:
    - Minimum length of 8 characters
    - Password confirmation match

    Returns:
        str: The validated master password
    """

    while True:
        #getpass is secure input collection method
        master_pwd = getpass_w_astriks('Enter your master password: ')
        confirm = getpass_w_astriks('Confirm you master password: ')

        if confirm == master_pwd:
            if len(master_pwd) >= 8:
                return master_pwd
            print('Password must be longer the 8 characters')
        else:
            print('Passwords do not match')

def getpass_w_astriks(prompt: str):

    """
    Collect a password input from the user with masked characters.

    Args:
        prompt (str): The message displayed to the user.

    Returns:
        str: The entered password (unmasked in return).
    """


    print(prompt, end='',flush=True)
    password = []

    while True:
        #Gets the character pressed
        ch = msvcrt.getch()
        
        #Checks if enter is pressed
        if ch == b'\r':
            print()
            break
        
        #Checks if backspace is pressed
        elif ch == b'\x08':
            if password != []:
                password.pop()
                sys.stdout.write('\b \b')

        #If neiter of those characters are pressed then it adds the character to password and writes an astrik
        else:
            password.append(ch.decode('utf-8'))
            sys.stdout.write('*')

        sys.stdout.flush()

    return ''.join(password)

def clear_clipboard():
    """
    Clear the clipboard after 60 seconds.

    This helps prevent accidental password leaks from copied values.
    """

    #Clears copied clipboard after 60 seconds
    time.sleep(60)
    pyperclip.copy('')
    print()
    print('Clipboard has been cleared')

def update_activity():
    """
    Update the last active timestamp.

    Called whenever a key press, mouse click, or scroll is detected
    to track user activity for auto-logout.
    """

    #Updates activity when it is called
    global last_active
    with lock:
        last_active = time.time()

def key_press(key):
    """
    Handle keyboard input event and update user activity.

    Args:
        key: The key that was pressed.
    """

    update_activity()

def scroll(x,y,dx,dy):
    """
    Handle mouse scroll event and update user activity.

    Args:
        x (int): The x-coordinate of the mouse.
        y (int): The y-coordinate of the mouse.
        dx (int): The horizontal scroll delta.
        dy (int): The vertical scroll delta.
    """

    update_activity()

def click(x,y,button, pressed):
    """
    Handle mouse click events and update user activity.

    Args:
        x (int): The x-coordinate of the click.
        y (int): The y-coordinate of the click.
        button: The mouse button clicked.
        pressed (bool): Whether the button was pressed or released.
    """

    if pressed:
        update_activity()

def check_time():
    """
    Monitor user inactivity and terminate program if idle too long.

    Checks every 20 seconds if the idle time has exceeded `time_threshold`.
    If exceeded, exits the application for security.
    """

    #Check to make sure that timeout time hasn't been exceeded
    while True:
        time.sleep(20)
        current_time = time.time()
        idle_time = current_time - last_active
        if idle_time > time_threshold:
            print('You have been in active for too long please')
            os._exit(0)

if __name__ == '__main__':

    #Intialize listeners
    keyboard_listener = keyboard.Listener(on_press=key_press)
    mouse_listener = mouse.Listener(on_click=click,on_scroll=scroll)
    keyboard_listener.start()
    mouse_listener.start()
    #Create the thread for check activity
    thread_check_activity = threading.Thread(target=check_time, daemon= True)
    thread_check_activity.start()

    main()