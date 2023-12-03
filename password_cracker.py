import hashlib
password_file = open("top-10000-passwords.txt", "r")
data = password_file.read()
password_list = data.split('\n')
password_file.close()

salt_file = open("known-salts.txt", "r")
salt_data = salt_file.read()
salt_list = salt_data.split('\n')
salt_file.close()

def crack_sha1_hash(hash, use_salts = False):

    password_found = False
    
    if use_salts:
        for password in password_list:
            for salt in salt_list:
                salted_password_ab = password + salt
                salted_password_ba =  salt + password
                hashed_salted_password_ab = hashlib.sha1(salted_password_ab.encode('utf-8')).hexdigest()
                hashed_salted_password_ba = hashlib.sha1(salted_password_ba.encode('utf-8')).hexdigest()
                
                if hashed_salted_password_ab == hash or hashed_salted_password_ba == hash:
                    password_found = True
                    return password
                
    else:
        for password in password_list:
            hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            if hashed_password == hash:
                password_found = True
                return password

    if password_found == False:
        return 'PASSWORD NOT IN DATABASE'    