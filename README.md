# Spectre
# Hexada

**Unfinished data encryption program**

_I admit that the program is not written in the best way, not with the best optimization, the code could have been written much simpler and smaller in my opinion, but I think this result at 15 years is not so bad, I quit working on this program on August 1, 2023_

**Сommand structure**

keys_status - _Outputs information about encryption keys_

**AES/command.py**

**Class KeyManager Command**
   : 128, 192, 256 - _return bit_

   - *create* key -aes 

   - *create key* -aes --size=<bit_size>

   - *create* -f (or) --file key -aes

   - *create* -f (or) --file key -aes --size=<bit_size>

   - *drop* -f (or) --file key -aes

**Class Encryptor Command**
   : ECB, CBC, CFB, OFB, CTR, GCM, XTS, CCM, EAX - _encryption mode (only work ECB, CBC, CFB, OFB, CTR)_

   - *encrypt* -in (or) -input <input_text> -aes
   - *encrypt* -fld (or) --file-directory <file_path> -aes
   - *encrypt* -dir (or) --directory <dir_path> -aes

   - *encrypt* -in (or) -input <input_text> -aes --mode=<cipher_mode>
   - *encrypt* -fld (or) -fl-dir (or) --file-directory <file_path> -aes --mode=<cipher_mode>
   - *encrypt* -dir (or) --directory <dir_path> -aes --mode=<cipher_mode>

**Class Decryptor Command**
   **AES** - _required data for decryption_

   : *Encrypted data* - input_text, file_directory, directory
   : *Encryption key* - key.pem
   : *Encryption key size* - 128, 192, 256
   : *Encryption mode* - ECB, CBC, CFB, OFB, CTR, GCM, XTS, CCM, EAX

   - *decrypt* -in (or) -input <encrypted_input_text> -aes
   - *decrypt* -fld (or) --file-directory <encrypted_file_path> -aes
   - *decrypt* -dir (or) --directory <encrypted_dir_path> -aes

   - *decrypt* -in (or) -input <encrypted_input_text> -aes --mode=<cipher_mode>
   - *decrypt* -fld (or) -fl-dir (or) --file-directory <encrypted_file_path> -aes --mode=<cipher_mode>
   - *decrypt* -dir (or) --directory <encrypted_dir_path> -aes --mode=<cipher_mode>


**RSA/command.py**

**Class KeyManager Command**
    _Most of the commands work with AES, I didn't write the RSA commands_

   : size for size in range(1024, 4097, 8) - _return bit_

   - *create* public_key -rsa
   - *create* private_key -rsa
   - *create* key_pair -rsa

   - *create* public_key -rsa --size=<bit_size>
   - *create* private_key -rsa --size=<bit_size>
   - *create* key_pair -rsa --size=<bit_size>

   - *create* -f (or) --file public_key -rsa
   - *create* -f (or) --file private_key -rsa
   - *create* -f (or) --file key_pair -rsa

   - *create* -f (or) --file public_key -rsa --size=<bit_size>
   - *create* -f (or) --file private_key -rsa --size=<bit_size>
   - *create* -f (or) --file key_pair -rsa --size=<bit_size>

   - *drop* -f (or) --file public_key -rsa
   - *drop* -f (or) --file private_key -rsa
   - *drop* -f (or) --file key_pair -rsa

**Class Encryptor Command**
   _Encryption commands are not completed_

   - *encrypt* -in (or) -input <input_text> -rsa
   - *encrypt* -fld (or) -fl-dir (or) --file-directory <file_path> -rsa
   - *encrypt* -dir (or) --directory <dir_path> -rsa

**Class Decryptor Command**
   _No commands have been written for the RSA algorithm, it is only a plan_

   **RSA** - _required data for decryption_

   : *Encrypted data* - input_text, file_directory, directory
   : *Encryption key* - public_key.pem, private_key.pem
   : *Encryption key size* - size for size in range(1024, 4097, 8)

   - *decrypt* -in (or) -input <input_text> -rsa
   - *decrypt* -fld (or) -fl-dir (or) --file-directory <encrypted_file_path> -rsa
   - *decrypt* -dir (or) --directory <encrypted_dir_path> -rsa
