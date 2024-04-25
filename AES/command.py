import os
import secrets
import binascii

from colorama import Fore, Style
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class BitSize:
    def __call__(self, func):
        def wrapper(self, bit_size: int):
            try:
                bit_size = int(bit_size)
            except ValueError:
                print(Fore.RED + '[-] ' + Style.RESET_ALL + f'\'{bit_size}\' Не можливий розмір ключа шифрування')
                return

            if bit_size not in self.get_supported_aes_key_sizes():
                print(Fore.RED + '[-] ' + Style.RESET_ALL + f'\'{bit_size}\' Не можливий розмір ключа шифрування')
                return

            return func(self, bit_size)

        return wrapper


class KeyManager:
    def __init__(self):
        super().__init__()
        self.key = secrets.token_hex(16)
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Keys')
        self.key_dir = os.path.join(self.keys_dir, 'key.pem')
        self.key_file = None

    @staticmethod
    def get_supported_aes_key_sizes():
        return [128, 192, 256]

    def keys_status(self):                                                                                              # keys_status
        print('\n* ' + Fore.BLUE + 'AES' + Style.RESET_ALL)
        if os.path.exists(self.key_dir) and os.path.getsize(os.path.join(self.key_dir)) > 0:
            key = open(self.key_dir, 'rb').read()
            key_size_bits = len(key) * 8
            print(
                Fore.GREEN + '\t[+] ' + Style.RESET_ALL + f'Key {key_size_bits}\t\t\t\t: ' +
                Fore.YELLOW + self.key_dir + Style.RESET_ALL
            )
        else:
            print(
                Fore.YELLOW + '\t[?] ' + Style.RESET_ALL + f'Key\t\t\t\t\t: ' +
                Fore.YELLOW + 'Ключ шифрування не знайден' + Style.RESET_ALL
            )

    def create_key_aes(self):                                                                                           # create key -aes
        self.key = secrets.token_hex(16)
        print(''.join([self.key[i:i + 64] for i in range(0, len(self.key), 64)]))

    @BitSize()
    def create_key_aes_bit_size(self, bit_size: int):                                                                   # create key -aes --size=<bit_size>
        bit_size = int(bit_size)
        self.key = secrets.token_hex(bit_size // 8)
        print(''.join([self.key[i:i + 64] for i in range(0, len(self.key), 64)]))

    def create_file_key_aes(self):                                                                                      # create -f (or) --file key -aes
        self.key = secrets.token_bytes(32)
        self.write_to_file(self.key_dir, self.key, 'Ключ шифрування')

    @BitSize()
    def create_file_key_aes_bit_size(self, bit_size: int):                                                              # create -f (or) --file key -ase --size=<bit_size>
        bit_size = int(bit_size)
        self.key = secrets.token_bytes(bit_size // 8)
        self.write_to_file(self.key_dir, self.key, 'Ключ шифрування')

    def write_to_file(self, file_path, contents, key_type):                                                             # create -f (or) --file key -aes --size=<bit_size>
        if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
            key_overwrite = input(
                Fore.YELLOW +
                '[?] ' + Style.RESET_ALL + f'{key_type} вже існує : ' + Fore.YELLOW +
                f'{file_path}\n' + Style.RESET_ALL +
                '\nВи бажаєте перезаписати ключ шифрування? ' + Fore.BLUE + '(Y/n)' + Style.RESET_ALL
            )

            if key_overwrite.lower() in ['y', 'yes']:
                try:
                    with open(file_path, 'wb') as file:
                        file.write(contents)
                        print(
                            Fore.GREEN + '[+] ' +
                            Style.RESET_ALL + f'{key_type} успішно перезаписан : ' + Fore.YELLOW +
                            f'{file_path}' + Style.RESET_ALL
                        )
                except Exception as e:
                    print(f'Помилка: {e}')
                    return
        else:
            try:
                with open(file_path, 'wb') as file:
                    file.write(contents)
                    print(
                        Fore.GREEN + '[+] ' +
                        Style.RESET_ALL + f'{key_type} успішно перезаписан : ' + Fore.YELLOW +
                        f'{file_path}' + Style.RESET_ALL
                    )
            except Exception as e:
                print(f'Помилка: {e}')
                return


class Encryptor:
    def __init__(self):
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Keys')
        self.key_dir = os.path.join(self.keys_dir, 'key.pem')
        self.cipher = None
        self.iv = None
        self.tag = None
        self.ciphertext = None

    @staticmethod
    def get_supported_aes_encrypt_mode():
        return ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'GCM', 'XTS', 'CCM', 'EAX']

    def encrypt_input_mode(self, input_text, cipher_mode):                                                              # encrypt -in <input_text> -aes --mode=<cipher_mode>
        try:
            key = open(self.key_dir, 'rb').read()

            self.iv = secrets.token_bytes(AES.block_size)

            if isinstance(input_text, list):
                input_text = ''.join(input_text)

            if cipher_mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                encrypted_data = cipher.encrypt(pad(input_text.encode(), AES.block_size))
                self.ciphertext = encrypted_data.hex()

            elif cipher_mode == 'CBC':
                cipher = AES.new(key, AES.MODE_CBC, self.iv)
                encrypted_data = cipher.encrypt(pad(input_text.encode(), AES.block_size))
                self.ciphertext = self.iv.hex() + encrypted_data.hex()

            elif cipher_mode == 'CFB':
                cipher = AES.new(key, AES.MODE_CFB, self.iv)
                encrypted_data = cipher.encrypt(input_text.encode())
                self.ciphertext = self.iv.hex() + encrypted_data.hex()

            elif cipher_mode == 'OFB':
                cipher = AES.new(key, AES.MODE_OFB, self.iv)
                encrypted_data = cipher.encrypt(input_text.encode())
                self.ciphertext = self.iv.hex() + encrypted_data.hex()

            elif cipher_mode == 'CTR':
                cipher = AES.new(key, AES.MODE_CTR, nonce=self.iv)
                encrypted_data = cipher.encrypt(input_text.encode())
                self.ciphertext = self.iv.hex() + encrypted_data.hex()

            elif cipher_mode == 'GCM':
                self.iv = secrets.token_bytes(12)
                cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv)
                encrypted_data, tag = cipher.encrypt_and_digest(input_text.encode())
                self.ciphertext = self.iv.hex() + encrypted_data.hex() + tag.hex()

            elif cipher_mode == 'EAX':
                cipher = AES.new(key, AES.MODE_EAX, nonce=self.iv)
                encrypted_data, tag = cipher.encrypt_and_digest(input_text.encode())
                self.ciphertext = self.iv.hex() + encrypted_data.hex() + tag.hex()

            elif cipher_mode == 'SIV':
                cipher = AES.new(key, AES.MODE_SIV, nonce=self.iv)
                encrypted_data = cipher.encrypt(pad(input_text.encode(), AES.block_size))
                self.ciphertext = self.iv.hex() + encrypted_data.hex()

            else:
                print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Недопустимый режим шифрования: ' + cipher_mode)
                return

        except PermissionError:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Программа не имеет прав для шифрования текста')
            return

        except ValueError:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Ключ шифрования не создан')
            return

        except Exception as e:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Ошибка при шифровании текста: ' + str(e))
            return

        else:
            print(
                Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Зашифрованный текст: ' + Fore.YELLOW +
                self.ciphertext + Style.RESET_ALL
            )
            return self.ciphertext

    def encrypt_to_file_mode(self, file_path, cipher_mode):
        try:
            with open(file_path, 'rb') as input_file:
                plaintext = input_file.read()

            with open(self.key_dir, 'rb') as key_file:
                key = key_file.read()

            iv = None

            if cipher_mode in ['CBC', 'CFB', 'OFB', 'CTR', 'GCM', 'EAX', 'SIV']:
                iv = secrets.token_bytes(AES.block_size)

            if cipher_mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                encrypted_data = cipher.encrypt(pad(plaintext, AES.block_size))

            elif cipher_mode == 'CBC':
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_data = cipher.encrypt(pad(plaintext, AES.block_size))

            elif cipher_mode == 'CFB':
                cipher = AES.new(key, AES.MODE_CFB, iv)
                encrypted_data = cipher.encrypt(plaintext)

            elif cipher_mode == 'OFB':
                cipher = AES.new(key, AES.MODE_OFB, iv)
                encrypted_data = cipher.encrypt(plaintext)

            elif cipher_mode == 'CTR':
                cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
                encrypted_data = cipher.encrypt(plaintext)

            elif cipher_mode == 'GCM':
                iv = secrets.token_bytes(12)
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                encrypted_data, tag = cipher.encrypt_and_digest(plaintext)

            elif cipher_mode == 'EAX':
                cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
                encrypted_data, tag = cipher.encrypt_and_digest(plaintext)

            elif cipher_mode == 'SIV':
                cipher = AES.new(key, AES.MODE_SIV, nonce=iv)
                encrypted_data = cipher.encrypt(pad(plaintext, AES.block_size))

            else:
                print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Недопустимый режим шифрования: ' + cipher_mode)
                return False

            with open(file_path, 'wb') as output_file:
                if iv:
                    output_file.write(iv)
                output_file.write(encrypted_data)

        except PermissionError:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Программа не имеет прав для шифрования файлов')
            return False

        except FileNotFoundError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Файл ' + Fore.YELLOW + file_path + Style.RESET_ALL + ' не найден'
            )
            return False
        except ValueError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Ключ шифрования не создан. Проверьте ключи шифрования ' +
                Fore.BLUE + 'keys_status' + Style.RESET_ALL
            )
            return False
        else:
            print(
                Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Файл ' + Fore.YELLOW + file_path + Style.RESET_ALL +
                ' успішно зашифрован'
            )
            return True

    def encrypt_to_dir_mode(self, dir_path, cipher_mode):                                                               # encrypt -dir (or) --directory <dir_path> -aes --mode=<cipher_mode>
        dir_path = str(dir_path)

        try:
            for root, dirs, files in os.walk(dir_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)

                    self.encrypt_to_file_mode(file_path, cipher_mode)

        except FileNotFoundError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Директорія ' +
                Fore.YELLOW + dir_path + Style.RESET_ALL + ' не знайдена'
            )
            return

        except NotADirectoryError:
            print(Fore.RED + '[-] ' + Fore.YELLOW + dir_path + Style.RESET_ALL + ' Вказан файл а не директорія')
            return

        except OSError:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Загальна помилка операційної системи при роботі з файлом')
            return

        except ValueError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Ключ шифрування не створений. Перевірьте ключи шифруваня' +
                Fore.BLUE + 'keys_status' + Style.RESET_ALL
            )
            return

        else:
            print(
                Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Директорія ' +
                Fore.YELLOW + dir_path + Style.RESET_ALL + ' успішно зашифрована'
            )


class Decryptor:
    def __init__(self):
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Keys')
        self.key_dir = os.path.join(self.keys_dir, 'key.pem')
        self.cipher = None
        self.iv = None
        self.tag = None
        self.plaintext = None

    def decrypt_input_text(self, input_text, cipher_mode):                                                              # decrypt -in <input_text> -aes --mode=<cipher_mode>
        try:
            key = open(self.key_dir, 'rb').read()

            if isinstance(input_text, list):
                input_text = ''.join(input_text)

            if cipher_mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted_data = cipher.decrypt(binascii.unhexlify(input_text))
                plaintext = unpad(decrypted_data, AES.block_size).decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            elif cipher_mode == 'CBC':
                iv = binascii.unhexlify(input_text[:32])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_data = cipher.decrypt(binascii.unhexlify(input_text[32:]))
                plaintext = unpad(decrypted_data, AES.block_size).decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            elif cipher_mode == 'CFB':
                iv = binascii.unhexlify(input_text[:32])
                cipher = AES.new(key, AES.MODE_CFB, iv)
                decrypted_data = cipher.decrypt(binascii.unhexlify(input_text[32:]))
                plaintext = decrypted_data.decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            elif cipher_mode == 'OFB':
                iv = binascii.unhexlify(input_text[:32])
                cipher = AES.new(key, AES.MODE_OFB, iv)
                decrypted_data = cipher.decrypt(binascii.unhexlify(input_text[32:]))
                plaintext = decrypted_data.decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            elif cipher_mode == 'CTR':
                iv = binascii.unhexlify(input_text[:32])
                cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
                decrypted_data = cipher.decrypt(binascii.unhexlify(input_text[32:]))
                plaintext = decrypted_data.decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            elif cipher_mode == 'GCM':
                iv = binascii.unhexlify(input_text[:24])
                tag = binascii.unhexlify(input_text[-32:])
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
                decrypted_data = cipher.decrypt_and_verify(binascii.unhexlify(input_text[24:-32]), tag)
                plaintext = decrypted_data.decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            elif cipher_mode == 'EAX':
                iv = binascii.unhexlify(input_text[:24])
                tag = binascii.unhexlify(input_text[-32:])
                cipher = AES.new(key, AES.MODE_EAX, nonce=iv, mac_len=16)
                decrypted_data = cipher.decrypt_and_verify(binascii.unhexlify(input_text[24:-32]), tag)
                plaintext = decrypted_data.decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            elif cipher_mode == 'SIV':
                iv = binascii.unhexlify(input_text[:32])
                cipher = AES.new(key, AES.MODE_SIV, nonce=iv)
                decrypted_data = cipher.decrypt(binascii.unhexlify(input_text[32:]))
                plaintext = unpad(decrypted_data, AES.block_size).decode()
                self.plaintext = ' '.join([plaintext[i:i + 5] for i in range(0, len(plaintext), 5)])

            else:
                print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Недопустимый режим расшифрования: ' + cipher_mode)
                return

        except PermissionError:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Програмі не вистачає прав для шифрування файлів')
            return False

        except ValueError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Ключ шифрування не створений. Перевірьте ключи шифруваня' +
                Fore.BLUE + 'keys_status' + Style.RESET_ALL
            )
            return

        else:
            print(
                Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Розшифрований текст: ' + Fore.YELLOW +
                self.plaintext + Style.RESET_ALL
            )
            return self.plaintext

    def decrypt_to_file_mode(self, file_path, cipher_mode):
        try:
            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            key = open(self.key_dir, 'rb').read()

            if cipher_mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted_data = cipher.decrypt(encrypted_data)
                plaintext = unpad(decrypted_data, AES.block_size)

            elif cipher_mode == 'CBC':
                iv = encrypted_data[:AES.block_size]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
                plaintext = unpad(decrypted_data, AES.block_size)

            elif cipher_mode == 'CFB':
                iv = encrypted_data[:AES.block_size]
                cipher = AES.new(key, AES.MODE_CFB, iv)
                decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
                plaintext = decrypted_data

            elif cipher_mode == 'OFB':
                iv = encrypted_data[:AES.block_size]
                cipher = AES.new(key, AES.MODE_OFB, iv)
                decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
                plaintext = decrypted_data

            elif cipher_mode == 'CTR':
                iv = encrypted_data[:AES.block_size]
                cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
                decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
                plaintext = decrypted_data

            elif cipher_mode == 'GCM':
                iv = encrypted_data[:12]
                tag = encrypted_data[-16:]
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
                decrypted_data = cipher.decrypt_and_verify(encrypted_data[12:-16], tag)
                plaintext = decrypted_data

            elif cipher_mode == 'EAX':
                iv = encrypted_data[:12]
                tag = encrypted_data[-16:]
                cipher = AES.new(key, AES.MODE_EAX, nonce=iv, mac_len=16)
                decrypted_data = cipher.decrypt_and_verify(encrypted_data[12:-16], tag)
                plaintext = decrypted_data

            elif cipher_mode == 'SIV':
                iv = encrypted_data[:AES.block_size]
                cipher = AES.new(key, AES.MODE_SIV, nonce=iv)
                decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
                plaintext = unpad(decrypted_data, AES.block_size)

            else:
                print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Недопустимый режим расшифрования: ' + cipher_mode)
                return False

            with open(file_path, 'wb') as decrypted_file:
                decrypted_file.write(plaintext)

        except Exception as e:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Ошибка при расшифровке файла: ' + str(e))
            return False

        else:
            print(
                Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Файл ' + Fore.YELLOW + file_path +
                Style.RESET_ALL + ' успішно расшифрован'
            )
            return True

    def decrypt_to_dir_mode(self, dir_path, cipher_mode):
        dir_path = str(dir_path)

        try:
            for root, dirs, files in os.walk(dir_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)

                    self.decrypt_to_file_mode(file_path, cipher_mode)

        except FileNotFoundError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Директорія ' +
                Fore.YELLOW + dir_path + Style.RESET_ALL + ' не знайдена'
            )
            return

        except NotADirectoryError:
            print(Fore.RED + '[-] ' + Fore.YELLOW + dir_path + Style.RESET_ALL + ' Вказан файл а не директорія')
            return

        except OSError:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Загальна помилка операційної системи при роботі з файлом')
            return

        except ValueError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Ключ шифрування не створений. Перевірьте ключи шифруваня' +
                Fore.BLUE + 'keys_status' + Style.RESET_ALL
            )
            return

        else:
            print(
                Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Директорія ' +
                Fore.YELLOW + dir_path + Style.RESET_ALL + ' успішно зашифрована'
            )
