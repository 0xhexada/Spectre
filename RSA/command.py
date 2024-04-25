import os

from colorama import Fore, Style
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class BitSize:
    def __call__(self, func):
        def wrapper(self, bit_size: int):
            bit_size = int(bit_size)

            if bit_size not in self.get_supported_rsa_key_sizes():
                print(Fore.RED + '[-] ' + Style.RESET_ALL + f"\'{bit_size}\' Не можливий розмір ключа шифрування")
                return

            return func(self, bit_size)
        return wrapper


class KeyManager:
    def __init__(self):
        super().__init__()
        self.key = None
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Keys')    # Хранит в себе информацию о директори ключей шифрования

        self.public_key = None
        self.public_key_dir = os.path.join(self.keys_dir, 'public_key.pem')                 # ..Spectre/RSA/Keys/public_key.pem
        self.public_key_file = None

        self.private_key = None
        self.private_key_dir = os.path.join(self.keys_dir, 'private_key.pem')               # ..Spectre/RSA/Keys/private_key.pem
        self.private_key_file = None

    @staticmethod
    def get_supported_rsa_key_sizes():
        return [size for size in range(1024, 4097, 8)]

    def keys_status(self):                                                                                              # keys_status
        print('\n* ' + Fore.BLUE + 'RSA' + Style.RESET_ALL)

        if os.path.isfile(self.public_key_dir) and os.path.getsize(self.public_key_dir) > 0:
            public_key = open(self.public_key_dir, 'rb').read()
            public_key_size_bits = RSA.import_key(public_key).size_in_bits()
            print(
                Fore.GREEN + '\t[+] ' + Style.RESET_ALL + f'Public Key {public_key_size_bits}\t\t: '
                + Fore.YELLOW + self.public_key_dir + Style.RESET_ALL
            )

        else:
            print(
                Fore.YELLOW + '\t[?] ' + Style.RESET_ALL + 'Public Key\t\t\t: ' +
                Fore.YELLOW + 'Відкритий ключ шифрування не знайден' + Style.RESET_ALL
            )

        if os.path.isfile(self.private_key_dir) and os.path.getsize(self.private_key_dir) > 0:
            private_key = open(self.private_key_dir, 'rb').read()
            private_key_size_bits = RSA.import_key(private_key).size_in_bits()
            print(
                Fore.GREEN + '\t[+] ' + Style.RESET_ALL + f'Private Key {private_key_size_bits}\t: ' +
                Fore.YELLOW + self.private_key_dir + Style.RESET_ALL + '\n'
            )

        else:
            print(
                Fore.YELLOW + '\t[?] ' + Style.RESET_ALL + 'Private Key\t\t\t: ' +
                Fore.YELLOW + 'Закритий ключ шифрування не знайден\n' + Style.RESET_ALL
            )

    def create_public_key_rsa(self):                                                                                    # create public_key -rsa
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        public_key_contents = self.public_key.export_key().decode()
        print(f'\n{public_key_contents}\n')

    def create_private_key_rsa(self):                                                                                   # create private_key -rsa
        self.key = RSA.generate(2048)
        self.private_key = self.key.export_key()
        private_key_contents = self.private_key.decode()
        print(f'\n{private_key_contents}\n')

    @BitSize()
    def create_public_key_rsa_bit_size(self, bit_size: int):                                                            # create public_key -rsa --size=<bit_size>
        bit_size = int(bit_size)
        self.key = RSA.generate(bit_size)
        self.public_key = self.key.publickey()
        public_key_contents = self.public_key.export_key().decode()
        print(f'\n{public_key_contents}\n')
        self.key = RSA.generate(2048)

    @BitSize()
    def create_private_key_rsa_bit_size(self, bit_size: int):                                                           # create private_key -rsa --size=<bit_size>
        bit_size = int(bit_size)
        self.key = RSA.generate(bit_size)
        self.private_key = self.key.export_key()
        private_key_contents = self.private_key.decode()
        print(f'\n{private_key_contents}\n')
        self.key = RSA.generate(2048)

    def create_file_public_key_rsa(self):                                                                               # create -f (or) -file public_key -rsa
        """
        Создает открытый ключ шифрования в файле public_key.pem

        Directory:
            self.keys_dir (os.path.abspath(__file__)), 'Keys'): D:.../Erypt 1.1.0/RSA/Keys/public_key.pem
        """

        self.key = RSA.generate(2048)
        public_key_contents = self.key.publickey().export_key(format='PEM')
        self._write_to_file(self.public_key_dir, public_key_contents, 'Відкритий ключ шифрування')

    def create_file_private_key_rsa(self):                                                                              # create -f (or) -file private_key -rsa
        """
        Создает закрытый ключ шифрования в файле public_key.pem

        Directory:
            self.keys_dir (os.path.abspath(__file__)), 'Keys'): D:.../Erypt 1.1.0/RSA/Keys/private_key.pem
        """

        self.key = RSA.generate(2048)
        private_key_contents = self.key.export_key(format='PEM')
        return self._write_to_file(self.private_key_dir, private_key_contents, 'Закритий ключ шифрування')

    @BitSize()
    def create_file_public_key_rsa_bit_size(self, bit_size: int):                                                       # create -f (or) --file public_key -rsa --size=<bit_size>
        """
        Создает открытый ключ шифрования в файле public_key.pem с размером bit_size

        Directory:
            self.keys_dir (os.path.abspath(__file__)), 'Keys'): D:.../Erypt 1.1.0/RSA/Keys/public_key.pem

        Args:
            bit_size (int): Размер ключа RSA
        """

        self.key = RSA.generate(int(bit_size))
        public_key_contents = self.key.publickey().export_key(format='PEM')
        return self._write_to_file(self.public_key_dir, public_key_contents, 'Відкритий ключ шифрування')

    @BitSize()
    def create_file_private_key_rsa_bit_size(self, bit_size: int):                                                      # create -f (or) --file private_key -rsa --size=<bit_size>
        """
        Создает закрытый ключ шифрования в файле private_key.pem с размером bit_size

        Directory:
            self.keys_dir (os.path.abspath(__file__)), 'Keys'): D:.../Erypt 1.1.0/RSA/Keys/private_key.pem

        Args:
            bit_size (int): Размер ключа RSA
        """

        self.key = RSA.generate(int(bit_size))
        private_key_contents = self.key.export_key(format='PEM')
        return self._write_to_file(self.private_key_dir, private_key_contents, 'Закритий ключ шифрування')

    def _write_to_file(self, file_path, contents, key_type):
        try:
            if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
                key_overwrite = input(
                    Fore.YELLOW + '[?] ' + Style.RESET_ALL + f'{key_type} вже існує : ' + Fore.YELLOW + f'{file_path}\n' +
                    Style.RESET_ALL + '\nВи бажаєте перезаписати ключ шифрування? ' + Fore.BLUE + '(Y/n)' + Style.RESET_ALL
                )

                if key_overwrite.lower() in ['y', 'yes']:
                    with open(file_path, 'wb') as file:
                        file.write(contents)
                        print(
                            Fore.GREEN + '[+] ' + Style.RESET_ALL + f'{key_type} Успішно перезаписан : '
                            + Fore.YELLOW + f'{file_path}' + Style.RESET_ALL
                        )

            else:
                with open(file_path, 'wb') as file:
                    file.write(contents)
                    print(
                        Fore.GREEN + '[+] ' + Style.RESET_ALL + f'{key_type} успішно записан : ' + Fore.YELLOW +
                        f'{file_path}' + Style.RESET_ALL
                    )

        except IOError as e:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + f'Помилка вводу/виводу при записі {key_type}: {str(e)}')

        except Exception as e:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + f'Помилка при записі {key_type}: {str(e)}')


class Encryptor:
    def __init__(self):
        super().__init__()
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Keys')
        self.public_key_dir = os.path.join(self.keys_dir, 'public_key.pem')

    def encrypt_file_rsa(self, file_path):
        file_path = str(file_path)
        try:
            with open(self.public_key_dir, 'rb') as public_key_file:
                public_key = RSA.import_key(public_key_file.read())
                cipher = PKCS1_OAEP.new(public_key)

            with open(file_path, 'rb') as file:
                encrypted_content = cipher.encrypt(file.read())
            with open(file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_content)

        except PermissionError:
            print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Програмі не вистачає прав для шифрування файлів')
            return False

        except FileNotFoundError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Файл ' + Fore.YELLOW + file_path + Style.RESET_ALL + ' не найден'
            )
            return False

        except ValueError:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Ключ шифрування не створений. Перевірьте ключи шифруваня' +
                Fore.BLUE + 'keys_status' + Style.RESET_ALL
            )
            return

        else:
            print(
                Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Файл ' +
                Fore.YELLOW + file_path + Style.RESET_ALL + ' успешно зашифрован'
            )
            return True

    def encrypt_dir_rsa(self, dir_path):
        dir_path = str(dir_path)
        try:
            for root, dirs, files in os.walk(dir_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    self.encrypt_file_rsa(file_path)

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
        super().__init__()
