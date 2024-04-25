from sys import path
import os
import shlex
import cmd

from colorama import Fore, Style

path.append('../Spectre/AES')
from AES.command import KeyManager as aes_key           # клас з функціями для створення ключа шифрування
from AES.command import Encryptor as aes_encrypt        # клас з фукції для шифрування тексту, файлів, директорій
from AES.command import Decryptor as aes_decrypt        # клас з функції для розшифрування текству, файлів, директорій (не дороблено)

path.append('../Spectre/RSA')
from RSA.command import KeyManager as rsa_key           # клас з функції для створення ключа шифрування
from RSA.command import Encryptor as rsa_encrypt        # клас з фукції для шифрування тексту, файлів, директорій (не дороблено)
from RSA.command import Decryptor as rsa_decrypt        # клас з функції для розшифрування текству, файлів, директорій (не дороблено)

__creator__ = 'Hexada'
__version__ = '1.0'


class CommandProcessor(cmd.Cmd):
    def __init__(self):
        super().__init__()
        self.aes_key = aes_key()
        self.aes_encrypt = aes_encrypt()
        self.aes_decrypt = aes_decrypt()
        self.rsa_key = rsa_key()
        self.rsa_encrypt = rsa_encrypt()
        self.rsa_decrypt = rsa_decrypt()

    def do_keys_status(self, arg):                                                                                      # keys_status
        self.aes_key.keys_status()
        self.rsa_key.keys_status()

    def do_create(self, arg):
        args = shlex.split(arg)

        if len(args) == 2:
            """
                - create key -aes 
                - create public_key -rsa
                - create private_key -rsa
                - create key_pair -rsa
            """
            if args[0] == 'key' and args[1] == '-aes':                                                                  # create key -aes
                self.aes_key.create_key_aes()

            if args[0] == 'public_key' and args[1] == '-rsa':                                                           # create public_key -rsa
                self.rsa_key.create_public_key_rsa()

            if args[0] == 'private_key' and args[1] == '-rsa':                                                          # create private_key -rsa
                self.rsa_key.create_private_key_rsa()

            if args[0] == 'key_pair' and args[1] == '-rsa':                                                             # create key_pair -rsa
                self.rsa_key.create_public_key_rsa()
                self.rsa_key.create_private_key_rsa()

        elif len(args) == 3:
            """
                - create key -aes --size=<bit_size>
                - create public_key -rsa --size=<bit_size>
                - create private_key -rsa --size=<bit_size>
                - create key_pair -rsa --size=<bit_size>
                - create -f (or) --file key -aes
                - create -f (or) --file public_key -rsa
                - create -f (or) --file private_key -rsa
                - create -f (or) --file key_pair -rsa
            """
            if args[0] == 'key' and args[1] == '-aes' and args[2].startswith('--size='):                                # create key -aes --size=<bit_size>
                bit_size = int(args[2][7:])
                self.aes_key.create_key_aes_bit_size(bit_size)

            if args[0] == 'public_key' and args[1] == '-rsa' and args[2].startswith('--size='):                         # create public_key -rsa --size=<bit_size>
                bit_size = int(args[2][7:])
                self.rsa_key.create_public_key_rsa_bit_size(bit_size)

            if args[0] == 'private_key' and args[1] == '-rsa' and args[2].startswith('--size='):                        # create private_key -rsa --size=<bit_size>
                bit_size = int(args[2][7:])
                self.rsa_key.create_private_key_rsa_bit_size(bit_size)

            if args[0] == 'key_pair' and args[1] == '-rsa' and args[2].startswith('--size='):                           # create key_pair -rsa --size=<bit_size>
                bit_size = int(args[2][7:])
                self.rsa_key.create_public_key_rsa_bit_size(bit_size)
                self.rsa_key.create_private_key_rsa_bit_size(bit_size)

            if args[0] in ['-f', '--file'] and args[1] == 'key' and args[2] == '-aes':                                  # create -f (or) --file key -aes
                self.aes_key.create_file_key_aes()

            if args[0] in ['-f', '--file'] and args[1] == 'public_key' and args[2] == '-rsa':                           # create -f (or) --file public_key -rsa
                self.rsa_key.create_file_public_key_rsa()

            if args[0] in ['-f', '--file'] and args[1] == 'private_key' and args[2] == '-rsa':                          # create -f (or) --file private_key -rsa
                self.rsa_key.create_file_private_key_rsa()

            if args[0] in ['-f', '--file'] and args[1] == 'key_pair' and args[2] == '-rsa':                             # create -f (or) --file key_pair -rsa
                self.rsa_key.create_file_public_key_rsa()
                self.rsa_key.create_file_private_key_rsa()


        elif len(args) == 4:
            """
                - create -f (or) --file key -aes --size=<bit_size>
                - create -f (or) --file public_key -rsa --size=<bit_size>
                - create -f (or) --file private_key -rsa --size=<bit_size>
                - create -f (or) --file key_pair -rsa --size=<bit_size>
            """
            if args[0] in ['-f', '--file'] and args[1] == 'key' and args[2] == '-aes' \
                    and args[3].startswith('--size='):                                                                  # create -f (or) --file key -aes --size=<bit_size>
                bit_size = int(args[3][7:])
                self.aes_key.create_file_key_aes_bit_size(bit_size)

            if args[0] in ['-f', '--file'] and args[1] == 'public_key' and args[2] == '-rsa' \
                    and args[3].startswith('--size='):                                                                  # create -f (or) --file public_key -rsa --size=<bit_size>
                bit_size = int(args[3][7:])
                self.rsa_key.create_file_public_key_rsa_bit_size(bit_size)

            if args[0] in ['-f', '--file'] and args[1] == 'private_key' and args[2] == '-rsa' \
                    and args[3].startswith('--size='):                                                                  # create -f (or) --file private_key -rsa --size=<bit_size>
                bit_size = int(args[3][7:])
                self.rsa_key.create_file_private_key_rsa_bit_size(bit_size)

            if args[0] in ['-f', '--file'] and args[1] == 'key_pair' and args[2] == '-rsa' \
                    and args[3].startswith('--size='):                                                                  # create -f (or) --file key_pair -rsa --size=<bit_size>
                bit_size = int(args[3][7:])
                self.rsa_key.create_file_public_key_rsa_bit_size(bit_size)
                self.rsa_key.create_file_private_key_rsa_bit_size(bit_size)

        else:
            print(
                Fore.RED + '[-] ' + Style.RESET_ALL + 'Невідома команда : ' + Fore.YELLOW + str(args) + Style.RESET_ALL
            )

    def do_drop(self, arg):
        args = shlex.split(arg)

        if len(args) == 3:
            """
                - drop -f (or) --file key -aes
                - drop -f (or) --file public_key -rsa
                - drop -f (or) --file private_key -rsa
                - drop -f (or) --file key_pair -rsa
            """
            """
            Видалення клюда не надійне, в майбютньому буде інструмент Shreder, якій буде видаляти дані безпечно, 
            видаляти буде як і ключи шифрування, так і любі другі файли або директорії. Shreder буде працювати по
            наступому пинципу - заповнення файла солью, шифрування солі, а потім вже видалення
            """
            try:
                if args[0] in ['-f', '--file'] and args[1] == 'key' and args[2] == '-aes':                              # drop -f (or) --file key -aes
                    with open(self.aes_key.key_dir, 'w') as file:
                        file.truncate(0)

                if args[0] in ['-f', '--file'] and args[1] == 'public_key' and args[2] == '-rsa':                       # drop -f (or) --file public_key -rsa
                    with open(self.rsa_key.public_key_dir, 'w') as public_key_file:
                        public_key_file.truncate(0)

                if args[0] in ['-f', '--file'] and args[1] == 'private_key' and args[2] == '-rsa':                      # drop -f (or) --file private_key -rsa
                    with open(self.rsa_key.private_key_dir, 'w') as private_key_file:
                        private_key_file.truncate(0)

                if args[0] in ['-f', '--file'] and args[1] == 'key_pair' and args[2] == '-rsa':                         # drop -f (or) --file key_pair -rsa
                    with open(self.rsa_key.public_key_dir, 'w') as public_key_file:
                        public_key_file.truncate(0)

                    with open(self.rsa_key.private_key_dir, 'w') as private_key_file:
                        private_key_file.truncate(0)

            except FileNotFoundError:
                print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Ключ не створений')
                return

            except PermissionError:
                print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Файл із ключем зайнятий іншим процесом')
                return

            else:
                print(Fore.GREEN + '[+] ' + Style.RESET_ALL + 'Ключ видален')

    def do_encrypt(self, arg):
        args = shlex.split(arg)

        if len(args) == 3:
            """
                - encrypt -in (or) -input <input_text> -aes
                - encrypt -fld (or) --file-directory <file_path> -aes
                - encrypt --dir (or) --directory <dir_path> -aes
                - encrypt -fld (or) -fl-dir (or) --file-directory <file_path> -rsa
                - encrypt --dir (or) --directory <dir_path> -rsa
            """
            if args[0] in ['-in', '--input'] and args[2] == '-aes':                                                     # encrypt -in (or) -input <input_text> -aes
                input_texts = args[1]
                cipher_mode = 'ECB'                                                                                     # default --mode=ecb
                self.aes_encrypt.encrypt_input_mode(input_texts, cipher_mode)

            if args[0] in ['-fld', '--file-directory'] and args[2] == '-aes':                                           # encrypt -fld (or) --file-directory <file_path> -aes
                file_path = args[1]
                cipher_mode = 'CFB'                                                                                     # default --mode=cfb
                self.aes_encrypt.encrypt_to_file_mode(file_path, cipher_mode)

            if args[0] in ['-dir', '--directory'] and args[2] == '-aes':                                                # encrypt --dir (or) --directory <dir_path> -aes
                dir_path = args[1]
                cipher_mode = 'CFB'                                                                                     # default --mode=cfb
                self.aes_encrypt.encrypt_to_dir_mode(dir_path, cipher_mode)

            if args[0] in ['-fld', '--file-directory'] and args[2] == '-rsa':                                           # encrypt -fld (or) --file-directory <file_path> -rsa
                file_path = args[1]
                self.rsa_encrypt.encrypt_file_rsa(file_path)

            if args[0] in ['-dir', '--directory'] and args[2] == '-rsa':                                                # encrypt --dir (or) --directory <dir_path> -rsa
                dir_path = args[1]
                self.rsa_encrypt.encrypt_dir_rsa(dir_path)

        elif len(args) == 4:
            """
                - encrypt -in (or) -input <input_text> -aes --mode=<cipher_mode>
                - encrypt -fld (or) -fl-dir (or) --file-directory <file_path> -aes --mode=<cipher_mode>
                - encrypt -dir (or) --directory <dir_path> -aes --mode=<cipher_mode>
            """
            if args[0] in ['-in', '--input'] and args[2] == '-aes' and args[3].startswith('--mode='):                   # encrypt -in (or) -input <input_text> -aes --mode=<cipher_mode>
                input_texts = args[1].split()
                cipher_mode = args[3][7:].upper()
                if cipher_mode == 'ECB':                    # --mode=ecb
                    cipher_mode = 'ECB'
                    self.aes_encrypt.encrypt_input_mode(input_texts, cipher_mode)
                elif cipher_mode == 'CBC':                  # --mode=cbc
                    cipher_mode = 'CBC'
                    self.aes_encrypt.encrypt_input_mode(input_texts, cipher_mode)
                elif cipher_mode == 'CFB':                  # --mode=cfb
                    cipher_mode = 'CFB'
                    self.aes_encrypt.encrypt_input_mode(input_texts, cipher_mode)
                elif cipher_mode == 'OFB':                  # --mode=ofb
                    cipher_mode = 'OFB'
                    self.aes_encrypt.encrypt_input_mode(input_texts, cipher_mode)
                elif cipher_mode == 'CTR':                  # --mode=ctr
                    cipher_mode = 'CTR'
                    self.aes_encrypt.encrypt_input_mode(input_texts, cipher_mode)
                else:
                    print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Неможливий режим шифрування : ' + cipher_mode)
                    return

            if args[0] in ['-fld', '--file-directory'] and args[2] == '-aes' and args[3].startswith('--mode='):         # encrypt -fld (or) --file-directory <file_path> -aes --mode=<cipher_mode>
                file_paths = [args[1]]
                cipher_mode = args[3][7:].upper()
                for file_path in file_paths:
                    if cipher_mode == 'ECB':                # --mode=ecb
                        self.aes_encrypt.encrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CBC':              # --mode=cbc
                        self.aes_encrypt.encrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CFB':              # --mode=cfb
                        self.aes_encrypt.encrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'OFB':              # --mode=ofb
                        self.aes_encrypt.encrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CTR':              # --mode=ctr
                        self.aes_encrypt.encrypt_to_file_mode(file_path, cipher_mode)
                    else:
                        print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Неможливий режим шифрування : ' + cipher_mode)
                        return

            if args[0] in ['-dir', '--directory'] and args[2] == '-aes' and args[3].startswith('--mode='):              # encrypt -dir (or) --directory <dir_path> -aes --mode=<cipher_mode>
                dir_path = args[1]
                cipher_mode = args[3][7:].upper()
                file_names = os.listdir(dir_path)
                file_paths = [os.path.join(dir_path, file_name) for file_name in file_names]
                for file_path in file_paths:
                    if cipher_mode == 'ECB':                # --mode=ecb
                        self.aes_encrypt.encrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CBC':              # --mode=cbc
                        self.aes_encrypt.encrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CFB':              # --mode=cfb
                        self.aes_encrypt.encrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'OFB':              # --mode=ofb
                        self.aes_encrypt.encrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CTR':              # --mode=ctr
                        self.aes_encrypt.encrypt_to_dir_mode(file_path, cipher_mode)
                    else:
                        print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Неможливий режим шифрування : ' + cipher_mode)
                        return

    def do_decrypt(self, arg):
        args = shlex.split(arg)

        if len(args) == 3:
            """
                - decrypt -in (or) --input <input_text> -aes
                - decrypt -fld (or) -fl-dir (or) --file-directory <file_path> -aes (не працює)
                - decrypt -dir (or) --directory <dir_path> -aes (не працює)
            """
            if args[0] in ['-in', '--input'] and args[2] == '-aes':                                                     # decrypt -in (or) --input <input_text> -aes
                input_texts = args[1]
                cipher_mode = 'ECB'                         # default --mode=ecb
                self.aes_decrypt.decrypt_input_text(input_texts, cipher_mode)

            if args[0] in ['-fld', '--file-directory'] and args[2] == '-aes':                                           # decrypt -fld (or) --file-directory <file_path> -aes
                file_path = args[1]
                cipher_mode = 'CFB'                         # default --mode=cfb
                self.aes_decrypt.decrypt_to_file_mode(file_path, cipher_mode)

            if args[0] in ['-dir', '--directory'] and args[2] == '-aes':                                                # decrypt -dir (or) --directory <dir_path> -aes
                dir_path = args[1]
                cipher_mode = 'CFB'                         # default --mode=cfb
                self.aes_decrypt.decrypt_to_dir_mode(dir_path, cipher_mode)

        elif len(args) == 4:
            if args[0] in ['-in', '--input'] and args[2] == '-aes' and args[3].startswith('--mode='):                   # decrypt -in (or) -input <input_text> -aes --mode=<cipher_mode>
                input_texts = args[1].split()
                cipher_mode = args[3][7:].upper()
                if cipher_mode == 'ECB':                    # --mode=ecb
                    cipher_mode = 'ECB'
                    self.aes_decrypt.decrypt_input_text(input_texts, cipher_mode)
                elif cipher_mode == 'CBC':                  # --mode=cbc
                    cipher_mode = 'CBC'
                    self.aes_decrypt.decrypt_input_text(input_texts, cipher_mode)
                elif cipher_mode == 'CFB':                  # --mode=cfb
                    cipher_mode = 'CFB'
                    self.aes_decrypt.decrypt_input_text(input_texts, cipher_mode)
                elif cipher_mode == 'OFB':                  # --mode=ofb
                    cipher_mode = 'OFB'
                    self.aes_decrypt.decrypt_input_text(input_texts, cipher_mode)
                elif cipher_mode == 'CTR':                  # --mode=ctr
                    cipher_mode = 'CTR'
                    self.aes_decrypt.decrypt_input_text(input_texts, cipher_mode)
                else:
                    print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Неможливий режим шифрування : ' + cipher_mode)
                    return

            if args[0] in ['-fld', '--file-directory'] and args[2] == '-aes' and args[3].startswith('--mode='):         # decrypt -fld (or) -file-directory <file_path> -aes --mode=<cipher_mode>
                file_paths = [args[1]]
                cipher_mode = args[3][7:].upper()
                for file_path in file_paths:
                    if cipher_mode == 'ECB':                # --mode=ecb
                        self.aes_decrypt.decrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CBC':              # --mode=cbc
                        self.aes_decrypt.decrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CFB':              # --mode=cfb
                        self.aes_decrypt.decrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'OFB':              # --mode=ofb
                        self.aes_decrypt.decrypt_to_file_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CTR':              # --mode=ctr
                        self.aes_decrypt.decrypt_to_file_mode(file_path, cipher_mode)
                    else:
                        print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Неможливий режим шифрування : ' + cipher_mode)
                        return

            if args[0] in ['-dir', '--directory'] and args[2] == '-aes' and args[3].startswith('--mode='):              # encrypt -dir (or) --directory <dir_path> -aes --mode=<cipher_mode>
                dir_path = args[1]
                cipher_mode = args[3][7:].upper()
                file_names = os.listdir(dir_path)
                file_paths = [os.path.join(dir_path, file_name) for file_name in file_names]
                for file_path in file_paths:
                    if cipher_mode == 'ECB':                # --mode=ecb
                        self.aes_decrypt.decrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CBC':              # --mode=cbc
                        self.aes_decrypt.decrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CFB':              # --mode=cfb
                        self.aes_decrypt.decrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'OFB':              # --mode=ofb
                        self.aes_decrypt.decrypt_to_dir_mode(file_path, cipher_mode)
                    elif cipher_mode == 'CTR':              # --mode=ctr
                        self.aes_decrypt.decrypt_to_dir_mode(file_path, cipher_mode)
                    else:
                        print(Fore.RED + '[-] ' + Style.RESET_ALL + 'Неможливий режим шифрування : ' + cipher_mode)
                        return

    def do_help(self, arg):
        print()

    def do_exit(self, arg):
        return True


if __name__ == '__main__':
    command_processor = CommandProcessor()
    command = ['python', 'command.py']
    command_processor.prompt = 'sp1> '
    print(
        Fore.YELLOW + "e • 6 • 4 • \\\t\t" + Fore.RED + "    ____                __           " + Fore.YELLOW + "\t\tb • 7 • A • >\n" +
        Fore.YELLOW + "> • q • \ • x\t\t " + Fore.RED + "  / __/___  ___  ____ / /_ ____ ___  " + Fore.YELLOW + "\t\te • 5 • \ • x\n" +
        Fore.YELLOW + "1 • 2 • \ • r\t\t " + Fore.RED + " _\ \ / _ \/ -_)/ __// __// __// -_) " + Fore.YELLOW + "\t\tT • E • \ • x\n" +
        Fore.YELLOW + "8 • 0 • \ • x\t\t " + Fore.RED + "/___// .__/\__/ \__/ \__//_/   \__/  " + Fore.YELLOW + "\t\t\ • x • c • f\n" +
        Fore.YELLOW + "8 • c • o • q\t\t " + Fore.RED + "    /_/                              " + Fore.YELLOW + "\t\t\ • x • e • 4\n" +
        Style.RESET_ALL +
        '\n+-=-=-=-=-=-=-=-=-=-+ ' +
        'Creator : ' + Fore.LIGHTBLUE_EX + __creator__ + Style.RESET_ALL +
        '   Version : ' + Fore.LIGHTBLUE_EX + __version__ + Style.RESET_ALL +
        ' +-=-=-=-=-=-=-=-=-=-+\n'
    )
    command_processor.cmdloop()
