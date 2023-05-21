# Pysafe
File encryptor

## Necessarry libraries installation:
    pip install -r requirements.txt
    
## How to use Pysafe (CLI):
    usage: pysafe.py [-h] [-p PATH] [-s SALT_SIZE] [-e] [-d]

    PySafe File Encryptor

    options:
      -h, --help            show this help message and exit
      -p PATH, --path PATH  Path to encrypt/decrypt
      -s SALT_SIZE, --salt-size SALT_SIZE
                            If this is set, a new salt with the passed size is
                            generated
      -e, --encrypt         Whether to encrypt the path, only -e or -d can be
                            specified.
      -d, --decrypt         Whether to decrypt the path, only -e or -d can be
                            specified.
