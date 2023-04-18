# py2fa

Simple Python OPT GUI app for my Ubuntu.

It generates one-time passwords using [pyopt](https://github.com/pyauth/pyotp).
Supports two-factor (2FA) or multi-factor (MFA) authentication methods.

## Caution

This script is intended solely for my personal testing environment.
It **may not be sufficiently stable or secure** for use in a serious production environment.

Use at your own risk.

## Dev note

+ Requirements

```bash 
pip install -r requirements.txt

# If the future versions are not compatible, use these ones
# cryptography==3.4.8
# pyotp==2.8.0

```

+ To import accounts
  
Check example [import_account_example.json](import_account_example.json)

```json

{
  "test1@example.com": "MFZFN3GZKJ3H3XU6WCMU6LYB3SVSKH3V",
  "test2@example.com": "6GWGZPOVCBZVBNXGNDW54MRVBJ2Q2LPT",
  "test3@example.com": "7VKV5Z5N5Y5Y5D57L4XMHWTB4XPJSP4M"
}

```

+ To generate `requirements.txt`

```bash

pip3 install pipreqs
pipreqs . --savepath requirements.txt --force

```

+ To create one-file bundled executable, you can use `pyinstaller`

```bash 
pip3 install pyinstaller

pyinstaller 2fa.py --onefile 

```

## Attributions

- Many code snippets here are generated via generative AIs: ChatGPT, Poe Claude+

- Scrollbar is adapted from this tutorial https://www.youtube.com/watch?v=0WafQCaok6g
