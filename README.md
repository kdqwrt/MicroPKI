# MicroPKI

## Реализация инфраструктуры открытых ключей (PKI)


## Технологический стек

-   Язык программирования: Python ≥ 3.12
-   Криптографическая библиотека: cryptography
-   CLI: argparse 
-   Логирование: logging 
-   Система сборки: через pyproject.toml
-   Тестирование: pytest


## Инструкции по сборке и запуску

## Сборка и запуск на Windows
### 1. Клонировать репозиторий
```bat
git clone https://github.com/kdqwrt/MicroPKI.git
cd MicroPKI
```

### 2. Создание виртуального окружения

``` bash
python -m venv .venv
```
Активация:
```
.venv\Scripts\activate
```
### 3. Установка проекта
```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```
### 4. Проверка
```bash
micropki --help
```

## Быстрый старт

### Создать директорию для passphrase-файлов
```bash
mkdir secrets
```
### Создать passphrase для Root CA
```bash
echo|set /p=rootpass>secrets\ca.pass
```
### Создать passphrase для Intermediate CA
```bash
echo|set /p=interpass>secrets\intermediate.pass
```
### Инициализировать Root CA
```bash
micropki ca init --subject "CN=Demo Root CA,O=MicroPKI,C=DE" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir pki --validity-days 3650 --force
```
### Выпустить Intermediate CA
```bash
micropki ca issue-intermediate --root-cert pki\certs\ca.cert.pem --root-key pki\private\ca.key.pem --root-pass-file secrets\ca.pass --subject "CN=MicroPKI Intermediate CA,O=MicroPKI,C=DE" --key-type rsa --key-size 4096 --passphrase-file secrets\intermediate.pass --out-dir pki --validity-days 1825 --pathlen 0 --force
```
### Выпустить server certificate
```bash
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\intermediate.pass --template server --subject "CN=example.com,O=MicroPKI,C=DE" --san dns:example.com --san dns:www.example.com --san ip:127.0.0.1 --out-dir pki\certs --validity-days 365
```
### Проверить цепочку сертификатов
```bash
micropki ca verify-chain --root-cert pki\certs\ca.cert.pem --intermediate-cert pki\certs\intermediate.cert.pem --leaf-cert pki\certs\example.com.cert.pem --template server
```
### Запустить тесты
```bash
python -m pytest -q
```

## Использование

### Инициализация Root CA (RSA-4096)

``` bash
micropki ca init --subject "CN=Demo Root CA,O=MicroPKI,C=DE" --key-type rsa --key-size 4096 --passphrase-file ./secrets/ca.pass --out-dir ./pki --validity-days 3650
```

### 4.2 Инициализация Root CA (ECC P-384)

``` bash
micropki ca init --subject "CN=ECC Root CA,O=MicroPKI" --key-type ecc --key-size 384 --passphrase-file ./secrets/ca.pass --out-dir ./pki --validity-days 3650
```

## Структура проекта
```text
MicroPKI/
├── micropki/
│   ├── __init__.py
│   ├── __main__.py
│   ├── ca.py
│   ├── certificates.py
│   ├── chain.py
│   ├── cli.py
│   ├── crypto_utils.py
│   ├── csr.py
│   ├── dn_parser.py
│   ├── logger.py
│   ├── policy.py
│   ├── serials.py
│   └── templates.py

├── tests/
│   ├── test_root_ca.py
│   ├── test_csr.py
│   ├── test_intermediate.py
│   ├── test_leaf_issue.py
│   ├── test_templates.py
│   └── test_sprint2.py
│
├── pyproject.toml
├── requirements.txt
└── README.md
```


