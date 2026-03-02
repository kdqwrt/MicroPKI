# MicroPKI

## Реализация инфраструктуры открытых ключей (PKI)


## Технологический стек

-   Язык программирования: Python ≥ 3.12
-   Криптографическая библиотека: cryptography
-   CLI: argparse (стандартная библиотека)
-   Логирование: logging (стандартная библиотека)
-   Система сборки: через pyproject.toml
-   Тестирование: pytest


##  Установка и сборка

### 1 Создание виртуального окружения

``` bash
python -m venv .venv
```

Windows:

``` bash
.\.venv\Scripts\activate
```

Linux/macOS:

``` bash
source .venv/bin/activate
```

### 2 Установка проекта

``` bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

После установки становится доступна команда:

``` bash
micropki --help
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
``` 
micropki-project/
├── micropki/                  # Основной пакет
│   ├── __init__.py
│   ├── cli.py                 # Парсер аргументов и точка входа CLI
│   ├── ca.py                  # Логика инициализации корневого CA
│   ├── certificates.py        # Генерация и сохранение X.509 сертификатов
│   ├── crypto_utils.py        # Генерация, сериализация и загрузка ключей
│   ├── dn_parser.py           # Парсинг отличительных имен (DN)
│   ├── logger.py              # Настройка логирования
│   └── policy.py              # Генерация документа с политикой
├── tests/                      # Модульные и интеграционные тесты
│   └── test_root_ca.py
├── requirements.txt            # Зависимости проекта
└── README.md                   # Данный файл
```


