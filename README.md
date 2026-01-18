# malware-analys-vsosh

Проект создан для Всероссийской Олимпиады Школьников по Предмету Информационная Безопасность. Идея заключается в анализе подозрительных файлов с использованием локального sandbox на базе Raspberry Pi 5 или другого Linux. Главная уникальность
в создании полноценной среды пользователя в виртуальной машине, скрывая факт ее
виртуализации.

## Быстрый старт
```bash
git clone <your-repo-url>
cd <repo-folder>

sudo apt update
sudo apt install -y python3 python3-venv git curl \
  firejail tcpdump clamav qemu-system-x86 qemu-system-arm qemu-utils
sudo freshclam

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp env.example .env
cp config.example.yaml config.yaml
cp allowed_users.example.json allowed_users.json

nano .env
nano allowed_users.json

python3 tgbot.py
```

## Требования

- Linux 
- Python 3.11+
- KVM для ускорения виртуализации 
- Пакеты: `firejail`, `tcpdump`, `clamav`, `qemu-system-x86`, `qemu-system-arm`, `qemu-utils`

## Установка

1. Склонируйте репозиторий и установите зависимости:
```bash
git clone <your-repo-url>
cd <repo-folder>
sudo apt update
sudo apt install -y python3 python3-venv git curl firejail tcpdump clamav qemu-system-x86 qemu-system-arm qemu-utils
sudo freshclam
```

2. Создайте виртуальное окружение и установите Python-зависимости:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Конфигурация

Скопируйте примеры конфигов и заполните их:
```bash
cp env.example .env
cp config.example.yaml config.yaml
cp allowed_users.example.json allowed_users.json
```

### `.env`

- `BOT_TOKEN` — токен Telegram-бота от @BotFather
- `VIRUSTOTAL_API_KEY` — опционально, ключ VirusTotal для проверки хэшей

### `allowed_users.json`

- `users` — список ID пользователей Telegram, которым разрешен доступ
- `admin` — администраторы
- `allowed_groups` — разрешенные чаты/группы

### `config.yaml`

Параметры статического анализа, пороги скоринга, настройки ClamAV и YARA.

### `vm_config.yaml`

Пути, параметры VM и настройки анти-VM эвристик.

## Подготовка VM

1. Создайте директории для VM и логов:
```bash
mkdir -p vm_images logs/vm
```

2. Подготовьте образы qcow2 и положите их в `vm_images/`:

- `vm_images/ubuntu-arm64.qcow2`
- `vm_images/ubuntu-x64.qcow2`

3. В `vm_config.yaml` проверьте пути и параметры VM, а также желаемые имена снапшотов (`clean`, `pool_ready`).

## MITRE ATT&CK 

```bash
mkdir -p mitre
curl -o mitre/enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

## Запуск

Вручную:
```bash
source venv/bin/activate
python3 tgbot.py
```

Скрипт:
```bash
./start_bot.sh
```

Ожидание  x64 VM и сохранение снапшота:
```bash
./wait_x64_and_snapshot.sh
```

## Systemd

1. 
sudo cp tgbot.service /etc/systemd/system/
sudo cp vm-pool.service /etc/systemd/system/
```

2.
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tgbot.service vm-pool.service
```

## Лицензия

GNU General Public License v3.0: https://www.gnu.org/licenses/gpl-3.0.html
