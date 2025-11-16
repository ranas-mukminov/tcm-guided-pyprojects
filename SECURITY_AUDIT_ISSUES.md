# Security and Code Quality Audit - Issues Report

Дата аудита: 2025-11-16
Проанализировано файлов: 8
Всего найдено проблем: 23

---

## Issue #1: [CRITICAL] Множественные синтаксические ошибки в exp_restrict_sql_injection.py

**Приоритет:** Критический
**Метки:** bug, syntax-error, critical
**Файл:** `exp_restrict_sql_injection.py`

### Описание
Файл содержит множественные синтаксические ошибки, которые делают код неработоспособным.

### Список ошибок:

1. **Строка 1:** Опечатка `mport` вместо `import`
   ```python
   mport requests  # ОШИБКА
   ```

2. **Строка 20:** Вызов несуществующей функции `injected_payload` (должно быть `injected_query`)
   ```python
   return injected_payload(payload)  # ОШИБКА
   ```

3. **Строка 25:** SQL синтаксическая ошибка + опечатка `lenght`
   ```python
   payload = "(select length(password from user where id = {} and lenght(password) <= {} limit 1)"
   # Пропущена закрывающая скобка после password
   # lenght -> length
   ```

4. **Строка 32:** Опечатка в имени переменной
   ```python
   for i in range(0, password_lenght):  # должно быть password_length
   ```

5. **Строка 57:** Неправильный отступ - return внутри while вместо for
   ```python
   while start <= end:
       # ...
       return found  # ОШИБКА: преждевременный выход
   ```

6. **Строка 73:** Пропущена закрывающая скобка
   ```python
   print("\t[-] User {} hash: {}".format(user_id, extract_hash_bst(charset, int(user_id, user_password_length)))
   # Не хватает закрывающей скобки
   ```

7. **Строка 76:** Пропущена открывающая кавычка
   ```python
   print(\t[X] User {} does not exist!".format(user_id))
   ```

### Шаги воспроизведения:
```bash
python exp_restrict_sql_injection.py
```

### Ожидаемое поведение:
Скрипт должен запускаться без синтаксических ошибок.

---

## Issue #2: [CRITICAL] Синтаксические ошибки в sql_injection_exploit.py

**Приоритет:** Критический
**Метки:** bug, syntax-error, critical
**Файл:** `sql_injection_exploit.py`

### Описание
Файл содержит те же синтаксические ошибки, что и exp_restrict_sql_injection.py, плюс отсутствует функция.

### Список ошибок:

1. **Строка 20:** Вызов несуществующей функции `injected_payload`
2. **Строка 25:** SQL синтаксическая ошибка + опечатка `lenght`
3. **Строка 54:** Пропущена открывающая кавычка в print
4. **Отсутствует функция** `extract_hash_bst`, которая вызывается в строке 73 (удалена из кода)

### Дополнительно:
- Неиспользуемая переменная `id = 0` в строке 23 функции `password_length`

---

## Issue #3: [CRITICAL] Runtime ошибки в buffer_overflow.py

**Приоритет:** Критический
**Метки:** bug, runtime-error, critical
**Файл:** `buffer_overflow.py`

### Описание
Скрипт содержит ошибки, которые приведут к сбою во время выполнения.

### Список ошибок:

1. **Строка 7:** Вызов `remote()` без обязательных параметров
   ```python
   io = remote()  # ОШИБКА: нужны host и port
   ```
   Должно быть: `io = remote('host', port)`

2. **Строка 24:** Опечатка в имени метода
   ```python
   io.sendLine(exploit)  # ОШИБКА
   ```
   Правильно: `io.sendline(exploit)` (маленькая 'l')

### Дополнительная проблема:
- Переменная `io` переопределяется дважды (строки 5 и 7), что может привести к путанице

---

## Issue #4: [CRITICAL] Использование несуществующей функции в sha256_cracking.py

**Приоритет:** Критический
**Метки:** bug, undefined-function, critical
**Файл:** `sha256_cracking.py`

### Описание
Скрипт использует несуществующую функцию `sha256sumhex` из библиотеки pwn.

### Список ошибок:

1. **Строка 17:** Функция `sha256sumhex` не существует
   ```python
   password_hash = sha256sumhex(password)  # ОШИБКА
   ```

   Правильное решение - использовать hashlib:
   ```python
   import hashlib
   password_hash = hashlib.sha256(password).hexdigest()
   ```

2. **Строка 20:** Логическая ошибка - `password_list` это файловый объект, не строка
   ```python
   p.success("Password hash found after {} attempts! {} hashes to {}!".format(attempts, password_list))
   # Должно быть: password.decode('latin-1')
   ```

---

## Issue #5: [HIGH] Критическая проблема производительности в host_scanner.py

**Приоритет:** Высокий
**Метки:** performance, resource-exhaustion, high
**Файл:** `host_scanner.py`

### Описание
Скрипт создает 65,535 потоков одновременно, что приведет к исчерпанию системных ресурсов.

### Проблема (строки 46-49):
```python
threads = []
for port in range(1,65536):
    thread = threading.Thread(target=scan_port, args=(target_ip, port))
    threads.append(thread)
    thread.start()
```

### Последствия:
- Исчерпание памяти
- Ошибка "too many open files"
- Возможный крах системы
- Медленная работа из-за переключения контекста

### Рекомендуемое решение:
Использовать `ThreadPoolExecutor` с ограниченным количеством рабочих потоков:

```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(scan_port, target_ip, port)
               for port in range(1, 65536)]
```

---

## Issue #6: [HIGH] Небезопасная практика SSH в ssh_login_brute_forcing.py

**Приоритет:** Высокий
**Метки:** security, mitm-vulnerability, high
**Файл:** `ssh_login_brute_forcing.py`

### Описание
Использование `AutoAddPolicy()` автоматически принимает любые SSH ключи хостов без проверки.

### Проблема (строка 14):
```python
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
```

### Уязвимость:
Это делает соединение уязвимым к атакам Man-in-the-Middle (MITM), так как не проверяется подлинность сервера.

### Рекомендации:
1. Для тестовых целей добавить комментарий о рисках
2. Для продакшена использовать:
   ```python
   client.load_system_host_keys()
   client.set_missing_host_key_policy(paramiko.RejectPolicy())
   ```

---

## Issue #7: [MEDIUM] Слабая проверка пароля в passwd-strengh.py

**Приоритет:** Средний
**Метки:** security, weak-validation, enhancement
**Файл:** `passwd-strengh.py` (также опечатка в имени файла)

### Описание
Проверка пароля только по длине недостаточна для определения надежности.

### Текущая реализация (строки 3-6):
```python
if len(passwd) < 8:
    print("Password is weak, must be at least 8 characters.")
else:
    print("Password is strong.")
```

### Проблемы:
1. Пароль "aaaaaaaa" считается сильным
2. Нет проверки на:
   - Заглавные буквы
   - Цифры
   - Специальные символы
   - Словарные слова
   - Повторяющиеся символы

### Рекомендуемые проверки:
- Минимум 8 символов
- Минимум 1 заглавная буква
- Минимум 1 строчная буква
- Минимум 1 цифра
- Минимум 1 специальный символ
- Проверка на распространенные пароли

### Дополнительно:
Опечатка в имени файла: `strengh` -> `strength`

---

## Issue #8: [MEDIUM] Отсутствие обработки исключений сети в web_login_form_brute_forcing.py

**Приоритет:** Средний
**Метки:** enhancement, error-handling
**Файл:** `web_login_form_brute_forcing.py`

### Описание
Отсутствует обработка сетевых ошибок при выполнении HTTP-запросов.

### Проблема (строка 15):
```python
r = requests.post(target, data={"username": username, "password": password})
```

### Возможные проблемы:
- Тайм-ауты
- Ошибки соединения
- HTTP ошибки (500, 503 и т.д.)
- DNS ошибки

### Рекомендуемое решение:
```python
try:
    r = requests.post(target, data={"username": username, "password": password}, timeout=5)
    r.raise_for_status()
except requests.exceptions.RequestException as e:
    sys.stdout.write(f"\n[!] Error: {e}\n")
    continue
```

---

## Issue #9: [LOW] Hardcoded конфигурация во всех файлах

**Приоритет:** Низкий
**Метки:** enhancement, code-quality, configuration
**Файлы:** Все

### Описание
Все скрипты имеют hardcoded значения (URL, пути к файлам, имена пользователей).

### Примеры:
- `sql_injection_exploit.py`: `target = "http://127.0.0.1:5000"`
- `sha256_cracking.py`: `password_file = "rockyou.txt"`
- `ssh_login_brute_forcing.py`: `host = "127.0.0.1"`, `username = "notroot"`

### Рекомендация:
Создать конфигурационный файл (config.ini или .env) или использовать аргументы командной строки:

```python
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--target', required=True, help='Target URL')
parser.add_argument('--wordlist', default='rockyou.txt', help='Password wordlist')
args = parser.parse_args()
```

---

## Issue #10: [LOW] Несоответствие PEP 8 - неконсистентные отступы

**Приоритет:** Низкий
**Метки:** code-quality, pep8, style
**Файлы:** `sql_injection_exploit.py`, `exp_restrict_sql_injection.py`

### Описание
Используются 2 пробела для отступов вместо рекомендуемых 4 (PEP 8).

### Пример:
```python
def injected_query(payload):
  global total_queries  # 2 пробела
  r = requests.post(...)  # 2 пробела
```

### Рекомендация:
Использовать инструменты форматирования:
```bash
black *.py
# или
autopep8 --in-place --aggressive *.py
```

---

## Issue #11: [LOW] Отсутствие docstrings и документации

**Приоритет:** Низкий
**Метки:** documentation, code-quality
**Файлы:** Все

### Описание
Функции не имеют docstrings, что затрудняет понимание их назначения.

### Пример отсутствующей документации:
```python
def boolean_query(offset, user_id, character, operator=">"):
    # Что делает эта функция? Какие параметры? Что возвращает?
    payload = "(select hex(substr(password, {}, 1)) from user where id = {}) {} hex('{}')".format(offset+1, user_id, operator, character)
    return injected_query(payload)
```

### Рекомендуемый формат:
```python
def boolean_query(offset, user_id, character, operator=">"):
    """
    Выполняет булевый SQL-запрос для извлечения одного символа пароля.

    Args:
        offset (int): Позиция символа в пароле (0-based)
        user_id (int): ID пользователя в базе данных
        character (str): Символ для сравнения
        operator (str): Оператор сравнения ('>' или '=')

    Returns:
        bool: True если условие выполнено, False в противном случае
    """
```

---

## Issue #12: [LOW] Отсутствие валидации пользовательского ввода

**Приоритет:** Низкий
**Метки:** security, input-validation
**Файлы:** `sql_injection_exploit.py`, `exp_restrict_sql_injection.py`

### Описание
Пользовательский ввод не валидируется перед использованием.

### Пример (строка 46):
```python
user_id = input("> Enter a user ID to extract the password hash: ")
# Нет проверки: это число? Положительное? В допустимом диапазоне?
```

### Рекомендация:
```python
try:
    user_id = int(input("> Enter a user ID to extract the password hash: "))
    if user_id < 1:
        raise ValueError("User ID must be positive")
except ValueError as e:
    print(f"[!] Invalid input: {e}")
    continue
```

---

## Сводная статистика по приоритетам:

- **CRITICAL (Критический):** 4 issue (код не работает)
- **HIGH (Высокий):** 2 issues (безопасность/производительность)
- **MEDIUM (Средний):** 2 issues (улучшения)
- **LOW (Низкий):** 4 issues (качество кода)

**Всего:** 12 issues

---

## Рекомендуемый порядок исправления:

1. Issue #1, #2, #3, #4 (CRITICAL) - исправить немедленно
2. Issue #5 (HIGH) - производительность host_scanner.py
3. Issue #6 (HIGH) - безопасность SSH
4. Issue #7, #8 (MEDIUM) - улучшения безопасности и обработки ошибок
5. Issue #9, #10, #11, #12 (LOW) - улучшения качества кода

---

## Инструкция по созданию issues в GitHub:

1. Перейдите в раздел Issues вашего репозитория
2. Для каждой проблемы нажмите "New Issue"
3. Скопируйте заголовок (например: "[CRITICAL] Множественные синтаксические ошибки в exp_restrict_sql_injection.py")
4. Скопируйте содержимое соответствующей секции
5. Добавьте метки (labels) указанные в каждом issue
6. Создайте issue

Или используйте GitHub CLI (если доступен):
```bash
# Пример создания issue
gh issue create --title "[CRITICAL] Множественные синтаксические ошибки в exp_restrict_sql_injection.py" \
                --body "$(cat issue_body.md)" \
                --label "bug,syntax-error,critical"
```
