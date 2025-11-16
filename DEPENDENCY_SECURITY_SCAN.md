# Dependency Security Scan Report

**Дата сканирования:** 2025-11-16
**Инструмент:** pip-audit 2.9.0
**Статус:** ✅ **PASSED** - Уязвимостей не обнаружено

---

## Сводка

```
No known vulnerabilities found
```

**Всего проверено пакетов:** 33
**Найдено уязвимостей:** 0
**Требуется исправлений:** 0

---

## Основные зависимости

| Пакет | Версия | Статус безопасности |
|-------|--------|---------------------|
| **requests** | 2.32.5 | ✅ Безопасно |
| **paramiko** | 4.0.0 | ✅ Безопасно |
| **pwntools** | 4.15.0 | ✅ Безопасно |

---

## Все проверенные зависимости

### HTTP и сетевые библиотеки
- requests 2.32.5 ✅
- urllib3 2.5.0 ✅
- certifi 2025.11.12 ✅
- charset-normalizer 3.4.4 ✅
- idna 3.11 ✅

### SSH и криптография
- paramiko 4.0.0 ✅
- cryptography 46.0.3 ✅
- bcrypt 5.0.0 ✅
- pynacl 1.6.1 ✅
- cffi 2.0.0 ✅

### Binary exploitation (pwntools)
- pwntools 4.15.0 ✅
- capstone 6.0.0a5 ✅
- pyelftools 0.32 ✅
- ropgadget 7.7 ✅
- unicorn 2.1.2 ✅

### Утилиты и вспомогательные библиотеки
- intervaltree 3.1.0 ✅
- sortedcontainers 2.4.0 ✅
- invoke 2.2.1 ✅
- mako 1.3.10 ✅
- markupsafe 3.0.3 ✅
- psutil 7.1.3 ✅
- pygments 2.19.2 ✅
- pyserial 3.5 ✅
- six 1.17.0 ✅
- colored-traceback 0.4.2 ✅
- packaging 25.0 ✅
- pycparser 2.23 ✅
- pysocks 1.7.1 ✅
- python-dateutil 2.9.0.post0 ✅
- rpyc 6.0.2 ✅
- plumbum 1.10.0 ✅
- unix-ar 0.2.1 ✅
- zstandard 0.25.0 ✅

---

## Методология сканирования

### Использованные инструменты

1. **pip-audit** (v2.9.0)
   - Официальный инструмент Python Packaging Authority
   - Проверяет зависимости против базы данных PyPI Advisory Database
   - Сканирует как прямые, так и транзитивные зависимости

### Команда сканирования

```bash
pip-audit -r requirements.txt --format json
```

### База данных уязвимостей

- **PyPI Advisory Database** - постоянно обновляемая база известных уязвимостей Python пакетов
- **CVE (Common Vulnerabilities and Exposures)** - международная база уязвимостей
- **GHSA (GitHub Security Advisories)** - предупреждения безопасности GitHub

---

## Рекомендации

### Текущее состояние: ОТЛИЧНО ✅

Все зависимости находятся в актуальном и безопасном состоянии. Уязвимостей не обнаружено.

### Лучшие практики

1. **Регулярное сканирование**
   ```bash
   # Запускать еженедельно
   pip-audit -r requirements.txt
   ```

2. **Автоматическое обновление**
   - Настроить GitHub Dependabot для автоматических PR с обновлениями
   - Использовать `pip-audit` в CI/CD pipeline

3. **Мониторинг новых уязвимостей**
   - Подписаться на security advisories для используемых пакетов
   - Следить за GitHub Security Alerts

4. **Фиксация версий**
   ```bash
   # Создать lock-файл с точными версиями
   pip freeze > requirements-lock.txt
   ```

---

## Автоматизация

### GitHub Actions Workflow

Рекомендуется добавить `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Еженедельно

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install pip-audit
        run: pip install pip-audit
      - name: Run security scan
        run: pip-audit -r requirements.txt
```

---

## История сканирований

| Дата | Пакетов | Уязвимостей | Статус |
|------|---------|-------------|--------|
| 2025-11-16 | 33 | 0 | ✅ PASSED |

---

## Контакты

По вопросам безопасности:
- Откройте issue на GitHub
- Email: (указать контактный email для security reports)

---

**Следующее сканирование:** Рекомендуется через 7 дней или при обновлении зависимостей

**Автоматически сгенерировано:** pip-audit 2.9.0
**Проект:** TCM Guided Python Security Projects
