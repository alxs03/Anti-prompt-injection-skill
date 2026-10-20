# Cursor

Скилл проекта: `.cursor/skills/sanitize/SKILL.md`. Он подключается, когда открыт этот репозиторий.

Пока скилл действует, агент не вызывает WebFetch и Read на чужой URL, PDF, DOCX, XLSX, PPTX или HTML. Вместо этого он запускает интерпретатор этого репозитория:

```bash
python -m sanitize_skill INPUT --out sanitize-out
```

Дальше он читает только `sanitize-out/model.json`. `evidence.json`, карантин и исходный файл не открывает.

Порог уровня лежит в домашнем `.sanitize/config.json`, не в настройках проекта. Чтобы скилл был доступен в других проектах, каталог `.cursor/skills/sanitize` копируют в личные скиллы Cursor.
