# Claude

В инструкциях проекта на время чтения чужих документов отключить инструменты сети, почты и произвольного shell, кроме запуска `sanitize`. Чтение файла и загрузка страницы заменяются командой:

```bash
python -m sanitize_skill INPUT --out sanitize-out
```

В контекст попадает `model.json`. `evidence.json` остаётся человеку. Цитаты в ответе сверяет `python -m sanitize_skill.quotes`.
