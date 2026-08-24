#!/usr/bin/env python3
"""Migrate ConfigPage and JeaPage to i18n."""
import json
import re
from pathlib import Path

ROOT = Path('/root/keeppam')
CATALOG_PATH = ROOT / 'web/src/i18n/catalog.ts'

# Load translations from embedded minimal set + extend via JSON if present
DATA_PATH = ROOT / 'scripts/config_jea_i18n.json'
if DATA_PATH.exists():
    CATALOG = json.loads(DATA_PATH.read_text(encoding='utf-8'))
else:
    CATALOG = {}

COMMON_REUSE = {
    "Сохранить": "common.save", "Отмена": "common.cancel", "Удалить": "common.delete",
    "Создать": "common.create", "Недостаточно прав": "common.forbidden",
    "Имя": "common.name", "Описание": "common.description", "Статус": "common.status",
    "да": "common.yes", "нет": "common.no", "Группа": "common.group",
    "Пользователь": "common.user", "Актив": "common.asset", "все": "common.all",
    "все дни": "cal.allDays",
}

def tcall(key):
    return f't("{key}")'

def main():
    if not CATALOG:
        print('No catalog data - run generate step first')
        return 1
    existing = CATALOG_PATH.read_text(encoding='utf-8')
    new_lines = []
    for key in sorted(CATALOG.keys()):
        if f'"{key}"' in existing:
            continue
        p = CATALOG[key]
        ru = p['ru'].replace('\\', '\\\\').replace('"', '\\"')
        en = p['en'].replace('\\', '\\\\').replace('"', '\\"')
        kk = p['kk'].replace('\\', '\\\\').replace('"', '\\"')
        if len(ru) > 80 or '\n' in ru:
            new_lines.append(f'  "{key}": {{\n    ru: "{ru}",\n    en: "{en}",\n    kk: "{kk}",\n  }},')
        else:
            new_lines.append(f'  "{key}": {{ ru: "{ru}", en: "{en}", kk: "{kk}" }},')
    if new_lines:
        block = '\n'.join(new_lines) + '\n'
        existing = existing.replace('} satisfies Record<string, Pair>;', block + '} satisfies Record<string, Pair>;')
        CATALOG_PATH.write_text(existing, encoding='utf-8')
        print(f'Added {len(new_lines)} catalog keys')
    for page, prefix in [('ConfigPage.tsx', 'config'), ('JeaPage.tsx', 'jea')]:
        path = ROOT / f'web/src/pages/{page}'
        text = path.read_text(encoding='utf-8')
        if 'useI18n' not in text:
            text = text.replace('import { useAuth } from "../auth";',
                'import { useAuth } from "../auth";\nimport { useI18n } from "../i18n";')
            text = re.sub(r'(export function \w+Page\(\) \{\n  const \{ user \} = useAuth\(\);)',
                r'\1\n  const { t, te } = useI18n();', text, count=1)
        if page == 'JeaPage.tsx':
            text = text.replace('const DAY_LABELS = ["Вс", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"];\n\n', '')
            text = text.replace('function formatDaysMask(mask: number): string {',
                'function formatDaysMask(mask: number, t: (k: string) => string): string {')
            text = text.replace('if (mask === 127) return "все дни";',
                'if (mask === 127) return t("cal.allDays");')
            text = re.sub(r'DAY_LABELS\[(\d+)\]', r't("cal.\1")', text)
            text = text.replace('formatDaysMask(mask)', 'formatDaysMask(mask, t)')
            text = text.replace('formatDaysMask(b.days_of_week)', 'formatDaysMask(b.days_of_week, t)')
        ru_to_key = dict(COMMON_REUSE)
        for k, v in CATALOG.items():
            if k.startswith(prefix + "."):
                ru_to_key[v["ru"]] = k
        fallback_load = "config.loadFailed" if prefix == "config" else "jea.loadFailed"
        fallback_save = "config.saveFailed" if prefix == "config" else "jea.saveFailed"
        tmpl = [
            (r'confirm\(`Удалить пакет «\$\{p\.name\}»\?\)', 'confirm(t("jea.deleteSshPackConfirm", { name: p.name }))'),
            (r'confirm\(`Удалить SQL-пакет «\$\{p\.name\}»\?\)', 'confirm(t("jea.deleteSqlPackConfirm", { name: p.name }))'),
            (r'confirm\(`Удалить HTTP-пакет «\$\{p\.name\}»\?\)', 'confirm(t("jea.deleteHttpPackConfirm", { name: p.name }))'),
            (r'confirm\(`Удалить пакет объектов «\$\{p\.name\}»\?\)', 'confirm(t("jea.deleteAppPackConfirm", { name: p.name }))'),
            (r'confirm\(`Удалить политику «\$\{p\.name\}»\? Привязки ACL останутся, ссылка сбросится\.`\)',
             'confirm(t("jea.deletePolicyConfirm", { name: p.name }))'),
            (r'confirm\("Отозвать tag ACL\? Пропадёт доступ ко всем подходящим активам\."\)',
             'confirm(t("jea.revokeTagAclConfirm"))'),
            (r'confirm\("Сгенерировать новый CA\? Старый ключ перестанет работать на целях\."\)',
             'confirm(t("config.rotateCaConfirm"))'),
            (r'setError\(err instanceof Error \? err\.message : "Ошибка загрузки"\)',
             f'setError(te(err, "{fallback_load}"))'),
            (r'setError\(err instanceof Error \? err\.message : "Ошибка сохранения"\)',
             f'setError(te(err, "{fallback_save}"))'),
            (r'setError\(err instanceof Error \? err\.message : "Ошибка удаления"\)',
             'setError(te(err, "jea.deleteFailed"))'),
            (r'setError\(err instanceof Error \? err\.message : "Ошибка preview"\)',
             'setError(te(err, "jea.previewFailed"))'),
            (r'setMsg\("([^"]+)"\)', None),  # handled below
        ]
        for pat, rep in tmpl:
            if rep is None:
                continue
            if prefix == "config" and "jea." in rep and "config." not in rep:
                continue
            if prefix == "jea" and "config." in rep and "jea." not in rep:
                continue
            text = re.sub(pat, rep, text)
        items = sorted(ru_to_key.items(), key=lambda x: -len(x[0]))
        for ru, key in items:
            if len(ru) < 2:
                continue
            esc = re.escape(ru)
            text = re.sub(rf'"{esc}"', tcall(key), text)
            text = re.sub(rf'>({esc})<', '>{' + tcall(key) + '}<', text)
            text = re.sub(rf'>({esc})</', '>{' + tcall(key) + '}</', text)
        path.write_text(text, encoding='utf-8')
        print(f'Updated {page}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
