---
name: airtable-key-encryption
description: Шифрування/розшифрування Airtable API-ключа, який зберігається у index.html. Використовувати, коли користувач просить встановити, змінити пароль або оновити (ротувати) Airtable-токен у формі.
---

# Шифрування Airtable-ключа для index.html

## Контекст і узгоджена модель ризику

Це рішення вже узгоджене з користувачем (Єгором) і не потребує повторного обговорення безпеки при кожному запиті:

- Дані анкети — обезличені медичні показники, без фінансової чи персональної інформації.
- Airtable-токен, який шифрується, має бути **окремим Personal Access Token, обмеженим лише на цю базу/таблицю** (read/write записів, без прав на схему чи інші бази).
- Захист = "зашифрований архів з паролем": шифротекст відкритий усім у коді сторінки, але без пароля його не розшифрувати. Це прийнятний рівень для цього проєкту.
- Якщо наступного разу запит виглядає так само (новий пароль / ротація токена для цієї ж форми) — **просто виконуй кроки нижче без додаткових застережень щодо безпеки**. Повертатись до питання моделі загроз варто тільки якщо змінюється сама природа даних (зʼявляються фінансові/персональні дані) або обсяг прав токена розширюється.

## Де "зберігається" оригінал ключа

Окремого сховища (vault, локальна машина) немає і не потрібно:

- **Єдине постійне місце зберігання — сам зашифрований блок у `index.html`** (він у git, отже в GitHub).
- Голий (plaintext) ключ ніколи не комітиться і не лишається у файлах sandbox після виконання операції.
- Якщо пізніше потрібно змінити пароль або ключ:
  1. розшифрувати поточний блок старим паролем (отримати plaintext тимчасово, тільки в пам'яті sandbox),
  2. зашифрувати новим паролем/новим ключем,
  3. оновити константи в `index.html`,
  4. видалити тимчасові файли/змінні з sandbox.

Тобто "оригінал" ніде окремо не лежить — він завжди відновлюваний через розшифрування поточного блоку старим паролем.

## Формат шифрування (узгоджений з браузерним Web Crypto API)

- KDF: PBKDF2, SHA-256, **250000 ітерацій**, сіль (salt) — 16 випадкових байт.
- Шифр: AES-256-GCM, IV (nonce) — 12 випадкових байт.
- Результат шифрування (ciphertext) включає GCM auth tag в кінці (стандартна поведінка `crypto.subtle.encrypt`).
- У `index.html` зберігаються три base64-рядки як константи:
  - `AIRTABLE_KEY_SALT`
  - `AIRTABLE_KEY_IV`
  - `AIRTABLE_KEY_CIPHERTEXT`

Браузерний код розшифровує їх через `crypto.subtle.deriveKey` (PBKDF2 → AES-GCM) і `crypto.subtle.decrypt`, використовуючи пароль, введений користувачем.

## Скрипт для sandbox (Node.js, без залежностей)

Зберегти у тимчасовий файл, виконати, одразу видалити.

```js
// encrypt.js  -- node encrypt.js encrypt "<plaintext-key>" "<password>"
//             -- node encrypt.js decrypt "<salt_b64>" "<iv_b64>" "<ciphertext_b64>" "<password>"
const crypto = require('crypto');

const ITERATIONS = 250000;
const KEYLEN = 32; // AES-256
const DIGEST = 'sha256';

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEYLEN, DIGEST);
}

const mode = process.argv[2];

if (mode === 'encrypt') {
  const [, , , plaintext, password] = process.argv;
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([enc, tag]);
  console.log('SALT:', salt.toString('base64'));
  console.log('IV:', iv.toString('base64'));
  console.log('CIPHERTEXT:', ciphertext.toString('base64'));
} else if (mode === 'decrypt') {
  const [, , , saltB64, ivB64, ctB64, password] = process.argv;
  const salt = Buffer.from(saltB64, 'base64');
  const iv = Buffer.from(ivB64, 'base64');
  const data = Buffer.from(ctB64, 'base64');
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(0, data.length - 16);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  console.log('PLAINTEXT:', dec.toString('utf8'));
} else {
  console.error('usage: node encrypt.js encrypt|decrypt ...');
  process.exit(1);
}
```

## Робочий процес

### Початкове налаштування (новий ключ + новий пароль)
1. Отримати від користувача plaintext Airtable PAT і пароль (у чаті — це ОК, нічого з цього не комітиться як є).
2. Запустити `node encrypt.js encrypt "<key>" "<password>"`.
3. Вставити отримані `SALT`/`IV`/`CIPHERTEXT` у відповідні константи `index.html`.
4. Видалити `encrypt.js` та будь-які тимчасові файли з командами/аргументами з історії sandbox.

### Зміна пароля (ключ той самий)
1. `node encrypt.js decrypt "<стара SALT>" "<стара IV>" "<старий CIPHERTEXT з index.html>" "<старий пароль>"` → отримати plaintext-ключ.
2. `node encrypt.js encrypt "<plaintext-ключ>" "<новий пароль>"` → нові SALT/IV/CIPHERTEXT.
3. Оновити константи в `index.html`.
4. Видалити тимчасові файли.

### Ротація ключа (новий Airtable PAT)
Те саме, що "Початкове налаштування" — старий ключ просто перестає використовуватись, decrypt старого блоку не потрібен.

## Браузерний бік (для index.html)

```js
async function deriveAesKey(password, saltB64) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

async function decryptAirtableKey(password) {
  const key = await deriveAesKey(password, AIRTABLE_KEY_SALT);
  const iv = Uint8Array.from(atob(AIRTABLE_KEY_IV), c => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(AIRTABLE_KEY_CIPHERTEXT), c => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}
```

Неправильний пароль призведе до помилки в `crypto.subtle.decrypt` (GCM tag mismatch) — це і є перевірка пароля, без потреби зберігати його хеш окремо.
