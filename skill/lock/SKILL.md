---
name: lock
description: Usa los secretos y variables de entorno del proyecto con `lock` sin ver su contenido. Aplica cuando haya un `.env.lock` en el repo, cuando haya que correr la app, tests o scripts que necesiten variables de entorno, agregar o rotar un secreto, o cuando el usuario mencione lock, secretos, .env o variables de entorno.
---

# lock: secretos sin verlos

`lock` guarda las variables de entorno cifradas y firmadas. En el repo pueden
estar en `.env.lock` (comiteado). Los **nombres** son publicos; los **valores**
solo se descifran con la clave del usuario (Touch ID en su Mac, `LOCK_KEY` en
servidores).

## Reglas

1. **Nunca leas valores.** No uses `lock get`, `lock load` ni `--no-redact`, y no
   corras comandos que impriman, codifiquen o copien variables (`env`, `printenv`,
   `echo $X`, `base64`, escribirlas a un archivo, `cat .env`).
2. **Nunca pidas que te peguen un secreto en el chat.** Si hace falta un valor,
   el usuario lo escribe en el prompt oculto de `lock set` en su terminal.
3. **Para ejecutar algo con el entorno, usa `lock run`:**
   ```bash
   lock run -- npm run dev
   lock run -- pytest
   lock run Navis -- node scripts/migrate.js   # entorno explicito
   ```
   Cada `lock run` muestra un dialogo de Touch ID con el entorno y el comando.
   Avisa antes en una linea ("voy a correr X con Navis, te va a pedir Touch ID").
   Usa comandos cortos y legibles para que el usuario entienda que aprueba. Si
   lo cancela, no insistas: pregunta.
4. La salida de `lock run` llega redactada (`[lock:NOMBRE]`). No intentes
   revertirlo ni esquivarlo.
5. **Nunca crees ni edites `.env` en texto plano**, ni escribas secretos en
   codigo, tests, logs o commits. Nunca edites `.env.lock` a mano.

## Consultas que no descifran (no piden Touch ID)

```bash
lock list            # entornos, versiones y destinatarios
lock list Navis      # nombres de las variables de Navis
lock check           # ¿el codigo usa variables que faltan en .env.lock? (lint orientativo)
```

## Agregar o cambiar variables

- Variable nueva que necesita un valor real: no lo pongas tu. Pidele al usuario:
  > "Falta `STRIPE_KEY` en Navis. Corre `lock set Navis/STRIPE_KEY` y escribe el valor en el prompt oculto."
- Secretos que se pueden generar (tokens de sesion, claves de firma propias):
  `lock set Navis/SESSION_SECRET --generate 32` (nadie ve el valor).
- Valores que no son secretos (puertos, URLs publicas):
  `printf 'https://api.ejemplo.com' | lock set Navis/API_BASE_URL`.
- Variables que pone la plataforma: agregalas a `.lockignore` (un nombre por
  linea, `PREFIJO_*` para prefijos).

Toda escritura pide Touch ID (descifrar y firmar comparten uno solo).

## Git

- `lock link <ENV>` (lo hace el usuario una vez por repo) instala dos hooks:
  pre-commit actualiza `.env.lock` desde la boveda; pre-push revisa que los
  commits que se suben no usen variables faltantes.
- Si el pre-push falla, no uses `--no-verify`: reporta que falta.
- `.env.lock` se comitea; `.env` nunca. `.env.lock` no se mergea como texto
  (`.gitattributes`): en un conflicto, la boveda manda (`lock dump --force`).

## Errores comunes

| Mensaje | Que hacer |
|---|---|
| `no hay claves ... Corre lock init` | Lo hace el usuario, no tu. |
| `ninguna de tus claves puede abrir X` | Esta maquina no es destinataria: el usuario la agrega con `lock recipient add`. |
| `lo firmo "..." que no es de confianza` | El archivo no viene de una identidad confiable. **No lo uses ni lo "arregles"**: avisa al usuario, puede ser un ataque. |
| `posible rollback` | Alguien volvio a una version vieja. Avisa al usuario. |
| `conflicto: ... contenido distinto` | Dos versiones divergentes: decide el usuario (`lock pull --force` o `lock dump --force`). |
| `Touch ID cancelado` | El usuario rechazo. Pregunta antes de reintentar. |
