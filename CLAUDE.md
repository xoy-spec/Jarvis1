# Jarvis (Lern- und Startup-KI)

Projekt von Laurin (Deutsch, Schüler). Antworten an ihn: Deutsch, kurz und präzise, bei iPad-Anleitungen sehr genaue Schritte.

## Aufbau
- `index.html`: die ganze App (eine Datei, Vanilla JS, Daten in localStorage). Version steht in den Einstellungen als "Jarvis vNN".
- `sw.js`, `manifest.json`, `icon.png`: PWA.
- `worker/worker.js`: Cloudflare-Worker `jarvis-api` (Proxy zu Anthropic, KV-Speicher `JARVIS_KV`).
  - Secrets bei Cloudflare, nie im Repo: `ANTHROPIC_API_KEY`, `JARVIS_CODE`, optional `JARVIS_GUESTS` (`Name:code,Name2:code2`), `GUEST_LIMIT`.
- Adresse der App: https://xoy-spec.github.io/Jarvis1/ (GitHub Pages, Zweig `main`).

## Stand
- Tabs: Start, Chat, Schule, Startup, Geld, Notizen. Büro ist ausgeblendet (Code noch drin, soll später in eine eigene Büro-KI).
- Schule: Modi Erklären, Hausaufgabe (Hinweise in Stufen), Quiz, Plan; Foto-Hilfe.
- Startup: Gründerkurs (6 Wochen), Idee, Lohnt sich?, Rechner, Verkaufen.
- Geld: Börsenspiel mit Spielgeld, Lernen, Sparplan. Live-Kurse und Krypto nur ab 18.
- Startfragen: Alter, Tätigkeit, Schulform, Klasse/Semester, Ziel. `profCtx()` passt die KI an. Unter 16 und 16-17 gelten Schutzregeln.

## Regeln
- Minderjährige: keine Anlage-, Trading- oder Krypto-Anleitungen, keine Gewinnversprechen, bei Geld und Verträgen auf Eltern hinweisen.
- Keine Geheimnisse (API-Schlüssel, Codes) ins Repo.
- Nach jeder Änderung im Browser testen (Playwright, Chromium), dann Version hochzählen und nach `main` pushen.
- Worker-Änderungen kann Laurin nur selbst bei Cloudflare einfügen (kein Zugriff von hier).

## Ziel
Beta Ende November 2026 mit begrenzten Nutzern. Offen: Login pro Person, Limits, Datenschutz und Impressum, Elternzustimmung unter 16, eigener Name und Logo, Karteikarten mit Wiederholung, Büro-Code entfernen, einheitliches Design.
