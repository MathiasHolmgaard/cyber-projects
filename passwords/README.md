# Password Strength Analyzer (NIST SP 800-63-4 Compliant)

En serverløs mikrotjeneste i Python (FastAPI) der fungerer som en Password Strength Analyzer baseret på moderne NIST SP 800-63-4 retningslinjer, med HIBP k-Anonymity integration samt Argon2id hashing demo.

## Funktioner

* **NIST SP 800-63-4 Validering**: Tjekker minimumslængde (8 tegn) og forbyder passwords der findes i datalæk.
* **Entropi og Kompleksitet**: Anvender `zxcvbn` til at evaluere entropi og advare mod almindelige passwords (ordbogsord, navne, mønstre), uden at kræve arbitrære specialtegn.
* **Have I Been Pwned (k-Anonymity)**: Tjekker sikkert mod HIBP databasen ved kun at sende de første 5 tegn af SHA-1 hashen.
* **Sikker Demonstrationshashing**: Viser hvordan et password hashes sikkert med Argon2id ifølge OWASP standarderne.

## Sådan kører du tjenesten

### Lokalt (med Docker Compose)
Den nemmeste og mest sikre måde at køre applikationen på er via Docker. Image-filen bygger på et letvægts `python:3.11-alpine` miljø og kører som non-root `appuser`.

1. Byg og start servicen:
   ```bash
   docker-compose up --build -d
   ```
2. API'et er nu tilgængeligt på `http://localhost:8000`.

Du kan teste API'et via de indbyggede Swagger UI docs på:  
`http://localhost:8000/docs`

### Miljøvariabler (Antigravity Cloud / Local)
Hvis du ønsker at benytte en HIBP API-nøgle for premium hastighed og adgang:
1. Opret en `.env` fil i projektets rod (eller sæt miljøvariablen direkte i Antigravity CI/CD):
   ```
   HIBP_API_KEY=din_hemmelige_nøgle_her
   ```

## Test af Endpoints

### 1. Analyser et password
```bash
curl -X 'POST' \
  'http://localhost:8000/analyze' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "password": "correcthorsebatterystaple!"
}'
```

### 2. Hash et password (Argon2id)
```bash
curl -X 'POST' \
  'http://localhost:8000/hash' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "password": "correcthorsebatterystaple!"
}'
```

## Teknologi Stack
* **Python 3.11** + **FastAPI**
* **pydantic** til validering og hemmeligholdelse af input (sikrer mod logging via `SecretStr`)
* **zxcvbn** for entropi/dictionary checks
* **httpx** til asynkrone HTTP-opkald
* **argon2-cffi** til hashing
