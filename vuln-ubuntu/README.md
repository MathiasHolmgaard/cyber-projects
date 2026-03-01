# Ubuntu Security Auditor

Dette værktøj udfører en omfattende sikkerhedsskaning af en Ubuntu-maskine og fremhæver potentielle sårbarheder i systemets konfiguration. Det tjekker brugerrettigheder, netværk, SSH-konfiguration, filsystemet og opdateringsstatus.

## Krav
- Python 3
- Ubuntu/Debian-baseret system
- Root/Sudo rettigheder til udførsel

## Sådan kører du værktøjet

Da scriptet skal have adgang til beskyttede filer (som `/etc/shadow`), netværksværktøjer og pakkemanageren, kræver det root-rettigheder:

```bash
sudo python3 auditor.py
```

Når scriptet er færdigt, genererer det to rapportfiler automatisk:
- `security_audit_report.json` (Maskinlæsbart format)
- `security_audit_report.md` (Læsbar rapport der let kan deles)

---

## 📖 Sådan tolkes rapporten

Rapporten er inddelt i tre hovedkategorier: **🔴 Sårbarheder**, **⚠️ Advarsler**, og **ℹ️ Information**. 

Her er en vejledning til at forstå og udbedre de typiske fund bygget ind i auditeringen:

### 1. Bruger- og adgangsstyring
- **Bruger har UID 0:** Hvis en anden bruger end `root` har User ID 0, har denne bruger fulde administrative systemrettigheder. 
  - *Løsning:* Verificer brugeren. Hvis den er unødvendig, fjernes den. Ellers ændres UID i `/etc/passwd`.
- **Bruger har et tomt kodeord:** Hvis loggen finder accounts uden en MD5/SHA hash i `/etc/shadow`, betyder det, at de kan logges direkte ind uden et kodeord.
  - *Løsning:* Tildel et reelt kodeord med `passwd <brugernavn>` eller deaktiver kontoen med `passwd -l <brugernavn>`.
- **Sudo gruppe (Info):** Værktøjet fremhæver hvilke brugere, der har adgang til superbruger-kommandoer (sudo).
  - *Løsning:* Kontrollér listen og fjern eventuelt uatoriserede brugere med `deluser <brugernavn> sudo`.

### 2. Netværk & Firewall
- **UFW er inaktiv:** Den indbyggede firewall på systemet er slået fra, hvilket efterlader alle kørende services åbne for tilgang fra netværket.
  - *Løsning:* Aktivér den med `sudo ufw enable`. Vigtigt: Sørg for at tilføje SSH før du aktiverer den, f.eks. `sudo ufw allow ssh`, da du ellers mister forbindelsen.
- **Telnet / RSH port åben:** Telnet (port 23) og RSH (port 514) sender al data - inklusiv kodeord - over nettet uden kryptering.
  - *Løsning:* Afinstaller disse forældede services (`sudo apt purge telnetd rsh-server`). Brug OpenSSH ift. administration.

### 3. SSH Konfiguration
- **PermitRootLogin:** At tillade en root-bruger at logge ind via nettet fjerner et lag af sikkerhed og gør serveren yderst modtagelig over for automatiseret *brute force*.
  - *Løsning:* Ændr dette til `PermitRootLogin prohibit-password` i f.eks. `/etc/ssh/sshd_config`, genstart dernæst SSH (`systemctl restart ssh`). Dette forhindrer adgangskodelogin som root, og tillader udelukkende nøglebaseret login for root, eller slå det helt fra.
- **SSH Protocol 1 tilladt:** En stærkt forældet og kryptografisk sårbar protokol.
  - *Løsning:* Sørg for i stedet kun at køre version 2 eller nyere.
- **PubkeyAuthentication sat til no:** Offentlig nøgle-autentifikation (SSH Keys) er betydeligt mere sikkert end statiske adgangskoder.
  - *Løsning:* Ændr til `PubkeyAuthentication yes`.

### 4. Filsystem
- **World-writable filer:** Finder filer, som af alle brugere på en maskine frit kan rettes i. Er der skrevet rettigheder for uautoriserede filer i f.eks. `/etc` kan dette være et seriøst kontroltab og potentielt skabe bagdøre.
  - *Løsning:* Ret til den rette permissions string via `chmod o-w <fil>`.
- **SUID/SGID bit (Info):** Denne bit tillader udførelsen af en fil men tvinger processen op i privilegie så den matcher den ejer (ofte root), der ejer selve filen. Dette er krævet (for f.eks. `sudo`), men unormale filer kan agere genvej til Privilege Escalation for angribere.
  - *Løsning:* Tjek outputlisten igennem mod typisk sikre filer (som f.eks. `/usr/bin/passwd`).

### 5. Opdateringsstatus
- **Manglende sikkerhedsopdateringer:** Der er nye lapper klar fra dine pakkeregistre, der omhandler kritiske rettelser.
  - *Løsning:* Installer disse opdateringer hurtigst muligt ved at køre `sudo apt update && sudo apt upgrade`.
