#!/usr/bin/env python3
import subprocess
import os
import sys
import json
from datetime import datetime

class UbuntuAuditor:
    def __init__(self):
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "warnings": [],
            "info": []
        }

    def run_command(self, cmd):
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return e.stdout + e.stderr
        except FileNotFoundError:
            return f"Kommandoen '{cmd[0]}' blev ikke fundet."
        except Exception as e:
            return str(e)

    def check_root_privileges(self):
        if os.geteuid() != 0:
            print("[\033[91mFejl\033[0m] Dette script skal køres med sudo-rettigheder for at kunne læse systemfiler og udføre netværkstjeks.")
            sys.exit(1)

    def audit_users_and_access(self):
        print("[*] Inspicerer bruger- og adgangsstyring...")
        
        # Tjek for brugere med UID 0 udover root
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = parts[2]
                        if uid == '0' and username != 'root':
                            self.report["vulnerabilities"].append({
                                "category": "Bruger- og adgangsstyring",
                                "issue": f"Kritisk: Brugeren '{username}' har UID 0 (root-rettigheder)."
                            })
        except Exception as e:
            self.report["warnings"].append(f"Kunne ikke læse /etc/passwd: {e}")

        # Tjek for tomme passwords i /etc/shadow
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        if password_hash == "" or password_hash == "U":
                            self.report["vulnerabilities"].append({
                                "category": "Bruger- og adgangsstyring",
                                "issue": f"Kritisk: Brugeren '{username}' har et tomt kodeord."
                            })
        except Exception as e:
            self.report["warnings"].append(f"Kunne ikke læse /etc/shadow: {e}")

        # Verificer sudo gruppen
        sudo_output = self.run_command(['getent', 'group', 'sudo'])
        if sudo_output and "Kommandoen" not in sudo_output:
            parts = sudo_output.strip().split(':')
            if len(parts) >= 4 and parts[3]:
                users = parts[3].split(',')
                self.report["info"].append({
                    "category": "Bruger- og adgangsstyring",
                    "issue": "Brugere i sudo-gruppen (skal manuelt verificeres).",
                    "details": users
                })
            else:
                self.report["info"].append({
                    "category": "Bruger- og adgangsstyring",
                    "issue": "Ingen brugere fundet i sudo-gruppen."
                })

    def audit_network_and_firewall(self):
        print("[*] Inspicerer netværk og firewall...")
        
        # Tjek firewall (UFW)
        ufw_status = self.run_command(['ufw', 'status'])
        if 'inactive' in ufw_status.lower() or 'ubrugelig' in ufw_status.lower() or 'not found' in ufw_status.lower() or 'off' in ufw_status.lower():
            self.report["vulnerabilities"].append({
                "category": "Netværk & Firewall",
                "issue": "UFW (Uncomplicated Firewall) er inaktiv eller ikke installeret."
            })
        else:
            self.report["info"].append({
                "category": "Netværk & Firewall",
                "issue": "UFW firewall lader til at være aktiv."
            })

        # Tjek for åbne porte og usikre tjenester
        ss_output = self.run_command(['ss', '-tuln'])
        if ss_output:
            if ':23 ' in ss_output:
                self.report["vulnerabilities"].append({
                    "category": "Netværk & Firewall",
                    "issue": "Telnet port 23 er åben."
                })
            if ':514 ' in ss_output:
                self.report["vulnerabilities"].append({
                    "category": "Netværk & Firewall",
                    "issue": "RSH port 514 er åben."
                })

    def audit_ssh_config(self):
        print("[*] Analyserer SSH konfiguration...")
        sshd_config_path = '/etc/ssh/sshd_config'
        
        if not os.path.exists(sshd_config_path):
            self.report["warnings"].append(f"Filen {sshd_config_path} blev ikke fundet.")
            return

        try:
            with open(sshd_config_path, 'r') as f:
                lines = f.readlines()
                
            permit_root = False
            ssh_v1 = False
            pubkey_auth = True
            
            for line in lines:
                line = line.strip()
                if line.startswith('#'): continue
                
                parts = line.split()
                if not parts: continue
                
                keyword = parts[0].lower()
                if keyword == 'permitrootlogin' and parts[1].lower() == 'yes':
                    permit_root = True
                if keyword == 'protocol' and '1' in parts[1]:
                    ssh_v1 = True
                if keyword == 'pubkeyauthentication' and parts[1].lower() == 'no':
                    pubkey_auth = False

            if permit_root:
                self.report["vulnerabilities"].append({
                    "category": "SSH Konfiguration",
                    "issue": "PermitRootLogin er sat til 'yes'. Dette øger risikoen for password-brute-forcing markant."
                })
            if ssh_v1:
                self.report["vulnerabilities"].append({
                    "category": "SSH Konfiguration",
                    "issue": "SSH Protocol 1 er tilladt. Dette er usikkert og forældet."
                })
            if not pubkey_auth:
                self.report["vulnerabilities"].append({
                    "category": "SSH Konfiguration",
                    "issue": "PubkeyAuthentication er sat til 'no'. Nøglebaseret login bør være aktiveret."
                })
                
        except Exception as e:
            self.report["warnings"].append(f"Kunne ikke læse SSH konfigurationen: {e}")

    def audit_filesystem(self):
        print("[*] Inspicerer filsystemet efter world-writable og SUID/SGID filer (kan tage lidt tid)...")
        
        # World-writable filer (udvalgte kritiske mapper for at spare tid)
        ww_cmd = ['find', '/etc', '/var/www', '/usr/local/bin', '-type', 'f', '-perm', '-0002', '-print']
        ww_files = self.run_command(ww_cmd)
        
        if ww_files and "Kommandoen" not in ww_files:
            files = [f for f in ww_files.split('\n') if f.strip()]
            if files:
                self.report["vulnerabilities"].append({
                    "category": "Filsystem",
                    "issue": f"Fandt {len(files)} 'world-writable' filer i kritiske mapper.",
                    "details": files[:10]
                })

        # SUID/SGID filer (søgning i standard binære stier)
        suid_cmd = ['find', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '-type', 'f', r'\(', '-perm', '-4000', '-o', '-perm', '-2000', r'\)', '-print']
        suid_files = self.run_command(suid_cmd)
        
        if suid_files and "Kommandoen" not in suid_files:
            files = [f for f in suid_files.split('\n') if f.strip() and "find: " not in f]
            if files:
                self.report["info"].append({
                    "category": "Filsystem",
                    "issue": f"Fandt {len(files)} filer med SUID/SGID bit.",
                    "details": files[:10]
                })

    def audit_updates(self):
        print("[*] Tjekker opdateringsstatus for sikkerhed...")
        cmd = ['apt-get', '-s', 'upgrade']
        output = self.run_command(cmd)
        
        security_updates = []
        if output and "Kommandoen" not in output:
            for line in output.splitlines():
                if line.startswith('Inst') and 'security' in line.lower():
                    security_updates.append(line)
                    
        if security_updates:
            pkgs = [u.split()[1] for u in security_updates if len(u.split()) > 1]
            self.report["vulnerabilities"].append({
                "category": "Opdateringsstatus",
                "issue": f"Der mangler i alt {len(security_updates)} sikkerhedsopdateringer.",
                "details": pkgs[:10]
            })
        else:
             self.report["info"].append({
                "category": "Opdateringsstatus",
                "issue": "Ingen ventende sikkerhedsopdateringer fundet."
            })

    def generate_output(self):
        json_file = "security_audit_report.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=4, ensure_ascii=False)
        print(f"[+] Gemt JSON-rapport: {json_file}")

        md_file = "security_audit_report.md"
        with open(md_file, "w", encoding="utf-8") as f:
            f.write("# 🛡️ Ubuntu Sikkerhedsaudit Rapport\n\n")
            f.write(f"**Genereret:** {self.report['timestamp']}\n\n")
            
            f.write("## 🔴 Sårbarheder\n")
            if not self.report["vulnerabilities"]:
                f.write("Ingen sårbarheder fundet. Fantastisk!\n\n")
            else:
                for v in self.report["vulnerabilities"]:
                    f.write(f"- **{v['category']}**: {v['issue']}\n")
                    if 'details' in v and v['details']:
                        f.write(f"  - *Detaljer/Eksempler:* {', '.join(v['details'])}\n")
                f.write("\n")

            f.write("## ⚠️ Advarsler\n")
            if not self.report["warnings"]:
                f.write("Ingen kørselsproblemer eller advarsler.\n\n")
            else:
                for w in self.report["warnings"]:
                    f.write(f"- {w}\n")
                f.write("\n")

            f.write("## ℹ️ Information for manuel vurdering\n")
            if not self.report["info"]:
                f.write("Intet at bemærke.\n\n")
            else:
                for i in self.report["info"]:
                    f.write(f"- **{i['category']}**: {i['issue']}\n")
                    if 'details' in i and i['details']:
                        f.write(f"  - *Detaljer/Eksempler:* {', '.join(i['details'])}\n")
                f.write("\n")
                
        print(f"[+] Gemt Markdown-rapport: {md_file}")
        print("\nSe README.md for hjælp til at tolke disse fund.")

    def run(self):
        print("Starter Ubuntu Security Hardening Audit...")
        self.check_root_privileges()
        self.audit_users_and_access()
        self.audit_network_and_firewall()
        self.audit_ssh_config()
        self.audit_filesystem()
        self.audit_updates()
        
        print("\nAudit fuldført. Genererer rapporter...")
        self.generate_output()

if __name__ == "__main__":
    auditor = UbuntuAuditor()
    auditor.run()
