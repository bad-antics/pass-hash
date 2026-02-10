from pass_hash.core import NTLMAnalyzer,PTHSimulator
a=NTLMAnalyzer()
h=a.generate_ntlm("Password123")
print(f"NTLM hash: {h}")
parsed=a.parse_hash(f"admin:500:aad3b435b51404eeaad3b435b51404ee:{h}")
print(f"Parsed: {parsed['user']} LM disabled: {parsed['lm_disabled']}")
s=PTHSimulator()
for t in s.list_techniques(): print(f"Technique: {t}")
