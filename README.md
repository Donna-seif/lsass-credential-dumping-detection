# LSASS Credential Dumping Detection

This project demonstrates detection logic for identifying suspicious access to LSASS (Local Security Authority Subsystem Service), commonly targeted for credential dumping attacks.

## 🔍 Detection Approach

The detection is based on multiple behavioral signals:

- Processes accessing LSASS
- Suspicious or high privilege access rights
- Memory operations (WriteVirtualMemory, ReadProcessMemory)
- Unsigned or untrusted processes

## 🛠 Implementation

- **Python script** to analyze logs and generate alerts
- **Sigma rule** to represent detection logic in a SIEM-friendly format
- **Sample JSON logs** for testing detection logic

## 🧠 Detection Logic

The detection uses a scoring-based approach combining multiple indicators to improve accuracy and reduce false positives.

## ⚠️ Evasion Considerations

The detection accounts for attacker techniques such as:

- Using legitimate processes
- Operating with lower privileges
- Using read-based credential access instead of memory writes

## 🚀 Future Improvements

- Add detection for PowerShell-based attacks
- Improve detection with process lineage analysis
- Expand to additional MITRE ATT&CK techniques
