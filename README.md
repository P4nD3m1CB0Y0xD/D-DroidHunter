# D-DroidHunter
D-DroidHunter is an automated pipeline for analyzing, detecting, and hunting malicious Android applications.
It provides a structured workflow that helps malware researchers, threat hunters, and security analysts efficiently identify, investigate, and classify Android threats.

The project integrates multiple tools and technologies to create a seamless malware analysis experience.
---
# ✨ Features
- 🔍 Automated APK Analysis: Streamlines static and dynamic inspection of Android apps.

- ⚡ Integration with MobSF: Uses the Mobile Security Framework to perform in-depth static analysis within Docker.

- 📊 Efficient Data Storage with DuckDB: Enables fast querying and storage of analysis results for scalable threat hunting.

- 🕵️ Threat Hunting Pipeline: Helps analysts correlate indicators and track suspicious behavior across multiple samples.

- 📝 Report Generation: Automatically produces structured JSON and PDF reports for intelligence sharing.
---
🚀 Getting Started
1. Install dependencies
```
pip install -r requirements.txt
```

3. Make the runner script executable
```
chmod +x run_droidhunter.sh
```

4. Run D-DroidHunter
```
./run_droidhunter.sh -v <VIRUSTOTAL_API_KEY>
```
---
🔗 Related Projects
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF): Mobile Security Framework used by D-DroidHunter for static & dynamic Android app analysis.
- [DuckDB](https://duckdb.org/): An embedded analytics database leveraged for storing and querying large-scale analysis results.
