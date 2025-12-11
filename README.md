
**README**

This repository contains a complete Python script that simulates a Security Orchestration, Automation, and Response (SOAR) workflow. It ingests security alerts, performs enrichment, calculates a weighted threat score, applies allowlist suppression, tags incidents with MITRE ATT&CK techniques, determines a final severity bucket, and generates structured output files (JSON, Markdown, and a log).

The project is structured within the xsoar_development folder, which serves as the root repository.
  
**Setup Instructions**

To set up and run the script, you need Python 3 and the PyYAML library.

1. Clone the Repository

Clone the project to your local machine:

```
Bash
git clone <YOUR_GITHUB_REPO_URL>

cd xsoar_development
```

2. Create a Virtual Environment (Recommended)

It is highly recommended to use a virtual environment:

```
Bash
python3 -m venv venv

source venv/bin/activate # On Linux/macOS

.\venv\Scripts\activate # On Windows (PowerShell)
```

3. Install Dependencies

Install the required YAML parsing library:

```
Bash

pip install pyyaml
```  



**How to Run the Script**

The script is executed via the command line, requiring the path to the alert file as the first argument.

Usage Syntax

```
Bash

python main.py alerts/<PATH_TO_ALERT_FILE>

```  

Example Run

Using the provided sample alert:
```
Bash

python main.py alerts/sentinel.json
```

Note: The script will output a detailed execution summary to the console and automatically create the output files in the out/ directory.