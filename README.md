## 🚀 Overview
CVE (Common Vulnerabilities and Exposures) is a Python-based project that automatically sends email alerts when new vulnerabilities are detected. This project leverages the CIRCL API to fetch the latest CVEs and uses Selenium for web scraping to gather detailed information. Additionally, it employs the Perplexity API to simplify CVE descriptions for non-technical readers.

### Key Features
- **Automated Alerts**: Sends email notifications when new CVEs are found.
- **Web Scraping**: Uses Selenium to scrape detailed CVE information from CVE.org.
- **AI Simplification**: Simplifies CVE descriptions using the Perplexity API.
- **Configuration Flexibility**: Supports custom email configurations and AI settings.

### Who This Project Is For
- Security professionals
- Developers
- IT administrators
- Anyone interested in staying informed about new vulnerabilities

## ✨ Features
- 📧 **Email Alerts**: Automatically notify you via email when new CVEs are detected.
- 🔍 **Web Scraping**: Extract detailed information from CVE.org using Selenium.
- 🤖 **AI Simplification**: Simplify CVE descriptions for non-technical users.
- 📅 **Scheduled Runs**: Run the script every 12 hours using GitHub Actions.

## 🛠️ Tech Stack
- **Programming Language**: Python
- **Libraries**: `requests`, `selenium`, `webdriver-manager`
- **Tools**: GitHub Actions, Perplexity API
- **System Requirements**: Python 3.11, Chrome browser

## 📦 Installation

### Prerequisites
- Python 3.11
- Chrome browser
- GitHub account

### Quick Start
```bash
# Clone the repository
git clone https://github.com/quietcod/CVE.git

# Navigate to the project directory
cd CVE

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export EMAIL_USER="your_email@example.com"
export EMAIL_PASS="your_email_password"
export PERPLEXITY_API_KEY="your_perplexity_api_key"
export AI_ENABLED="true"
export PERPLEXITY_MODEL="sonar-small-chat"
```

### Alternative Installation Methods
- **Docker**: (if applicable)
- **Development Setup**: (if applicable)

## 🎯 Usage

### Basic Usage
```python
# Run the script
python cve.py
```

### Advanced Usage
- **Configuration**: Modify `cve_notifier/config.py` to set custom email and AI configurations.
- **Customization**: Adjust the `cve_notifier/ai_simplifer.py` and `cve_notifier/scrapper.py` modules to fit specific needs.

## 📁 Project Structure
```
CVE/
├── cve.py
├── cve_notifier/
│   ├── __init__.py
│   ├── ai_simplifer.py
│   ├── circl_client.py
│   ├── config.py
│   ├── emailer.py
│   ├── main.py
│   ├── scrapper.py
│   └── storage.py
├── seen_cves.json
├── requirements.txt
└── .github/
    └── workflows/
        └── cve.yml
```

### Architecture Overview

The CVE project is designed to automatically send email alerts when new vulnerabilities are found. The architecture consists of several components:

1. **CVE Notifier**: The main module that orchestrates the process of fetching new CVEs, processing them, and sending email alerts.
2. **CIRCL Client**: A module that fetches the latest CVEs from the CIRCL API.
3. **AI Simplifier**: A module that uses the Perplexity API to simplify technical CVE descriptions into plain language.
4. **Emailer**: A module that sends email alerts to specified recipients.
5. **Scraper**: A module that uses Selenium to scrape detailed information about CVEs from websites.
6. **Storage**: A module that handles the persistence of seen CVE IDs.

### Deployment Instructions

To deploy the CVE project, follow these steps:

1. **Set Up GitHub Actions**:
   - The project uses GitHub Actions for scheduling and running the CVE alert script.
   - Ensure that the necessary secrets (`EMAIL_USER`, `EMAIL_PASS`, `PERPLEXITY_API_KEY`, `GH_TOKEN`) are set up in the GitHub repository settings.

2. **Schedule the Workflow**:
   - The workflow is scheduled to run every 12 hours (`0 */12 * * *`).
   - You can also manually trigger the workflow using the GitHub Actions interface.

3. **Run the Script**:
   - The script is executed using the `main.py` entry point.
   - It fetches new CVEs, processes them, and sends email alerts if new CVEs are found.

## 🔧 Configuration
- **Environment Variables**:
  - `EMAIL_USER`: Email sender login.
  - `EMAIL_PASS`: App password.
  - `PERPLEXITY_API_KEY`: (optional) enables AI summaries when `AI_ENABLED=true`.
  - `AI_ENABLED`: "true" or "false".
  - `PERPLEXITY_MODEL`: AI model to use (default: "sonar-small-chat").

- **Configuration Files**:
  - `cve_notifier/config.py`: Contains configuration settings for email, AI, and API.

## 🤝 Contributing
- Fork the repository
- Create a new branch (`git checkout -b feature/your-feature`)
- Commit your changes (`git commit -am 'Add some feature'`)
- Push to the branch (`git push origin feature/your-feature`)
- Open a Pull Request

### Code Style Guidelines
- Follow PEP 8 style guide
- Use meaningful variable and function names
- Add comments to complex code sections

### Pull Request Process
- Ensure your code is well-tested
- Write clear commit messages
- Address any feedback from reviewers
