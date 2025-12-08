# CVE Notification System 🛡️

This project is a CVE (Common Vulnerabilities and Exposures) notification system that keeps you informed about the latest security vulnerabilities. It fetches CVE data from the CIRCL API, identifies new CVEs, enriches them with additional information scraped from the web, and sends email notifications to a list of recipients. The system also uses AI to simplify complex CVE descriptions, making them easier to understand.

## 🚀 Key Features

- **CVE Data Fetching:** Retrieves the latest CVE data from the CIRCL API.
- **New CVE Identification:** Compares fetched CVEs with a list of previously seen CVEs to identify new vulnerabilities.
- **CVE Enrichment:** Scrapes additional information about CVEs from external sources, including descriptions and CVSS scores.
- **AI-Powered Simplification:** Uses the Perplexity AI API to simplify technical CVE descriptions into plain language.
- **Email Notifications:** Sends email notifications containing summaries of new CVEs to a configurable list of recipients.
- **State Management:** Persists the list of seen CVEs to avoid sending duplicate notifications.
- **Configurable:**  Easily configurable via environment variables for API keys, email settings, and other parameters.
- **Polite Scraping:** Implements delays between scraping requests to avoid overloading target websites.
- **Error Handling:** Robust error handling and logging throughout the application.

## 🛠️ Tech Stack

- **Backend:**
    - Python 3.x
- **API Client:**
    - `requests`
- **Web Scraping:**
    - `selenium`
    - `webdriver_manager`
- **AI Simplification:**
    - Perplexity AI API
- **Email:**
    - `smtplib`
    - `email.mime`
- **Data Storage:**
    - `json` (for storing seen CVEs)
- **Configuration:**
    - `os` (for environment variables)
- **Logging:**
    - `logging` (Python's built-in logging library)

## 📦 Getting Started

### Prerequisites

- Python 3.x installed
- Pip package manager
- Google Chrome installed (for web scraping)
- ChromeDriver (automatically managed by `webdriver_manager`, but may require manual installation if facing issues)
- Perplexity AI API key (optional, for AI-powered simplification)
- Email account with app password enabled (for sending email notifications)

### Installation

1.  Clone the repository:

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  Create a virtual environment (recommended):

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate  # On Windows
    ```

3.  Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

### Running Locally

1.  Set the required environment variables:

    ```bash
    export EMAIL_USER="your_email@gmail.com"
    export EMAIL_PASS="your_email_app_password"
    export RECIPIENTS="recipient1@example.com,recipient2@example.com"
    export PERPLEXITY_API_KEY="your_perplexity_api_key" # Optional, if AI_ENABLED=True
    ```

    **Note:** It's highly recommended to set these environment variables in a `.env` file and load them using a library like `python-dotenv`.

2.  Run the `cve.py` script:

    ```bash
    python cve.py
    ```

    This will start the CVE notification system, which will fetch CVE data, identify new CVEs, and send email notifications.

## 📂 Project Structure

```
.
├── cve.py                      # Main entry point of the application
├── cve_notifier
│   ├── __init__.py
│   ├── main.py                 # Core logic of the CVE notification system
│   ├── config.py               # Configuration parameters
│   ├── circl_client.py         # Client for interacting with the CIRCL API
│   ├── storage.py              # Manages persistence of seen CVE IDs
│   ├── scrapper.py             # Scrapes CVE details from websites
│   ├── ai_simplifer.py         # Simplifies CVE descriptions using AI
│   ├── emailer.py              # Sends email notifications
├── requirements.txt            # Project dependencies
└── README.md                   # This file
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

## 📝 License

This project is licensed under the [MIT License](LICENSE).

## 📬 Contact

If you have any questions or suggestions, feel free to contact me at [quietcod@protonmail.com](mailto:quietcod@protonmail.com).

## 💖 Thanks

Thanks for checking out this project! I hope it helps you stay informed about the latest security vulnerabilities.
