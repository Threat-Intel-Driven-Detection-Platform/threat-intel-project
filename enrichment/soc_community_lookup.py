import requests
import re
import sys


BASE_URL = "https://ioc.ghtk.vn/"


def lookup_ioc(ioc):
    try:
        response = requests.get(
            BASE_URL,
            params={"ioc": ioc},
            timeout=20
        )

        response.raise_for_status()

        text = re.sub(r"<[^>]+>", " ", response.text)
        text = text.replace("&nbsp;", " ")
        text = re.sub(r"\s+", " ", text).strip()

        verified_match = re.search(
            r"Status:\s*(Verified|Not Verified|The IoC not found)",
            text,
            re.IGNORECASE
        )

        message_match = re.search(
            r"Message:\s*(.*?)(?=var color|$)",
            text,
            re.IGNORECASE
        )

        result = {
            "value": ioc,
            "source": "SOC-Community",
            "verified": False,
            "status": "unknown",
            "message": ""
        }

        if verified_match:
            status = verified_match.group(1).strip()

            if status.lower() == "verified":
                result["verified"] = True
                result["status"] = "malicious"
            elif "not found" in status.lower():
                result["status"] = "not_found"
            else:
                result["status"] = "not_verified"

        if message_match:
            message = message_match.group(1).strip()
            message = re.sub(r"\s+", " ", message)
            result["message"] = message

        return result

    except requests.RequestException as e:
        return {
            "value": ioc,
            "source": "SOC-Community",
            "verified": False,
            "status": "error",
            "message": str(e)
        }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:")
        print("python enrichment\\soc_community_lookup.py <IOC>")
        sys.exit(1)

    ioc = sys.argv[1].strip()

    result = lookup_ioc(ioc)

    print("\nSOC-Community Lookup")
    print("--------------------")
    print("IOC:", result["value"])
    print("Source:", result["source"])
    print("Verified:", result["verified"])
    print("Status:", result["status"])
    print("Message:", result["message"])