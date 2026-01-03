import requests
import json
import os
import sys
import time
import re
import ipaddress
from dotenv import load_dotenv
from ipwhois import IPWhois
from ipwhois.exceptions import WhoisLookupError, HTTPLookupError

def get_taegis_token(client_id, client_secret, auth_url):
    """
    Step 2: Get an Access Token from the Taegis authentication endpoint.
    """
    print(f"Attempting to get access token from {auth_url}...")
    
    payload = {"grant_type": "client_credentials"}
    
    try:
        response = requests.post(
            auth_url,
            auth=(client_id, client_secret),
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            print("Error: 'access_token' not found in response.")
            return None
            
        print("Successfully retrieved access token.")
        return access_token
        
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response content: {response.text}")
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
    
    return None

def query_alerts_api(access_token, tenant_id, graphql_url):
    """
    Step 3: Query the Alerts API with the obtained access token.
    """
    print(f"Querying GraphQL API at {graphql_url}...")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Tenant-Context": tenant_id
    }
    
    graphql_query = """
    query alertsServiceSearch($in: SearchRequestInput = {cql_query: "FROM alert WHERE severity >= 0.1 AND severity <= 0.58 AND status = 'OPEN' EARLIEST=-1d", limit: 10}) {
        alertsServiceSearch(in: $in) {
            status
            reason
            alerts {
                total_results
                list {
                    id
                    metadata {
                        title
                        description
                        severity
                    }
                }
            }
        }
    }
    """
    
    payload = {"query": graphql_query}
    
    try:
        response = requests.post(
            graphql_url,
            headers=headers,
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        response_data = response.json()
        print("Successfully queried API.")
        return response_data
        
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response content: {response.text}")
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
        
    return None

def get_whois_info(ip_address):
    """
    Performs a WHOIS lookup for a given IP address.
    Returns a simplified dictionary or None.
    """
    print(f"  Performing WHOIS lookup for {ip_address}...")
    try:
        # MODIFIED: The timeout argument is now passed here.
        obj = IPWhois(ip_address, timeout=5)
        
        # The lookup methods no longer need the timeout argument.
        results = obj.lookup_rdap(inc_raw=False) 
        
        # Parse RDAP structure
        org = results.get('network', {}).get('name', 'N/A')
        country = results.get('network', {}).get('country', 'N/A')
        asn_desc = results.get('asn_description', 'N/A')

        if not org or org == 'N/A':
             # Fallback to WHOIS if RDAP name is missing
             results_whois = obj.lookup_whois(inc_raw=False) # MODIFIED: timeout removed
             nets = results_whois.get('nets')
             if nets and isinstance(nets, list) and len(nets) > 0:
                org = nets[0].get('description', 'N/A')
                if not country or country == 'N/A':
                    country = nets[0].get('country', 'N/A')

        
        return {
            "organization": str(org), 
            "country": str(country),
            "asn_info": str(asn_desc)
        }
        
    except (WhoisLookupError, HTTPLookupError) as e:
        print(f"  WHOIS lookup error for {ip_address}: {e}")
        return None
    except Exception as e:
        print(f"  Unexpected WHOIS error for {ip_address}: {e}")
        return None

def analyze_with_ollama(alerts_data, ollama_url, model_name):
    """
    Step 4: Enrich alerts with WHOIS data, then send to Ollama for analysis.
    """
    print("\nStarting analysis process...")
    
    try:
        alerts_list = alerts_data.get("data", {}).get("alertsServiceSearch", {}).get("alerts", {}).get("list", [])
        
        if not alerts_list:
            print("No alerts found in the Taegis response to analyze.")
            return None

        # --- Enrichment Step ---
        print("Enriching alerts with WHOIS data (this may take a moment)...")
        # Regex to find IP v4 addresses
        ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        for alert in alerts_list:
            metadata = alert.get('metadata', {})
            # Check for IPs in both title and description
            alert_text = metadata.get('title', '') + " " + metadata.get('description', '')
            
            # Find all unique IPs
            found_ips = set(ip_regex.findall(alert_text))
            
            if found_ips:
                whois_enrichment = {}
                for ip in found_ips:
                    whois_data = get_whois_info(ip) 
                    if whois_data:
                        whois_enrichment[ip] = whois_data
                
                if whois_enrichment:
                    # Add the new data directly to the alert object
                    alert['enrichment'] = {'whois': whois_enrichment}

        # --- End of Enrichment Step ---

        # Convert the *enriched* list to JSON
        alerts_json_str = json.dumps(alerts_list, indent=2)
        
        # --- Updated prompt ---
        prompt = f"""
Here is a list of medium-high security alerts in JSON format from the Taegis API.
Some alerts have been **pre-enriched with WHOIS data** in an `enrichment` field.

{alerts_json_str}

Please act as a SOC security analyst. Your task is to analyze this data.
1.  Assess all alerts and look for any patterns or correlations.
2.  **Use the provided WHOIS data** in the `enrichment` sections to inform your analysis. For example, is an IP from a suspicious organization or country?
3.  Calculate an **average alert score** (based on the `severity` field, which is 0.0-1.0) and provide it as the first item.
4.  Write a brief, **one-paragraph executive summary** of your findings, stating whether these alerts appear to be a coordinated threat or benign noise.
5.  Finally, if any alerts had WHOIS data, **create a simple markdown table** that lists the `alert.id`, the `ip_address`, and its `organization` from the WHOIS data.
"""
        
        print(f"Sending enriched data to Ollama at {ollama_url} with model {model_name}...")
        
        ollama_payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False 
        }
        
        ollama_api_url = f"{ollama_url}/api/generate"
        
        # Increased timeout for potentially long analysis
        response = requests.post(
            ollama_api_url,
            json=ollama_payload,
            timeout=120
        )
        
        response.raise_for_status()
        
        # Handle potential non-JSON or streaming-like responses
        try:
            ollama_response = response.json()
            analysis = ollama_response.get("response")
        except json.JSONDecodeError:
            # Sometimes Ollama responds with newline-delimited JSON objects
            # We'll just grab the last one's response.
            print("Decoding JSON as stream...")
            analysis = None
            for line in response.text.strip().split('\n'):
                try:
                    line_json = json.loads(line)
                    if line_json.get("response"):
                        analysis = line_json.get("response")
                except json.JSONDecodeError:
                    continue 
            if analysis is None:
                raise 

        
        if analysis:
            print("\n--- Ollama Analysis ---")
            print(analysis.strip())
            print("-------------------------")
            return analysis.strip()
        else:
            print("Error: No 'response' field found in Ollama's output.")
            print(f"Full Ollama response: {ollama_response}")

    except requests.exceptions.ConnectionError:
        print(f"\nError: Could not connect to Ollama at {ollama_url}.")
        print("Please ensure Ollama is running and accessible.")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while contacting Ollama: {http_err}")
        print(f"Response content: {response.text}")
    except requests.exceptions.RequestException as err:
        print(f"An error occurred while contacting Ollama: {err}")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON response from Ollama.")
        print(f"Raw response: {response.text}")
        
    return None

def send_to_webhook(analysis_content, webhook_url):
    """
    Step 5: Send the analysis output to a webhook.
    """
    print(f"Sending analysis to webhook...")
    
    payload = {
        "text": f"**Daily Taegis Alert Summary:**\n\n{analysis_content}"
    }
    
    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        print("Successfully sent analysis to webhook.")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error sending to webhook: {http_err}")
        print(f"Response content: {response.text}")
    except requests.exceptions.RequestException as err:
        print(f"An error occurred sending to webhook: {err}")

def main():
    """
    Main function to run the Taegis API client.
    """
    load_dotenv()
    
    # --- Configuration ---
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    TENANT_ID = os.getenv("TENANT_ID")
    WEBHOOK_URL = os.getenv("WEBHOOK_URL")
    
    if not all([CLIENT_ID, CLIENT_SECRET, TENANT_ID, WEBHOOK_URL]):
        print("Error: Missing required environment variables.")
        print("Please set CLIENT_ID, CLIENT_SECRET, TENANT_ID, and WEBHOOK_URL in your .env file.")
        return 
        
    if "your_client_id" in CLIENT_ID:
        print("Warning: It looks like you're using placeholder credentials.")
        
    # --- Set your region's URLs ---
    API_BASE_URL = "https://api.delta.taegis.secureworks.com"
    AUTH_URL = f"{API_BASE_URL}/auth/api/v2/auth/token"
    GRAPHQL_URL = f"{API_BASE_URL}/graphql"
    
    # --- Ollama Configuration ---
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3:12b") 
    
    print(f"Using Ollama at: {OLLAMA_BASE_URL} with model {OLLAMA_MODEL}")
    
    # --- Run the steps ---
    
    token = get_taegis_token(CLIENT_ID, CLIENT_SECRET, AUTH_URL)
    
    if token:
        alerts_data = query_alerts_api(token, TENANT_ID, GRAPHQL_URL)
        
        if alerts_data:
            analysis_result = analyze_with_ollama(alerts_data, OLLAMA_BASE_URL, OLLAMA_MODEL)
            
            if analysis_result:
                send_to_webhook(analysis_result, WEBHOOK_URL)
            else:
                print("No analysis was generated, skipping webhook.")
    else:
        print("Failed to get token, skipping API query.")

# --- This block remains the same ---
if __name__ == "__main__":
    
    SECONDS_IN_A_DAY = 24 * 60 * 60 
    
    print("Starting the daily alert analysis service...")
    print("The script will run once now, and then every 24 hours.")
    
    while True:
        try:
            print(f"\n--- Running Daily Tasks (Timestamp: {time.ctime()}) ---")
            main() # Run all the logic
            print(f"--- Tasks Complete. Sleeping for {SECONDS_IN_A_DAY} seconds (24 hours)... ---")
            time.sleep(SECONDS_IN_A_DAY)
            
        except KeyboardInterrupt:
            print("\nStopping the service. Goodbye!")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            print("Will retry after a 1-hour sleep...")
            time.sleep(3600)
