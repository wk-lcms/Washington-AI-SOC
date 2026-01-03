import requests
import json
import os
import sys
import time  # <-- ADDED: For the sleep function
from dotenv import load_dotenv

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
    query alertsServiceSearch($in: SearchRequestInput = {cql_query: "FROM alert WHERE severity >= 0.1 AND severity <= 0.59 AND status = 'OPEN' EARLIEST=-1d", limit: 10}) {
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

def analyze_with_ollama(alerts_data, ollama_url, model_name):
    """
    Step 4: Send the alert data to Ollama for analysis.
    """
    print(f"\nSending alert data to Ollama at {ollama_url} with model {model_name}...")
    
    try:
        alerts_list = alerts_data.get("data", {}).get("alertsServiceSearch", {}).get("alerts", {}).get("list", [])
        
        if not alerts_list:
            print("No alerts found in the Taegis response to analyze.")
            return None

        alerts_json_str = json.dumps(alerts_list, indent=2)
        
        prompt = f"""
Here is a list of medium - high security alerts in JSON format from the Taegis API:

{alerts_json_str}

Please act as a SOC security analyst. These are medium to high alerts that may be a threat, or may be benign. Please assess all of these alerts, look for any patterns, and consider any patterns that emerge. Summarize whether these are a concern or not. Create a a brief, one-paragraph summary based on all of your findings, and return that. Please provide an average alert score, and include that as the first section in your response. Please also look for any alerts that contain the string "VPN" or reference IP addresses, and do an online whois search for the IP addresses involved in that alert. Provide the Whois information for that specific alert in a table below the summary paragraph. Otherwise, if no IP address exists in the VPN or IP address alert, ignore the table.

"""
        
        ollama_payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False 
        }
        
        ollama_api_url = f"{ollama_url}/api/generate"
        
        response = requests.post(
            ollama_api_url,
            json=ollama_payload,
            timeout=60
        )
        
        response.raise_for_status()
        
        ollama_response = response.json()
        analysis = ollama_response.get("response")
        
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
    
    # Payload format for Slack/Mattermost.
    # For Discord, use: {"content": "..."}
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
        # We don't exit(1) anymore, so the loop can retry
        return 
        
    if "your_client_id" in CLIENT_ID:
        print("Warning: It looks like you're using placeholder credentials.")
        
    # --- Set your region's URLs ---
    API_BASE_URL = "https://api.delta.taegis.secureworks.com"
    AUTH_URL = f"{API_BASE_URL}/auth/api/v2/auth/token"
    GRAPHQL_URL = f"{API_BASE_URL}/graphql"
    
    # --- Ollama Configuration ---
    OLLAMA_BASE_URL = "http://host.docker.internal:11434"
    OLLAMA_MODEL = "gemma3:12b"
    
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


# --- MODIFIED: This block now runs the main() function in a loop ---
if __name__ == "__main__":
    
    # 24 hours * 60 minutes/hour * 60 seconds/minute
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
            # Allows you to stop the script manually with Ctrl+C
            print("\nStopping the service. Goodbye!")
            break
        except Exception as e:
            # Catch any other unexpected errors
            print(f"An unexpected error occurred: {e}")
            print("Will retry after a 1-hour sleep...")
            time.sleep(3600) # Sleep for 1 hour on failure
