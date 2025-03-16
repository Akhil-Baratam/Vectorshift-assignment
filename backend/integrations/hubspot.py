import os
import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64 
import requests
import hashlib
from dotenv import load_dotenv
from urllib.parse import urlencode


from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

# Load environment variables
load_dotenv()

# Fetch OAuth credentials from .env file
CLIENT_ID = os.getenv("HUBSPOT_CLIENT_ID")
CLIENT_SECRET = os.getenv("HUBSPOT_CLIENT_SECRET")
REDIRECT_URI = os.getenv("HUBSPOT_REDIRECT_URI")
authorization_url=f'https://app-na2.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri=http://localhost:8000/integrations/hubspot/callback&scope=crm.objects.contacts.write%20oauth%20crm.objects.companies.read%20crm.lists.read%20crm.objects.deals.read%20crm.schemas.contacts.read%20crm.objects.deals.write%20crm.objects.contacts.read'


async def authorize_hubspot(user_id, org_id):
    """Generates the OAuth authorization URL for HubSpot."""
    
    # Generate state data for security
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id
    }

    print(f"Saving state data to Redis: {state_data}")
    
    # Encode state in base64
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode("utf-8")).decode("utf-8")
    print(f"Encoded state data: {encoded_state}")



    # Generate PKCE code challenge (same as Airtable)
    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode("utf-8"))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode("utf-8").replace("=", "")

    # Construct OAuth URL with state and PKCE
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read",
        "response_type": "code",
        "state": encoded_state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"https://app.hubspot.com/oauth/authorize?{urlencode(params)}"

    # Store state & code verifier in Redis for later validation (expires in 10 minutes)
    await asyncio.gather(
        add_key_value_redis(f"hubspot_state:{org_id}:{user_id}", json.dumps(state_data), expire=600),
        add_key_value_redis(f"hubspot_verifier:{org_id}:{user_id}", code_verifier, expire=600),
    )

    print(f"State_data successfully saved: {state_data}")

    return auth_url

async def oauth2callback_hubspot(request: Request):
    """Handles HubSpot OAuth callback, exchanges auth code for access token."""

    # 1️⃣ Handle OAuth error responses
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error"))

    # 2️⃣ Extract 'code' and 'state' from request query params
    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")

    print(f"Incoming callback - Code: {code}, State: {encoded_state}")

    # 3️⃣ Decode state and extract user_id & org_id
    try:
        state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode("utf-8"))
        original_state = state_data.get("state")
        user_id = state_data.get("user_id")
        org_id = state_data.get("org_id")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    # 4️⃣ Retrieve and validate stored state from Redis
    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f"hubspot_state:{org_id}:{user_id}"),
        get_value_redis(f"hubspot_verifier:{org_id}:{user_id}")
    )
    if saved_state is None:
        raise HTTPException(status_code=400, detail="State not found in Redis.")

    print(f"Saved_state: {saved_state}")
    print(f"Original_state: {original_state}")
    thirdcheck = json.loads(saved_state).get("state")  
    print(f"third_check: {thirdcheck}")

    if not saved_state or original_state != thirdcheck:
        raise HTTPException(status_code=400, detail="State validation failed.")


    # 5️⃣ Exchange the code for an access token
    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                "https://api.hubapi.com/oauth/v1/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code_verifier": code_verifier.decode("utf-8"),
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            ),
            delete_key_redis(f"hubspot_state:{org_id}:{user_id}"),
            delete_key_redis(f"hubspot_verifier:{org_id}:{user_id}"),
        )

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to exchange authorization code.")

    # 6️⃣ Store tokens in Redis
    await add_key_value_redis(f"hubspot_credentials:{org_id}:{user_id}", json.dumps(response.json()), expire=600)

    # 7️⃣ Return HTML to close OAuth popup window (same as Airtable & Notion)
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id: str, org_id: str):
    """Retrieves the stored HubSpot access token from Redis."""
    
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    
    if not credentials:
        raise HTTPException(status_code=401, detail="HubSpot credentials not found. Please reauthorize.")

    return json.loads(credentials)

async def create_integration_item_metadata_object(response_json: str) -> IntegrationItem:
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None),
        name=response_json.get('firstname', None),
        type='contact',
        creation_time=response_json.get('createdAt', None),
        last_modified_time=response_json.get('updatedAt',None)
    )

    return integration_item_metadata

async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    credentials = json.loads(credentials)
    async with httpx.AsyncClient() as client:
        response = await client.get(
            'https://api.hubapi.com/crm/v3/objects/contacts',
            headers={
                'Authorization': f'Bearer {credentials.get("access_token")}',
                'Notion-Version': '2022-06-28',
            },
        )

        if response.status_code == 200:
            results = response.json()['results']
            coroutines = [create_integration_item_metadata_object(result) for result in results]
            list_of_integration_item_metadata = await asyncio.gather(*coroutines)
            
            print(f'list_of_integration_item_metadata of hubspot: {list_of_integration_item_metadata}')
            return list_of_integration_item_metadata
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to fetch contacts")  