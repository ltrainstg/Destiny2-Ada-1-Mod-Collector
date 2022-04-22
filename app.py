from flask import Flask, abort, request, redirect, url_for, render_template, session
import urllib
from base64 import b64encode
import requests
from dotenv import load_dotenv
import os
import pickle 


app = Flask(__name__)
app.secret_key = 'jnfjNVU1FNpuc0fh-c,3v-302vhm,-h'




# If not using a .env file can also hardcode these variables below 
load_dotenv()  # take environment variables from .env.
client_id = os.getenv('DESTINY_CLIENT_ID')
client_secret = os.getenv('DESTINY_SECRET')
api_key = os.getenv('DESTINY_API_KEY')
AUTH_URL = f'https://www.bungie.net/en/OAuth/Authorize?response_type=code&client_id={client_id}&'
#### Functions 

# Save state parameter used in CSRF protection: 
def save_created_state(state):
    session['state_token'] = state
    pass

def make_authorization_url():
    # Generate a random string for the state parameter
    from uuid import uuid4
    state = str(uuid4())
    save_created_state(state)
    return state

def is_valid_state(state):
    saved_state = session['state_token']
    if state == saved_state:
        print("States match, you are who you say you are!")
        return True
    else:
        return False
    
def get_token(code, client_id, client_secret):
    print("Code:" + code)
    print("client_id: "+ client_id)
    print("client_secret: "+ client_secret)
    X = client_id + ':' + client_secret
    X = b64encode(bytes(X, 'utf-8')).decode('ascii')


    headers = {
        "Authorization": "Basic " + X,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "authorization_code",
        "code": code
    }
    r = requests.post("https://www.bungie.net/platform/app/oauth/token/", headers = headers, data=data)
    return(r)



def get_user(api_key, my_token):
    url = 'https://www.bungie.net/Platform/User/GetCurrentBungieNetUser/'
    my_headers = my_headers = {"X-API-Key": api_key, "Authorization": "Bearer " + my_token}
    response = requests.get(url, headers = my_headers)
    # If this is your destiny username you did it!
    response.json()['Response']['displayName']
    uniqueName = response.json()['Response']['uniqueName']
    return(uniqueName)


class ManifestLog:
    def __init__(self):
        # See: https://bungie-net.github.io/#Destiny2.GetDestinyManifest
        self.manifest_url = 'https://www.bungie.net/Platform/Destiny2/Manifest'
        self.manifest_version =     {
        'DestinyCollectibleDefinition': "" ,
        'DestinyInventoryItemLiteDefinition':"",
        'DestinyVendorDefinition': ""
        }
        self.manifest =     {
        'DestinyCollectibleDefinition': "" ,
        'DestinyInventoryItemLiteDefinition':"",
        'DestinyVendorDefinition': ""
        }
    def update(self):
        print('Begin Update')

        import requests
        english_manifest_dict = requests.get(self.manifest_url).json()['Response']['jsonWorldComponentContentPaths']['en']

        for key in self.manifest_version:
            
            current_manifest_version = english_manifest_dict[key]
            if current_manifest_version != self.manifest_version[key]:
                manifest_url = 'https://www.bungie.net/' +current_manifest_version
                print('Updating:' + key)
                self.manifest_version[key] = current_manifest_version
                manifest_response = requests.get(manifest_url)
                self.manifest[key] = manifest_response.json()
            else:
                print(f'{key}: No Update Needed')
                
    def get_item(self, item_hash):
        return self.manifest['DestinyInventoryItemLiteDefinition'][item_hash]
        
    def get_collectable(self, collection_hash):
        return self.manifest['DestinyCollectibleDefinition'][collection_hash]
   

    
# Setup for manifest


filename = 'manifest_log.pkl'
if os.path.exists(filename):  
    with open(filename,'rb') as file_object:
        raw_data = file_object.read()
        manifest_log = pickle.loads(raw_data)
        manifest_log.update()
else:
    manifest_log = ManifestLog()
    manifest_log.update()
    serialized = pickle.dumps(manifest_log)
    with open(filename,'wb') as file_object:
        file_object.write(serialized)
        
# Result 
def get_total_ada_status(my_collection, all_ada_items, manifest_log):
    mod_collection_list = []
    for item in all_ada_items: 
        item_data = manifest_log.get_item(str(item['itemHash']))
        # item type 19 is mods so only keep those
        if item_data['itemType'] == 19:
            ## Some items are no longer collectible and do not have a hash.
            if 'collectibleHash' in item_data.keys():
                mod_collection_list.append(item_data['collectibleHash'])

    collected_lst = []
    uncollected_lst = []
    for item in mod_collection_list:
        current_state = my_collection[str(item)]['state']
        if current_state == 64:
            collected_lst.append(item)
        elif current_state== 65:
            uncollected_lst.append(item)
        else: 
            raise Exception(f"Sorry, State:{current_state} was not accounted for.")

    str_return = 'You own {} out of {} mods from Ada-1'.format(len(collected_lst), len(mod_collection_list))

    return(str_return)


def ada_helper(today_ada_items, manifest_log, my_list = ''):
    mod_for_sale = []
    mod_description = []
    mod_img = []
    can_buy = []
    
    for item in today_ada_items:
        item_data = manifest_log.get_item(str(today_ada_items[item]['itemHash']))
        if item_data['itemType'] == 19:
            mod_for_sale.append(item_data['displayProperties']['name'])
            mod_description.append(item_data['displayProperties']['description'])
            mod_img.append(item_data['displayProperties']['icon'])
            if today_ada_items[item]['saleStatus'] == 0:
                    can_buy.append(item_data['displayProperties']['name'])
                
    if my_list == "can_buy":
        return can_buy
    elif my_list == "mod_for_sale":
        return mod_for_sale
    else:
        raise "Error"
    

def get_current_ada_status(today_ada_items, manifest_log):
    can_buy = ada_helper(today_ada_items, manifest_log, my_list = 'can_buy')
                
    if can_buy == []:
        str_return = 'Ada-1 is not selling any mods you do not have.'
    else:
        str_return = 'Ada-1 is selling {} mods you do not own: {}'.format(len(can_buy), '|'.join(can_buy))
        
    return( str_return)

def get_ada_mods(today_ada_items,manifest_log ):
    mod_for_sale = ada_helper(today_ada_items, manifest_log, my_list = 'mod_for_sale')
    str_return = 'Today Ada-1 is selling: {}'.format( '|'.join(mod_for_sale))
    return(str_return)

def destiny2_api_public(url, api_key, token = None):
    """This is the main function for everything. It requests the info from the bungie servers
    by sending a url."""
    #print(url)
    my_headers = my_headers = {"X-API-Key": api_key}
    if token is not None:
        my_headers = my_headers = {"X-API-Key": api_key, "Authorization": "Bearer " + token}
    response = requests.get(url, headers = my_headers)
    return response

##### 

@app.route('/')
@app.route('/index')
def index():
    state = make_authorization_url()
    state_params = {'state': state}
    url = AUTH_URL + urllib.parse.urlencode(state_params)
    print(url)
    #url = 'https://www.google.com'
    #return('Hello World')
    return render_template('index.html', url=url)

@app.route('/callback')
def bungie_callback():
    #print("CALLBACK1")
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    #print("CALLBACK2")
    state = session.get('state_token')
    print("State:" + state)
    if not is_valid_state(state):
        print("Uh-oh, this request wasn't started by us!")
        abort(403)
    session.pop('state_token', None)
    code = request.args.get('code')
    print("Code:" + code)
    #return "You were redirected. Congrats :)!"
    access_code = code
    token_r = get_token(code, client_id, client_secret)
    token = token_r.json()['access_token']
    print(token)
    user = get_user(api_key, token)
    
    # Get Ada-1 Data
    baseurl = 'https://bungie.net/Platform/Destiny2'
    query = urllib.parse.quote(user.encode('utf8'))
    membership_type= '-1' ## This is ALL by default
    player_url = f'{baseurl}/SearchDestinyPlayer/{membership_type}/{query}/'
    player_summary = destiny2_api_public(player_url, api_key)
    membership_type = player_summary.json()['Response'][0]['membershipType']
    membership_id = player_summary.json()['Response'][0]['membershipId']
    # Get 1st character on the list. I assume if multiple characters they all have the same shop since I think mods are shared. 
    components = '100' # This component gives basic profile information
    url = f'{baseurl}/{membership_type}/Profile/{membership_id}/?components={components}'
    r = destiny2_api_public(url, api_key, token)
    character_id = r.json()['Response']['profile']['data']['characterIds'][0]
    ## Hardcode ada-1's vendorID
    vendor_id = '350061650'
    all_ada_items = manifest_log.manifest[ 'DestinyVendorDefinition']['350061650']['itemList']

    today_ada_url = f'http://www.bungie.net/Platform/Destiny2/{membership_type}/Profile/{membership_id}/Character/{character_id}/Vendors/{vendor_id}/?components=402'
    today_ada_response = destiny2_api_public(today_ada_url, api_key, token)
    today_ada_items = today_ada_response.json()['Response']['sales']['data']
    # Get Personal Collection

    my_collection_url = f'http://www.bungie.net/Platform/Destiny2/{membership_type}/Profile/{membership_id}/?components=800'
    my_collection_reponse = destiny2_api_public(my_collection_url, api_key)
    my_collection = my_collection_reponse.json()['Response']['profileCollectibles']['data']['collectibles']

    A = get_total_ada_status(my_collection, all_ada_items, manifest_log)
    B = get_current_ada_status(today_ada_items, manifest_log)
    C = get_ada_mods(today_ada_items,manifest_log)
    
    return f"Welcome {user}. {A} {B} {C}"


if __name__ == '__main__':
    app.run(debug=True)