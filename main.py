import requests,json,urllib3,csv

urllib3.disable_warnings()

def getToken(account, password):
    URL = 'https://10.10.10.54/api/fmc_platform/v1/auth/generatetoken'

    HEADERS = {'Content-Type': 'application/json'}

    accessToken = ""
    response = requests.post(URL, headers=HEADERS, auth= requests.auth.HTTPBasicAuth(account, password), verify=False)
    authHeaders = response.headers
    accessToken = authHeaders.get('X-auth-access-token', default='None')
    return accessToken


def getDevices(token):
    URL = 'https://10.10.10.54/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords'
    HEADERS = {'Content-Type': 'application/json'}

    HEADERS['X-auth-access-token'] = token

    response = requests.get(URL, headers=HEADERS, verify=False)

    response= response.json()
    items= response["items"]
    print("List of devices")
    for item in items:
        print(item["id"])

    device = input("select a device: ")

    getAccesPolicy(token,device)

def getAccesPolicy(token, idDevice):
    URL = 'https://10.10.10.54/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments?expanded=true'
    HEADERS = {'Content-Type': 'application/json'}

    HEADERS['X-auth-access-token'] = token

    response = requests.get(URL, headers=HEADERS, verify=False)
    response = response.json()

    accessPolicy=0
    items = response["items"]
    for item in items:
        if item["policy"]["type"] == "AccessPolicy":
            targetDevices = item["targets"]
            for targetDevice in targetDevices:
                if targetDevice["id"] == idDevice:
                    accessPolicy=item["policy"]["id"]

    if accessPolicy == 0 : 
        print ("there aren't access policies for this device")
    else:
        detailAccessPolicy(token, accessPolicy)

def detailAccessPolicy(token, idAccesPolicy):

    URL = f'https://10.10.10.54/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments/{idAccesPolicy}'

    HEADERS = {'Content-Type': 'application/json'}

    HEADERS['X-auth-access-token'] = token

    response = requests.get(URL, headers=HEADERS, verify=False)
    response = response.json()
    policy= response["policy"]
    policyType = policy["type"]
    #policyDescription = policy["description"]
    policyName= policy["name"]
    policyId= policy["id"]

    createCSV(policyType, policyName, policyId)
    #print(f"Access Policy for this device:\nType: {policyType}\nName: {policyName}\nId: {policyId}")

def createCSV(policyType, policyName, policyId):
    data=[["Type", "Name", "Id"],
    [policyType,policyName,policyId]]

    myFile= open('data.csv','w')
    with myFile:
        writer= csv.writer(myFile)
        writer.writerows(data)

    print("file .csv was created with the Access Policy Data")

account=input("Usuario: ")
password= input("Password: ")
getDevices(getToken(account, password))

