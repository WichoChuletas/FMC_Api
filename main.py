import requests,json,urllib3

urllib3.disable_warnings()

def getToken(account, password):
    URL = 'https://10.10.10.54/api/fmc_platform/v1/auth/generatetoken'

    HEADERS = {'Content-Type': 'application/json'}

    accessToken = ""
    response = requests.post(URL, headers=HEADERS, auth= requests.auth.HTTPBasicAuth(account, password), verify=False)
    authHeaders = response.headers
    accessToken = authHeaders.get('X-auth-access-token', default='None')
    return accessToken


account=input("Usuario: ")
password= input("Password: ")
print(getToken(account,password))