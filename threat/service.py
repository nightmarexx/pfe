import os
import requests

def get_url():
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'

    params = {'apikey': 'c6c0f01017b99df69fc4062421dfe7ab8079adbdc6a3fcf5741aee9b060dec25', 'url': 'www.google.com'}

    response = requests.post(url, data=params)

    print(response.json())