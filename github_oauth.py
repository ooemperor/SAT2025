import requests


def main():
    """
    simple method to request your github information
    not really working since github is playing stupid and the simple web requests are causing some problems.
    :return:
    """
    scope = "{read: user user: email}"
    client_id = ""
    client_secret = ""
    device_code = ""
    url = "https://github.com/login/oauth/access_token"

    payload = {'client_id': client_id,
               'client_secret': client_secret,
               'grant_type': scope,
               'device_code': device_code}
    files = [

    ]
    headers = {'Accept': 'application/json'}

    response = requests.request("POST", url, headers=headers, data=payload, files=files)
    assert response.status_code == 200
    print(response.text)

    token = response.text["access_token"]

    url2 = "https://api.github.com/user"
    auth_token = f"Bearer {token}"
    headers2 = {'Authorization': auth_token, "Accept": "application/vnd.github+json"}
    resp2 = requests.request("GET", url2, headers=headers2)
    assert resp2.status_code == 200
    print("Your result is: ")
    print(resp2.text)


if __name__ == '__main__':
    main()
