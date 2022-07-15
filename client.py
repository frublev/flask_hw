import requests

URL = 'http://127.0.0.1:5000'
# TOKEN = 'fc76db23-9056-4c51-b549-ab9004c1901b'
TOKEN = '3fc099d0-109d-498c-8e7d-419198a7b65c'


def create_user(user_name, password):
    response = requests.post(f'{URL}/create_user/',
                             json={'user_name': user_name, 'password': password})
    print(response.status_code)
    print(response.json())


def log_in(user_name, password):
    response = requests.post(f'{URL}/login/',
                             json={'user_name': user_name, 'password': password})
    print(response.status_code)
    print(response.json())


def view_user(user_id, user_name):
    response = requests.get(f'{URL}/user/{user_id}/', headers={'user_name': user_name, 'token': TOKEN})
    print(response.status_code)
    print(response.json())


def view_all_users():
    response = requests.get(f'{URL}/user/')
    print(response.status_code)
    print(response.json())


def create_ads(user_id):
    response = requests.post(f'{URL}/create_ads/',
                             json={'head': f'Title {user_id}', 'body': f'Text{user_id}, Text{user_id}, Text{user_id}'},
                             headers={'token': TOKEN})
    print(response.status_code)
    print(response.json())


def view_all_ads():
    response = requests.get(f'{URL}/ads/')
    print(response.status_code)
    print(response.json())


def view_ads(ads_id):
    response = requests.get(f'{URL}/ads/{ads_id}/')
    print(response.status_code)
    print(response.json())


def delete_ads(ads_id):
    response = requests.delete(f'{URL}/ads/{ads_id}/', headers={'token': TOKEN})
    print(response.status_code)
    print(response.json())


def patch_ads(ads_id):
    response = requests.patch(f'{URL}/ads/{ads_id}/',
                             json={'head': 'Title 3-1', 'body': 'Text3-1, Text3-1, Text3-1'},
                             headers={'token': TOKEN})
    print(response.status_code)
    print(response.json())


# create_user('User_5', 'password_5')
# log_in('User_5', 'password_5')
# view_all_users()
# view_user(7, 'User_5')
# create_ads('User_5')
# view_all_ads()
# delete_ads(10)
# patch_ads(9)
view_ads(9)
