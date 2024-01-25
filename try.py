response = {'User': [{'email': 'amos@gmail.com', 'created_at': '2024-01-25T09:24:18.645503'}]}

current_user = response['User'][0]

print(current_user['email'])