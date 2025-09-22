# Visitor Management Django App

## Setup

1. Clone repo.

2. Create virtual environment:
   ```bash
   python3 -m venv env
   source env/bin/activate
```

Install requirements:  

 ```

pip install -r requirements.txt
   ```






Create a MySQL database and user. Example SQL:

```
CREATE DATABASE visitor_db CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER 'visitor_user'@'localhost' IDENTIFIED BY 'visitor_pass';
GRANT ALL PRIVILEGES ON visitor_db.* TO 'visitor_user'@'localhost';
FLUSH PRIVILEGES;
```


Copy .env from the example and update values.

Run migrations:
```
python manage.py migrate
```



Create a superuser: 
```
  python manage.py createsuperuser

```

Run the dev server:   
```
python manage.py runserver

```


Visit:

http://127.0.0.1:8000/accounts/login/ to login.

http://127.0.0.1:8000/ to view visitors.