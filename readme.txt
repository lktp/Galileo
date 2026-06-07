# 1. Pull down the clean codebase from GitHub
git clone https://github.com/lktp/Galileo.git
cd YOUR_REPO_NAME

# 2. Build a fresh virtual environment on the new machine
python3 -m venv .venv
source .venv/bin/activate

# 3. Install all project dependencies in one shot!
pip install -r requirements.txt

# 4. Initialize the fresh production database and run your server
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
