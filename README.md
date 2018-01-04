# catalog_app
A simple web application built to demonstrate my knowledge of python, flask, CRUD, and authentication.

## Table of Contents
1. [Implementation](#implementation)
  * [Dependencies](#dependencies)
  * [Installation](#installation)
  * [Quick Start Guide](#quick-start-guide)
2. [Contributing](#contributing)

## Implementation

### Dependencies

#### Python
Catalog Online was built using Python 3. Notice it may not work on older versions of Python.

#### SQLAlchemy
Catalog Online leverages SqlAlchemy for building and manage the database.
Documentation for SqlAlchemy can be found here <a>https://www.sqlalchemy.org/</a>

####  Google OAuth 2.0
Catalog Online leverage's Google OAuth 2.0 for 3rd party login. Below are the
steps for setting creating the OAuth Client ID.
1. Go to Google APIs Console — https://console.developers.google.com/apis
2. Create a project
3. Choose Credentials from the menu on the left.
4. Create an OAuth Client ID and configure consent screen.
5. Download OAuth Client Id json file to (cloned repository)/src directory
4. Rename file to "client_secret.json"  

### Installation
* Install Python3 per the instructions provided <a>https://wiki.python.org/moin/BeginnersGuide/Download</a>
* Clone the repository

### Quick Start Guide
* Open terminal
* `cd` to the (cloned repository)/src directory
* Execute `python3 catalog_app.py`
* Login via google account.

### Additional Setup via leveraging catalog_app api
* add user - ```localhost:5000/catalog/user
{"username": "test", "password": "test"}```
* add category - ```localhost:5000/catalog/api/v1/category {"name": "<category_name>", "description": "<category_description"}```

## Contributing
Open an issue first to discuss potential changes/additions.
