#!/usr/bin/env python3
#
# The Catalog Web application.
from flask import Flask, redirect, request, url_for, abort, g, \
     jsonify, make_response, render_template, flash
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
from database.data_access import get_users, get_user_by_id, \
     get_user_by_username, add_user, verify_auth_token, \
     get_user_by_email, add_3rd_prty_user, get_all_categories, \
     add_category, get_category_by_id, del_category_by_id, \
     upd_category, get_all_items_by_category, get_item_by_id, \
     add_item, upd_item, del_item_by_id

# Import oauth2 libraries
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import random
import string


app = Flask(__name__)
auth = HTTPBasicAuth()

# Setup Client id
CLIENT_ID = json.loads(
                 open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Web Application"


@auth.verify_password
def verify_password(username_or_token, password):
    # Attempt to authenticate token
    user_id = verify_auth_token(username_or_token)

    if user_id:
        user = get_user_by_id(user_id)
    else:
        user = get_user_by_username(username_or_token)
        if not user or not user.verify_password(password):
            return False

    g.user = user
    return True


@app.route('/catalog/login')
def showLogin():
    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/catalog', methods=['GET'])
def showCatalog():
    # Retrieve all categories
    category_result = get_categories()
    data = json.loads(category_result.data.decode('utf-8'))
    categories = data['Category']

    # Retrieve first category's items
    category = categories[0]
    items_result = get_items_by_category(category['id'])
    data = json.loads(items_result.data.decode('utf-8'))
    items = data['Item']

    return render_template('catalog.html', categories=categories,
                           items=items)


@app.route('/catalog/<string:category_name>/items', methods=['GET'])
def showCategory(category_name):
    return render_template('catalog.html')


@app.route('/catalog/<int:category_id>/items/<string:item_name>',
           methods=['GET'])
def showItem(category_id, item_name):
    return render_template('catalog.html')


# Catalog API calls
@app.route('/catalog/api/v1/categories')
def get_categories():
    # Retrieve data for the categories
    categories = get_all_categories()
    return jsonify(Category=[category.serialize
                   for category in categories])


@app.route('/catalog/api/v1/category/<int:category_id>')
@auth.login_required
def get_category(category_id):
    # Retrieve data for category
    category = get_category_by_id(category_id)
    if category is not None:
      return jsonify(Category=[category.serialize])
    else:
      return jsonify({'message': 'No category found'}), 201


@app.route('/catalog/api/v1/category', methods=['POST'])
@auth.login_required
def new_category():
    # Add a new category
    name = request.json.get('name')
    description = request.json.get('description')

    add_category(name, description)
    return jsonify({'message': 'New category added'}), 201


@app.route('/catalog/api/v1/category/<int:category_id>/update',
           methods=['PUT'])
@auth.login_required
def update_category(category_id):
    # Update parameter new user
    name = request.json.get('name')
    description = request.json.get('description')
    category = upd_category(category_id, name, description)
    if category is not None:
      return jsonify({'message': "Category with id ({}) was updated.\
                      ".format(category_id)}), 201
    else:
      return jsonify({'message': 'No category found'}), 201


@app.route('/catalog/api/v1/category/<int:category_id>/delete',
           methods=['DELETE'])
@auth.login_required
def del_category(category_id):
    # Delete category based on category id
    category = del_category_by_id(category_id)
    if category is not None:
        return jsonify({'message': "Category with id ({}) was deleted.\
                        ".format(category_id)}), 201
    else:
        return jsonify({'message': 'No category found.'}), 201


# Item API calls
@app.route('/catalog/api/v1/categories/<int:category_id>/items')
def get_items_by_category(category_id):
    # Retrieve items for the categories
    items = get_all_items_by_category(category_id)
    return jsonify(Item=[item.serialize
                   for item in items])


@app.route('/catalog/api/v1/categories/<int:category_id>/items/<int:item_id>')
@auth.login_required
def get_item(category_id, item_id):
    # Retrieve data for item
    item = get_item_by_id(item_id)
    if item is not None:
      return jsonify(Item=[item.serialize])
    else:
      return jsonify({'message': 'No category found'}), 201


@app.route('/catalog/api/v1/categories/<int:category_id>/items',
           methods=['POST'])
@auth.login_required
def new_item(category_id):
    # Add a new category
    name = request.json.get('name')
    description = request.json.get('description')
    user_id = request.json.get('user_id')

    add_item(name, description, category_id, user_id)
    return jsonify({'message': 'New item added'}), 201


@app.route('/catalog/api/v1/categories/<int:category_id>/items/<int:item_id>/update',
           methods=['PUT'])
@auth.login_required
def update_item(category_id, item_id):
    # Update parameter new user
    name = request.json.get('name')
    description = request.json.get('description')
    item = upd_item(item_id, name, description)
    if item is not None:
      return jsonify({'message': "Item with id ({}) was updated.\
                      ".format(category_id)}), 201
    else:
      return jsonify({'message': 'No category found'}), 201


@app.route('/catalog/api/v1/categories/<int:category_id>/items/<int:item_id>/delete',
           methods=['DELETE'])
@auth.login_required
def del_item(category_id, item_id):
    # Delete category based on category id
    item = del_item_by_id(item_id)
    if item is not None:
        return jsonify({'message': "Item with id ({}) was deleted.\
                        ".format(item_id)}), 201
    else:
        return jsonify({'message': 'No category found.'}), 201


@app.route('/catalog/user', methods=['POST'])
def new_user():
    # Add new user
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        print("Missing arguments")
        abort(400)

    user = get_user_by_username(username)

    if user is not None:
        print('Existing Username')
        return jsonify({'message': 'User already exists'}), 200

    add_user(username, password)
    return jsonify({'message': 'New user added'}), 201


@app.route('/catalog/api/v1/user/<int:id>', methods=['GET'])
def get_user(id):
    user = get_user_by_id(id)
    if not user:
        print('Invalid user id provided.')
        return jsonify({'message': 'Invalid user id provided.'}), 200
    return jsonify({'username': user.username})


@app.route('/catalog/api/v1/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


@app.route('/catalog/oauth/<provider>', methods=['POST'])
def login(provider):
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if provider == 'internal':
        login_session['provider'] = 'internal'
        verified = verify_password(request.form['username'],
                                   request.form['password'])

        if verified is True:
            login_session['username'] = g.user.username
            login_session['user_id'] = g.user.id
            login_session['picture'] = g.user.picture
            login_session['email'] = g.user.email
            login_session['user_token'] = g.user.generate_auth_token()

            return redirect(url_for('showCatalog'))
        else:
            flash("Username and password are invalid.")
            return redirect(url_for('showLogin'))

        return jsonify({'message': 'Internal Provider'})

    if provider == 'google':
        login_session['provider'] = 'google'

        # Obtain authorization code
        auth_code = request.data

        # Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secret.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(
                                     json.dumps('Failed to upgrade the \
                                                authorization code.'),
                                     401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = 'https://www.googleapis.com/oauth2/v1/tokeninfo'
        result = requests.post(url,
                               params={'access_token': access_token},
                               headers={'content-type':
                                        'application/x-www-form-urlencoded'})

        result = result.json()

        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result
                                                .get('error_description')),
                                     500)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result.get('user_id') != gplus_id:
            response = make_response(
                                     json.dumps(
                                                "Token's user ID doesn't \
                                                match given user ID."),
                                     401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result.get('issued_to') != CLIENT_ID:
            response = make_response(
                                     json.dumps("Token's client ID does \
                                                not match app's."), 401)
            print("Token's client ID does not match app's.")
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_access_token = login_session.get('access_token')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            print("Current user is already connected.")
            response = make_response(json.dumps('Current user is already \
                                                connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Store the access token in the session for later use.
        # login_session['access_token'] = credentials.access_token
        login_session['access_token'] = access_token
        login_session['gplus_id'] = gplus_id

        # Get user info
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']

        user = get_user_by_email(login_session['email'])

        if user is None:
            add_3rd_prty_user(login_session['username'],
                              login_session['picture'],
                              login_session['email'])
            user = get_user_by_email(login_session['email'])

        # Generate token
        token = user.generate_auth_token()
        login_session['user_token'] = token
        login_session['user_id'] = user.id

        # Send back token to the client
        # return jsonify({'token': token.decode('ascii')})
        return 'Success'
    else:
        return jsonify({'message': 'Unrecognizied Provider'})


@app.route('/catalog/disconnect')
def disconnect():
    print('login_session[provider]: {}'.format(login_session.get('provider')))
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_token']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


@app.route('/catalog/gdisconnect')
def gdisconnect():
    print('access_token: {}'.format(login_session.get('access_token')))

    # Only disconnect a connected user.
    if 'access_token' not in login_session:
        response = make_response(json.dumps(
                                 'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = login_session['access_token']

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
                           params={'token': access_token},
                           headers={'content-type':
                                    'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')

    if status_code == 200:
        del login_session['access_token']
        del login_session['gplus_id']
        response = make_response(json.dumps(
                                 'Credentials successfully revoked.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
                                 'Failed to revoke token for given user.',
                                 400))
        response.headers['Content-Type'] = 'application/json'
        return response


if __name__ == '__main__':
    app.secret_key = 'ppa_bew_golatac_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
