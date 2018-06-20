from flask import Flask, render_template, request, redirect, jsonify, \
  url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from model import Base, Category, CategoryItem, User
from flask import session as login_session
import random
import string


from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)


CLIENT_ID = json.loads(
            open('client_secret.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(func):
    """
        decorator to check login status.
        If user is not logged in redirect to login page.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('login')
        else:
            return func(*args, **kwargs)
    return wrapper


@app.route('/login')
def showLogin():
    """
        Create a state token to prevent request forgery.
        Store it in the session for later validation.
    """
    state = ''.join(random.choice(string.ascii_uppercase+string.digits)
                    for x in xrange(32)
                    )
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
        Authenticate the user with facebook account.
        First, Exchange the token then get user info.
        Finally, store the user information in the session.
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # exchange token for long lived server side token with GET
    access_token = request.data

    app_id = json.loads(open('fb_client_secret.json', 'r')
                        .read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secret.json', 'r').read())['web']['app_secret']
    url = ("https://graph.facebook.com/oauth/access_token?"
           "grant_type=fb_exchange_token&client_id=%s"
           "&client_secret=%s&fb_exchange_token=%s" % (
            app_id, app_secret, access_token)
           )

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user Info from API
    # userinfo_url ='https://graph.facebook.com/v2.2/me'
    userinfo_url = "https://graph.facebook.com/v2.8/me"

    # strip expire tag from access token
    # print userinfo_url
    # token = result.split("&")[0]
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = ("https://graph.facebook.com/v2.8/me?access_token=%s"
           "&fields=name,id,email" % token
           )
    # url = 'https://graph.facebook.com/v2.2/me?%s' % token

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access :%S" %url
    # print "API JSON result: %s" %result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    login_session['access_token'] = token

    # Get user Pictures
    url = ("https://graph.facebook.com/v2.8/me/picture?access_token=%s"
           "&redirect=0&height=200&width=200" % token
           )

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; border-radius:\
     150px;-webkit-border-radius:150px;-moz-border-radius: 150px"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """
        Disconnect the user logged with Facebook service
    """
    facebook_id = login_session['facebook_id']
    # The access token must be included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
        Authenticate the user with google account.
        First, Verify the access token then, store it for later use.
    """

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
              json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check that access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)

    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
          json.dumps("Token's user ID dosen't match given user ID"), 401)
        response.headers['Content-Type'] = 'application.json'
        return response
    # verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
          json.dumps("Token's client ID dose not match app's"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    # if stored_access_token is not None and gplus_id == stored_gplus_id:

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            "Current user is already connected"), 200,)
        response.headers['Content-Type'] = 'application/json'
        return response

    # store the access token in the session for later use

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # get user Info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
    -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


def createUser(login_session):
    newUser = User(username=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'],
                   )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        username=login_session['username']).one()
    # user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    """
        Disconnect the user logged in with google service
    """

    # only disconnect a connected user
    # credentials = login_session.get('credentials')
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # execute HTTP GET request to revoke current token.
    # access_token = credentials.access_token
    # print 'In gdisconnect access token is %s', access_token
    # print 'User name is: '
    # print login_session['username']

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # print 'result is '
    # print result
    if result['status'] == '200':
        print 'result status 200'
        # del login_session['access_token']
        # del login_session['gplus_id']
        # del login_session['username']
        # del login_session['email']
        # del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        print 'gdisconnect success'
        return response
    # for whatever reason, the given token was invalid
    else:
        response = make_response(
          json.dumps('Failed to revoke token for given user', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Categories Information
@app.route('/category/<int:category_id>/item/JSON')
def categoryJSON(category_id):
    catgory = session.query(Category).filter_by(id=category_id).one()
    items = session.query(CategoryItem).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def categoryItemJSON(category_id, item_id):
    item = session.query(CategoryItem).filter_by(id=item_id).one()
    return jsonify(item=item.serialize)


@app.route('/category/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/')
@app.route('/category/')
def showCategories():
    """
        Show all categories.
    """
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('categories.html', categories=categories)


@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
        Create a new category
        Only logged in user can creat category.
    """

    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               description=request.form['description'],
                               user_id=login_session['user_id']
                               )
        session.add(newCategory)
        flash('New Category \'%s\' Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('new_category.html')


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    """
        Edit a category
        Only authorized user can edit category.
        If user not logged in redirect to login page.
    """
    editedCategory = session.query(Category).filter_by(id=category_id).one()

    # check if user own this category
    if editedCategory.user_id == login_session['user_id']:
        flash("You are not authorized to edit this category. \
            You can only edit your own category.")
        # return redirect(url_for('showItem', category_id=category_id))
        return redirect(url_for('showCategories'))

    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited \"%s\"' % editedCategory.name)
            # return redirect(url_for('showCategories'))
            return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('editCategory.html', category=editedCategory)


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    """
        Delete a category
        Only an authorized user can delete a category.
        If user not logged in redirect to login page.
    """
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()

    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert\
                ('You are not authorized to delete this category. \
                Please create your own category in order to delete.');}\
                </script><body onload='myFunction()''>"

    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('\'%s\' Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showCategories', category_id=category_id))
    else:
        return render_template('delete_category.html',
                               category=categoryToDelete
                               )


@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/item/')
def showItem(category_id):
    """
        Show Category items
    """

    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(CategoryItem).filter_by(
        category_id=category_id).all()
    user_auth = True

    # set user_auth false if user dosen't own this category
    if ('username' not in login_session or
            category.user_id != login_session['user_id']):
        user_auth = False

    return render_template('item.html', items=items, category=category,
                           creator=creator, user_auth=user_auth,
                           )


@app.route('/category/<int:category_id>/item/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_id):
    """
        Create a new item
        Only an authorized user can create an item in the category.
        A user must be logged in and the owner of the category.
        If there is no information in the login session,
        redirect to login page.
    """
    category = session.query(Category).filter_by(id=category_id).one()

    # check if user own this category. Only owner can add items.
    if category.user_id != login_session['user_id']:
        flash("You are not authorized to add an item. \
            You can only add an item to your own category.")
        return redirect(url_for('showItem', category_id=category_id))
        # return redirect(url_for('showCategories'))

    if request.method == 'POST':
        newItem = CategoryItem(
            name=request.form['name'], description=request.form['description'],
            category_id=category_id, user_id=category.user_id)
        session.add(newItem)
        session.commit()
        flash('New  Item  %s  Successfully Created' % (newItem.name))
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('new_item.html', category_id=category_id)


# Edit a item
@app.route(
    '/category/<int:category_id>/item/<int:item_id>/edit',
    methods=['GET', 'POST']
         )
@login_required
def editItem(category_id, item_id):
    """
        Edit an item.
        Only an authorized user can edit an item.
        If there is no information in the login session,
        redirect to login page.
    """
    editedItem = session.query(CategoryItem).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()

    # check if user own this item. Only owner can edit.
    if category.user_id != login_session['user_id']:
        flash("You are not authorized to edit. \
            You can only edit your own item.")
        return redirect(url_for('showItem', category_id=category_id))

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('edit_item.html', category_id=category_id,
                               item_id=item_id, item=editedItem)


# Delete a item
@app.route(
    '/category/<int:category_id>/item/<int:item_id>/delete',
    methods=['GET', 'POST'])
@login_required
def deleteItem(category_id, item_id):
    """
        Delete an item.
        Only an authorized user can delete an item.
        If there is no information in the login session,
        redirect to login page.
    """
    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(CategoryItem).filter_by(id=item_id).one()

    # check if user own this item. Only owner can delete.
    if category.user_id != login_session['user_id']:
        flash("You are not authorized to delete. \
            You can only delete your own item")
        return redirect(url_for('showItem', category_id=category_id))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('delete_item.html',
                               item=itemToDelete,  category_id=category_id,
                               )


@app.route('/disconnect')
def disconnect():
    """
        Log out based on provider
        Delete all information in the session.
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have been successfully logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
