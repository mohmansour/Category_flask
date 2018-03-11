from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Sport, Item, User, Latest
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Category"


# Connect to Database and create database session
engine = create_engine('sqlite:///sport.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secret.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secret.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
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

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Sport Information
@app.route('/sport/<int:sport_id>/menu/JSON')
def sportMenuJSON(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    items = session.query(Item).filter_by(
        sport_id=sport_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/sport/<int:sport_id>/menu/<int:item_id>/JSON')
def ItemJSON(sport_id, item_id):
    Item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=Item.serialize)


@app.route('/sport/JSON')
def sportsJSON():
    sports = session.query(Sport).all()
    latests = session.query(Latest).all()
    return jsonify(sports=[r.serialize for r in sports], latests=[l.serialize for l in latests])


# Show all Sports (done)
@app.route('/')
@app.route('/sport/')
def showSports():
    sports = session.query(Sport).order_by(asc(Sport.name))
    latests = session.query(Latest).all()
    if 'username' not in login_session:
        return render_template('publicsports.html', sports=sports, latests=latests)
    else:
        return render_template('sports.html', sports=sports, latests=latests)

# Create a new Sport (done)


@app.route('/sport/new/', methods=['GET', 'POST'])
def newSport():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newSport = Sport(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newSport)
        session.commit()
        flash('New sport %s Successfully Created' % newSport.name)
        return redirect(url_for('showSports'))
    else:
        return render_template('newSport.html')

# Edit a Sport (done)


@app.route('/sport/<int:sport_id>/edit/', methods=['GET', 'POST'])
def editSport(sport_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedSport = session.query(Sport).filter_by(id=sport_id).one()
    if editedSport.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this sport. Please create your own sport in order to edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedSport.name = request.form['name']
            session.add(editedSport)
            flash('sport Successfully Edited %s' % editedSport.name)
            session.commit()
            return redirect(url_for('showSports'))
    else:
        return render_template('editSport.html', sport=editedSport)


# Delete a Sport (done)
@app.route('/sport/<int:sport_id>/delete/', methods=['GET', 'POST'])
def deleteSport(sport_id):
    if 'username' not in login_session:
        return redirect('/login')
    sportToDelete = session.query(Sport).filter_by(id=sport_id).one()
    if sportToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this sport. Please create your own sport in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        related1 = session.query(Latest).filter_by(sport_id=sport_id).all()
        session.delete(related1)
        session.commit()
        related2 = session.query(Item).filter_by(sport_id=sport_id).all()
        session.delete(related2)
        session.commit()
        session.delete(sportToDelete)
        flash('%s Successfully Deleted' % sportToDelete.name)
        session.commit()
        return redirect(url_for('showSports', sport_id=sport_id))
    else:
        return render_template('deleteSport.html', sport=sportToDelete)

# Show a Sport menu (done)


@app.route('/sport/<int:sport_id>/')
@app.route('/sport/<int:sport_id>/menu/')
def showMenu(sport_id):
    sport = session.query(Sport).filter_by(id=sport_id).one()
    creator = getUserInfo(sport.user_id)
    items = session.query(Item).filter_by(
        sport_id=sport_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicmenu.html', items=items, sport=sport, creator=creator)
    else:
        return render_template('menu.html', items=items, sport=sport, creator=creator)

# Create a new menu item (done)


@app.route('/sport/<int:sport_id>/menu/new/', methods=['GET', 'POST'])
def newItem(sport_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add menu items to this sport. Please create your own sport in order to add items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        newItem = Item(
            name=request.form['name'], description=request.form['description'], sport_id=sport_id, user_id=sport.user_id)
        session.add(newItem)
        session.commit()
        latestToDelete = session.query(Latest).first()
        session.delete(latestToDelete)
        session.commit()
        newLatest = Latest(name=request.form['name'], description=request.form['description'],
                           sport_id=sport_id, user_id=sport.user_id, item_id=newItem.id)
        session.add(newLatest)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', sport_id=sport_id))
    else:
        return render_template('newmenuitem.html', sport_id=sport_id)

# Edit a menu item (done)


@app.route('/sport/<int:sport_id>/menu/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(sport_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(id=item_id).one()
    sport = session.query(Sport).filter_by(id=sport_id).one()
    if login_session['user_id'] != sport.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this sport. Please create your own sport in order to edit items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', sport_id=sport_id))
    else:
        return render_template('editmenuitem.html', sport_id=sport_id, item_id=item_id, item=editedItem)


# Delete a menu item (done)
@app.route('/sport/<int:sport_id>/menu/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(sport_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    sport = session.query(Sport).filter_by(id=sport_id).one()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != sport.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete menu items to this sport. Please create your own sport in order to delete items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        flash('Menu Item Successfully Deleted')
        session.commit()
        return redirect(url_for('showMenu', sport_id=sport_id))
    else:
        return render_template('deletemenuitem.html', item=itemToDelete)


# Disconnect based on provider (done)
@app.route('/disconnect')
def disconnect():
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
        flash("You have successfully been logged out.")
        return redirect(url_for('showSports'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showSports'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
