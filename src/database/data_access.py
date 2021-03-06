#!/usr/bin/env python3
#
# The Catalog Web application data access layer.
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database.database_setup import Base, User, Category, Item

'''Set up database engine and database session '''
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# User data access methods
def get_users():
    '''Retrieve all records from the User table'''
    users = session.query(User).all()
    return users


def get_user_by_id(id):
    '''Retrieve user by id from the User table'''
    try:
        user = session.query(User).filter_by(id=id).one()
        return user
    except NoResultFound:
        return None


def get_user_by_username(username):
    '''Retrieve user by name from the User table'''
    try:
        user = session.query(User).filter_by(username=username).one()
        return user
    except NoResultFound:
        return None


def get_user_by_email(email):
    '''Retrieve user by email from the User table'''
    try:
        user = session.query(User).filter_by(email=email).one()
        return user
    except NoResultFound:
        return None


def add_user(username, password):
    '''Insert new user into the User table'''
    newUser = User(username=username)
    newUser.hash_password(password)
    session.add(newUser)
    session.commit()


def add_3rd_prty_user(username, picture, email):
    '''Insert new 3rd party user into the User table'''
    newUser = User(username=username, picture=picture, email=email)
    session.add(newUser)
    session.commit()


def verify_auth_token(token):
    '''Verify token'''
    return User.verify_auth_token(token)


# Category data access methods
def get_all_categories():
    '''Retrieve all records from the Category table'''
    try:
        categories = session.query(Category).all()
        return categories
    except NoResultFound:
        return None


def get_category_by_id(id):
    '''Retrieve category record based on id from the Category table'''
    try:
        category = session.query(Category).filter_by(id=id).one()
        return category
    except NoResultFound:
        return None


def get_category_by_name(name):
    '''Retrieve category record based on name from the Category table'''
    try:
        category = session.query(Category).filter_by(name=name).one()
        return category
    except NoResultFound:
        return None


def add_category(name, description):
    '''Add a category record to the Category table'''
    category = Category(name=name, description=description)
    session.add(category)
    session.commit()


def upd_category(id, name, description):
    '''Update category record in the Category table'''
    try:
        category = session.query(Category).filter_by(id=id).one()
        category.name = name
        category.description = description
        session.add(category)
        session.commit()
        return 'Success'
    except NoResultFound:
        return None


def del_category_by_id(id):
    '''Delete a category record from the Category table'''
    try:
        category = session.query(Category).filter_by(id=id).one()
        session.delete(category)
        session.commit()
        return 'Success'
    except NoResultFound:
        return None


# Item data access methods
def get_all_items_by_category(category_id):
    '''Retrieve all records from the Item table for given category_id'''
    try:
        items = session.query(Item) \
                       .filter_by(category_id=category_id).all()
        return items
    except NoResultFound:
        return None


def get_item_by_id(id):
    '''Retrieve item record based on id from the Item table'''
    try:
        item = session.query(Item).filter_by(id=id).one()
        return item
    except NoResultFound:
        return None


def get_item_by_name(name):
    '''Retrieve item record based on name from the Item table'''
    try:
        item = session.query(Item).filter_by(name=name).one()
        return item
    except NoResultFound:
        return None


def add_item(name, description, category_id, user_id):
    '''Add a item record to the item table'''
    item = Item(name=name, description=description,
                category_id=category_id, creator_id=user_id)
    session.add(item)
    session.commit()


def upd_item(id, name, description):
    '''Update item record in the Item table'''
    try:
        item = session.query(Item).filter_by(id=id).one()
        item.name = name
        item.description = description
        session.add(item)
        session.commit()
        return 'Success'
    except NoResultFound:
        return None


def del_item_by_id(id):
    '''Delete a item record from the Item table'''
    try:
        item = session.query(Item).filter_by(id=id).one()
        session.delete(item)
        session.commit()
        return 'Success'
    except NoResultFound:
        return None
