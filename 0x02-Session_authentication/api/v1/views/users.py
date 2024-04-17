#!/usr/bin/env python3
""" Module of Users views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/users', methods=['GET'], strict_slashes=False)
def view_all_users() -> str:
    """ GET /api/v1/users
    """
    users = [user.to_json() for user in User.all()]
    return jsonify(users)


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
def view_one_user(user_id: str = None) -> str:
    """ GET /api/v1/users/:id
    """
    if user_id is None:
        abort(404)
    if user_id == "me":
        if request.current_user is None:
            abort(404)
        user = request.current_user
        return jsonify(user.to_json())
    user = User.get(user_id)
    if user is None:
        abort(404)
    if request.current_user is None:
        abort(404)
    return jsonify(user.to_json())


@app_views.route('/users/<user_id>', methods=['DELETE'], strict_slashes=False)
def delete_user(user_id: str = None) -> str:
    """ DELETE /api/v1/users/:id
    """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    user.remove()
    return jsonify({}), 200


@app_views.route('/users', methods=['POST'], strict_slashes=False)
def create_user() -> str:
    """ POST /api/v1/users/
    """
    data = request.get_json()
    error_msg = validate_user_data(data)

    if error_msg is None:
        try:
            user = create_user_instance(data)
            user.save()
            return jsonify(user.to_json()), 201
        except Exception as e:
            error_msg = "Can't create User: {}".format(e)

    return jsonify({'error': error_msg}), 400


def validate_user_data(data):
    if not data:
        return "Wrong format"
    if data.get("email", "") == "":
        return "email missing"
    if data.get("password", "") == "":
        return "password missing"
    return None


def create_user_instance(data):
    user = User()
    user.email = data.get("email")
    user.password = data.get("password")
    user.first_name = data.get("first_name")
    user.last_name = data.get("last_name")
    return user


@app_views.route('/users/<user_id>', methods=['PUT'], strict_slashes=False)
def update_user(user_id: str = None) -> str:
    """ PUT /api/v1/users/:id
    """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    data = None
    try:
        data = request.get_json()
    except Exception as e:
        data = None
    if data is None:
        return jsonify({'error': "Wrong format"}), 400
    if data.get('first_name') is not None:
        user.first_name = data.get('first_name')
    if data.get('last_name') is not None:
        user.last_name = data.get('last_name')
    user.save()
    return jsonify(user.to_json()), 200
