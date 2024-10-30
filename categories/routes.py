import redis
import json
from flask import jsonify, request
from . import categories_bp
import traceback

# Redis connection
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# CREATE a new category (public route)
@categories_bp.route('/create', methods=['POST'])
def create_category():
    try:
        data = request.json
        category_id = data.get('category_id')
        name = data.get('name')

        if not category_id or not name:
            return jsonify({'message': 'Category ID and name are required!'}), 400

        if redis_client.exists(f"category:{category_id}"):
            return jsonify({'message': 'Category already exists!'}), 400

        redis_client.hset(f"category:{category_id}", "name", name)
        return jsonify({'message': 'Category created successfully!'}), 201

    except Exception as e:
        return jsonify({'message': str(e)}), 500


# READ all categories (public route)
@categories_bp.route('/', methods=['GET'])
def get_all_categories():
    try:
        categories = []
        keys = redis_client.keys('category:*')
        decoded_keys = [key.decode('utf-8') for key in keys]  # Decode from bytes to strings

        print(decoded_keys)
        for key in decoded_keys:
            # Fetch all fields and values from the Redis hash
            category_data = redis_client.hgetall(key)
            print(category_data)
            if category_data:
                category = {
                    "category_id": key.split(":")[1],  # Extract category_id from the key
                    "name": category_data.get(b'name').decode('utf-8')  # Decode from bytes to a regular string
                }
                categories.append(category)

        return jsonify(categories), 200

    except Exception as e:
        # traceback.print_exc(e)
        return jsonify({'message': str(e)}), 500


# READ a specific category (public route)
@categories_bp.route('/<category_id>', methods=['GET'])
def get_category(category_id):
    try:
        category_key = f"category:{category_id}"
        category_data = redis_client.hgetall(category_key)

        if not category_data:
            return jsonify({'message': 'Category not found!'}), 404

        category = {
            "category_id": category_id,
            "name": category_data.get("name")
        }

        return jsonify(category), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# UPDATE a category (public route)
@categories_bp.route('/<category_id>', methods=['PUT'])
def update_category(category_id):
    try:
        data = request.json
        name = data.get('name')

        if not name:
            return jsonify({'message': 'Name is required!'}), 400

        category_key = f"category:{category_id}"

        if not redis_client.exists(category_key):
            return jsonify({'message': 'Category not found!'}), 404

        redis_client.hset(category_key, "name", name)
        return jsonify({'message': 'Category updated successfully!'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


# DELETE a category (public route)
@categories_bp.route('/<category_id>', methods=['DELETE'])
def delete_category(category_id):
    try:
        category_key = f"category:{category_id}"

        if not redis_client.exists(category_key):
            return jsonify({'message': 'Category not found!'}), 404

        redis_client.delete(category_key)
        return jsonify({'message': 'Category deleted successfully!'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500
