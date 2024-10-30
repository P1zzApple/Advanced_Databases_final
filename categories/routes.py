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



def get_subcat(category_id):
    try:
        category_key = f"category:{category_id}"
        category_data = redis_client.hgetall(category_key)

        if not category_data:
            raise ValueError("Category not found!")

        # Retrieve subcategory IDs
        subcategory_ids = redis_client.smembers(f"{category_key}:subcategories")
        subcategories = []

        for subcategory_id in subcategory_ids:
            subcategory_data = redis_client.hgetall(f"subcategory:{subcategory_id.decode('utf-8')}")
            if subcategory_data:
                subcategories.append({
                    "subcategory_id": subcategory_id.decode('utf-8'),  # Decode to string
                    "name": subcategory_data.get(b'name').decode('utf-8')  # Decode to string
                })

        return subcategories

    except Exception as e:
        print(f"Error: {e}")
        return []


@categories_bp.route('/<category_id>', methods=['GET'])
def get_category_with_subcategories(category_id):
    try:
        category_key = f"category:{category_id}"
        category_data = redis_client.hgetall(category_key)

        if not category_data:
            return jsonify({'message': 'Category not found!'}), 404

        # Retrieve subcategory IDs
        subcategory_ids = redis_client.smembers(f"{category_key}:subcategories")
        subcategories = []

        for subcategory_id in subcategory_ids:
            subcategory_data = redis_client.hgetall(f"subcategory:{subcategory_id.decode('utf-8')}")
            if subcategory_data:
                subcategories.append({
                    "subcategory_id": subcategory_id.decode('utf-8'),  # Decode to string
                    "name": subcategory_data.get(b'name').decode('utf-8')  # Decode to string
                })

        response = {
            "category_id": category_id,
            "name": category_data.get(b'name').decode('utf-8'),
            "subcategories": subcategories
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@categories_bp.route('/', methods=['GET'])
def get_all_categories():
    try:
        categories = []
        keys = redis_client.keys('category:*')  # Get all keys that start with 'category:'
        decoded_keys = [key.decode('utf-8') for key in keys]  # Decode from bytes to strings

        # Filter to include only main category keys
        for key in decoded_keys:
            if not key.endswith(':subcategories'):  # Only include keys that are not subcategory keys
                category_data = redis_client.hgetall(key)
                if category_data:
                    category = {
                        "category_id": key.split(":")[1],  # Extract category ID
                        "name": category_data.get(b'name').decode('utf-8'),  # Decode category name
                        "subcategories": get_subcat(key.split(":")[1])
                    }
                    categories.append(category)
            
                
        return jsonify(categories), 200

    except Exception as e:
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
