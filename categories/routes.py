import redis
import json
from flask import jsonify, request
import traceback
from . import categories_bp

# Redis connection
redis_client = redis.Redis(host='localhost', port=6379, db=0)



# CREATE a new category (protected route)
@categories_bp.route('/create', methods=['POST'])
def create_category(current_user):
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

        for key in keys:
            # Get all fields of the category hash directly from Redis
            category_data = redis_client.hgetall(key)
            if category_data:
                # Redis stores everything as strings, so you might want to handle type conversion if necessary
                category = {
                    "category_id": key.split(":")[1],  # Extract category_id from the key
                    "name": category_data.get("name")
                }
                categories.append(category)

        return jsonify(categories), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': str(e)}), 500


# READ a specific category (protected route)
@categories_bp.route('/<category_id>', methods=['GET'])
def get_category(current_user, category_id):
    try:
        category = get_json_from_redis(f"category:{category_id}")

        if not category:
            return jsonify({'message': 'Category not found!'}), 404

        return jsonify(category), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# UPDATE a category (protected route)
@categories_bp.route('/<category_id>', methods=['PUT'])
def update_category(current_user, category_id):
    try:
        data = request.json
        name = data.get('name')

        if not name:
            return jsonify({'message': 'Name is required!'}), 400

        if not redis_client.exists(f"category:{category_id}"):
            return jsonify({'message': 'Category not found!'}), 404

        redis_client.hset(f"category:{category_id}", "name", name)
        return jsonify({'message': 'Category updated successfully!'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# DELETE a category (protected route)
@categories_bp.route('/<category_id>', methods=['DELETE'])
def delete_category(current_user, category_id):
    try:
        if not redis_client.exists(f"category:{category_id}"):
            return jsonify({'message': 'Category not found!'}), 404

        redis_client.delete(f"category:{category_id}")
        return jsonify({'message': 'Category deleted successfully!'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# GET all products in a category (protected route)
@categories_bp.route('/<category_id>/products', methods=['GET'])
def get_products_by_category(current_user, category_id):
    try:
        category_key = f"category:{category_id}"

        # Check if category exists
        if not redis_client.exists(category_key):
            return jsonify({'message': 'Category not found!'}), 404

        products = []

        # Get all subcategories for the category
        subcategories = redis_client.smembers(f"{category_key}:subcategories")

        for subcategory_id in subcategories:
            subcategory_key = f"subcategory:{subcategory_id}"

            # Get all products for each subcategory
            product_ids = redis_client.smembers(f"{subcategory_key}:products")

            for product_id in product_ids:
                product_key = f"product:{product_id}"
                product = redis_client.hgetall(product_key)

                if product:
                    product['product_id'] = product_id  # Add product_id to the response
                    products.append(product)

        return jsonify(products), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500


# CREATE a subcategory under a category (protected route)
@categories_bp.route('/<category_id>/subcategory', methods=['POST'])
def create_subcategory(current_user, category_id):
    try:
        data = request.json
        subcategory_id = data.get('subcategory_id')
        name = data.get('name')

        if not subcategory_id or not name:
            return jsonify({'message': 'Subcategory ID and name are required!'}), 400

        subcategory_key = f"subcategory:{subcategory_id}"
        redis_client.hset(subcategory_key, "name", name, "category_id", category_id)

        redis_client.sadd(f"category:{category_id}:subcategories", subcategory_id)

        return jsonify({'message': 'Subcategory created successfully!'}), 201
    except Exception as e:
        
        return jsonify({'message': str(e)}), 500
