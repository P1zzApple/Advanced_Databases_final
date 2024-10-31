import redis
import json
from flask import jsonify, request
from . import categories_bp
from auth.routes import token_required
import traceback
from .engine import output,recommend


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



@categories_bp.route('/<category_id>/products', methods=['GET'])
def get_products_by_category(category_id):
    try:
        category_key = f"category:{category_id}"
        
        # Check if the category exists
        if not redis_client.exists(category_key):
            return jsonify({'message': 'Category not found!'}), 404

        # Retrieve subcategory IDs associated with this category
        subcategory_ids = redis_client.smembers(f"{category_key}:subcategories")
        
        products = []

        # Iterate through each subcategory to find associated products
        for subcategory_id in subcategory_ids:
            subcategory_key = f"subcategory:{subcategory_id.decode('utf-8')}"
            # Assuming products are stored in a set under each subcategory
            product_ids = redis_client.smembers(f"{subcategory_key}:products")

            for product_id in product_ids:
                product_key = f"product:{product_id.decode('utf-8')}"
                product_data = redis_client.hgetall(product_key)
                
                if product_data:
                    product = {
                        "product_id": product_id.decode('utf-8'),
                        "name": product_data.get(b'name').decode('utf-8'),
                        "description": product_data.get(b'description').decode('utf-8'),
                        "price": float(product_data.get(b'price')),
                        "stock_quantity": int(product_data.get(b'stock_quantity')),
                        "ratings": float(product_data.get(b'ratings')),
                        "tags": json.loads(product_data.get(b'tags').decode('utf-8')),
                        "images": json.loads(product_data.get(b'images').decode('utf-8')),
                    }
                    products.append(product)

        # Pagination parameters
        page = request.args.get('page', default=1, type=int)  # Default to page 1
        limit = request.args.get('limit', default=10, type=int)  # Default limit to 10
        total_products = len(products)

        # Calculate pagination
        start = (page - 1) * limit
        end = start + limit
        paginated_products = products[start:end]

        # Prepare response with pagination info
        response = {
            'total_products': total_products,
            'total_pages': (total_products + limit - 1) // limit,  # Ceiling division to calculate total pages
            'current_page': page,
            'products': paginated_products
        }

        return jsonify(response), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'message': str(e)}), 500



@categories_bp.route('/product/like', methods=['POST'])
@token_required
def store_user_preferences(user):
    user_email = user['email']  # Get the email from the token payload
    
    # Validate input data
    data = request.get_json()
    liked_product_id = data.get('likedProductId')  # Single liked product
    liked_product_tags = data.get('likedProductTags')  # Tags for the liked product

    if not liked_product_id:
        return jsonify({'message': 'Liked product ID is required!'}), 400

    if liked_product_tags is None:
        liked_product_tags = []  # Default to an empty list if no tags are provided

    try:
        # Construct the key for user preferences
        user_preferences_key = f"user:{user_email}:preferences"
        
        # Remove existing liked product and tags
        redis_client.hdel(user_preferences_key, "liked_product", "liked_product_tags")

        # Store user preferences in Redis using a hash
        redis_client.hset(user_preferences_key, "liked_product", liked_product_id)
        redis_client.hset(user_preferences_key, "liked_product_tags", json.dumps(liked_product_tags))
        
        return jsonify({
            'message': 'Preferences saved successfully!',
            'liked_product': liked_product_id,
            'liked_product_tags': liked_product_tags
        }), 200

    except Exception as e:
        print(f"Error saving preferences: {e}")
        return jsonify({'message': 'An error occurred while saving preferences.'}), 500



@categories_bp.route('/recommendations', methods=['GET'])
@token_required
def get_recommendations(user):
    user_email = user["email"]

    try:
        # Retrieve user preferences from Redis
        user_preferences_key = f"user:{user_email}:preferences"
        liked_product_id = redis_client.hget(user_preferences_key, "liked_product")
        liked_product_tags_json = redis_client.hget(user_preferences_key, "liked_product_tags")

        if not liked_product_id or not liked_product_tags_json:
            return jsonify({'message': 'No liked products found for this user.'}), 404

        # Decode the liked product tags from JSON
        liked_product_tags = json.loads(liked_product_tags_json)

        # Fetch similar products based on the liked tags
        similar_products = recommend(liked_product_tags)

        # Prepare the response
        if not similar_products:
            return jsonify({'message': 'No recommendations found based on your preferences.'}), 404
        
        # Get details for recommended products
        recommended_product_details = output(similar_products)

        return jsonify({'products':recommended_product_details}), 200

    except Exception as e:
        print(f"Error retrieving recommendations: {e}")
        traceback.print_exc(e)
        return jsonify({'message': 'An error occurred while retrieving recommendations.'}), 500
