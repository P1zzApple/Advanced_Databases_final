import redis
import json

# Connect to Redis
r = redis.Redis(host='redis-17786.c232.us-east-1-2.ec2.redns.redis-cloud.com', port=17786, password='qaA9XpXI5NdIuHWrcluse37dzG0Ose7F')

print('Waiting for connection...')
r.set('test_key', b'Connection successful')
print(r.get('test_key'))

mac = ["Apple", "Laptop", "M1-Pro", "MacBook"]  # for test purposes
product_keys = r.keys('product:*')  # Retrieve product keys from Redis

def recommend(tags):
    similar = []
    for product_key in product_keys:
        # Decode the product key from bytes to string
        product_key_str = product_key.decode('utf-8')
        
        # Get the tags for each product and decode them from bytes
        other_tags = json.loads(r.hget(product_key, b'tags').decode('utf-8'))
        
        # Check for intersection with the provided tags
        if any(item in other_tags for item in tags):
            similar.append(product_key_str)
    return similar

def output(outputs):
    all_products_data = []  # Change from dict to list
    for output in outputs:
        p_data = r.hgetall(output)
        product_info = {}
        for key, value in p_data.items():
            product_info[key.decode('utf-8')] = value.decode('utf-8')  # Decode keys and values
        all_products_data.append(product_info)  # Append product info to the list
    return all_products_data

macdac = recommend(mac)
recommended_products = output(macdac)  # Get the detailed information of recommended products

# Output the recommendations as a JSON object
print(json.dumps(recommended_products, indent=4))  # Pretty-print the JSON output
