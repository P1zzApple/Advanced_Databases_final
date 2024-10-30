import redis as r
# from likes

r = r.Redis(
  host='redis-17786.c232.us-east-1-2.ec2.redns.redis-cloud.com',
  port=17786,
  password='qaA9XpXI5NdIuHWrcluse37dzG0Ose7F')
print('Waiting for connection...')
r.set('test_key', b'Connection successful')
print(r.get('test_key'))

mac = ["Apple", "Laptop", "M1-Pro", "MacBook"]
product_ahh = r.keys('product:*')
products = []
for ahh in product_ahh:
    product = r.hgetall(ahh)
    products.append(product)
print('all of all products:', products)



