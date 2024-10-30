import redis as r
# from likes

r = r.Redis(
  host='redis-17786.c232.us-east-1-2.ec2.redns.redis-cloud.com',
  port=17786,
  password='qaA9XpXI5NdIuHWrcluse37dzG0Ose7F')

print('Waiting for connection...')
r.set('test_key', b'Connection successful')
print(r.get('test_key'))

mac = ["Apple", "Laptop", "M1-Pro", "MacBook"]  # for test purposes
product_ahh = r.keys('product:*')


def recommend(tags):
    similar = []
    for ahh in product_ahh:
        other_tags = r.hget(ahh, b'tags').decode('utf-8')
        if [item for item in tags if item in other_tags]:
            p_id = ahh.decode('utf-8')
            similar.append(p_id)
            #print(r.hgetall(ahh.decode('utf-8')))
    return similar


def output(outputs):
    all_products_data = {}
    for output in outputs:
        all_products_data[output] = {}
        p_data = r.hgetall(output)
        for key, value in p_data.items():
             all_products_data[output][key] = value.decode('utf-8')
    return all_products_data


macdac = recommend(mac)
#print(macdac)
print(output(macdac))
