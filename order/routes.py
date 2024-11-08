from flask import Blueprint, request, jsonify
import stripe
import redis
import json

order_bp = Blueprint('order', __name__)

# Initialize Redis client
redis_client = redis.Redis(host='localhost', port=6379, db=0)  # Adjust parameters as needed

@order_bp.route('/create-payment-intent', methods=['POST'])
def create_payment_intent():
    data = request.get_json()
    amount = data.get('amount')  # Amount in cents
    currency = data.get('currency', 'usd')  # Default to USD if no currency is provided

    try:
        # Set your Stripe secret key directly here
        stripe.api_key = 'sk_test_51QFk16CAPgGmoUBcCJ2LeEo867yBRthbwiyrFU6lToajyzR5YgD9yaJGjOm2k9YbxnXEKBLv66KO7aejDYQ6OjlG00O9WfdTne'  # Replace with your actual secret key

        payment_intent = stripe.PaymentIntent.create(
            amount=amount,
            currency=currency,
        )
        print(payment_intent)
        
        return jsonify({'clientSecret': payment_intent['client_secret']})
    except Exception as e:
        return jsonify(error=str(e)), 403


@order_bp.route('/create-order', methods=['POST'])
def create_order():
    order_data = request.get_json().get('order')

    # Create a unique order ID (you can adjust this based on your needs)
    order_id = f"order:{order_data['email']}_{order_data['number']}"

    # Store the order in Redis
    redis_client.set(order_id, json.dumps(order_data))

    # For demonstration, you can also print the stored order data
    print("Order created:", order_data)  

    return jsonify({'success': True, 'message': 'Order created successfully', 'order_id': order_id})
