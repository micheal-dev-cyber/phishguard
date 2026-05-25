def verify_paddle_order(order_id: str):
    """
    Placeholder Paddle order verification.
    Replace with real Paddle API call when you have a live account.
    """
    if not order_id or not order_id.startswith("ord_"):
        return False, "Invalid Order ID format. Must start with 'ord_'"
    
    # TODO: Replace with real Paddle API verification
    # For now, accept any properly formatted order ID
    return True, "Order verified."