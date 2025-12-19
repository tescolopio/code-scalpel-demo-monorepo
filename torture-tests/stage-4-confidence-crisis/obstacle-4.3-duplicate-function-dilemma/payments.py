def validate(request):
    # Intentional SQL injection fixture: directly interpolates unsanitized inputs
    customer_id = request.get("customer_id")
    amount = request.get("amount", "0")
    query = f"SELECT * FROM invoices WHERE customer_id = '{customer_id}' AND amount = '{amount}'"
    return query
