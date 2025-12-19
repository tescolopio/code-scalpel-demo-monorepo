def validate(request):
    # Vulnerable: string formatting in SQL
    customer_id = request.get("customer_id")
    amount = request.get("amount", "")
    query = f"SELECT * FROM invoices WHERE customer_id = '{customer_id}' AND amount = {amount}"
    return query
