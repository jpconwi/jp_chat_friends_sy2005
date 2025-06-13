def format_messages(rows):
    return [
        {
            "sender": row[0],
            "content": row[1],
            "timestamp": row[2].isoformat()
        }
        for row in rows
    ]
