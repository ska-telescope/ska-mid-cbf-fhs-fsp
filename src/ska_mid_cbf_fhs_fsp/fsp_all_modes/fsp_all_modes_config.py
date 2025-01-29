schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "FSP All Modes Controller Configuration",
    "description": "Configuration object for the FSP All Modes Controller",
    "type": "object",
    "properties": {
        "config_id": {"type": "string"},
    },
    "required": [
        "config_id",
    ],
}

# fmt: off
example_config = {
    "config_id": "1",
}
