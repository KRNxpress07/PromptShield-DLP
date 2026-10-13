"""Explicit model-facing schemas; no reflection or host capabilities."""
SPECS = {
    'list_directory': ('path',), 'read_file': ('path',),
    'write_file': ('path', 'content'), 'append_file': ('path', 'content'),
    'delete_file': ('path',), 'file_exists': ('path',),
    'get_file_metadata': ('path',), 'simulate_network_request': ('target',),
    'simulate_command_execution': ('command',),
}


def argument_limit(key, limits):
    return limits.max_path_length if key == 'path' else limits.max_write_size if key == 'content' else 1024


def tool_definitions(limits):
    return [{'type': 'function', 'function': {
        'name': name, 'description': 'Synthetic virtual sandbox operation only.',
        'parameters': {'type': 'object', 'properties': {
            key: {'type': 'string', 'maxLength': argument_limit(key, limits)} for key in keys
        }, 'required': list(keys), 'additionalProperties': False},
    }} for name, keys in SPECS.items()]


def valid_arguments(name, arguments, limits):
    valid = (type(name) is str and name in SPECS and type(arguments) is dict
            and set(arguments) == set(SPECS[name])
            and all(type(v) is str and len(v) <= argument_limit(k, limits)
                    for k, v in arguments.items()))
    if not valid:
        return False
    try:
        for value in arguments.values():
            value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True
