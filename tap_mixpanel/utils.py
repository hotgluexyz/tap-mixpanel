
EXPORT_HOSTS = {
    'default': 'https://data.mixpanel.com/api',
    'eu':      'https://data-eu.data.mixpanel.com/api',
    'in':      'https://data-in.data.mixpanel.com/api',
}
STANDARD_HOSTS = {
    'eu':      'https://eu.mixpanel.com/api',
    'default': 'https://mixpanel.com/api',
    'in':      'https://in.mixpanel.com/api',
}

def get_export_host(region):
    return EXPORT_HOSTS.get(region, EXPORT_HOSTS['default'])

def get_standard_host(region):
    return STANDARD_HOSTS.get(region, STANDARD_HOSTS['default'])
