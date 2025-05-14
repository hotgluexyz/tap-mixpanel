#!/usr/bin/env python3

import sys
import json
import argparse
from datetime import datetime, timedelta, date
import singer
from singer import metadata, utils
from singer.utils import strptime_to_utc, strftime
from tap_mixpanel.client import MixpanelClient
from tap_mixpanel.discover import discover
from tap_mixpanel.sync import sync
from tap_mixpanel.utils import get_standard_host
LOGGER = singer.get_logger()

REQUIRED_CONFIG_KEYS = [
    'project_timezone',
    'date_window_size',
    'attribution_window',
    'start_date',
    'user_agent'
]


def  do_discover(client, properties_flag, denest_properties, url):

    LOGGER.info('Starting discover')
    catalog = discover(client, properties_flag, denest_properties, url)
    json.dump(catalog.to_dict(), sys.stdout, indent=2)
    LOGGER.info('Finished discover')


@singer.utils.handle_top_exception(LOGGER)
def main():

    parsed_args = singer.utils.parse_args(REQUIRED_CONFIG_KEYS)

    start_date = parsed_args.config['start_date']
    start_dttm = strptime_to_utc(start_date)
    now_dttm = utils.now()
    delta_days = (now_dttm - start_dttm).days
    if delta_days >= 365:
        delta_days = 365
        start_date = strftime(now_dttm - timedelta(days=delta_days))
        LOGGER.warning("WARNING: start_date greater than 1 year maxiumum for API.")
        LOGGER.warning("WARNING: Setting start_date to 1 year ago, {}".format(start_date))

    #Initialize necessary keys into the dictionary.
    params = parsed_args.config

    username                = params.get("username")
    password                = params.get("password")
    service_account_name    = params.get("service_account_name")
    service_account_secret  = params.get("service_account_secret")
    api_secret              = params.get("api_secret")
    project_id              = params.get("project_id")

    has_basic     = bool(username and password)
    has_service   = bool(service_account_name and service_account_secret)
    has_token     = bool(api_secret)

    # Ensure exactly one auth method is specified
    mode_count = sum([has_basic, has_service, has_token])
    if mode_count == 0:
        raise Exception("No credentials provided; supply either username/password, service account, or api_secret.")

    # Enforce project_id where required
    if (has_basic or has_service) and not project_id:
        kind = "Username/Password" if has_basic else "Service Account"
        raise Exception(f"project_id is required for {kind} authentication.")

          
    with MixpanelClient(parsed_args.config.get('api_secret', None),
                        parsed_args.config.get('username', None),
                        parsed_args.config.get('password', None),
                        parsed_args.config.get('project_id', None),
                        parsed_args.config.get('user_agent', None),
                        parsed_args.config.get('service_account_name', None),
                        parsed_args.config.get('service_account_secret', None),
                        parsed_args.config.get('data_region', None)) as client:

        state = {}
        if parsed_args.state:
            state = parsed_args.state

        config = parsed_args.config
        properties_flag = config.get('select_properties_by_default')
        denest_properties_flag = config.get('denest_properties', 'true')
        data_region = config.get('data_region', None)
        url = get_standard_host(data_region)
        

        if parsed_args.discover:
            do_discover(client, properties_flag, denest_properties_flag, url)
        elif parsed_args.catalog:
            sync(client=client,
                 config=config,
                 catalog=parsed_args.catalog,
                 state=state,
                 start_date=start_date)

if __name__ == '__main__':
    main()
