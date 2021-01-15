import os
import json

import sqlite3

import uuid
import time
from time import sleep
from datetime import datetime, timedelta

import requests


class CarbonBlackCloud:
    '''
        This is a wrapper around CBC's APIs.
        Import this class to interact with the various CBC endpoints.
    '''

    def __init__(self, config, log):
        '''
            Initialize the CarbonBlackCloud class. Assign self variables for use
                throughout the script.

            Inputs:
                config loaded with the settings from the config.ini

            Outputs:
                self
        '''
        try:
            self.class_name = 'CarbonBlackCloud'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)

            self.config = config
            self.url = clean_url(config['CarbonBlack']['url'])
            self.org_key = config['CarbonBlack']['org_key']
            self.api_id = config['CarbonBlack']['api_id']
            self.api_key = config['CarbonBlack']['api_key']
            self.cust_api_id = config['CarbonBlack']['custom_api_id']
            self.cust_api_key = config['CarbonBlack']['custom_api_key']
            self.lr_api_id = config['CarbonBlack']['lr_api_id']
            self.lr_api_key = config['CarbonBlack']['lr_api_key']
            self.headers = {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'User-Agent': config['user_agent']
            }
            self.feed = None
            self.iocs = None
            self.new_reports = []
            self.device_id = None
            self.session_id = None
            self.supported_commands = None

        except Exception as err:
            self.log.exception(err)

    #
    # CBC Platform
    #
    def get_alerts(self, start_time=None, end_time=None, limit=None):
        '''
            !!! Description here....
            [] add pagination to get full results
        '''
        # Define the request basics
        url = '/'.join([self.url, 'appservices/v6/orgs', self.org_key, 'alerts/_search'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = {
            'criteria': {
                'category': ['THREAT'],
                'reputation': ['KNOWN_MALWARE', 'PUP', 'SUSPECT_MALWARE'],
                'create_time': {
                    'start': start_time,
                    'end': end_time
                },
                'group_results': False,
                'minimum_severity': 3
            },
            'sort': [{'field': 'create_time', 'order': 'DESC'}],
            'rows': 100,
            'start': 0
        }

        # Request the data from the endpoint
        r = requests.post(url, headers=headers, data=json.dumps(body))

        # If the request was successful
        if r.status_code == 200:
            data = r.json()
            self.log.info('[%s] Found {0} alerts'.format(len(data['results'])), self.class_name)
            return data

        else:
            self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
            raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    def get_processes(self, body=None):
        '''
            The Get Processes API is asyncronous. We first make the request for the search,
                then use the `job_id` to get the results. Pagination may occur.
        '''
        # Define the request basics
        url = '/'.join([self.url, 'api/investigate/v2/orgs', self.org_key, 'processes/search_jobs'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

        # print('### {0}'.format(json.dumps(body, indent=4)))

        # Request the data from the endpoint
        r = requests.post(url, headers=headers, data=json.dumps(body))

        # If the request was successful
        if r.status_code == 200:
            # Get the job_id
            job_id = r.json()['job_id']

            # Prep recursion
            start = 0
            rows = 500
            page = 0
            total = rows
            processes = None

            while start < total:
                process_results = self.get_process_results(job_id, start, rows)

                # Make sure the search has completed before moving on
                tries = 0
                while process_results['contacted'] != process_results['completed']:
                    if tries > 5:
                        self.log.error('[%s] !!! Tried {0} times to get {1}. Giving up.'.format(tries, job_id), self.class_name)
                        raise RuntimeError('[%s] !!! Tried {0} times to get {1}. Giving up.'.format(tries, job_id), self.class_name)

                    tries += 1

                    # Slowly increase the wait time
                    sleep(tries)

                    process_results = self.get_process_results(job_id, start, rows)

                if processes is None:
                    processes = process_results
                else:
                    processes['results'] += process_results['results']

                total = process_results['num_available']
                start = start + rows
                page += 1

            processes['pages'] = page

            return processes

        else:
            self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
            raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    def get_process_results(self, job_id, start, rows):
        '''
        '''
        self.log.info('[%s] Getting process results for job {0} starting from {1} with {2} rows.'.format(job_id, start, rows), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'api/investigate/v2/orgs', self.org_key, 'processes/search_jobs', job_id, 'results'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        params = {
            'start': start,
            'rows': rows
        }

        r = requests.get(url, headers=headers, params=params)

        if r.status_code == 200:
            data = r.json()

            return data

        self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
        raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    def get_device(self, device_id):
        '''
            !!! comment here
        '''
        self.log.info('[%s] Getting device information: {0}.'.format(device_id), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'appservices/v6/orgs', self.org_key, 'devices/_search'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = {
            'criteria': {
                'id': ['{0}'.format(device_id)]
            }
        }

        # Request the data from the endpoint
        r = requests.post(url, headers=headers, data=json.dumps(body))

        # If the request was successful
        if r.status_code == 200:
            self.log.info('[%s] Pulled device information: {0}.'.format(device_id), self.class_name)
            data = r.json()
            return data
        
        self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
        raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    def isolate_device(self, device_id):
        '''
            Isolate a device.

            Inputs
                device_id (int):    The ID of the device

            Raises
                TypeError when device_id is not an integer

            Output
                An object of the device
        '''

        if isinstance(device_id, int) is False:
            raise TypeError('Expected device_id input type is int.')

        try:
            url = '/'.join([self.url, 'appservices/v6/orgs', self.org_key, 'device_actions'])
            headers = self.headers
            headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
            body = {
                'action_type': 'QUARANTINE',
                'device_id': [device_id],
                'options': {
                    'toggle': 'ON'
                }
            }

            # Request the data from the endpoint
            r = requests.post(url, headers=headers, data=json.dumps(body))

            # If the request was successful
            if r.status_code == 200:
                return True

            else:
                self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
                raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def update_policy(self, device_id, policy_name):
        '''
            Updates a device's policy to the given policy_name.

            Inputs
                device_id (int):    The ID of the device
                policy_name (str):  The name of the policy

            Raises
                TypeError when device_id is not an integer
                TypeError when policy_name is not a string

            Output
                An object of the device
        '''

        self.log.info('[%s] update_policy()', self.class_name)

        if isinstance(device_id, int) is False:
            raise TypeError('Expected device_id input type is integer.')
        if isinstance(policy_name, str) is False:
            raise TypeError('Expected policy_name input type is string.')

        try:
            policy_id = self.get_policy_id(policy_name)

            if policy_id is not None:
                url = '/'.join([self.url, 'appservices/v6/orgs', self.org_key, 'device_actions'])
                headers = self.headers
                headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
                body = {
                    'action_type': 'UPDATE_POLICY',
                    'device_id': [device_id],
                    'options': {
                        'policy_id': policy_id
                    }
                }
                r = requests.post(url, headers=headers, data=json.dumps(body))
                if r.status_code == 204:
                    self.log.info('[%s] Moved device with id {0} to policy "{1}".'.format(device_id, policy_name), self.class_name)
                    return True

                else:
                    self.log.exception('[%s] update_policy(): Error: {0}'.format(r.status_code), self.class_name)

            self.log.info('[%s] No Policy with name "{0}" found.'.format(policy_name), self.class_name)
            return None

        except Exception as err:
            self.log.exception('[%s] update_policy(): %s', self.class_name, err)

    def get_policy_id(self, policy_name):
        self.log.info('[%s] Looking for policy with name "{0}".'.format(policy_name), self.class_name)

        url = '/'.join([self.url, 'integrationServices/v3/policy'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.api_key, self.api_id)

        r = requests.get(url, headers=headers)

        if r.status_code == 200:
            data = r.json()
            policies = data['results']

            for policy in policies:
                if policy['name'] == policy_name:
                    self.log.info('[%s] Found policy "{0}" with id "{1}".'.format(policy_name, policy['id']), self.class_name)

                    return int(policy['id'])

            self.log.info('[%s] No Policy with name "{0}" found.'.format(policy_name), self.class_name)
            return None

    def get_process_limits(self):
        '''
            !!! Description here....
        '''
        # Define the request basics
        url = '/'.join([self.url, 'api/investigate/v1/orgs', self.org_key, 'processes/limits'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

        # Request the data from the endpoint
        r = requests.get(url, headers=headers)

        # If the request was successful
        if r.status_code == 200:
            data = r.json()
            lower = convert_time(data['time_bounds']['lower'])
            upper = convert_time(data['time_bounds']['upper'])
            self.log.info('[%s] Process limits: Start {0} End {1}'.format(lower, upper), self.class_name)
            return data

        else:
            self.log.error('[%s] Error {0}: {1}'.format(r.status_code, r.text), self.class_name)
            raise Exception('Error {0}: {1}'.format(r.status_code, r.text))

    #
    # CBC Enterprise EDR
    #
    def get_all_feeds(self):
        '''
            Pull all feeds from Enterprise EDR.

            Inputs: None

            Output
                An object of the feeds
        '''

        self.log.info('[%s] Getting all feeds', self.class_name)

        url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

        try:
            r = requests.get(url, headers=headers)
            feeds = r.json()
            self.log.info('[%s] Pulled {0} feeds'.format(len(feeds['results'])), self.class_name)
            return feeds['results']

        except Exception as err:
            self.log.exception(err)

    def get_feed(self, feed_id=None, feed_name=None, use_cache=True):
        '''
            Gets the details for a single feed. If feed_name is provided, it will
                pull all feeds and filter by name. If feed_id is provided, it
                pulls based on that id.

            Inputs
                feed_id (str):      ID of the feed to pull
                feed_name (str):    Name of the feed to pull

            Raises
                TypeError when feed_id is not an integer
                TypeError when feed_name is not a string

            Outputs
                Object  an object of found feed
                None    no feed was found
                False   both feed_id and feed_name provided
                False   neither feed_id nor feed_name provided
        '''

        self.log.info('[%s] Getting feed', self.class_name)

        if isinstance(feed_id, str) is False and feed_id is not None:
            raise TypeError('Expected feed_id input type is string.')
        if isinstance(feed_name, str) is False and feed_name is not None:
            raise TypeError('Expected feed_name input type is string.')

        if feed_id is None and feed_name is None:
            self.log.info('[%s] Missing feed_id and feed_name. Need at least one', self.class_name)
            raise Exception('Missing feed_id and feed_name. Need at least one')

        if feed_id is not None and feed_name is not None:
            self.log.info('[%s] Both feed_id and feed_name provided. Please only provide one', self.class_name)
            raise Exception('Both feed_id and feed_name provided. Please only provide one')

        if self.feed is not None and use_cache is True:
            return self.feed

        try:
            # If the feed_name was provided, get all the feeds and check their names
            if feed_name is not None:
                feeds = self.get_all_feeds()
                for feed in feeds:
                    if feed['name'] == feed_name:
                        feed_id = feed['id']
                        break

            # If no feeds were found, return None
            if feed_id is None:
                self.log.info('[%s] No feed found with name "{0}"'.format(feed_name), self.class_name)
                return None

            try:
                url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds', feed_id])
                headers = self.headers
                headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

                r = requests.get(url, headers=headers)
                feed = r.json()

                # Save to cache
                self.feed = feed

                # Build a cache of the existing IOCs in the feed
                # This is used for deduplication when IOCs are added
                if self.iocs is None:
                    self.iocs = []

                for report in feed['reports']:
                    for ioc in report['iocs_v2']:
                        for value in ioc['values']:
                            self.iocs.append(value)

                self.log.info('[%s] Pulled feed "{}"'.format(feed['feedinfo']['name']), self.class_name)
                return feed

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def create_feed(self, name, url, summary):
        '''
            Creates a new feed in CBC Enterprise EDR

            Inputs
                name (str):     Name of the feed to create
                url (str):      URL of the feed
                summary (str):  Summary of the feed

            Raises
                TypeError when name is not a string
                TypeError when url is not a string
                TypeError when summary is not a string

            Output
                An object of the newly created feed
        '''
        self.log.info('[%s] Creating feed "{}"'.format(name), self.class_name)

        if isinstance(name, str) is False:
            raise TypeError('Expected name input type is string.')
        if isinstance(url, str) is False:
            raise TypeError('Expected url input type is string.')
        if isinstance(summary, str) is False:
            raise TypeError('Expected summary input type is string.')

        try:
            feed_info = {
                'name': name,
                'owner': self.org_key,
                'provider_url': url,
                'summary': summary,
                'category': 'Partner',
                'access': 'private',
            }

            feed = {
                'feedinfo': feed_info,
                'reports': []
            }

            url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds'])
            headers = self.headers
            headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)

            r = requests.post(url, headers=headers, json=feed)

            if r.status_code == 200:
                new_feed = r.json()
                feed['feedinfo']['id'] = new_feed['id']


                self.log.info('[%s] Created feed "{0}" with 0 indicators'.format(name), self.class_name)
            else:
                self.log.error('[%s] Error creating feed: {0} {1}'.format(r.status_code, r.text), self.class_name)

            return feed

        except Exception as err:
            self.log.exception(err)

    def update_feed(self, feed_name):
        # If watchlists are enabled in take_action() and there were bad emails, update the watchlist
        if self.new_reports is None or len(self.new_reports) == 0:
            return None

        # Get the feed so we can get the id
        feed = self.get_feed(feed_name=feed_name)
        for report in self.new_reports:
            feed['reports'].append(report)
        feed_id = feed['feedinfo']['id']

        url = '/'.join([self.url, 'threathunter/feedmgr/v2/orgs', self.org_key, 'feeds', feed_id, 'reports'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = { "reports": feed['reports'] }

        r = requests.post(url, headers=headers, json=body)
        data = r.json()

        return data

    def create_report(self, timestamp, title, description, severity, link, tags, sha256):
        '''
            Creates a report for Enterprise EDR feeds

            Inputs
                timestamp (int):    Epoch timestamp to be added to the report
                title (str):        Title of the report
                description (str):  Description of the report
                severity (int):     Severity of the report [1-10]
                link (str):         Link to report
                tags (list of str): List of tags
                md5 (str):          Hash IOC to be added to the report

            Raises
                TypeError if timestamp is not an integer
                TypeError if title is not a string
                TypeError if description is not a string
                TypeError if severity is not a string
                TypeError if link is not a string
                TypeError if tags is not a list
                TypeError if md5 is not a string
                ValueError if md5 is not 32 characters long

            Output
                An object of the newly created report
        '''

        if isinstance(timestamp, int) is False:
            raise TypeError('Expected timestamp input type is integer.')
        if isinstance(title, str) is False:
            raise TypeError('Expected title input type is string.')
        if isinstance(description, str) is False:
            raise TypeError('Expected description input type is string.')
        if isinstance(severity, int) is False:
            raise TypeError('Expected severity input type is integer.')
        if isinstance(link, str) is False:
            raise TypeError('Expected link input type is string.')
        if isinstance(tags, list) is False:
            raise TypeError('Expected tags input type is a list of strings.')
        if isinstance(sha256, str) is False:
            raise TypeError('Expected sha256 input type is string.')
        if len(sha256) != 64:
            raise ValueError('Expected sha256 to be 64 characters long')

        self.log.info('[%s] Creating new report', self.class_name)

        if self.iocs is None:
            self.iocs = []

        try:
            report = {
                'id': str(uuid.uuid4()),
                'timestamp': timestamp,
                'title': title,
                'description': description,
                'severity': severity,
                'link': link,
                'tags': tags,
                'iocs_v2': [{
                    'id': sha256,
                    'match_type': 'equality',
                    'values': [sha256],
                    'field': 'process_hash'
                }]
            }

            # Keep track of reports for batch submission
            self.new_reports.append(report)
            # Keep track of IOCs for deduplication
            self.iocs.append(sha256)

            self.log.info('[%s] Created report: {}'.format(report), self.class_name)

            return report

        except Exception as err:
            self.log.exception(err)

    def get_binary(self, sha256, expiration=300):
        '''
            Get file from CBC
        '''
        self.log.info('[%s] Getting binary URL for {0}'.format(sha256), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'ubs/v1/orgs', self.org_key, 'file/_download'])
        headers = self.headers
        headers['X-Auth-Token'] = '{0}/{1}'.format(self.cust_api_key, self.cust_api_id)
        body = {
            'sha256': [sha256],
            'expiration_seconds': expiration
        }

        # Request the data from the endpoint
        r = requests.post(url, headers=headers, data=json.dumps(body))

        # If the request was successful
        if r.status_code == 200:
            data = r.json()
            self.log.info('[%s] Found binary URL for {0}'.format(sha256), self.class_name)
            return data
        
        if r.status_code == 404:
            self.log.error('[%s] Unable to find binary for {0}'.format(sha256), self.class_name)
        else:
            self.log.error('[%s] Error: {0} {1}'.format(r.status_code, r.text), self.class_name)
        
        return None
    
    #
    # CBC Live Response helpers
    #
    def start_session(self, device_id, wait=False):
        '''
            Starts a CBC LiveResponse session. The session_id is saved in
                self.session_id

            Inputs
                device_id (int):    ID of the device to start the session on
                wait (bool):        Overrides default wait action. Checks get_session() every 15 seconds if True

            Raises
                TypeError when device_id is not an integer
                TypeError when wait is not a boolean
                Exception when response status_code is anything other than 200

            Output
                data (dict):    Raw JSON of get_session() response if wait is True
                data (dict):    Raw JSON of request to start session if wait is False
        '''

        if isinstance(device_id, int) is False:
            raise TypeError('Expected device_id input type is integer.')
        if isinstance(wait, bool) is False:
            raise TypeError('Expected wait input type is boolean.')

        try:
            self.log.info('[%s] Starting LR session', self.class_name)
            url = '{0}/integrationServices/v3/cblr/session/{1}'.format(self.url, device_id)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }
            r = requests.post(url, headers=headers)

            if r.status_code == 200:
                data = r.json()

                self.device_id = device_id
                self.session_id = data['id']
                self.supported_commands = data['supported_commands']

                self.log.info(json.dumps(data, indent=4))

                if wait:
                    while data['status'] == 'PENDING':
                        sleep(15)
                        data = self.get_session()

                return data

            else:
                raise Exception('{0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def get_session(self):
        '''
            Get the status of a session

            Inputs: None

            Raises
                Exception if no session is established
                Exception if response status_code is not 200

            Output
                data (dict):    Returns the raw JSON of the request
        '''

        try:
            if self.session_id is None:
                self.log.info('[%s] Cannot get session status. No session established for session ID {0}'.format(self.session_id),
                              self.class_name)
                raise Exception('No session established')

            self.log.info('[%s] Getting status of session: {0}'.format(self.session_id), self.class_name)

            url = '{0}/integrationServices/v3/cblr/session/{1}'.format(self.url, self.session_id)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }
            r = requests.get(url, headers=headers)

            if r.status_code == 200:
                data = r.json()
                self.log.info(json.dumps(data, indent=4))
                self.supported_commands = data['supported_commands']

                return data

            else:
                raise Exception('{0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def send_command(self, command, argument=None, wait=False):
        '''
            Sends a LiveResponse command to an endpoint

            Inputs
                command (str):      Command to execute
                arguments (str):    Supporting arguments for the command
                wait (bool):        If True, wait until command is finished and return result
                                    If False, send response from request

            Raises
                TypeError if command is not a string
                TypeError if argument is not a string or None

            Outputs
                data (dict): Raw JSON from command_status(data[id]) if wait is True
                data (dict): Raw JSON from response to request if wait is False
        '''

        if isinstance(command, str) is False:
            raise TypeError('Expected command input type is string.')
        if argument is not None and isinstance(argument, str) is False:
            raise TypeError('Expected argument input type is string or None.')

        self.log.info('[%s] Sending command to LR session: {0}'.format(command), self.class_name)

        try:
            if self.session_id is None:
                self.log.error('Error: no session')
                return 'Error: no session'

            if command not in self.supported_commands:
                self.log.error('Error: command not in available commands: {0}'.format(command))
                return 'Error: command not in available commands: {0}'.format(command)

            try:
                url = '{0}/integrationServices/v3/cblr/session/{1}/command'.format(self.url, self.session_id)
                headers = {
                    'Content-Type': 'application/json',
                    'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
                }

                body = {
                    'session_id': self.session_id,
                    'name': command
                }
                if argument is not None:
                    body['object'] = argument

                r = requests.post(url, headers=headers, json=body)

                data = r.json()

                self.log.info(json.dumps(data, indent=4))

                if wait:
                    sleep(1)
                    while data['status'] == 'pending':
                        sleep(5)
                        data = self.command_status(data['id'])

                return data

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def command_status(self, command_id):
        '''
            Get the status of a previously submitted command

            Inputs
                command_id (int):   ID of the command previously submitted

            Raises
                TypeError if command_id is not an integer
                Exception if no session is established

            Output:
                Raw JSON of the response
        '''

        if isinstance(command_id, int) is False:
            raise TypeError('Expected command_id input type is integer.')

        self.log.info('[%s] Getting status of LR command: {0}'.format(command_id), self.class_name)

        try:
            if self.session_id is None:
                self.log.info('[%s] Cannot get session status. No session established for session with ID {0}'.format(self.session_id),
                              self.class_name)
                raise Exception('No session established')

            self.log.info('[%s] Getting status of command: {0}'.format(command_id), self.class_name)

            url = '{0}/integrationServices/v3/cblr/session/{1}/command/{2}'.format(self.url, self.session_id,
                                                                                   command_id)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }
            r = requests.get(url, headers=headers)

            if r.status_code == 200:
                data = r.json()

                self.log.info(json.dumps(data, indent=4))
                return data

            else:
                raise Exception('{0}: {1}'.format(r.status_code, r.text))

        except Exception as err:
            self.log.exception(err)

    def close_session(self):
        '''
            Closes a LiveResponse session.

            Inputs: None

            Outputs
                Raw JSON response from the request

            > Note: When closing a LR session on an endpoint, if there are any
                other active sessions on that endpoint they will be closed as well.
        '''

        self.log.info('[%s] Closing session: {0}'.format(self.session_id), self.class_name)

        try:
            if self.session_id is None:
                self.log.info('Error: no session')
                return 'Error: no session'

            url = '{0}/integrationServices/v3/cblr/session'.format(self.url)
            headers = {
                'Content-Type': 'application/json',
                'X-Auth-Token': '{0}/{1}'.format(self.lr_api_key, self.lr_api_id)
            }

            body = {
                'session_id': self.session_id,
                'status': 'CLOSE'
            }

            r = requests.put(url, headers=headers, json=body)

            data = r.json()

            self.log.info(json.dumps(data, indent=4))
            return data

        except Exception as err:
            self.log.exception(err)


class Lastline:
    def __init__(self, config, log):
        '''
            Initialize the Lastline class

            Inputs
                config: Dict containing settings from config.ini

            Output
                self
        '''
        try:
            self.class_name = 'Lastline'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)
            self.config = config

            self.url = clean_url(config['Lastline']['url'])
            self.api_key = config['Lastline']['api_key']
            self.api_token = config['Lastline']['api_token']
            self.headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cache-Control': 'no-cache',
                'User-Agent': config['user_agent']
            }
            self.auth = {
                'key': self.api_key,
                'api_token': self.api_token
            }

            self.submits = 0

        except Exception as err:
            self.log.exception(err)

    def authenticate(self):
        # Define the request basics
        url = '/'.join([self.url, 'authentication/login'])
        params = {
            'key': self.api_key,
            'api_token': self.api_token
        }

        # Request the data from the endpoint
        r = requests.post(url, headers=self.headers, params=params)

        # If the request was successful
        if r.status_code == 200:
            return r.json()
        
        else:
            self.log.exception('[%s] Error: {0} {1}'.format(r.status_code, r.text))

    def query_hash(self, md5=None, sha256=None):
        '''
            !!! Coming soon...
            [] check to see if 
        '''

        if md5 is None and sha256 is None:
            self.log.error('[%s] query_hash() requires a MD5 or SHA256. None provided.')
        
        if md5 is not None and sha256 is not None:
            self.log.error('[%s] query_hash() requires either MD5 or SHA256. Both provided.')

        if md5 is not None:
            hash_algorithm = 'md5'
            hash_value = md5
        else:
            hash_algorithm = 'sha256'
            hash_value = sha256

        self.log.info('[%s] Querying for {0} of {1}'.format(hash_algorithm, hash_value), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'analysis/query/file_hash'])
        params = {
            'hash_algorithm': hash_algorithm,
            'hash_value': hash_value
        }
        params.update(self.auth)

        # Request the data from the endpoint
        r = requests.post(url, headers=self.headers, params=params)

        # If the request was successful
        if r.status_code == 200:
            data = r.json()['data']

            self.log.info('[%s] Found {0} results for {1}'.format(data['files_found'], hash_value), self.class_name)

            return data
        
        else:
            self.log.exception('[%s] Error: {0} {1}'.format(r.status_code, r.text))

    def get_result(self, uuid):
        '''
            !!! Coming soon...
            [] check to see if 
        '''

        # !!! check to make sure uuid is a string

        self.log.info('[%s] Getting report for task_uuid {0}'.format(uuid), self.class_name)

        # Define the request basics
        url = '/'.join([self.url, 'analysis/get_result'])
        params = {
            'uuid': uuid
        }
        params.update(self.auth)

        # Request the data from the endpoint
        r = requests.post(url, headers=self.headers, params=params)

        # If the request was successful
        if r.status_code == 200:
            data = r.json()['data']
            self.log.info('[%s] Found report for task_uuid {0}'.format(uuid), self.class_name)
            return data
        
        else:
            self.log.exception('[%s] Error: {0} {1}'.format(r.status_code, r.text))

    def submit_url(self, cb_url):
        # Define the request basics
        url = '/'.join([self.url, 'analysis/submit/url'])
        params = { 'url': cb_url }
        params.update(self.auth)

        self.log.info('[%s] Submitting URL for analysis', self.class_name)

        # Request the data from the endpoint
        r = requests.post(url, headers=self.headers, params=params)

        # If the request was successful
        if r.status_code == 200:
            data = r.json()['data']
            self.log.info('[%s] Submitted URL for analysis. Got task_uuid {0}'.format(data['task_uuid']), self.class_name)
            self.submits += 1
            return data
        
        else:
            self.log.exception('[%s] Error: {0} {1}'.format(r.status_code, r.text))

    def get_completed(self, start_time=None, end_time=None):
        '''
            start_time: Request tasks completed after this time. (required)
            end_time: Request tasks completed before this time. (optional, default=<current timestamp>)
        '''
        # Define the request basics
        url = '/'.join([self.url, 'analysis/get_completed'])
        label = []

        params = {}
        if start_time is not None:
            params['after'] = start_time
            label.append('after {0}'.format(start_time))
        if end_time is not None:
            params['before'] = end_time
            label.append('before {0}'.format(end_time))
        params.update(self.auth)

        label = ' and '.join(label)

        self.log.info('[%s] Searching for completed tasks {0}'.format(label), self.class_name)

        # Request the data from the endpoint
        r = requests.post(url, headers=self.headers, params=params)

        # If the request was successful
        if r.status_code == 200:
            data = r.json()['data']
            self.log.info('[%s] Found: {0} completed tasks {1}'.format(len(data['tasks']), label), self.class_name)
            return data
        
        else:
            self.log.exception('[%s] Error: {0} {1}'.format(r.status_code, r.text))


class Database:
    '''
        A helper class for working with the database actions requires for this integration.
    '''

    def __init__(self, config, log):
        '''
            Initialise the database object. Create database and tables if they
                don't exist.

            Inputs
                config (str):   Dict containing settings from config.ini

            Output:
                self
        '''

        try:
            self.class_name = 'Database'
            self.log = log
            self.log.info('[%s] Initializing', self.class_name)

            self.config = config
            self.conn = None

            db_path = os.path.join(config['app']['path'], config['sqlite3']['filename'])
            self.connect(db_path)

            sql = [
                '''CREATE TABLE IF NOT EXISTS processes (
                    id integer PRIMARY KEY,
                    timestamp text,
                    sha256 text,
                    process_guid text,
                    status text
                );''',

                '''CREATE TABLE IF NOT EXISTS reports (
                    id integer PRIMARY KEY,
                    timestamp text,
                    sha256 text,
                    status text,
                    task_uuid text,
                    reports text
                );''',

                '''CREATE TABLE IF NOT EXISTS last_pull (
                    id integer PRIMARY KEY,
                    timestamp text
                );''',

                '''SELECT * FROM last_pull'''
            ]

            try:
                cursor = self.conn.cursor()
                cursor.execute(sql[0])
                cursor.execute(sql[1])
                cursor.execute(sql[2])
                cursor.execute(sql[3])
                rows = cursor.fetchall()

                if len(rows) == 0:
                    last_pull = convert_time('now')
                    sql = '''INSERT INTO last_pull(timestamp) VALUES(?)'''
                    cursor.execute(sql, (last_pull,))
                    self.conn.commit()
                    self.log.info('[%s] Created tables and added current timestamp as last pull time', self.class_name)

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def connect(self, db_file):
        '''
            Connects to the sqlite3 database
            Inputs
                db_file (str):  The name of the database file (str)
            Raises
                TypeError if db_file is not a string
            Output
                conn (obj): Returns an object of the connection
        '''

        if isinstance(db_file, str) is False:
            raise TypeError('Expected type of db_file is string.')

        self.log.info('[%s] Connecting to database: {0}'.format(db_file), self.class_name)

        try:
            if self.conn is not None:
                self.log.info('[%s] Connection is already established', self.class_name)
                return self.conn

            try:
                self.conn = sqlite3.connect(os.path.join(os.getcwd(), db_file))
                self.log.info('[%s] Connected to {0} using sqlite {1}'.format(db_file, sqlite3.version),
                              self.class_name)
                return self.conn

            except Exception as err:
                self.log.exception(err)

        except Exception as err:
            self.log.exception(err)

    def close(self):
        '''
            Closes the database connection
            Inputs: None
            Output
                Object of the closed connection
        '''

        self.log.info('[%s] Closing connection', self.class_name)

        try:
            if self.conn:
                self.conn.close()
                self.conn = None

            self.log.info('[%s] Connection closed', self.class_name)

        except Exception as err:
            self.log.exception(err)

    def last_pull(self, timestamp=None):
        '''
            Get or set the last pull time in the database
            Inputs:
                timestamp:
                    If None, get the last pull time from the database
                    Otherwise set the last pull time with either the epoch (int)
                        or ISO8601 format (str)
            Output:
                Returns the last pull timestamp from the database if timestamp is None
                Returns the database response if timestamp == epoch or ISO8601
        '''
        if self.conn is None:
            raise Exception('No connection to database')

        try:
            if timestamp is not None and isinstance(timestamp, (str, int)) is False:
                raise Exception('Timestamp must be a string, integer, or None')

            # Get or set last pull timestamp
            if timestamp is None:
                self.log.info('[%s] Getting last pull', self.class_name)
                sql = 'SELECT timestamp FROM last_pull WHERE id = 1'
                cursor = self.conn.cursor()
                cursor.execute(sql)
                rows = cursor.fetchall()

                if len(rows) == 0:
                    data = None
                else:
                    data = rows[0][0]
                return data

            else:
                if isinstance(timestamp, int):
                    timestamp = convert_time(timestamp)

                self.log.info('[%s] Updating last pull to {0}'.format(timestamp), self.class_name)

                timestamp = (timestamp,)
                sql = 'UPDATE last_pull SET timestamp = ? WHERE id = 1'
                cursor = self.conn.cursor()
                cursor.execute(sql, timestamp)
                self.conn.commit()

                self.log.info('[%s] Updated last pull to {0}'.format(timestamp), self.class_name)
                return True

        except Exception as err:
            self.log.exception(err)
            self.log.warning('[%s] No results found in database. Returning None.', self.class_name)
            return None

    def get_record(self, table, **data):
        '''
            Looks for any rows in the database with the provided info
            
            Inputs
                table (str): the table name that will be queried
                data (kwarg)
                    if the table is 'processes':
                        data['process_guid'] (str) [REQUIRED]
                    if the table is 'reports':
                        data['sha256'] (str)
                        data['task_uuid'] (str)
            
            Raises
                Exception if no connection to the database is established

                if the table is 'processes':
                    ValueError if process_guid is not provided
                    TypeError if process_guid is not a string
                if the table is 'reports':
                    ValueError if sha256 is missing
                    TypeError if sha256 is not a string
                    ValueError if sha256 is not 64 characters
            
            Output
                Returns any rows found matching the provided info. If no results
                    were found, returns None
        '''

        if self.conn is None:
            raise Exception('No connection to database')

        sql_filter_keys = []
        sql_filter_values = []

        if table == 'processes':
            if 'process_guid' not in data:
                raise ValueError('[%s] Missing required filed of process_guid', self.class_name)
            if isinstance(data['process_guid'], str) is False:
                raise TypeError('[%s] Expected process_guid input type is string.', self.class_name)

            sql_filter_keys.append('process_guid = ?')
            sql_filter_values.append(data['process_guid'])

        if table == 'reports':
            if 'sha256' in data:
                if isinstance(data['sha256'], str) is False:
                    raise TypeError('[%s] Expected sha256 input type is string.', self.class_name)
                if len(data['sha256']) != 64:
                    raise ValueError('[%s] The sha256 provided is not 64 characters long: {0}.'.format(data['sha256']), self.class_name)
                
                sql_filter_keys.append('sha256 = ?')
                sql_filter_values.append(data['sha256'])
            if 'task_uuid' in data:
                if isinstance(data['task_uuid'], str) is False:
                    raise TypeError('[%s] Expected task_uuid input type is string.', self.class_name)

                sql_filter_keys.append('task_uuid = ?')
                sql_filter_values.append(data['task_uuid'])

        if len(sql_filter_keys) == 0:
            self.log.error('[%s] No filter criteria provided', self.class_name)
            raise Exception('[%s] No filter criteria provided', self.class_name)

        sql_filter_values = tuple(sql_filter_values)
        sql_filter_keys = ' AND '.join(sql_filter_keys)

        try:
            sql = 'SELECT * FROM {0} WHERE {1};'.format(table, sql_filter_keys)
            self.log.info('[%s] Getting record(s) with filter(s): {0} {1}'.format(sql, sql_filter_values), self.class_name)

            cursor = self.conn.cursor()
            cursor.execute(sql, sql_filter_values)
            rows = cursor.fetchall()
            if len(rows) > 0:
                self.log.info('[%s] Found {0} results'.format(len(rows)), self.class_name)
                return rows

            self.log.info('[%s] Unable to find any results', self.class_name)
            return None

        except Exception as err:
            self.log.exception(err)

    def add_record(self, table, **data):
        '''
            Adds a file to the database

            Inputs
                sha256 (str):

            Raises
                Exception if no database connection exists
                TypeError if sha256 is not a string
                ValueError if sha256 is not 64 characters long

            Output
                row_id (int):   Returns the row ID of the new entry
        '''

        if self.conn is None:
            raise Exception('No connection to database')

        timestamp = convert_time('now')

        if table == 'processes':
            if 'sha256' not in data:
                raise ValueError('[%s] Missing required filed of sha256', self.class_name)
            if isinstance(data['sha256'], str) is False:
                raise TypeError('[%s] Expected sha256 input type is string.', self.class_name)
            if len(data['sha256']) != 64:
                raise ValueError('[%s] The sha256 provided is not 64 characters long: {0}.'.format(data['sha256']), self.class_name)
            if 'process_guid' not in data:
                raise ValueError('[%s] Missing required process_guid', self.class_name)
            if isinstance(data['process_guid'], str) is False:
                raise TypeError('process_guid must be a string')
            if self.get_record(table, process_guid=data['process_guid']):
                raise Exception('Process already exists: {0}'.format(data['process_guid']))

            sql_values = (timestamp, data['sha256'], data['process_guid'], data['status'],)
            sql_query = 'INSERT INTO {0}(timestamp,sha256,process_guid,status) VALUES(?,?,?,?)'.format(table)

        if table == 'reports':
            if 'sha256' not in data:
                raise ValueError('[%s] Missing required filed of sha256', self.class_name)
            if isinstance(data['sha256'], str) is False:
                raise TypeError('[%s] Expected sha256 input type is string.', self.class_name)
            if len(data['sha256']) != 64:
                raise ValueError('[%s] The sha256 provided is not 64 characters long: {0}.'.format(data['sha256']), self.class_name)
            if self.get_record(table, sha256=data['sha256']):
                raise Exception('Hash already exists: {0}'.format(data['sha256']))
            if 'status' not in data:
                raise ValueError('[%s] Missing required filed of status', self.class_name)
            if 'task_uuid' not in data:
                raise ValueError('[%s] Missing required filed of task_uuid', self.class_name)
            if 'reports' not in data:
                raise ValueError('[%s] Missing required filed of reports', self.class_name)

            sql_values = (timestamp, data['sha256'], data['status'], data['task_uuid'], json.dumps(data['reports']),)
            sql_query = 'INSERT INTO {0}(timestamp,sha256,status,task_uuid,reports) VALUES(?,?,?,?,?)'.format(table)

        try:
            cur = self.conn.cursor()
            cur.execute(sql_query, sql_values)
            self.conn.commit()

            return cur.lastrowid

        except Exception as err:
            self.log.exception(err)

    def update_record(self, table, **data):
        '''
            !!  Coming soon...

            Inputs
                md5 (str):      MD5 hash to add to the row
                sha256 (str):   SHA256 hash to add to the row
                status (str):   Status from Zscaler report

            Raises
                Exception if not connection exists

            Output
                data (list):    Returns the results of the new row
        '''
        if self.conn is None:
            raise Exception('No connection to database')

        timestamp = convert_time('now')

        if table == 'processes':
            if 'sha256' not in data:
                raise ValueError('[%s] Missing required filed of sha256', self.class_name)
            if isinstance(data['sha256'], str) is False:
                raise TypeError('[%s] Expected sha256 input type is string.', self.class_name)
            if len(data['sha256']) != 64:
                raise ValueError('[%s] The sha256 provided is not 64 characters long: {0}.'.format(data['sha256']), self.class_name)
            if 'process_guid' not in data:
                raise ValueError('[%s] Missing required process_guid', self.class_name)
            if isinstance(data['process_guid'], str) is False:
                raise TypeError('process_guid must be a string')
            if self.get_record(table, process_guid=data['process_guid']):
                raise Exception('Process already exists: {0}'.format(data['process_guid']))

            sql_values = (timestamp, data['sha256'], data['process_guid'], data['status'],)
            sql_query = 'INSERT INTO {0}(timestamp,sha256,process_guid,status) VALUES(?,?,?,?)'.format(table)

        if table == 'reports':
            if 'sha256' not in data:
                raise ValueError('[%s] Missing required filed of sha256', self.class_name)
            if isinstance(data['sha256'], str) is False:
                raise TypeError('[%s] Expected sha256 input type is string.', self.class_name)
            if len(data['sha256']) != 64:
                raise ValueError('[%s] The sha256 provided is not 64 characters long: {0}.'.format(data['sha256']), self.class_name)
            if self.get_record(table, sha256=data['sha256']):
                raise Exception('Hash already exists: {0}'.format(data['sha256']))
            if 'status' not in data:
                raise ValueError('[%s] Missing required filed of status', self.class_name)
            if 'task_uuid' not in data:
                raise ValueError('[%s] Missing required filed of task_uuid', self.class_name)
            if 'reports' not in data:
                raise ValueError('[%s] Missing required filed of reports', self.class_name)

            # sql_query = 'INSERT INTO {0}(timestamp,status,task_uuid,reports) VALUES(?,?,?,?) WHERE sha256 = ?'.format(table)
            sql_query = 'UPDATE {0} SET timestamp = ?, status = ?, task_uuid = ?, reports = ? WHERE sha256 = ?'
            sql_values = (timestamp, data['status'], data['task_uuid'], json.dumps(data['reports']), data['sha256'],)

        try:
            cur = self.conn.cursor()
            cur.execute(sql_query, sql_values)
            self.conn.commit()

            return cur.lastrowid

        except Exception as err:
            self.log.exception(err)


def convert_time(timestamp):
    '''
        Converts epoch or ISO8601 formatted timestamp

        Inputs
            timestamp
                epoch time (int)
                ISO8601 time (str)
                datetime object (class)
                'now' (str)

        Raises
            TypeError if timestamp is not a string, integer or datetime object

        Output
            If timestamp was epoch, returns ISO8601 version of timestamp
            If timestamp was ISO8601, returns epoch version of timestamp
            If timestamp was datetime object, returns ISO8601 version of timestamp
            If timestamp was 'now', returns ISO8601 of current time

        > Note: All times are treated as GMT
    '''

    if isinstance(timestamp, (str, int, datetime)) is False:
        raise TypeError('timestamp is expected to be an integer, string or datetime object. Got {0}'.format(type(timestamp)))

    try:
        iso_format = '%Y-%m-%dT%H:%M:%SZ'

        if isinstance(timestamp, int):
            if len(str(timestamp)) == 13:
                timestamp = int(timestamp / 1000)

            utc_dt = datetime(1970, 1, 1) + timedelta(seconds=timestamp)
            converted_time = utc_dt.strftime(iso_format)

        elif isinstance(timestamp, str):
            if timestamp == 'now':
                return time.strftime(iso_format, time.gmtime())

            utc_dt = datetime.strptime(timestamp, iso_format)
            converted_time = int((utc_dt - datetime(1970, 1, 1)).total_seconds())

        else:
            converted_time = timestamp.strftime(iso_format)

        return converted_time

    except Exception as err:
        print(err)
        # self.log.exception('[%s] Error: {0}'.format(err), self.class_name)


def str2bool(item):
    return item.lower() in ['true', '1']


def config2dict(config):
    '''
        This method converts a configparser variable to a dict to
            enable addition of new values.
        Source: https://stackoverflow.com/a/57024021/1339829
    '''
    return { i: { i[0]: i[1] for i in config.items(i) } for i in config.sections() }


def clean_url(url):
    # if missing protocol, add https
    url = 'https://' + url if url[:8] != 'https://' else url
    # if it has a / at the end, remove it
    url = url[0:-1] if url[-1] == '/' else url
    return url

''' Used to track action script executions '''
script_queue = {}
