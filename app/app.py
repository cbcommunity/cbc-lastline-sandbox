# -*- coding: utf-8 -*-

import os
import sys
import configparser
import argparse
import logging as log
import requests
import subprocess
import json
from datetime import datetime, timedelta

# Import helpers
from lib.helpers import CarbonBlackCloud, Lastline, Database, convert_time, str2bool, config2dict

# Globals
config = None
db = None
cb = None
ll = None

def init():
    '''
        Initialze all of the objects for use in the integration

        Inputs: None

        Outputs:
            config: A dictionary of the settings loaded from config.conf
            db: An object with everything needed for this script to work with sqlite3
            cb: An object with everything needed for this script to work with CarbonBlack Cloud
            ll: An object with everything needed for this script to work with Lastline endpoints
    '''

    global config, db, cb, ll

    # Check to make sure config file exists
    app_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(app_path, 'config.conf')
    if os.path.isfile(config_path) is False:
        log.exception('[APP.PY] Unable to find config.conf in {0}'.format(app_path))
        raise Exception('[APP.PY] Unable to find config.conf in {0}'.format(app_path))

    # Get setting from config.ini
    config = configparser.ConfigParser()
    config.read(config_path)
    config = config2dict(config)

    config['app'] = { 'path': app_path }

    # Configure logging
    level = log.getLevelName(config['logging']['level'])
    log_path = os.path.join(app_path, config['logging']['filename'])
    log.basicConfig(filename=log_path, format='[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s', level=level)

    # Log = log.getLogger('myLogger')
    # Log.setLevel(level)

    log.info('\n\n[APP.PY] Sarted Lastline Sandbox Connector for VMware Carbon Black Cloud')

    # Configure CLI input arguments
    parser = argparse.ArgumentParser(description='Fetch events for messages delivered in the specified time period which contained a known threat')
    parser.add_argument('--last-pull', default='None', help='Set the last pull time in ISO8601 format')
    parser.add_argument('--start-time', default='None', help='Set the start time in ISO8601 format')
    parser.add_argument('--end-time', default='None', help='Set the end time in ISO8601 format')
    parser.add_argument('--now', action='store_true', default=False, help='Output the current GMT time in ISO8601 format. Does not pull any data.')
    args = parser.parse_args()

    if args.now:
        print('Current time GMT in ISO8601 format: {0}'.format(convert_time('now')))
        sys.exit(0)

    if args.last_pull == 'None':
        args.last_pull = None
    if args.start_time == 'None':
        args.start_time = None
    if args.end_time == 'None':
        args.end_time = None

    # Init database
    db = Database(config, log)

    # If a last_pull was provided, update the database with it
    if args.last_pull is not None:
        db.last_pull(args.last_pull)

    config['CarbonBlack']['start_time'] = args.start_time
    config['CarbonBlack']['end_time'] = args.end_time
    config['CarbonBlack']['ubs_enabled'] = str2bool(config['CarbonBlack']['ubs_enabled'])
    # Define some integraiton basics
    config['version'] = 'v1.0'
    config['user_agent'] = 'VMware Carbon Black Cloud Connector / cbc-lastline {0}'.format(config['version'])

    # Init CarbonBlackCloud
    cb = CarbonBlackCloud(config, log)

    # Init Lastline
    ll = Lastline(config, log)

    return config, db, cb, ll


def take_action(report, sha256, cb_processes):
    '''
        This method will identify which actions are enabled in the config file
            and execute each appropriately.

        Inputs:
            email: An object from Lastline with details about the email (and attachments)
            sha256: A string of the SHA256 of the malicous attachment
            cb_processes: An array of objects containing processes related to the hash

        Outputs:
            config: A dictionary of the settings loaded from config.conf
            db: An object with everything needed for this script to work with sqlite3
            cb: An object with everything needed for this script to work with CarbonBlack Cloud
            pp: An object with everything needed for this script to work with Lastline endpoints
    '''

    # Populate actions with either None or the action defined
    actions = {}
    for action in config['actions']:
        if config['actions'][action] == '':
            actions[action] = None
        else:
            actions[action] = config['actions'][action]

    # The watchlist action should only be run once per hash, not per process
    # Create/update watchlist feed
    if 'watchlist' in actions and actions['watchlist'] is not None:
        # The threats are in an array. We need to figure out which one
        #   represents the hash being processed
        for threat in report['threatsInfoMap']:
            if threat['threat'] == sha256:
                break

        # Build the Report arguments
        timestamp = convert_time(convert_time('now'))
        title = '{} {} {}: {}'.format(threat['threatStatus'],
                                      threat['classification'],
                                      threat['threatType'], sha256)

        # !!! need to populate threat feed description
        description = 'A description can go here.'

        # Lastline's scoring is 0-100, CBC EEDR is 1-10
        if report['malwareScore'] == 0:
            severity = 1
        else:
            severity = round(report['malwareScore'] / 10)

        url = threat['threatUrl']
        tags = [threat['threatStatus'], threat['threatType'], threat['classification']]

        # Get the feed ready
        if cb.iocs is None:
            cb.iocs = []

        # If the feed has already been pulled, it is cached in cb.feed
        if cb.feed is None:
            # Get the feed
            feed = cb.get_feed(feed_name=actions['watchlist'])

            # If the feed doesn't exist, create it
            if feed is None:
                summary = 'SHA256 indicators that tested positive in Lastline'
                feed = cb.create_feed(actions['watchlist'], 'https://www.lastline.com', summary)

        # If IOC is not tracked in watchlist, add it
        if sha256 not in cb.iocs:
            # Build the Report. cb.create_report caches the new reports in cb.new_reports
            cb.create_report(timestamp, title, description, severity, url, tags, sha256)

    # The rest of the actions we want to run once per process, not per hash
    # Save a list of devices so we don't run the action on a device twice
    for process in cb_processes:
        device_id = int(process['device_id'])
        process_guid = process['process_guid']

        records = db.get_record('processes', process_guid=process_guid)

        # If the process has already been analyzed, skip it
        if records is not None:
            continue

        # Send data to webhook
        if 'webhook' in actions and actions['webhook'] is not None:
            try:
                url = actions['webhook']
                headers = {
                    'Content-Type': 'application/json'
                }
                body = {
                    'report': report,
                    'sha256': sha256,
                    'process': process
                }
                r = requests.post(url, headers=headers, json=body)
                
                if str(r.status_code()[0]) == '2':
                    log.info('[APP.PY] Sent data to webhook.\nRecieved {0}: {1}'.format(r.status_code, r.text))

                else:
                    log.warning('[APP.PY] {0}: {1}'.format(r.status_code, r.text))
            except Exception as error:
                log.error('[APP.PY] {0}'.format(error))

        # Run a script
        if 'script' in actions and actions['script'] is not None:
            process_pid = process['process_pid'][0]
            action_script(device_id, pid=process_pid, file_path=process['process_name'])

        # Isolate endpoint
        if 'isolate' in actions and str2bool(actions['isolate']):
            cb.isolate_device(device_id)

        # Change device's policy
        if 'policy' in actions and actions['policy'] is not None:
            cb.update_policy(device_id, actions['policy'])

        # db.add_record(device_id, process_guid, sha256)


def action_script(device_id, pid=None, file_path=None):
    '''
        This method take the command from the config file and runs the provided script.
        This method should be customized to fit any unique needs for a custom action script.

        Inputs:
            device_id: The id of the device to connect to. This should be an integer
            pid: The id of the process to kill if it is running. This should be an integer
            file_path: The path to the file that should be deleted if found. This should be a string

        Outputs:
            All outputs are directed to the log file configured in the config file under the logging section
    '''

    log.info('[action_script()] Running Script {0}'.format(config['actions']['script']))
    script_cwd = os.path.dirname(os.path.realpath(__file__))
    stdin = stdout = subprocess.PIPE

    if isinstance(device_id, int) is False:
        device_id = int(device_id)

    if isinstance(pid, int) is False:
        pid = int(pid)

    # Replace elements
    script = config['actions']['script']
    script = script.replace('{device_id}', str(device_id))
    script = script.replace('{pid}', str(pid))
    script = script.replace('{file_path}', file_path)
    script = script.split(' ')

    # This is the command that is sent, with the arguments
    cmd = [os.path.join(script_cwd, script[0])]

    # The command and arguments are passed as an array to the script execution where each argument is an
    #   item in the array. Some of the args could have spaces (like file_path). This section will concatenate
    #   arguments as a string and correctly organize them by items in the array
    args = []
    arg_tmp = []
    for arg in script[1:]:
        # If the first 2 chars are --, it is an arg key
        if arg[0:2] == '--':
            # Add any arg values and clear the cache
            if len(arg_tmp):
                args.append(' '.join(arg_tmp))
                arg_tmp = []
            # Add the arg key
            args.append(arg)

        # Otherwise it is (or is a part of) an arg value
        else:
            # Add the value to the cache of values
            arg_tmp.append(arg)

    # Add any remaining arg values
    args.append(' '.join(arg_tmp))

    log.info('[APP.PY] Running action script: {0} {1}'.format(cmd, args))

    # Run the script
    subprocess.Popen(cmd + args, stdout=stdout, stdin=stdin)


def analyze_processes():
    '''
        Get all processes that have a reputation as provided in the config file
    '''
    fn_name = 'APP.PY'

    # Remove extra spaces
    reputations = config['CarbonBlack']['reputation'].replace(' ', '')
    # Start building the query
    reputations = reputations.replace(',', ' OR process_effective_reputation:')
    query = 'process_effective_reputation:{0}'.format(reputations)

    # Enable debugging
    # * Used for debugging. This will limit the search to only the process hash defined
    if 'debug' in config:
        if 'cb_sample_hash' in config['debug']:
            if config['debug']['cb_sample_hash'] is not None:
                query = 'process_hash:{0}'.format(config['debug']['cb_sample_hash'])

    # Build the request body
    # ! This has a test device hard coded to prevent tampering with other endpoints
    search_body = {
        'query': query,
        'criteria': {
            'device_os': ['WINDOWS'],
            'device_id': ['3984889']
        },
        'fields': [
            '*',
            'device_os',
            'process_effective_reputation',
            'process_reputation',
            'process_sha256',
            'process_cmdline',
            'parent_reputation',
            'parent_guid',
            'parent_hash',
            'parent_name',
            'parent_effective_reputation'
        ],
        'rows': 5000,
        'time_range': {
            'window': '-{0}'.format(config['CarbonBlack']['window'])
        }
    }

    search_body['query'] = query
    # !! convert this to a JSON string
    log.debug('[%s] Created query to search for processes: {0}'.format(search_body), fn_name)

    # Run the search and get results
    processes = cb.get_processes(search_body)
    log.info('[%s] Found {0} processes matching the criteria.'.format(len(processes['results'])), fn_name)

    # Used to prevent duplicate submissions to Lastline
    hash_cache = []

    for process in processes['results']:
        process_guid = process['process_guid']
        sha256 = process['process_sha256']
        action_required = False

        # Check to see if this process has already been inspected
        process_record = db.get_record('processes', process_guid=process_guid)

        # If the process HAS NOT been inspected or is still pending
        # * Does the PROCESS need to be inspected?
        if process_record is None or process_record[0][4] == 'pending':
            if process_record is None:
                log.debug('[%s] The process "{0}" has not been inspected before.'.format(process_guid), fn_name)
            else:
                log.debug('[%s] The process "{0}" is pending. Checking this process again.'.format(process_guid), fn_name)

            if sha256 in hash_cache:
                log.debug('[%s] The hash has already been submitted for inspection this script iteration', fn_name)
                continue

            # Check to see if this hash has already been inspected in the past        
            # * Check the database to see if the HASH has been inspected in the past
            hash_record = db.get_record('reports', sha256=sha256)

            # If the hash HAS been inspected, is it completed or pending?
            # * Has the HASH been inspected before?
            if hash_record is not None:
                report_status = hash_record[0][3]
                task_uuid = hash_record[0][4]
                reports = json.loads(hash_record[0][5])

                # If the hash HAS already been inspected, return the results
                # * Is the REPORT COMPLETE?
                # ? Sometimes the report is stored with child 'tasks', sometimes without
                if report_status == 'complete':
                    if 'tasks' in reports:
                        # * For each TASK in the report
                        for task in reports['tasks']:
                            # * Is the score > the action_threashold?
                            if task['score'] >= int(config['Lastline']['action_threashold']):
                                log.warn('[%s] Taking action on process "{0}" with hash "{1}"'.format(process_guid, sha256))
                                # * take_action
                                action_required = True

                    else:
                        if reports['score'] >= int(config['Lastline']['action_threashold']):
                            log.warn('[%s] Taking action on process "{0}" with hash "{1}"'.format(process_guid, sha256))
                            # * take_action
                            action_required = True
                        
                    # * Save PROCESS to the local database as COMPLETE
                    db.add_record('processes', sha256=sha256, process_guid=process_guid, status='complete')

                # If the hash is still pending
                else:
                    log.info('[%s] Hash "{0}" is still pending in the database.'.format(sha256), fn_name)
                    ll_result = ll.get_result(task_uuid)

                    if ll_result is not None:
                        if ll_result['score'] >= int(config['Lastline']['action_threashold']):
                            log.warn('[%s] Taking action on process "{0}" with hash "{1}"'.format(process_guid, sha256))
                            action_required = True

                        else:
                            log.info('[%s] Report score for {0} is {1}. Not high enough to take action.'.format(task_uuid, ll_result['score']), fn_name)

                        db.update_record('processes', sha256=sha256, process_guid=process_guid, status='complete')
                        db.update_record('reports', sha256=sha256, status='complete', task_uuid=task_uuid, reports=ll_result)

                    else:
                        log.info('[%s] Hash "{0}" is still pending in Lastline'.format(sha256), fn_name)
                        hash_cache.append(sha256)


            # If the hash HAS NOT been inspected
            else:
                # Check to see if it HAS already been detonated in Lastline
                ll_lookup = ll.query_hash(sha256=sha256)
                # print(ll_lookup)

                # If the file HAS been detonated, save the results locally
                if ll_lookup['files_found'] > 0:
                    for task in ll_lookup['tasks']:
                        score = task['score']
                        task_uuid = task['task_uuid']

                        if score >= int(config['Lastline']['action_threashold']):
                            # Get the report
                            task['report'] = ll.get_result(task_uuid)

                            # !!! add report to database
                            action_required = True

                    db.add_record('reports', sha256=sha256, status='complete', task_uuid=task_uuid, reports=ll_lookup)
                    db.add_record('processes', sha256=sha256, process_guid=process_guid, status='complete')

                # If the file HAS NOT been detonated
                else:
                    if config['CarbonBlack']['ubs_enabled'] is not True:
                        log.info('[%s] Unable to pull binary from CBC. Please enable Universal Binary Store in the console and in the config.conf file.', fn_name)
                    # UBS is only availabe on Windows devices. The process_search should have filtered this
                    if process['device_os'] == 'WINDOWS' and sha256 not in hash_cache:
                        # Get the binary from CBC EEDR UBS and submit to Lastline
                        cb_binary = cb.get_binary(sha256)

                        if cb_binary is not None:
                            binary_url = cb_binary['found'][0]['url']
                            ll_submission = ll.submit_url(binary_url)

                            db.add_record('reports', sha256=sha256, status='pending', task_uuid=ll_submission['task_uuid'], reports=ll_submission)
                            db.add_record('processes', sha256=sha256, process_guid=process_guid, status='pending')

                        else:
                            log.warning('[%s] Unable to find binary for {0}'.format(sha256), fn_name)

                        hash_cache.append(sha256)

                    else:
                        log.warning('[%s] UBS is only available on Windows devices. This device is {0}'.format(process['device_os']), fn_name)
                        db.add_record('processes', sha256=sha256, process_guid=process_guid, status='complete')
            
            if action_required:
                log.debug('[%s] Taking action on process "{0}"'.format(process_guid))
                take_action(reports, sha256, process)

        # If it HAS been inspected
        else:
            log.info('[%s] Process with guid "{0}" was already inspected.'.format(process['process_guid']), fn_name)

    log.info('[%s] Submitted {0} new files to Lastline for analysis.'.format(ll.submits), fn_name)


def analyze_reports():
    '''
        Coming soon...
    '''
    fn_name = 'APP.PY'

    # Convert ISO8601 to Lastline format
    last_pull = datetime.strptime(db.last_pull(), "%Y-%m-%dT%H:%M:%S%z")
    last_pull = datetime.strftime(last_pull, "%Y-%m-%d %H:%M:%S")
    new_reports = ll.get_completed(start_time=last_pull)
    
    search_body = {
        'fields': [
            '*',
            'device_os',
            'process_effective_reputation',
            'process_reputation',
            'process_sha256',
            'process_cmdline',
            'parent_reputation',
            'parent_guid',
            'parent_hash',
            'parent_name',
            'parent_effective_reputation'
        ],
        'rows': 5000,
        'time_range': {
            'window': '-2w'
        }
    }

    for task in new_reports['tasks']:
        report = ll.get_result(task)
        task_uuid = report['task_uuid']
        db_record = db.get_record('reports', task_uuid=task_uuid)

        if db_record is None and 'sha256' in report['analysis_subject']:
            log.info('[%s] Found a new report that did not originate from this script.', fn_name)
            sha256 = report['analysis_subject']['sha256']

            log.info('[%s] Adding Report for SHA256 {0} with task_uuid {1} to the database.'.format(sha256, task_uuid), fn_name)
            # Add the report so we don't duplicate a search for it
            db.add_record('reports', sha256=sha256, status='complete', task_uuid=task_uuid, reports=report)

            log.info('[%s] Searching for any processes with SHA256 {0}'.format(sha256), fn_name)
            # Update the search_body with a query now that we have the sha256
            search_body['query'] = 'process_hash:{0}'.format(sha256)
            processes = cb.get_processes(search_body)

            for process in processes:
                proc_record = db.get_record('processes', process_guid=process['process_guid'])
                if proc_record is None:
                    print('take_action(report, {0}, {1})'.format(sha256, process['device_id']))
                    take_action(report, sha256, process)
                    db.add_record('processes', sha256=sha256, process_guid=process['process_guid'], status='complete')

        if db_record is not None:
            print(json.dumps(db_record, indent=4))
            log.info(json.dumps(db_record, indent=4))
        
        if 'sha256' not in report['analysis_subject']:
            log.warn('[%s] Report is missing SHA256. Skipping report with task_uuid {0}'.format(task_uuid), fn_name)
        # sha256 = report['analysis_subject']['sha256']


def main():
    # Get inits
    init()

    # Get all processes that have the reputation listed in the config file
    analyze_processes()

    # Get all detonations from Lastline Sandbox and search for processes matching bad files
    analyze_reports()

    # Once all of the reports and processes have been analyzed, check to see if any new IOCs
    #   are cached and waiting to be added to the watchlist. If so, add them.
    if 'watchlist' in config['actions'] and config['actions']['watchlist'] is not None:
        cb.update_feed(config['actions']['watchlist'])

    # Update the last_pull time
    db.last_pull(timestamp=convert_time('now'))

    # Close the connection to the database
    db.close()


if __name__ == '__main__':
    main()
