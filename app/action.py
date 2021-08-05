#!/bin/sh
# -*- coding: utf-8 -*-
# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: MIT

import os
import re
import sys
import json
import argparse
import configparser
import logging as log

from time import sleep

from lib.helpers import CarbonBlackCloud, config2dict

def init():
    app_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(app_path, 'config.conf')
    if os.path.isfile(config_path) is False:
        raise Exception('[ACTION.PY] Unable to find config.conf in {0}'.format(app_path))

    # Get setting from config.ini
    config = configparser.ConfigParser()
    config.read(config_path)
    config = config2dict(config)

    # Configure logging
    log_level = log.getLevelName(config['logging']['level'])
    log_path = os.path.join(app_path, config['logging']['filename'])
    log.basicConfig(filename=log_path, format='[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s', level=log_level)
    log.info('\n[ACTION.PY] Initializing script')

    # Get inputs
    log.debug('[ACTION.PY] Getting cli inputs')
    parser = argparse.ArgumentParser(description='Take action on an endpoint via LiveResponse')
    parser.add_argument("--device_id", help='Log activity to a file', required=True)
    parser.add_argument('--pid', help='Process ID to kill if running', required=True)
    parser.add_argument('--file_path', help='Process path to delete the file', default=None)
    parser.add_argument('--close', action='store_true', default=False, help='Close the session when script completes')
    args = parser.parse_args()
    log.debug('[ACTION.PY] Finished cli inputs')

    # Init CarbonBlack
    cb = CarbonBlackCloud(config, log)

    return cb, args


def main():
    cb, args = init()

    device_id = int(args.device_id)
    pid = args.pid
    file_path = args.file_path

    log.info('[ACTION.PY] Starting Live Response session with device {}'.format(device_id))

    # Check to see if Live Response is enabled on the endpoint
    device_info = cb.get_device(device_id)
    device = device_info['results'][0]
    last_contact = device['last_contact_time']
    tries = 0

    while tries < 30:
        tries += 1

        if 'LIVE_RESPONSE_ENABLED' in device['sensor_states']:
            break

        if device['last_contact_time'] != last_contact and 'LIVE_RESPONSE_ENABLED' not in device['sensor_states']:
            log.error('[Main] Policy "{0}" ({1}) does not have Live Response enabled.'.format(device['policy_name'], device['policy_id']))
            raise Exception('Policy "{0}" ({1}) does not have Live Response enabled.'.format(device['policy_name'], device['policy_id']))

        device_info = cb.get_device(device_id)
        device = device_info['results'][0]

        log.info('Current policy "{0}" ({1}) does not have Live Response enabled. Checking for policy update in 15 seconds.'.format(device['policy_name'], device['policy_id']))

        sleep(15)


    # If LR is enabled, start LR flow
    lr_session = cb.start_session(device_id, wait=True)
    if lr_session is False:
        log.error('[ACTION.PY] Unable to start Live Response session')
        sys.exit(1)


    log.info('[ACTION.PY] Connected to endpoint: {0}'.format(device_id))

    # Check to see if the process is still running
    lr_command = cb.send_command('process list', wait=True)
    if lr_command is False:
        log.error('[ACTION.PY] Unable to send Live Response command')
        sys.exit(1)

    found = False
    
    for process in lr_command['processes']:
        if str(process['pid']) == pid:
            log.info('[ACTION.PY] Process is running, killing process')

            found = True
            # Send kill command
            lr_command = cb.send_command('kill', argument=pid, wait=True)

        else:
            # Also search for the file_path in the process list
            clean_path = re.sub(r'\\\\', '\\\\', process['command_line'], 0, re.MULTILINE)
            clean_path = clean_path.lower()
            file_path = file_path.lower()
            if clean_path.find(file_path) >= 0:
                log.info('[ACTION.PY] Process is running, killing process')

                found = True
                # Send kill command
                lr_command = cb.send_command('kill', argument=str(process['pid']), wait=True)                

    if found is False:
        log.info('[ACTION.PY] Process {0} was not running on device {1}'.format(pid, device_id))

    # Send delete command
    log.info('[ACTION.PY] Deleting file from endpoint')
    lr_command = cb.send_command('delete file', argument=file_path, wait=True)

    if args.close:
        cb.close_session()
        log.debug('[ACTION.PY] Closed session')


if __name__ == "__main__":
    sys.exit(main())