import sys
import argparse
import configparser
import logging as log

from time import sleep

from lib.helpers import CarbonBlackCloud

log.basicConfig(filename='app.log', format='[%(asctime)s] <pid:%(process)d> %(message)s', level=log.DEBUG)
log.info('Sarted action script')


def init():
    log.debug('Initializing script')

    # Get configs
    log.debug('Getting configs')
    config = configparser.ConfigParser()
    config.read('config.conf')
    log.debug('Finished getting configs')

    # Get inputs
    log.debug('Getting cli inputs')
    parser = argparse.ArgumentParser(description='Take action on an endpoint via LiveResponse')
    parser.add_argument("--device_id", help='Log activity to a file', required=True)
    parser.add_argument('--pid', help='Process ID to kill if running', required=True)
    parser.add_argument('--file_path', help='Process path to delete the file', default=None)
    parser.add_argument('--close', action='store_true', default=False, help='Close the session when script completes')
    args = parser.parse_args()
    log.debug('Finished cli inputs')

    # Init CarbonBlack
    cb = CarbonBlackCloud(config, log)

    return cb, args


def main():
    cb, args = init()

    device_id = int(args.device_id)
    pid = args.pid
    file_path = args.file_path

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
    cb.start_session(device_id, wait=True)

    log.debug('[Main] Connected to endpoint: {0}'.format(device_id))

    # Check to see if the process is still running
    lr_command = cb.send_command('process list', wait=True)

    found = False
    for process in lr_command['processes']:
        if str(process['pid']) == pid:
            log.debug('[Main] Process is running, killing process')

            found = True
            # Send kill command
            lr_command = cb.send_command('kill', argument=pid, wait=True)

    if found is False:
        log.debug('[Main] Process {0} was not running on device {1}'.format(pid, device_id))

    # Send kill command
    log.debug('[Main] Deleting file from endpoint')
    lr_command = cb.send_command('delete file', argument=file_path, wait=True)

    if args.close:
        cb.close_session()
        log.debug('[Main] Closed session')


if __name__ == "__main__":
    sys.exit(main())
