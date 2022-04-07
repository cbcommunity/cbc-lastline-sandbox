
# Lastline Sandbox Connector for VMware Carbon Black Cloud

This is an integration between Lastline's product and VMware Carbon Black Cloud (CBC).

**Latest Version:** v0.9.1  
**Release Date:** March 2021


## Overview

This is an integration between **Lastline Sandbox** and **VMware Carbon Black Cloud** (CBC).

The integration with CBC has 2 phases:

1. CBC to Lastline
    - Pull all Processes with File Reputation of NOT_LISTED (configurable in the config.conf).
    - Query Lastline for any previous sandbox reports for the hash.
    - If the file has been detonated and it is malicious, take action. This applies to Endpoint Standard or EEDR.
    - If the file hasn't been detonated yet by Lastline, and if Upload all new binaries to CB is enabled, pull the binary from CBC and send to Lastline for detonation. This only applies to EEDR.
2. Lastline to CBC
    - Every 30 minutes query Lastline for any new detonations.
    - Search CBC for any Processes matching the report hashes and take action.

Action options consist of:
   - Adding to a CBC Enterprise EDR Watchlist Feed
   - Passing the SHA256, process information, and email information to a webhook
   - Running a script (kills process/deletes file with CBC Live Response by default)
   - Isolating the endpoint
   - Moving the endpoint into a different or updated policy

## Requirements
    - Python 3.x with sqlite3
    - VMware Carbon Black Cloud Endpoint Standard or Enterprise EDR
    - Lastline Sandbox

## License
Use of the Carbon Black API is governed by the license found in the [LICENSE.md](https://github.com/cbcommunity/cbc-lastline-sandbox/blob/main/LICENSE.md) file.

## Support
This integration is an open sourced project. Please submit a Pull Request for any changes.

----

## Installation

Clone the repository into a local folder.

    git clone https://github.com/cbcommunity/cbc-lastline-sandbox.git

Install the requirements

    pip install -r requirements.txt

Edit the `config.conf` file and update with your configurations

## Configuration

All of the configurable settings for the integration can be found in [`config.conf`](cbcommunity/cbc-lastline-sandbox/blob/master/app/config.conf).

### Carbon Black Configuration
You will need to create 1 API Access Level and 3 API keys

#### Custom Access Level Permissions

|    **Category**   | **Permission Name** | **.Notation Name** |        **Create**       |         **Read**        |        **Update**       | **Delete** |       **Execute**       |
|:-----------------:|:-------------------:|:------------------:|:-----------------------:|:-----------------------:|:-----------------------:|:----------:|:-----------------------:|
| Custom Detections | Feeds               | org.feeds          | :ballot_box_with_check: | :ballot_box_with_check: |                         |            |                         |
| Device            | Quarantine          | device.quarantine  |                         |                         |                         |            | :ballot_box_with_check: |
| Device            | General Information | device             |                         | :ballot_box_with_check: |                         |            |                         |
| Device            | Policy Assignment   | device.policy      |                         |                         | :ballot_box_with_check: |            |                         |
| Search            | Events              | org.search.events  | :ballot_box_with_check: | :ballot_box_with_check: |                         |            |                         |
| Universal Binary Store | File           | ubs.org.file       |                         | :ballot_box_with_check: |                         |            |                         |

#### Access Levels (API key type)
1. Custom [select your Custom Access Level]
2. API
3. Live Response (optional, used in [action.py](https://github.com/cbcommunity/cbc-lastline-sandbox/blob/main/app/action.py))

The Organization Key can be found in the upper-left of the **Settings** > **API Keys** page.

| CarbonBlack         | Configure Carbon Black Cloud       |
|:--------------------|:-----------------------------------|
| `url`               | URL of CBC instance                |
| `org_key`           | Org Key                            |
| `api_id`            | API ID                             |
| `api_key`           | API Secret Secret Key              |
| `custom_api_id`     | Custom API ID                      |
| `custom_api_key`    | Custom API Secret Key              |
| `lr_api_id`         | LiveResponse API ID                |
| `lr_api_key`        | LiveResponse API Secret Key        |
| `window`            | Window of time to search for SHA256 processes. Maximum 2 weeks |

----

### Lastline Configuration

To configure the integration with Lastline, the `url`, `api_key`, and `api_token` fields are required.


| **Lastline**  | **Configure Lastline**   |
|:----------------|:-------------------------------|
| `url`           | URL for Lastline               |
| `api_key`       | API Key                        |
| `api_token`     | API Token                      |

----

### NSX Configuration

An optional action is to add a NSX tag to a device. This could be used to isolate the endpoint on a VLAN, enable certain features to inspect network traffic, or just segreate for investigation.

Ensure to add a tag to the `actions` section if you complete this section.

| **NSX**    | **Configure NSX** |
|------------|-------------------|
| `url`      | URL for NSX       |
| `username` | API username      |
| `password` | API password      |

----

Python 3.x ships by default with sqlite. If for some reason you don't have sqlite, you will need to install it (`pip install sqlite3`). This database is used to keep track of and de-dupe lookups on the same process.

| **sqlite3**         | **Configure sqlite3**                                |
|:--------------------|:-----------------------------------------------------|
| `filename`          | Filename of the sqlite3 database                     |
| `deprecation`       | Amount of time the records will live in the database |

----

When a process with the a malicious hash is detected, actions are triggered. By default all actions are disabled. Uncomment and populate with a value to enable.

| **actions**         | **Configure Actions**              |
|:--------------------|:-----------------------------------|
| `watchlist`         | Name of watchlist to populate      |
| `webhook`           | URL to `POST` a JSON object of the event and sandbox report |
| `script`            | A script to execute                |
| `isolate`           | Isolate the endpoint?              |
| `policy`            | Policy to move offending devices   |
| `nsx_tag`           | Add a NSX tag to the device        |

## Running the Script

The script has the following CLI options:

    optional arguments:
      -h, --help            show this help message and exit
      --last-pull LAST_PULL
                            Set the last pull time in ISO8601 format
      --start-time START_TIME
                            Set the start time in ISO8601 format
      --end-time END_TIME   Set the end time in ISO8601 format
      --now                 Output the current GMT time in ISO8601 format. Does not pull any data.

The `--last_pull` option overwrites the `last_pull` value stored in the database and will pull CBC Endpoint Standard or CBC Enterprise EDR processes since that time.

To manually specify a timeframe use the `--start-time` and `--end-time` arguments.

### Examples

Typical usage:

    python app.py

Specify start date:

    python app.py --last_pull 2021-01-01T12:34:56Z

## Docker

A Dockerfile is included. First build the image using the following command from the project's root folder:

    docker build -t cbc-lastline-sandbox .

Make sure your [app/config.conf](https://github.com/cbcommunity/cbc-lastline-sandbox/blob/main/app/config.conf) file is populated with the correct values.

Run the script with the following command:

    docker run --rm -it -v $PWD/app:/app --name=cbc-lastline-sandbox cbc-lastline-sandbox
   
## Development

Want to load a dev environment locally to test and tweak the code? Use the following command in the root of the repo folder to launch a dev environment on port 3000 of your local machine.

	# Linux, macOS, or PowerShell
	docker run -it --init \
		--name cbc-lastline-sandbox \
		-p 3000:3000 \
		-v "$(pwd):/home/project:cached" \
		theiaide/theia-python:next

	# Windows (cmd.exe)
	docker run -it --init \
		--name cbc-lastline-sandbox \
		-p 3000:3000 \
		-v "%cd%:/home/project:cached" \
		theiaide/theia-python:next

Once the container is running, open a browser and go to http://localhost:3000. After the console loads, run the following command in the IDE's terminal:

	./dev-setup.sh

This will update the instance and install the required modules. Use `python3` to execute the scripts.
