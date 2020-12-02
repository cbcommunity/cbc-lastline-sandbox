This is the pseudo code for the Lastline Sandbox integration. There are 2 primary parts to this integration:
 1. Send binaries to LL for detonation
 2. Get detonation results and scan for the files on the endpoints

## Part 1
- [x] pull all alerts since last successful run
    - [x] for each alert
        - [] check to see if LL has already detonated the file (search by sha256)
            - [] if the file has been analyzed
                - [] get report
            - [] if the file has not been analyzed
                - [] pull the raw binary from CBC
                - [] push the binary to LL sandbox

## Part 2
- [] pull all LL detonation results since last successful run (~30 minutes)
    - [] for each result
        - [] search for all processes that match the sha256
            - [] for each process
                - [] check the db to see if we have already handled this process
                    - [] if hash in in db
                        - [] skip it
                    - [] if hash is not in db
                        - [] take action (see actions below)
                        - [] save to database to prevent duplicate searches

Actions include:  
1. add sha256 to watchlist  
2. send sandbox report and process info to webhook  
3. run a script  
4. move device to another policy  
5. isolate device  