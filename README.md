# miraichan
Python3 parallelised basic auth web scanner

I wrote this tool to quickly scan a large network for default / compromised credentials through web based Basic Authorization.

Initial testing in a home environment yields ~1k requests/minute without rate limiting.

Feel free to cannibalise it to scale any other modules and functions for large numbers of targets!

Key objectives in designing this tool:
- Native to python3
- Scales well with large networks
- Standardised CSV output
- Extremely customisable configuration
- Various options to validate success and failure
- Easy to read live status output

Optimisations made:
- Multithreaded to n threads
- Workers feed directly from OS file handle (less memory required)
- Conditional bailouts to prevent unnecessary checks
- Resume function to rescue failed runs

## Usage
The script is self-documenting and includes an exhaustive help listing available through `python3 miraichan.py -h`

```
usage: miraichan.py [options] (-l user | -L file) (-p pass | -P file) -o outfile targets

Python based basic auth scanner

positional arguments:
  targets               filename containing targets (IPs / hostnames)

options:
  -h, --help            show this help message and exit
  -o file, --outfile file
                        filename for output csv file
  -l USER, --login USER
                        username to use for auth
  -p PASS, --password PASS
                        password to use for auth
  -L FILE, --logins FILE
                        filename containing usernames to use for auth
  -P FILE, --passwords FILE
                        filename containing passwords to use for auth
  --pitchfork           combine user/pass by line (default)
  --clusterbomb         combine user/pass by cartesian join
  --paths PATH [PATH ...]
                        URL path(s) to basic auth page (default = /)
  --resume N            resume from an arbitrary line in targets file

success criteria:
  --no-precheck         disable default precheck to ensure page serves basic auth
  --success STRING      response string required to qualify a success
  --fail STRING         response string sufficient to qualify a fail

connection:
  defaults to attempt HTTP on 80 and HTTPS on 443

  --no-tls              only attempt HTTP
  --tls                 only attempt HTTPS
  --verify              enable TLS certificate verification
  --ports X [X ...]     port(s) to connect on (will be forced for chosen protocols)
  --threads THREADS     number of threads to spawn (default = 10)
  --timeout TIMEOUT     seconds to timeout requests (default = 10)
```

Some additional options are availble as constants at the start of the script for power users:
- `proxies`
  - This is passed directly to the requests proxies context
- `headers`
  - Use this to set custom headers for your environment including user agent string
- `buffer_size`
  - Adjusts how many bytes a worker grabs from the targets file handle (rounded up by line)
- `debug`
  - Disables the pretty progress bar in favour of masocistic verbosity >:D

## CSV Output

Output is standardised as a comma delimited UTF-8 encoded file with the following fields:
- status [str]
  - `success` - The request passed the set success criteria. By default this requires the page to present the `WWW-Authentication` header and subsequently not return status `401` when credentials are supplied.
  - `fail` - The request failed due to bad credentials or the set fail string.
  - `noauth` - The web server failed to present a basic auth realm.
  - `rejection` - The request was actively rejected (e.g. firewall, DNS failure, invalid service).
  - `timeout` - The target was unreachable within the set timeout period.

## Future Goals
- [ ] Additional field testing for uncaught errors
- [ ] Add database connectors for easier workflows
- [ ] Add distrubuted execution modes for serious networking power
