# TODO

- [x] Load secret-id from systemd-credentials
- [x] Add check to only allow PID 1 to access
- [x] Check if the caller is also a systemd service otherwise return an error
- [x] Add whitelisting of systemd services that are allowed to access the secrets
- [x] Add socket activation support
