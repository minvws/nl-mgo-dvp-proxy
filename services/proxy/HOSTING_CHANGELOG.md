- ### NEXT FUTURE RELEASE

- ### [0.13.0] 2025-04-30
    - No changes required

- ### [0.12.0] 2025-03-21
    - No changes required

- ### [0.11.0] 2025-02-28
    - No changes required

- ### [0.10.0] 2025-02-07
    - No changes required

- ### [0.9.0] 2025-01-31
    (added in 0.9.0 but was not added in the changelog back then)

    ### Added:
    - `oidc`
      - client_assertion_jwt_pvt_key_path
        - string: relative path to the private key that must be generated using tools/generate-client-assertion-jwt-key-pair.py
      - client_assertion_jwt_pub_key_path
        - string: relative path to the public key that must be generated using tools/generate-client-assertion-jwt-key-pair.py
    ### Deleted:
    - `oidc`
        - `client_assertion_jwt_key_path`

- ### [0.8.0] 2025-01-17
    ### Added:
    - `oidc` section
        - client_id
            - A client id from the VAD Test environment. The client_id needs to correspond with a client entry on the VAD/MAX server.
        - callback_endpoint
            - value: /oidc/callback
        - state_secret_path
            - Should be generated using tools/generate-oidc-state-secret.py
            - example: secrets/oidc-state.key
        - client_assertion_jwt_key_path
            - Path to the private key that must be generated using tools/generate-client-assertion-jwt-key-pair.py
            — The corresponding public key must be available in the VAD/MAX (and its path must be included in clients.json)
            - example: secrets/jwt.key

    - `vad_http_client` section
        - url
            - url of the VAD/MAX server
            - value: https://vad.test.mgo.irealisatie.nl
        - client_cert
            - value: empty
        - client_key
            - value: empty
        - ca_cert=
            - value: empty


- ### [0.7.0] 2024-12-13

    #### Added:
    - `telemetry` section
      - enabled
          - boolean - determines whether to collect telemetry data.
      - service_name
        - string - The name to use for this service to send telemetry data to the gRPC server.
      - collector_grpc_url
        - string - The URL of the gRPC server that will receive the telemetry data.
        - example: http://jaeger:4317

- ### [0.6.0] 2024-10-04

    ### Update
    - `oauth.tls` section should be moved/rename to `oauth_tls` section

    ### Added:
    - `logging` section
    - `logging.logger_name`: "dvp_proxy"
        - The name of the logger used for application logs

- ### [0.5.0] 2024-09-18

    ### Added:
    - `oauth` section
    - `oauth.client_id`: str
        - The oauth client id to use for the application
    - `oauth.state_signing_key_paths`: str
        - Accepts multiple key paths, separated by a comma, only the first key is used to encrypt the state parameter, all keys will be attempted when decrypting the state parameter
        - The [Fernet](https://cryptography.io/en/latest/fernet/) symmetric key used to sign the state parameter in the oauth flow
        - can be generated with the [generate script](tools/generate_oauth_state_signing_key.py)
        - script accepts stdin path for the key relative to project root
        - script accepts `--force` flag to overwrite existing key
    - `oauth.signature_lifetime_secs`: int
        - The lifetime of the signed state parameter in seconds
        - Default: 900
    - `oauth_redirect_url`: str
        - The URL that the authorization server will redirect to after the user has authenticated
    - `mock_oauth_servers`: bool
        - Whether or not to use the MedMij OAuth mocking setup
    - `oauth.tls`
        - `client_cert`: str
            - Path to client certificate file
        - `client_key`: str
            - Path to client key file
        - `ca_cert`
            - The path to the CA certificate file

  #### Added:

  [app.conf](app.conf)
  - [circuit_breaker] section
  - [redis] section

  - `circuit_breaker.fail_max`: 3
    - Amount of failures before the circuit breaker opens
  - `circuit_breaker.reset_timeout`: 10
    - amount of seconds before the circuit breaker attempts to close a circuit again
  - `circuit_breaker.state_storage`: redis
    - The state storage for the circuit breaker, can be either "in_memory" or "redis"

  - `redis.host`: redis
    - The host of the redis server
  - `redis.port`: 6379
    - The port of the redis server
  - `redis.username`: ""
    - The username for the redis server
  - `redis.password`: ""
    - The password for the redis server
  - `redis.ssl`: True
    - If the redis server should be connected to using SSL
  - `redis.mutual_auth`: False
    - If the redis server should be connected to using mutual authentication
  - `redis.ssl_certfile`: "/src/certs/out/redis-local.crt"
    - The path to the SSL certificate file, required if `redis.mutual_auth` is True
  - `redis.ssl_keyfile`: "/src/certs/out/redis-local.key"
    - The path to the SSL key file, required if `redis.mutual_auth` is True
  - `redis.ssl_ca_certs`: "/src/certs/out/ca.crt"
    - The path to the SSL CA certificate file, required if `redis.ssl` is True


- ### [0.4.1] 2024-07-25

  No changes required

- ### [0.4.0] 2024-07-23

    #### Added:

    [app.conf](app.conf)

    - `metric.adapter=statsd`
      - For local development an metric client stub was added, which required a `metric.adapter` config setting

    #### Changed:
    - From now on, Uvicorn should run the application using the `--factory` flag.
      The reason for this is that we encapsulated the scope of the application factory.
      This part of the uvicorn command: `uvicorn app.main:app` should be changed to: `uvicorn --factory app.main:create_app`.

    [app.conf](app.conf)

    - Section `[statsd]` renamed to `[metric]`
    - `[default].env`: change the value to "development" instead of "test" (on test environment only).

    #### Removed:

    [app.conf](app.conf)

    - `target_header_name`
      - This value has been hardcoded as it is very unlikely that it will ever change.
    - `signature_validation.signature_name`
      - This value has been hardcoded as it is very unlikely that it will ever change.

- ### [0.3.1] - 2024-06-20

  No changes required

- ### [0.3.0] - 2024-06-19
    #### Add:

    [app.conf](app.conf)

    - `target_header_name`: x-mgo-dva-target
      - The name of the header that contains the DVA a request is targeting
    - `statsd.prefix`: "proxy.${default:env}"

    #### Removed:

    [app.conf](app.conf)

    - `mock_url`
      - Removed because remote DVA's (and the mock DVA) are now targeted through the `{target_header_name}` header, and no longer are hardcoded

- ### [0.2.1] - 2024-06-06

  No changes required

- ### [0.2.0] - 2024-06-05

  No changes required

- ### [0.1.0] - 2024-05-27

    #### Add:

    [app.conf](app.conf)

    - `[signature_validation]` section
    - `signature_validation.verify_signed_requests`: false
    - `signature_validation.public_key_paths`:
    - `signature_validation.signature_name`: mgo_signature

    #### Changed:

    - Change version from 0.0.4 to 0.1.0 to start using semver properly

- ### [0.0.3] - PRE-RELEASE

    #### Add:

    [app.conf](app.conf)

    - `default.use_tls`: true
    - `tls.client_cert`: "/path/to/client.crt"
    - `tls.client_key`: "/path/to/client.key"
    - `tls.ca_cert`: "/path/to/ca.crt"
    - `retry.max_retries`: 1
    - `retry.backoff`: 0.2
    - `retry.backoff_factor`: 2.0
    - `statsd.host`
    - `statsd.port`

    #### Changed:

    [app.conf](app.conf)
    - `default.mock_url`: make sure the URL starts with: "https://"
