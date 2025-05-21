# VAD Client app integration manual

This document describes the steps to integrate a client app with the VAD through
the MGO DVP Proxy.

## Actors

-   VAD (Vertrouwde Authenticatie Dienst)
-   DVP Proxy
-   Client app

## Overview

The VAD is a service that provides an interface that allows DigiD TVS SAML
logins using the OIDC protocol. The VAD provides a rather standardized OIDC
implementation, but there is an additional call that differs from the OIDC
standard. This additional call is needed because the VAD uses PKCE (Proof Key
for Code Exchange) for the authorization code flow.

## Prerequisites

-   The client app needs a callback endpoint.
    -   This callback endpoint will be used when the entire OIDC flow is
        completed. Because of the way the MGO infrastructure is set up, when the
        flow completes with a userinfo object, the VAD will send this userinfo
        to the DVP proxy. But because we are in an automatic flow based on
        redirects, we cannot send this response directly. Instead the client app
        should expose an endpoint on which it is capable of retrieving data from
        the query string, so that the DVP Proxy can redirect the user to this
        endpoint with the base64 encoded userinfo object in the query string.
-   The DVP Proxy requires a few additional
    [configuration settings](../services/proxy/app.conf) with regards to the
    VAD:
    -   The `[oidc]` section must have a `client_id` matching a client
        registered in the VAD service being used
    -   The `[vad_http_client]` section must have a `url` pointing to the VAD
        service being used

## Flow

### 1. Getting the authorization URL

The client app needs to get the authorization URL, so it can redirect the user
to the VAD login page. This authorization URL is typically a URL that is
enriched by a backend service with the necessary parameters. The client app
should call the DVP Proxy to get the authorization URL. We hit the `/oidc/start`
endpoint on the DVP Proxy with the following parameters:

```
{
  "client_callback_url": "https://client.app/oidc/userinfo/callback"
}
```

After we make this request, the DVP Proxy will return a response with the
authorization URL. This response will look like this:

```
{
  "https://localhost:8006/authorize?response_type=code&client_id=e7b8a6f4-8c3e-4f6a-9b8e-3f8b6a7e8c3e&redirect_uri=http://localhost:8801/oidc/callback&scope=openid&state=gAAAAABnj36P2hhUOpd7qMg6faf1WnGK9wNTGZuAIUzMeLcEJizi6cxYEXteh05b6L83qyF3cKP2kG9kxV_HlAy2xF5NFsQZaNCv35d4PasPXwqQjEGjKh1Ge4qMeRIPyt_QTdTkukE0GqLR8lU4SVBtJmfIWnxp9xWtAZCUiIRB-Gpq7mNTsEG1QjeaAjEkh9-1LEBXpFlS8LTAP9fluVe2oY_CAeYP3TMJHzc-d-WtmSACVjLjg4bZmW1jWJLCFhyK6horx2Yv_Y2RSGl84Ul0wLEM-VGQRmf3oNlkWEuXaq7vPSp4cIfGaPUK4-ijMAZfz_sKOtDqRB6KzKZR6Be3C4KYuS3Zb2xjFob1vr93p-TqzyXC5_U=&code_challenge=7WUbrem7oXnsTnTgIHFQa_7ORt8n6Bsugvw3z1c_oIQ&code_challenge_method=S256&nonce=fab6ea151152a99ddea8097398d475e0"
}
```

The parameters that have been added to the URL are:

-   `response_type=code`

    -   The type of response that the we want to receive from the VAD.

-   `client_id=e7b8a6f4-8c3e-4f6a-9b8e-3f8b6a7e8c3e`

    -   The client ID that is registered at the VAD.

-   `redirect_uri=http://localhost:8801/oidc/callback`

    -   The URL that the VAD should redirect the user to after the user has
        logged in.

-   `scope=openid`

    -   scope that is requested from the VAD.

-   `state=gAAAAABnj36P2hhUOpd7qMg6faf1WnGK9wNTGZuAIUzMeLcEJizi6cxYEXteh05b6L83qyF3cKP2kG9kxV_HlAy2xF5NFsQZaNCv35d4PasPXwqQjEGjKh1Ge4qMeRIPyt_QTdTkukE0GqLR8lU4SVBtJmfIWnxp9xWtAZCUiIRB-Gpq7mNTsEG1QjeaAjEkh9-1LEBXpFlS8LTAP9fluVe2oY_CAeYP3TMJHzc-d-WtmSACVjLjg4bZmW1jWJLCFhyK6horx2Yv_Y2RSGl84Ul0wLEM-VGQRmf3oNlkWEuXaq7vPSp4cIfGaPUK4-ijMAZfz_sKOtDqRB6KzKZR6Be3C4KYuS3Zb2xjFob1vr93p-TqzyXC5_U=`

    -   The state parameter contains information that the DVP Proxy needs to
        support the authentication flow.

-   `code_challenge=7WUbrem7oXnsTnTgIHFQa_7ORt8n6Bsugvw3z1c_oIQ`
    -   The code challenge that is used in the PKCE flow.
-   `code_challenge_method=S256`
    -   The method that is used to generate the code challenge.
-   `nonce=fab6ea151152a99ddea8097398d475e0`
    -   The nonce that is used to prevent replay attacks.

If enabled, the VAD also returns a Set-Cookie header containing an (encrypted)
auth session ID. Should the client attempt a subsequent login within the
expiration time of the auth session, authentication via DigiD is skipped.

### 2. Redirecting the user to the VAD

The client app should open a browser with the authorization URL received from
the DVP Proxy.

Note: in case of an active auth session, the rest of step 2 is not applicable.

The user will then be redirected to the VAD login page. On this page the user
will select the option `Inloggen met DigiD`. After the user has logged in, the
VAD will handle the login procedure and will then redirect the user to the
redirect URI that was provided in the authorization URL.

### 3. Handling the callback

The redirect will send the user to the URL that was provided in the
`/oidc/start` request. Typically, such request will look like:

```
https://client.app/oidc/userinfo/callback?userinfo=eyJyZWZlcmVuY2VfcHNldWRvbnltIjp7InJpZCI6ImV5SmhiR2NpT2lBaVJFbFNJaXdnSW1WdVl5STZJQ0pCTWpVMlIwTk5JaXdnSW10cFpDSTZJQ0pTUlVzdE1TSjkuLlVrbFdSZ0FBQUFCX19fX19fX192LVE9PS5KNUQzelBHdHlpdTljZGRGX2R1R0pIeXNEbzRWNElfbHpKM2hVek5NTjdsS1FPUi1zblRYbUxkWkJGX01BSjhHSEFmdXFKdG5rZmRjaHZuTjRpc0JSSDZ0Y2xPaF9rU1VObVk3UDExX2ttTVZ1YjhxaC1vQXlTcGMuUjJCZWh3UVVhcWNTbjhwYkJuYWdzUT09IiwicGRuIjoiMS4xLlI3bDJOOHAxc3pINXc5ek53Z01XbDhXUXJGUElRTTQzWEhxelBwVjhvbzA9In0sInBlcnNvbiI6eyJhZ2UiOjI0LCJuYW1lIjp7ImZpcnN0X25hbWUiOiJGcm91a2UiLCJwcmVmaXgiOm51bGwsImxhc3RfbmFtZSI6IkphbnNlbiIsImluaXRpYWxzIjoiRi4iLCJmdWxsX25hbWUiOiJGcm91a2UgSmFuc2VuIn19fQ==
```

It is expected for the client apps to be able to handle this request, and
extract the parameters that were sent in the query string. These parameters
should be stored in the client app's state, so that they can be used when
requesting user information. The userinfo object consists of:

-   `rid`: a string containing the Reference ID used to subsequently retrieve a
    client pseudonym (PDN)
-   `person`: A JSON object with two properties: `age` (optional) and `name`
    (JSON object with optional name parts)
-   `sub`: a subject identifier string containing the auth session ID
