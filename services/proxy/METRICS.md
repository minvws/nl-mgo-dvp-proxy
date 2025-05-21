# Purpose of this document
This document is used to track all metrics that are measured in the `proxy` service.
The {{HOST}} parameter is a default parameter that is used to identify the environment the proxy is running in (e.g. localhost,staging,production)

| METRIC KEY                                              | METRIC TYPE        | DESCRIPTION                                     | METRIC VARIABLES | Variables description                                        | Bucket class       |
| ------------------------------------------------------- | ------------------ | ----------------------------------------------- | ---------------- | ------------------------------------------------------------ | ------------------ |
| stats.timers.{{HOST}}.{{dva}}.latency                   | timer              | used to calculate the latency in calls to dva's | dva              | the DVA being targeted                                       |                    |
| stats.{{HOST}}.{{dva}}.dva_call_count                   | counter            | used to count ALL outgoing requests to a DVA    | dva              | the DVA being targeted                                       |                    |
| stats.$environment.{{DVA}}.dva_response_size.{{bucket}} | counter (bucketed) | used to count incoming DVA response sizes       | dva, bucket      | the DVA being targeted, the bucket that the value falls into | ResponseSizeBucket |

