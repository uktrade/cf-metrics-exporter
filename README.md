# cf-process-metrics-exporter

CloudFoundry Prometheus metrics exporter, limited in scope to only expose process metrics.


## Required environment variables

| Variable              | Description | Example |
| ---                   | ---         | ---     |
| `LOGIN_BASE`          | Base URL of the CloudFoundry UAA server, including a trailing slash | `https://login.london.cloud.service.gov.uk/`
| `API_BASE`            | Base URL of the CloudFoundry API server, including a trailing slash | `https://api.london.cloud.service.gov.uk/`
| `USERS__i__USERNAME`  | For any integer `i`, the username of a user with Audit permission on spaces for which to get metrics | _not shown_
| `USERS__i__PASSWORD`  | For any integer `i`, the password of a user with Audit permission on spaces for which to get metrics | _not shown_


The below environment variables are also required, but typically populated by PaaS.

| Variable        | Description | Example |
| ---             | ---         | ---     |
| `PORT`          | The port for the application to listen on | `8080`
