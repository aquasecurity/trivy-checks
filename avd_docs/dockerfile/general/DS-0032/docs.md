
"RUN instruction with a pipe should use 'set -o pipefail' to ensure that errors in any part of the pipe are caught.
If you are using a shell that does not support pipefail, consider switching to /bin/bash or /bin/ash."


### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.docker.com/build/building/best-practices/#using-pipes


