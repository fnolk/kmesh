# macOS agent LaunchAgent

Copy `com.kmesh.agent.plist` to `~/Library/LaunchAgents/`. Replace `REPLACE_WITH_USER` and `REPLACE_WITH_TARGET_ID`. Enroll the target with the same data directory:

```sh
kmesh --data-dir "$HOME/Library/Application Support/kmesh" \
  --server-addr mesh.example.com \
  agent enroll --target-id <target-id> --enrollment-code '<enrollment-code>'
```

The enrollment command creates the target state. Confirm that `kmesh` is installed at `/usr/local/bin/kmesh`, then load the LaunchAgent.

Load it with:

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.kmesh.agent.plist
launchctl enable gui/$(id -u)/com.kmesh.agent
```

Remove it with `launchctl bootout gui/$(id -u)/com.kmesh.agent`.
