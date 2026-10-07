# macOS agent LaunchAgent

Copy `com.kmesh.agent.plist` to `~/Library/LaunchAgents/` after replacing both `REPLACE_WITH_USER` and `REPLACE_WITH_TARGET_ID`. Confirm `kmesh` is installed at `/usr/local/bin/kmesh` and the target agent credentials exist in the selected data directory.

Load it with:

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.kmesh.agent.plist
launchctl enable gui/$(id -u)/com.kmesh.agent
```

Remove it with `launchctl bootout gui/$(id -u)/com.kmesh.agent`.
