# CLI language and display guide

This guide covers human-readable kmesh command help, results, errors, and the
interactive admin shell. Command names, flags, API fields, and serialized values
remain compatibility interfaces.

## Language reference

CLI help, results, errors, and shell messages use English. They follow ASD-STE100
Issue 9 vocabulary and sentence rules. Review new output against the current
standard, dictionary, and project glossary.

The official [downloads page](https://www.asd-ste100.org/STE_downloads.html)
identifies Issue 9, January 2025, as the current edition. The
[official FAQ](https://www.asd-ste100.org/STE_faq.html) explains its controlled
vocabulary, restricted word meanings and parts of speech, and project-specific
technical nouns and verbs. A familiar word is not necessarily approved for
every use. Keep a project glossary; do not declare every software term exempt.

The [Issue 9 standard](https://www.asd-ste100.org/assets/files/ASD-STE100_ISSUE9.pdf)
gives these useful rules for CLI instructions:

- Use short instruction sentences, with at most 20 words.
- Give one instruction per sentence, except for simultaneous actions.
- Use imperative verbs for instructions.
- Put a necessary condition before the instruction it controls.
- Keep notes informational; put required actions in the instructions.
- Avoid noun groups longer than three words unless a technical term needs them.

For descriptive CLI prose, use 25 words as the sentence-length ceiling. A heading,
column label, command example, or machine value is not a prose sentence. Do not
remove necessary words or change a command identifier to meet a word count.

These are writing aids, not a substitute for the full standard. The
[STEMG guidance on tools](https://asd-ste100.org/STEsoftware.html) also explains
that automated checks cannot establish correctness or replace an informed
review.

## Project terminology

Use the same term for the same object in help, output, errors, and documentation.

| Term | Meaning in kmesh |
| --- | --- |
| user | A server account identified by its user ID. |
| platform role | The fixed `member` or `admin` value in `system_role`. It controls platform administration. |
| access group | A named set of users with the same target access needs. |
| grant | An access group's permission to connect to a target. The `grant` command gives this permission. |
| target | A registered machine reached through its target agent. |
| target ID | The stable identifier accepted by commands. A rename does not change it. |
| target name | The display name and source of the OpenSSH alias. |
| API token | A bearer credential used to authenticate API requests. |
| token ID | The identifier used to list or revoke an API token. It is not the credential. |
| token value | The secret JWT returned when an API token is issued. |
| data directory | The base path for local or server data. |
| agent state | The saved server address, credentials, device identity, and SSH settings for a target agent. |
| SSH public key | The public key registered for a user's public-key login. |
| key fingerprint | A digest used to compare public keys. It is not the key ID. |
| enrollment code | A one-time credential used to enroll a target agent. |
| enroll | Verb: enrolls, enrolled, enrolled. Use a one-time enrollment code to create agent credentials for a target on a server. |
| relay connection | One endpoint transport handled by the private relay. |
| SSH session | The session that can map to multiple relay connections. |

Preserve exact spellings for identifiers such as `--json`, `public-key`,
`ssh_connect`, `PrivateDirect`, and `KMESH_TOKEN`. Use human-readable labels around
these identifiers when useful. Existing command spellings remain valid even when
the surrounding prose uses a longer technical term.

## Wording checklist

- Start command descriptions with the action: "Show user accounts" or "Create an access group."
- Use active voice. State who or what failed when that information is available.
- Keep required arguments, units, defaults, and side effects explicit.
- Say whether an operation adds, removes, or replaces assignments. These actions differ.
- Keep IDs distinct from names, labels, and credential values.
- Prefer concrete results over a generic success message when the command has a useful result.
- Give an error's cause and a safe next action when known. Do not invent a cause.
- Keep security facts precise. "Offline" does not mean "disabled" or "not permitted."
- Use English for generated CLI prose. Preserve user data and third-party diagnostics as data.
- Avoid decorative punctuation, mixed-language labels, and redundant introductory text.

Examples of the intended style:

```text
Save this API token now. It is shown only once.
No SSH public keys.
The user does not exist.
If the token has expired, create a replacement token.
Set access groups for this user. To remove all groups, use an empty group ID list.
```

These examples illustrate project style. They are not individually certified
dictionary-compliance examples.

## Admin display review

The following criteria guide implementation and review; they do not imply that
every view provides every field.

- Put the object ID first and keep it complete and copyable. Never use an
  ambiguous shortened ID as an action target.
- Use stable column labels, predictable ordering, row counts, and explicit empty
  states. Keep absence, zero, unknown, and a failed lookup distinguishable.
- Show account state separately from target connectivity. A target can be enabled
  and offline, or disabled and online.
- Show token states accurately: revoked takes precedence over expired; active
  requires neither condition. State the time basis for displayed timestamps.
- Keep routine token views metadata-only. Show secret values only for the
  commands that issue them. Do not copy secrets into summaries or diagnostics.
- Prefer public-key fingerprints in compact relationship views. Keep the public
  key and its management ID distinguishable and available in the documented
  detailed or machine-readable output.
- Show the relationship that answers the administrator's question: a user's
  platform role and access groups, an access group's users and targets, or a target's granting groups.
  Distinguish configured grants from effective access and current connectivity.
- Do not present missing or failed join data as an empty relationship. Fail
  clearly, or mark partial results explicitly.
- Protect terminal output from control characters in names, labels, and server
  responses. Long text must not erase the meaning of nearby rows.
- Avoid one network request per displayed cell. Bound concurrency where used and
  document if a joined view is assembled from multiple, non-atomic reads.
- Keep read-only views read-only. A short display command must never issue a
  token, change permissions, or revoke a credential.
- Show a user's platform role and access groups in separate fields.
- Show access group IDs in grant tables and access path columns.
- State that platform roles control administration and access groups control SSH access.

## Aliases and compatibility

- Use the current canonical commands and flags. Add explicit aliases rather than
  accepting arbitrary command prefixes.
- Use each alias for one meaning at its command level. Prefer readable resource
  names in documentation and short aliases for repeated interactive use.
- Show aliases in help. Make shell completion recognize the same aliases as the
  one-shot parser, including action aliases after a resource alias.
- Preserve argument order, validation, normalization, and destructive semantics
  across aliases. Do not create a different operation behind a shorter spelling.
- Keep current JSON response fields stable within one protocol version. Change the
  protocol version when a required field or operation changes.
- Keep command data on stdout and diagnostics on stderr. `proxy` stdout carries
  only SSH bytes; `ssh-config` stdout must remain valid OpenSSH configuration.
- Keep JSON output valid and free of banners, table headings, or progress text.
- `show` displays matching records or a detail view.
- `list` displays every matching record.
- `create` adds a resource with a new ID.
- `delete` removes a resource and its dependent rows.
- `add` creates the named relationship.
- `remove` deletes the named relationship.
- `enable` permits new use of a resource; `disable` stops new use.
- `rename` changes a display name and keeps its stable ID.
- `issue` creates a one-time credential for the named target.
- `manage` selects and runs the administration commands for the named resource.

These are kmesh CLI command verbs. Use them only with the meanings above.
- Test help, aliases, completion, empty results, long labels, control characters,
  token expiry, secret exclusion, and existing invocation forms.
