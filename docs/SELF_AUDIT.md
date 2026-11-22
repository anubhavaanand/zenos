# Self-audit

Before an independent audit, ZENOS audits its own source with Cloudflare's open-source
[security-audit-skill](https://github.com/cloudflare/security-audit-skill), pinned to commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`
after reading every file of it. It runs at least three times, and again before every release. Code it has to run is
run only inside ZENOS's own sandbox (bubblewrap with every namespace unshared, its seccomp filter, no network, an
unprivileged user, size-capped memory, files and time). What it finds is fixed with tests before it goes in; what
it found is published once the fixes are released (SECURITY.md).

## Run 1 (source at `16c844b`, fixed in 0.2.0, published 6 Nov 2026)

28 weaknesses found; 27 fixed with tests in commit `8b65896`, which the 0.2.0 image is built from; the last one
needed a change of design and is fixed in the source after 0.2.0 (the last row). "Who" is who could use it before the fix.

| Part | Who | What could happen | Fix |
|---|---|---|---|
| Messenger, the PC's local port | another account on the PC, or a web page open in a browser (DNS rebinding, cross-site requests) | use the messenger as the user: read, send, link devices, answer approvals | the port answers only the PC's own window: the request must name 127.0.0.1/localhost at that port, carry no other site's Origin, and show a key written to a file only the account can read |
| Messenger relay, request bodies | anyone who can reach the relay | stop the relay with a body that is not JSON, or exhaust memory with a large one | bodies capped at 1 MiB; bad JSON is a 400, not a crash |
| Messenger relay, who an account is | any account on the relay | claim any organization and clearance (L5) in its own key bundle | name, organization and clearance come from the relay's directory, kept by its administrator; an unlisted account is L1 |
| Messenger relay, new channels | any account | create a channel with other people already in it, above its own clearance | a new channel holds only its creator, at most at the creator's clearance; others come in through the checked invitation |
| Messenger relay and federation, message levels | any account | send or fetch a message marked above the sender's or recipient's clearance | the relay refuses levels above either clearance |
| Federation, safety-check answers | anyone who can reach the relay | fill the "safe / need help" counts with made-up answers | an answer must be signed by a device registered on the relay; one per person |
| Messenger window | another device in a conversation | run script in the window through a reaction, a level field or a message kind | what another device sends is checked when it arrives (known kinds, level 1-5, plain short emoji) and escaped in the window |
| Guard, pre-filed operations | the desk user | reset how much of an approved plan was used, extend its time, or point the plan file at a system file that the guard (root) then overwrites | the guard keeps the use count itself, ends a plan at the earliest of its limits, and reads the user's files without following links |
| Guard, what keeps running during a stop | the desk user | keep a program running while the PC is stopped by naming it like the messenger or the display | only programs only root can change are kept running, checked by the program the kernel runs, not by its name |
| Guard, the USB folder | the desk user | have root copy a linked system file into quarantine, or stop the guard with a pipe named like a sealed file | links and pipes are not followed; a file is copied without following links |
| Network cut while an L4+ file is open | the desk user | lift the cut by writing 0 to a file in their own folder | the cut holds while the process given the plaintext, or any process it started, is alive; the file can only add to it |
| AI guard | any account on the PC | make the guard learn an unlimited list of addresses | at most 20 new addresses per account per hour and 256 in all, host names only |
| Key agent, AI guard not running | anyone who can stop it | open L3+ files while the AI guard is stopped | when the AI guard is installed and not running, L3+ files stay closed |
| Approval page (demo) | another account on the PC, or a web page | approve as an officer, or inject markup through a request file | the page answers only who shows its key (a file only the account can read); every shown value is escaped or a number |
| Audit node | an enrolled PC | stop a request handler with a record that is not an object | every record is checked to be an object first |
| ZENOS Data, storage reads | someone who saw one signed read | replay it within the time window | each read carries a nonce that is refused the second time |
| ZENOS Data, sign-in tokens | a server holding a person's token | use it at another server | a token names the server it was made for and lives at most an hour |
| Vulnerability watch, mitigations | whoever obtained the officers' signatures on a malformed record | write extra lines into a system setting file | the record's id and CVE list are accepted only in their plain shapes |
| Package wrapper (dpkg) | an administrator tricked into installing | install a package that skips the checks by giving it another name, or a whole folder with -R | every file argument is checked as a package; -R is refused while checks are on |
| API model pins | whoever can change the model setting | point a pinned model at another port, plain HTTP or another path of the same host | the pin covers the whole address; only https |
| App windows | a page shown inside an app window | use the app's bridge to read files anywhere in the home folder (keys, settings) | the bridge answers only the app's own page; paths are held to the person's folders (no hidden folders), drives, and the opened file |
| Office AI relay | a web page open in a browser | make the relay call any address, including local services | only the app's own page, with a JSON request; only https (http only for this PC) |
| Storage grid, manifests | another peer | place a different manifest under a file's id first and block the real one | the id is bound to the uploader's key and the manifest is signed by it |
| Storage grid, no administrator key | a peer that says nothing | be treated as cleared for L5 | a peer that claims nothing is L1 |
| Repository automation | a step running the repository's code | use a token that can write to the repository | collecting and publishing are separate jobs; the job with the write token runs none of the repository's code |
| Feedback board, AI answers | someone posting on the board | steer the AI reviewer into posting links under its name | an AI answer with a link or address waits for a maintainer |
| Credentials vault (fixed after 0.2.0, in the source) | a program of the same user | pose as the browser or messenger and ask for a password after the phone approval | a root launcher (`zenos-launchd`) starts the browser and the messenger and records each start; the vault serves only a recorded process, which other programs of the user cannot attach to (`ptrace_scope = 1`) |

## Run 2 (source at `5c2a979`, fixed in 0.2.1, published 23 Nov 2026)

Six hunters, each on one area (the messenger, the supply chain and feedback board, the root services, the server
side, the apps and storage), with run 1's findings known to them. 21 weaknesses confirmed and fixed with tests; 7
more that the run pointed at but did not confirm were checked and fixed too (five of them with tests). Published with
0.2.1, which carries the fixes.

The fixes, by part (commit `548cbb3`). The run's own report kept 21 as confirmed and 7 as pointed at; the rows below
follow the fixes, one row per weakness or per group of the same kind in one place. "Who" is who could use it before
the fix.

| Part | Who | What could happen | Fix |
|---|---|---|---|
| Approval page (demo) | any other local server the person's browser visits | collect the page's key, which was kept in a cookie (a browser sends a 127.0.0.1 cookie to every port on 127.0.0.1) | the key travels only in the address and in each form, never in a cookie; no referrer, no caching |
| Office apps, messenger window | another account on the PC | listen on the app's port first, so the window shows its page and receives what the person types (or the messenger's key) | the window opens only when the kernel says the listening socket belongs to this person (`zenos_portcheck.py`); logs move out of the shared `/tmp` |
| Approvals, match codes | the desk user | try every 4-digit match code until one fits | after 5 wrong codes the request is refused for good |
| Apps and picker, level folders | the desk user | make a file count as lower or higher level by putting it in a folder elsewhere named like a level folder | only the real Desktop level folders count, by the file's real path |
| Built-in browser, downloads | a web site | choose a download name that writes outside Downloads, as a hidden file, or through a link left there | only a plain printable name is kept; an existing name or link is never written through |
| Feedback board, proposals | someone posting on the board | keep a held post's text in a proposal's title and in the AI's grouping | a held post leaves its proposal, which is rebuilt from visible posts or withdrawn; only checked posts are grouped |
| Feedback board, sign-in | someone who sends a sign-in link | sign another person's browser in as themselves (login CSRF) | the sign-in state is also kept in a cookie of the browser that started it and checked at the callback |
| Feedback board, AI answers | someone posting on the board | get a link past the check with spelled-out or full-width dots, addresses or schemes | the check reads the answer after Unicode normalization and catches those forms; such an answer waits for a maintainer |
| Messages, approvals from a phone | a device answering through the relay | claim that a passkey answer was made near the PC | an answer from afar is always marked as relayed |
| Messages, linked phone | a linked phone that is not government-issued | read or change drafts (text typed in L3+ conversations), saved items and do-not-disturb | such a phone sees and changes only what is read |
| Image build | whoever controls the Node.js archive | have its key trusted by apt for every archive on the installed system | the key is valid only for that archive (kept in the ZENOS package), no second global copy |
| Storage, repair | a peer in the storage grid | stop repair for every file with one malformed manifest, or fill a node's disk with manifests | manifests have a fixed shape and size and count against the node's limit; one bad file is skipped |
| Passkey approvals | someone who saw an approval | send the same passkey signature again with another "near" claim (the claim is not signed and many phones keep the counter at 0) | each signature counts once, whatever the outcome |
| ZENOS Data | another enrolled server | open another server's records with a copy of a record and a table of the same name | shares and records are bound to the server that wrote them; each server's records are kept apart |
| ZENOS Data, data peers | anyone who can reach the port | fill the ledger and state with unsigned requests | an unsigned or unknown request leaves no line, decision or state (a counter only) |
| Sandbox for code the audit runs | the program being run | take the PC down by memory, disk, processes or output | memory, file size, CPU time, processes, `/tmp` and kept output are capped |
| Release ledger | one audit node of several | stop updates or confuse the check with a record of the wrong shape | records of the wrong shape are skipped; the majority still decides; a failure of the check is a refusal, never a crash |
| Package installs (`zenos-dpkg`) | someone who can run dpkg with a file | give dpkg a pipe or device, or a file after `--`, so it reads bytes other than those checked | only regular files are installed, checked again on the open file; every argument after `--` is a file |
| AI guard | any account on the PC | teach a name that points at the ZENOS servers or an administrator-listed service, cutting them off | learned entries are host names only and never block those addresses |
| Audit node | a PC enrolled on it | reach another PC's file through a chain name; hide that a PC went silent by sending an old batch again | names cannot join machine and chain; a PC counts as heard from only by a fresh, signed, newer status |
| Guard, the USB exit | the desk user | take files out unseen with a hidden name, a temporary name or a subfolder | every file anywhere inside the exit counts, by content, whatever its name |
| Guard, what keeps running | the desk user | pass a program off as a ZENOS service with `-c` code ending in a comment that names one | only the exact shape of a ZENOS start counts: no `-c`, `-m` or code from the environment |
| Guard, signatures | the desk user | count one officer twice by spelling the name differently, or sign their own request | distinct officers only, never the requester |
| Key agent | the desk user | hand the socket that receives L4+ plaintext to another process, which then escapes the network cut | every process holding the client end of the connection counts as holding the plaintext |
| Network sentinel | the desk user | lift the cut by starting a child and exiting | the cut holds while any holder or its children are alive; the user's own flag can only add to it |
| Sign-in ledger | any account on the PC | write made-up sign-ins into the root ledger through the journal | only journald's own fields count; sign-ins come from systemd-logind, failed passwords from PAM in a root process |
| Trust watch | an account that can change a file it runs | have root run a changed program | it runs only programs whose file and folders only root can change |

## Run 3 (source at `7eda2eb`, fixed in 0.2.1, published 23 Nov 2026)

Six hunters again: the messenger, the root services, the server side, the apps, the supply chain and public
infrastructure, and one whose only task was to break run 2's fixes. 10 weaknesses confirmed and 7 more found by
reading the source, all fixed with tests; 4 further points tightened. One hunter's review of part of the messenger's
federation code was cut short and went into run 4. Published with 0.2.1, which carries the fixes.

The fixes, by part (commit `aef9a53`), one row per weakness or per group of the same kind in one place.

| Part | Who | What could happen | Fix |
|---|---|---|---|
| Office app windows | a document with a link in it | take the window, with the file's content and the level clipboard, to another page | the window stays on its own app; links open in the browser |
| App shell, native commands | a page shown in an app window | pass a path outside the allowed folders to commands whose paths were not checked (Studio export, AI image, font subsetting, file exists) | every path argument of those commands goes through the same folder check |
| Feedback board, AI text | someone posting on the board | get a domain past the check written as "x [.] com", "x dot com" or a messaging service by name, including in the hold reason shown to everyone | those forms are caught; the hold reason gets the same check |
| Feedback board, votes | a banned or busy account | change votes after a ban, or fill the database with toggles | a banned account changes nothing; at most 60 changes per account |
| Messages, linked phone | a linked phone that is not government-issued | read or answer L3+ meetings and content of message kinds a blank-list missed | above L2 such a phone gets only who, when and what kind; content fields are dropped; it cannot change or answer L3+ items |
| Messages, passkey answers | a device answering through the relay | pass on an answer that the PC side reads differently from the phone side | an answer that is not plain JSON with the marker exactly 1 is not passed on |
| Messenger relay, channel level | a channel's owner | let people in at L1 and then raise the channel to L4, keeping members not cleared for it | raising a level is refused while any member is not cleared or is outside the organization |
| Storage, repair | a dishonest storage node | claim shards it does not hold, so every file looks whole while honest copies are lost | spot checks ask for the shard itself; a node caught is not believed for an hour |
| Red alerts | another account on the PC | take the desk account's messenger port and receive the alert and the messenger's key | the alert goes only to a messenger that runs as the desk user |
| Passkey approvals | anyone who can reach the guard | have a number or marker read differently by Python and JavaScript (NaN, `true` for 1); push a real signature out of the list with made-up ones | plain JSON only, the marker exactly 1; only signatures that verify are remembered |
| Approvals | another account on the PC | lock a request for the next officer by sending an approval already given again with wrong codes | a given approval does not count toward the wrong-code limit |
| Package installs (`zenos-dpkg`) | someone who can run dpkg | slip a file past the check as the value of an option, or as a name that is missing or a folder at check time | options that take a value are known; an install takes existing regular package files only |
| Audit node, size | a PC enrolled on it, or a person on it through their own ledger | fill the node's disk | each PC has a limit per chain; refused batches are noted once an hour |
| Audit node, alerts | a person on an enrolled PC | raise forged alerts from their own ledger, hiding a real one for the quiet time | alerts come only from the root-written guard ledger |
| Audit node, reads | anyone who can reach its port | read which files were opened by whom on which PC, and which PCs are stopped | those answers go only to an enrolled reader (the key service) with a signed, fresh request; operators enroll the key service once |
| Password vault | the person whose browser it serves | load other modules into the browser or messenger through `NODE_PATH` | a start with `NODE_PATH` is not served |
| ZENOS Data, storage peers | one taken-over server | fill a storage peer for every other server | each server has its own share of the peer |
| Guard, bulk reads | the desk user | read many sealed files unseen by renaming them off `.zen` | a sealed file counts by its content, whatever its name |
| Release signing | whoever carries the file to an officer | have an officer sign a package other than the one they think | the record is shown and checked against the officer's own copy (`--deb`), or confirmed by typing the start of its SHA-256 |

## Found while fixing run 3 (fixed in 0.2.1, published 23 Nov 2026)

Found in the same parts of the code while fixing run 3's findings, not by a run; fixed with tests in the commits named.

| Part | Who | What could happen | Fix |
|---|---|---|---|
| Network sentinel, restarts (`70f34bb`) | the desk user | have a child of an L4+ holder forgotten when the sentinel restarts, so its connections are no longer cut | the children found so far are kept in a file only root writes and read again at start |
| Audit node, intake (`ed012a0`) | anyone who can reach the node | make it read batches of up to 32 MiB into memory, many at once, before anything is checked | the PC names itself first; only an enrolled machine's batch is read, at most 8 at a time, and a slow sender is dropped |
| Messenger relay, one-time prekeys (`f16de74`) | any account on the relay | empty another account's one-time prekeys by asking again and again | each account may use up a limited number per hour; past that it gets the bundle without one |
| Key service, rate counts (`0e2e46a`) | anyone who can send it requests | grow its memory without limit with counts for keys never seen again | counts with nothing left in the window are dropped |
| Phone sign-in (`5202e9b`) | the process between the PC and the phone | show the phone one site, account or key and have the passkey sign another | the phone works out the signed digest itself and shows and uses only what is in it |
| Messages, push (`619dbc8`) | a linked device | have the PC send requests to any address (the local network, another port) as a "push subscription"; have a notification open another site | only HTTPS addresses at a browser maker's push service with keys of the standard sizes; a notification opens a page of this app only |
| Messages, calls (`5f97ddd`) | anyone who can message the person | switch, and so cut off, a call by sending a call key | a key counts only from someone in the call who belongs to its conversation, for this call, in the shape of a key |
| Federation, intake (`239911b`) | anyone who can reach the relay | make it read large bodies before anything is checked | before a body is read: a listed organization, a recent request and a size its kind needs |
| Vulnerability watch (`3c0eebc`) | whoever can change a mitigation record after it was applied | add CVEs to an applied record, which then counted as mitigated | a record counts only while its digest is the one that was signed and applied |
| Key agent and sentinel (`7389ae8`) | the desk user | start a child from an L4+ holder and leave it between two looks of the sentinel | each holder is put in a cgroup of its own; everything it starts stays there |
| Network sentinel, raw sockets (`70f34bb`) | root or a program with CAP_NET_RAW | send frames below the packet filter with a packet or XDP socket | such sockets are frozen unless held by a listed network program; any XDP socket is |

## Run 4 (source at `ce17f1e`, fixed in 0.2.1, published 23 Nov 2026)

The run before a release, as a quick scoped pass: the code changed since run 3, plus the messenger's federation code in
full (cut short in run 3). Four reconnaissance agents, five hunters (messenger server, messenger page, root services,
release and CI, server side and app shell), one final coverage critic and five verifiers, none of which had hunted
what it checked. No code was run inside the audit (the sandbox's memory and disk limits could not be enforced in the
environment it ran in), so the verifiers kept all 17 candidates as needing validation, with exact blockers, rather
than confirming any. All 17 are fixed in the source with tests; for eight, the test written for the fix fails on the
audited source. Six further areas in scope that the critic named go into the next run. Published with 0.2.1, which
carries the fixes.

The 17 candidates and their fixes (commits `66b7d20` and `c18ac28`). The verifiers could not run code in the audit, so
none is marked confirmed there; the eight marked "test fails before" have a test that fails on the audited source and
passes after the fix.

| Part | Who | What could happen | Fix |
|---|---|---|---|
| App shell | a local HTML or SVG file dropped on an app window | become the app's page with access to local files, since the bridge checked only the top-level address | the window shows only its own page (or a blank one), ignores new windows, and drops are cancelled; tested |
| Messages, channel calls (test fails before) | someone in the same organization who is not in the channel | plant a channel call's key, level or end marker | a message naming a channel counts only from a member of that channel |
| Federation, intake | anyone who can reach the relay | make it check member-list signatures and start the decision program for unsigned, badly signed or stale requests | stale, replayed and badly signed requests are refused before any of that; member entries are cached; responses read with a size cap |
| Messenger relay, accounts (test fails before) | anyone who can reach the relay | register `__proto__` and so pass as enrolled accounts with made-up clearance | account maps have no prototype; account names have a fixed shape |
| Messenger relay, one-time prekeys (test fails before) | any account on the relay | still empty another account's one-time prekeys (the budget of 30 was more than the 20 a device publishes) | limits per requester and target, per target and per requester; a handed-out prekey is never offered again; clients top up below 20 |
| Messenger relay, phone numbers (test fails before) | anyone who can reach the relay | bind a phone number to an account not yet registered and later move it to their own device | registration needs an existing account and the device's own signature or the account's own number; at most 3 codes per number per hour |
| Messages page, times (test fails before) | anyone who can message the person, a federated organization included | hide the rest of a conversation with a crafted time | a time that is not a time is replaced by when it arrived; times are escaped where drawn |
| Messages page, events (test fails before) | someone in the same organization | stop the person's Messages page from drawing, even after reload, with one malformed event | events of the wrong shape are dropped and written to the audit log |
| Messages page, relay fields (test fails before) | the relay | put markup into the page through an approval level or channel history | those fields are escaped |
| Storage, repair | a dishonest storage node | stop repair of the files it leads by holding a shard and doing nothing | if a file stays incomplete, the next holder in rank takes over after a grace period; tested |
| Red alerts (test fails before) | the desk user | have root write through links in the desk user's folder, with a chosen recipient path | the alert files are written as the desk user, not as root; recipient names have a fixed shape |
| Audit node, intake | a PC that names an enrolled machine | make the node read and parse up to 32 MiB per request before any signature | the PC proves its key over a fresh, single-use proof before the body is read; the whole body must arrive within 60 s; tested |
| ZENOS Data, key peers (test fails before) | an enrolled server | exceed a share rate limit with requests at the same moment | counting, deciding and recording happen under one lock per server |
| Guard, pre-filed plans | a desk user with an approved plan | use one officer approval on several PCs | a plan names the PC it was filed on and is honoured only there; tested |
| Key agent and network cut | a program holding L4+ plaintext | use the network before the cut is in force, or through connections opened earlier | L4+ is opened only once the sentinel confirms the cut; the holder's account sends nothing, on old connections too; tested |
| Key service, replay nonces | one rooted PC | stall key release for every PC with nonces | nonces are kept per PC with a fixed bound and dropped in order; tested |
| Release signing, mitigations | whoever carries a mitigation record to the officers | have officers sign a root sysctl or modprobe change they were not shown, with an empty confirmation | the mitigation's id, CVEs and action are shown; signing needs 16 characters of its record digest; tested |

Changes others may notice are in the [CHANGELOG](../CHANGELOG.md) under 0.2.0 and 0.2.1.
