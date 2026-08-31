# Samples

No binaries are distributed in this repository.

Committing live malware to a public git repository gets the repository flagged,
triggers endpoint protection on every clone, and violates many organisations'
device policies. Use the hashes below.

| File | SHA-256 | Role |
|---|---|---|
| `RuntimeBroker.exe` | `cf0d4b3837b9a23fb46cbb0a90f5ecae6b7dcd5b1f13b9d4a5fe0de7cec85041` | stage 2, the subject of this analysis |
| `HowToFishTrainer.exe` | `b971a5c1915861d611bf56d718f084406325890e5f47d9a1f64e982481e3b2b8` | stage 1, trojanised game trainer |

Both are on VirusTotal. Look them up by hash; if you need the binary itself,
check MalwareBazaar for the same hash.

If you handle these: they are live. The stage-2 loader marks itself critical via
`RtlSetProcessIsCritical`, so force-terminating it on a real host will bugcheck
the machine. Detonate in a VM you are prepared to discard, or analyse under
emulation as this repository does.