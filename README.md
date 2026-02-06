# Link

## Favicons

### Automatic (default)

Run the updater to download site favicons into `favicons/` and rewrite the `favicon` column in `link2.csv`:

```bash
python scripts/update_favicons.py
```

By default, any row that is **not pinned** will be refreshed from the web.

### Forced local favicon (pinning)

Sometimes you want a specific entry to always use a local icon, even if `scripts/update_favicons.py` runs.

- Put your manual icon file under `favicons_forced/`
- Set the CSV row's `favicon` to point to it (e.g. `./favicons_forced/my_icon.ico`)

Example (`link2.csv`):

```csv
group,name,favicon,link
My,Router,./favicons_forced/tplink.ico,http://192.168.0.1
```

When `favicon` points under `./favicons_forced/`, the updater will **skip** that row and will not overwrite it.

You can change the pin directory:

```bash
python scripts/update_favicons.py --forced-dir favicons_forced
```
