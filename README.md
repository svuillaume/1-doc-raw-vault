# raw-vault (prototype)

An encrypted copy of 1-doc's `raw/` folder, meant for a **private** git repo. GitHub only ever holds unreadable files.

- **Master secret:** generate it with `python raw_vault.py genmaster` or `openssl rand -hex 32`. Never type a phrase of your own, and never paste it in a chat. Keep it out of git. In the repo it lives only as the Actions secret `VAULT_MASTER`.
- **Encrypt:** `python raw_vault.py encrypt ~/path/to/llm_wiki/raw vault` (unchanged files keep their bytes, so commits stay small).
- **Restore:** `python raw_vault.py decrypt vault ./raw-restored`.
- **Rotation:** monthly, by `.github/workflows/rewrap.yml` (or by hand: `python raw_vault.py wrap vault`). Only `vault/wraps/` changes. The previous month's wrap is kept as a grace period; older ones are deleted and refused.
- **Leaving the team:** change the master secret and run `encrypt` into a new vault with the new master; the old one stops working at the next wrap.
- **Tests:** `python -m pytest -q`.

Not part of the Chrome plugin yet.

- ** git add vault && git commit -m "Add encrypted raw sources" && git push **

```
Use genmster or openssl rand -hex 32 to update VAULT_KEY

cd ~/tmp/personal_project/new_wiki/raw-vault
export VAULT_MASTER=‘$VAULT_MASRTER’
../llm_wiki/venv/bin/python raw_vault.py encrypt ../llm_wiki/raw vault
git add vault && git commit -m "Add encrypted raw sources" && git push

```
