# Cowrie decoy files

- `base_fs.pickle`: the default filesystem shipped with Cowrie 3.1.1 (`cowrie/data/fs.pickle`,
  sha256 `c54b9d6d550db961fb003cd94760918e2dce36d87632b3cfcb1205665731f941`), BSD-3-Clause,
  see `COWRIE_LICENSE.rst`. `builder/render.py` copies it per decoy, removes Cowrie's
  fingerprints (`/.dockerenv`, the default user `phil`) and adds the agent-designed files.
  It is loaded with `pickle`, so only ever replace it with a file from a Cowrie release.
- `static/`: legacy template files for `plant_breadcrumb(template=...)`. The environment is now
  designed by the agent (build mode) and rendered by code; see `builder/`.
