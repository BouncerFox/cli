Phase 1 contract fixtures live in `cli/testdata/contracts/phase1` and are the canonical source for this workspace.

Run the local contract check from `cli/`:

`go test ./pkg/platform ./pkg/config ./pkg/upload -run 'Phase1|ExtractSkillMetadata' -v`

If you change any canonical fixture JSON in `phase1/`, refresh `phase1/manifest.json` in the same change so the recorded SHA-256 digests still match the fixture bytes.
