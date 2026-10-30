//go:build linux

package freshstore

// These public synthetic bytes pin the local grammar; they are not proof formats or quotas.
const literalObjectA = `{"data":"eA==","installation_id":"i","kind":"freshstore-object/1","name":"a","object_kind":"blob","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"g:1111111111111111111111111111111111111111111111111111111111111111","revision":1,"schema":"freshstore/1","scope":"s"}`
const literalObjectADigest = "ee36935a85eab4b9e87cdbfcb10228a4343f55cbd6fbe753d309faa493915a21"
const literalObjectB = `{"data":"eXo=","installation_id":"i","kind":"freshstore-object/1","name":"b","object_kind":"blob","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"g:1111111111111111111111111111111111111111111111111111111111111111","revision":1,"schema":"freshstore/1","scope":"s"}`
const literalObjectBDigest = "6b531e60bb6c16159c16fbb2c31cc3319ecd31942b7e7ab28e10da33b9ad8936"
const literalManifestA = `{"dependencies":[{"digest":"ee36935a85eab4b9e87cdbfcb10228a4343f55cbd6fbe753d309faa493915a21","encoded":300,"kind":"blob","name":"a","raw":1,"raw_digest":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}],"installation_id":"i","kind":"freshstore-manifest/1","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"g:1111111111111111111111111111111111111111111111111111111111111111","revision":1,"schema":"freshstore/1","scope":"s"}`
const literalManifestADigest = "8371a8459fdd568eb799ca504fdf21cf3a8ae2a7144b65b61e8f025f0cd82323"
const literalManifestAb = `{"dependencies":[{"digest":"ee36935a85eab4b9e87cdbfcb10228a4343f55cbd6fbe753d309faa493915a21","encoded":300,"kind":"blob","name":"a","raw":1,"raw_digest":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"},{"digest":"6b531e60bb6c16159c16fbb2c31cc3319ecd31942b7e7ab28e10da33b9ad8936","encoded":300,"kind":"blob","name":"b","raw":2,"raw_digest":"68d617d6d2ee5715af77d9795566cfaba9a43a33d14cbbc95831c507c935bad1"}],"installation_id":"i","kind":"freshstore-manifest/1","pin":"0000000000000000000000000000000000000000000000000000000000000000","previous":"g:1111111111111111111111111111111111111111111111111111111111111111","revision":1,"schema":"freshstore/1","scope":"s"}`
const literalManifestAbDigest = "3ef2705e33481d903e1696d805fd20af84e80a011c62eef512c180565900b705"
const boundaryRaw = 786210
const boundaryName = "a"
const boundaryDigest = "74b5f31cbae10bdf56505562090ee0171c795fa0649b860dc73c1d3abd7e6dc8"
const overBoundaryDigest = "d1719d1af2d43f9e15d00065ebe2399de057cc75f9f49e9cc98ee8ac04df75b6"
